"""SSH client pour interroger Fail2ban via fail2ban-client."""
from __future__ import annotations

import io
import logging
import re
from typing import Any

import paramiko

from .const import AUTH_METHOD_KEY, AUTH_METHOD_PASSWORD

_LOGGER = logging.getLogger(__name__)


class Fail2banSSHClient:
    """
    Gère la connexion SSH et les commandes fail2ban-client.

    Supporte deux méthodes d'authentification :
      - AUTH_METHOD_PASSWORD : mot de passe (peut aussi être réutilisé pour sudo)
      - AUTH_METHOD_KEY      : clé privée (PEM/OpenSSH), avec passphrase optionnelle
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        auth_method: str = AUTH_METHOD_PASSWORD,
        password: str | None = None,
        private_key: str | None = None,
        key_passphrase: str | None = None,
        use_sudo: bool = False,
        timeout: int = 10,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._auth_method = auth_method
        self._password = password or ""
        self._private_key = private_key or ""
        self._key_passphrase = key_passphrase or None
        self._use_sudo = use_sudo
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Connexion
    # ------------------------------------------------------------------

    def _get_pkey(self) -> paramiko.PKey:
        """
        Charge la clé privée depuis la chaîne stockée.
        Essaie les formats dans l'ordre : Ed25519, ECDSA, RSA, DSS.
        Lève ValueError si aucun format ne correspond.
        """
        key_str = self._private_key.strip()
        passphrase = self._key_passphrase

        key_types: list[type[paramiko.PKey]] = [
            paramiko.Ed25519Key,
            paramiko.ECDSAKey,
            paramiko.RSAKey,
            paramiko.DSSKey,
        ]

        last_exc: Exception | None = None
        for key_cls in key_types:
            try:
                return key_cls.from_private_key(
                    io.StringIO(key_str), password=passphrase
                )
            except (paramiko.SSHException, ValueError, UnicodeDecodeError) as exc:
                last_exc = exc

        raise ValueError(
            f"Format de clé privée non reconnu ou passphrase incorrecte : {last_exc}"
        )

    def _get_client(self) -> paramiko.SSHClient:
        """Crée et retourne un client SSH connecté selon la méthode d'auth."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict[str, Any] = {
            "hostname": self._host,
            "port": self._port,
            "username": self._username,
            "timeout": self._timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }

        if self._auth_method == AUTH_METHOD_KEY:
            connect_kwargs["pkey"] = self._get_pkey()
        else:
            connect_kwargs["password"] = self._password

        client.connect(**connect_kwargs)
        return client

    # ------------------------------------------------------------------
    # Exécution de commandes
    # ------------------------------------------------------------------

    def _run_command(
        self, client: paramiko.SSHClient, command: str, needs_sudo: bool = True
    ) -> str:
        """
        Exécute une commande SSH et retourne la sortie stdout.

        needs_sudo : True = applique sudo si use_sudo est activé (commande fail2ban-client)
                     False = pas de sudo ( commandes standard : which, test, etc...)
        """
        apply_sudo = self._use_sudo and needs_sudo
        if apply_sudo:
            if self._auth_method == AUTH_METHOD_PASSWORD and self._password:
                # On peut piper le mot de passe à sudo
                safe_pwd = self._password.replace("'", "'\\''")
                command = f"echo '{safe_pwd}' | sudo -S {command}"
            else:
                # Avec clé SSH : sudo doit être configuré NOPASSWD
                command = f"sudo {command}"

        # Masque le mot de passe dans les logs si présent
        log_cmd = command
        if self._password:
            log_cmd = command.replace(self._password, "***")
        _LOGGER.debug("Exécution commande SSH: %s", log_cmd)

        _, stdout, stderr = client.exec_command(command, timeout=self._timeout)
        output = stdout.read().decode("utf-8").strip()
        error = stderr.read().decode("utf-8").strip()

        error_filtered = "\n".join(
            line for line in error.splitlines()
            if not line.startswith("[sudo]") and "password for" not in line
        )
        if error_filtered:
            _LOGGER.debug("Stderr: %s", error_filtered)

        return output

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    def test_connection(self) -> str | None:
        """
        Teste la connexion SSH et la présence de fail2ban-client.
        Retourne None si tout est OK, sinon un code d'erreur string.
        """
        try:
            client = self._get_client()
            try:
                output = self._run_command(client, "which fail2ban-client", needs_sudo=False)
                if not output:
                    return "fail2ban_not_found"
                self._run_command(client, "fail2ban-client ping", needs_sudo=True)
                return None
            finally:
                client.close()
        except paramiko.AuthenticationException:
            return "invalid_auth"
        except ValueError:
            return "invalid_key"
        except (paramiko.SSHException, OSError):
            return "cannot_connect"
        except Exception:  # noqa: BLE001
            return "unknown"

    def get_all_data(self) -> dict[str, Any]:
        """
        Récupère toutes les données Fail2ban via SSH.
        Retourne un dict structuré avec les infos globales et par jail.
        """
        data: dict[str, Any] = {
            "jails": [],
            "jails_count": 0,
            "jails_data": {},
            "version": None,
            "status": "unknown",
            "auth_method": self._auth_method,
        }

        try:
            client = self._get_client()
            try:
                version_out = self._run_command(client, "fail2ban-client version")
                data["version"] = version_out.strip() if version_out else "N/A"

                ping_out = self._run_command(client, "fail2ban-client ping")
                data["status"] = "running" if "pong" in ping_out.lower() else "stopped"

                if data["status"] != "running":
                    return data

                status_out = self._run_command(client, "fail2ban-client status")
                jails = _parse_jails_list(status_out)
                data["jails"] = jails
                data["jails_count"] = len(jails)

                for jail in jails:
                    jail_out = self._run_command(
                        client, f"fail2ban-client status {jail}"
                    )
                    data["jails_data"][jail] = _parse_jail_status(jail_out)

            finally:
                client.close()

        except paramiko.AuthenticationException:
            _LOGGER.error("Erreur d'authentification SSH vers %s", self._host)
            data["status"] = "auth_error"
        except ValueError as err:
            _LOGGER.error("Clé privée invalide vers %s: %s", self._host, err)
            data["status"] = "auth_error"
        except (paramiko.SSHException, OSError) as err:
            _LOGGER.error("Erreur SSH vers %s: %s", self._host, err)
            data["status"] = "connection_error"
        except Exception as err:  # noqa: BLE001
            _LOGGER.exception("Erreur inattendue Fail2ban: %s", err)
            data["status"] = "error"

        return data


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_jails_list(output: str) -> list[str]:
    for line in output.splitlines():
        if "Jail list:" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                raw = parts[1].strip()
                if raw:
                    return [j.strip() for j in raw.split(",") if j.strip()]
    return []


def _parse_jail_status(output: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "filter_currently_failed": 0,
        "filter_total_failed": 0,
        "filter_file_list": [],
        "actions_currently_banned": 0,
        "actions_total_banned": 0,
        "actions_banned_ips": [],
    }

    int_fields = {
        "Currently failed": ("filter_currently_failed", int),
        "Total failed": ("filter_total_failed", int),
        "Currently banned": ("actions_currently_banned", int),
        "Total banned": ("actions_total_banned", int),
    }
    list_fields = {
        "File list": "filter_file_list",
        "Banned IP list": "actions_banned_ips",
    }

    for line in output.splitlines():
        clean = re.sub(r"^[\|\`\- ]+", "", line).strip()

        for label, (key, cast) in int_fields.items():
            if clean.startswith(label + ":"):
                val = clean.split(":", 1)[1].strip()
                try:
                    result[key] = cast(val)
                except (ValueError, TypeError):
                    pass
                break

        for label, key in list_fields.items():
            if clean.startswith(label + ":"):
                val = clean.split(":", 1)[1].strip()
                if val:
                    result[key] = [v.strip() for v in val.split() if v.strip()]
                break

    return result
