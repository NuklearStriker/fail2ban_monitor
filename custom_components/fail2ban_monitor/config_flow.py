"""Config flow pour Fail2ban Monitor."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectOptionDict,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import (
    AUTH_METHOD_KEY,
    AUTH_METHOD_PASSWORD,
    CONF_AUTH_METHOD,
    CONF_KEY_PASSPHRASE,
    CONF_PRIVATE_KEY,
    CONF_SCAN_INTERVAL,
    CONF_USE_SUDO,
    DEFAULT_PORT,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_USE_SUDO,
    DOMAIN,
)
from .ssh_client import Fail2banSSHClient

_LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schémas
# ---------------------------------------------------------------------------

STEP_BASE_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_AUTH_METHOD, default=AUTH_METHOD_PASSWORD): SelectSelector(
            SelectSelectorConfig(
                options=[
                    SelectOptionDict(value=AUTH_METHOD_PASSWORD, label="Mot de passe"),
                    SelectOptionDict(value=AUTH_METHOD_KEY, label="Clé privée SSH"),
                ],
                translation_key="auth_method",
            )
        ),
    }
)

STEP_AUTH_PASSWORD_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PASSWORD): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD)
        ),
        vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
            int, vol.Range(min=10, max=3600)
        ),
        vol.Optional(CONF_USE_SUDO, default=DEFAULT_USE_SUDO): bool,
    }
)

STEP_AUTH_KEY_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PRIVATE_KEY): TextSelector(
            TextSelectorConfig(
                type=TextSelectorType.TEXT,
                multiline=True,
            )
        ),
        vol.Optional(CONF_KEY_PASSPHRASE): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD)
        ),
        vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
            int, vol.Range(min=10, max=3600)
        ),
        vol.Optional(CONF_USE_SUDO, default=DEFAULT_USE_SUDO): bool,
    }
)

OPTIONS_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
            int, vol.Range(min=10, max=3600)
        ),
        vol.Optional(CONF_USE_SUDO, default=DEFAULT_USE_SUDO): bool,
    }
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _build_client(base: dict[str, Any], auth: dict[str, Any]) -> Fail2banSSHClient:
    """Construit le client SSH depuis les données des deux étapes."""
    auth_method = base[CONF_AUTH_METHOD]
    return Fail2banSSHClient(
        host=base[CONF_HOST],
        port=base.get(CONF_PORT, DEFAULT_PORT),
        username=base[CONF_USERNAME],
        auth_method=auth_method,
        password=auth.get(CONF_PASSWORD) if auth_method == AUTH_METHOD_PASSWORD else None,
        private_key=auth.get(CONF_PRIVATE_KEY) if auth_method == AUTH_METHOD_KEY else None,
        key_passphrase=auth.get(CONF_KEY_PASSPHRASE),
        use_sudo=auth.get(CONF_USE_SUDO, DEFAULT_USE_SUDO),
    )


# ---------------------------------------------------------------------------
# Config flow
# ---------------------------------------------------------------------------

class Fail2banConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """
    Flux de configuration en deux étapes :
      1. Infos serveur + choix de la méthode d'auth
      2a. Mot de passe
      2b. Clé privée SSH (+ passphrase optionnelle)
    """

    VERSION = 1

    def __init__(self) -> None:
        self._base_data: dict[str, Any] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Étape 1 : serveur + méthode d'authentification."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._base_data = user_input
            auth_method = user_input[CONF_AUTH_METHOD]

            if auth_method == AUTH_METHOD_KEY:
                return await self.async_step_auth_key()
            return await self.async_step_auth_password()

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_BASE_SCHEMA,
            errors=errors,
        )

    async def async_step_auth_password(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Étape 2a : authentification par mot de passe."""
        errors: dict[str, str] = {}

        if user_input is not None:
            client = _build_client(self._base_data, user_input)
            error = await self.hass.async_add_executor_job(client.test_connection)

            if error is None:
                host = self._base_data[CONF_HOST]
                port = self._base_data.get(CONF_PORT, DEFAULT_PORT)
                await self.async_set_unique_id(f"{host}:{port}")
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=f"Fail2ban @ {host}",
                    data={**self._base_data, **user_input},
                )
            errors["base"] = error

        return self.async_show_form(
            step_id="auth_password",
            data_schema=STEP_AUTH_PASSWORD_SCHEMA,
            errors=errors,
        )

    async def async_step_auth_key(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Étape 2b : authentification par clé privée SSH."""
        errors: dict[str, str] = {}

        if user_input is not None:
            client = _build_client(self._base_data, user_input)
            error = await self.hass.async_add_executor_job(client.test_connection)

            if error is None:
                host = self._base_data[CONF_HOST]
                port = self._base_data.get(CONF_PORT, DEFAULT_PORT)
                await self.async_set_unique_id(f"{host}:{port}")
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=f"Fail2ban @ {host} (clé SSH)",
                    data={**self._base_data, **user_input},
                )
            errors["base"] = error

        return self.async_show_form(
            step_id="auth_key",
            data_schema=STEP_AUTH_KEY_SCHEMA,
            errors=errors,
            description_placeholders={
                "key_hint": "Collez le contenu complet de votre clé privée "
                "(-----BEGIN ... PRIVATE KEY-----  ...  -----END ... PRIVATE KEY-----)"
            },
        )

    @staticmethod
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> Fail2banOptionsFlow:
        return Fail2banOptionsFlow(config_entry)


# ---------------------------------------------------------------------------
# Options flow
# ---------------------------------------------------------------------------

class Fail2banOptionsFlow(config_entries.OptionsFlow):
    """Gère les options modifiables après la configuration initiale."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current = self._config_entry.options or self._config_entry.data

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_SCAN_INTERVAL,
                        default=current.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                    ): vol.All(int, vol.Range(min=10, max=3600)),
                    vol.Optional(
                        CONF_USE_SUDO,
                        default=current.get(CONF_USE_SUDO, DEFAULT_USE_SUDO),
                    ): bool,
                }
            ),
        )
