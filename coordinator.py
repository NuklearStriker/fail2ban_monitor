"""DataUpdateCoordinator pour Fail2ban Monitor."""
from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN
from .ssh_client import Fail2banSSHClient

_LOGGER = logging.getLogger(__name__)


class Fail2banCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordonne la récupération des données Fail2ban."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: Fail2banSSHClient,
        scan_interval: int,
        host: str,
    ) -> None:
        self.client = client
        self.host = host

        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{host}",
            update_interval=timedelta(seconds=scan_interval),
        )

    async def _async_update_data(self) -> dict[str, Any]:
        """Récupère les données Fail2ban via SSH."""
        try:
            data = await self.hass.async_add_executor_job(self.client.get_all_data)
        except Exception as err:  # noqa: BLE001
            raise UpdateFailed(f"Erreur lors de la mise à jour Fail2ban: {err}") from err

        if data.get("status") in ("connection_error", "auth_error"):
            raise UpdateFailed(
                f"Impossible de se connecter au serveur Fail2ban ({data['status']})"
            )

        return data
