"""Intégration Fail2ban Monitor pour Home Assistant."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import HomeAssistant

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
    PLATFORMS,
)
from .coordinator import Fail2banCoordinator
from .ssh_client import Fail2banSSHClient

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Configure l'intégration à partir d'une entrée de configuration."""
    data = entry.data
    options = entry.options

    auth_method = data.get(CONF_AUTH_METHOD, AUTH_METHOD_PASSWORD)
    scan_interval = options.get(
        CONF_SCAN_INTERVAL, data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    )
    use_sudo = options.get(CONF_USE_SUDO, data.get(CONF_USE_SUDO, DEFAULT_USE_SUDO))

    client = Fail2banSSHClient(
        host=data[CONF_HOST],
        port=data.get(CONF_PORT, DEFAULT_PORT),
        username=data[CONF_USERNAME],
        auth_method=auth_method,
        password=data.get(CONF_PASSWORD) if auth_method == AUTH_METHOD_PASSWORD else None,
        private_key=data.get(CONF_PRIVATE_KEY) if auth_method == AUTH_METHOD_KEY else None,
        key_passphrase=data.get(CONF_KEY_PASSPHRASE),
        use_sudo=use_sudo,
    )

    coordinator = Fail2banCoordinator(
        hass=hass,
        client=client,
        scan_interval=scan_interval,
        host=data[CONF_HOST],
    )

    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok
