"""Binary sensors pour Fail2ban Monitor."""
from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import Fail2banCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Configure les binary sensors."""
    coordinator: Fail2banCoordinator = hass.data[DOMAIN][entry.entry_id]
    host = entry.data[CONF_HOST]

    async_add_entities(
        [Fail2banDaemonBinarySensor(coordinator, entry, host)],
        update_before_add=True,
    )


class Fail2banDaemonBinarySensor(
    CoordinatorEntity[Fail2banCoordinator], BinarySensorEntity
):
    """Indique si le daemon Fail2ban est actif."""

    _attr_device_class = BinarySensorDeviceClass.RUNNING
    _attr_has_entity_name = True
    _attr_name = "Daemon actif"

    def __init__(
        self,
        coordinator: Fail2banCoordinator,
        entry: ConfigEntry,
        host: str,
    ) -> None:
        super().__init__(coordinator)
        self._host = host
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_daemon_running"

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=f"Fail2ban @ {self._host}",
            manufacturer="Fail2ban",
            model="Fail2ban Server",
            sw_version=self.coordinator.data.get("version"),
            configuration_url=f"ssh://{self._host}",
        )

    @property
    def is_on(self) -> bool:
        return self.coordinator.data.get("status") == "running"

    @property
    def extra_state_attributes(self) -> dict:
        return {
            "status": self.coordinator.data.get("status"),
            "version": self.coordinator.data.get("version"),
            "host": self._host,
        }
