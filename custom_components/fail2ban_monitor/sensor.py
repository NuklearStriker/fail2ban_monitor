"""Sensors pour Fail2ban Monitor."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from homeassistant.components.sensor import (
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import Fail2banCoordinator


# ---------------------------------------------------------------------------
# Descriptions des capteurs globaux
# ---------------------------------------------------------------------------
@dataclass
class Fail2banSensorDescription(SensorEntityDescription):
    value_fn: Callable[[dict], Any] = lambda d: None
    attributes_fn: Callable[[dict], dict] | None = None


GLOBAL_SENSORS: tuple[Fail2banSensorDescription, ...] = (
    Fail2banSensorDescription(
        key="jails_count",
        name="Nombre de jails",
        icon="mdi:shield-lock-outline",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="jails",
        value_fn=lambda d: d.get("jails_count", 0),
        attributes_fn=lambda d: {"jails": d.get("jails", [])},
    ),
    Fail2banSensorDescription(
        key="total_banned",
        name="Total IP bannies",
        icon="mdi:ip-network-outline",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="IP",
        value_fn=lambda d: sum(
            jd.get("actions_currently_banned", 0)
            for jd in d.get("jails_data", {}).values()
        ),
        attributes_fn=lambda d: {
            "all_banned_ips": _collect_all_banned_ips(d),
        },
    ),
    Fail2banSensorDescription(
        key="total_failed",
        name="Total tentatives échouées",
        icon="mdi:alert-circle-outline",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="tentatives",
        value_fn=lambda d: sum(
            jd.get("filter_currently_failed", 0)
            for jd in d.get("jails_data", {}).values()
        ),
    ),
)


def _collect_all_banned_ips(data: dict) -> list[str]:
    """Collecte toutes les IPs bannies de tous les jails."""
    ips: list[str] = []
    for jd in data.get("jails_data", {}).values():
        ips.extend(jd.get("actions_banned_ips", []))
    return list(set(ips))


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Configure tous les capteurs Fail2ban."""
    coordinator: Fail2banCoordinator = hass.data[DOMAIN][entry.entry_id]
    host = entry.data[CONF_HOST]
    entities: list[SensorEntity] = []

    # Capteurs globaux
    for description in GLOBAL_SENSORS:
        entities.append(
            Fail2banGlobalSensor(coordinator, entry, host, description)
        )

    # Capteurs par jail (créés dynamiquement selon les jails découverts)
    jails = coordinator.data.get("jails", [])
    for jail in jails:
        entities.extend(_build_jail_sensors(coordinator, entry, host, jail))

    async_add_entities(entities, update_before_add=True)

    # Listener pour ajouter de nouveaux jails dynamiquement
    _prev_jails: set[str] = set(jails)

    def _async_check_new_jails() -> None:
        nonlocal _prev_jails
        current_jails = set(coordinator.data.get("jails", []))
        new_jails = current_jails - _prev_jails
        if new_jails:
            new_entities: list[SensorEntity] = []
            for jail in new_jails:
                new_entities.extend(
                    _build_jail_sensors(coordinator, entry, host, jail)
                )
            async_add_entities(new_entities, update_before_add=True)
        _prev_jails = current_jails

    entry.async_on_unload(
        coordinator.async_add_listener(_async_check_new_jails)
    )


def _build_jail_sensors(
    coordinator: Fail2banCoordinator,
    entry: ConfigEntry,
    host: str,
    jail: str,
) -> list[SensorEntity]:
    """Construit la liste des capteurs pour un jail donné."""
    return [
        Fail2banJailSensor(
            coordinator=coordinator,
            entry=entry,
            host=host,
            jail=jail,
            key="filter_currently_failed",
            name=f"{jail} - Tentatives actuelles",
            icon="mdi:magnify",
            unit="tentatives",
        ),
        Fail2banJailSensor(
            coordinator=coordinator,
            entry=entry,
            host=host,
            jail=jail,
            key="filter_total_failed",
            name=f"{jail} - Total tentatives",
            icon="mdi:magnify-plus-outline",
            unit="tentatives",
        ),
        Fail2banJailSensor(
            coordinator=coordinator,
            entry=entry,
            host=host,
            jail=jail,
            key="actions_currently_banned",
            name=f"{jail} - IP bannies",
            icon="mdi:shield-alert",
            unit="IP",
        ),
        Fail2banJailSensor(
            coordinator=coordinator,
            entry=entry,
            host=host,
            jail=jail,
            key="actions_total_banned",
            name=f"{jail} - Total bans",
            icon="mdi:shield-off-outline",
            unit="bans",
        ),
        Fail2banJailFileSensor(
            coordinator=coordinator,
            entry=entry,
            host=host,
            jail=jail,
        ),
        Fail2banJailBannedIPsSensor(
            coordinator=coordinator,
            entry=entry,
            host=host,
            jail=jail,
        ),
    ]


# ---------------------------------------------------------------------------
# Entités
# ---------------------------------------------------------------------------

class _Fail2banBaseSensor(CoordinatorEntity[Fail2banCoordinator], SensorEntity):
    """Base pour tous les capteurs Fail2ban."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: Fail2banCoordinator,
        entry: ConfigEntry,
        host: str,
    ) -> None:
        super().__init__(coordinator)
        self._host = host
        self._entry = entry

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


class Fail2banGlobalSensor(_Fail2banBaseSensor):
    """Capteur global (agrégat de tous les jails)."""

    entity_description: Fail2banSensorDescription

    def __init__(
        self,
        coordinator: Fail2banCoordinator,
        entry: ConfigEntry,
        host: str,
        description: Fail2banSensorDescription,
    ) -> None:
        super().__init__(coordinator, entry, host)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_global_{description.key}"
        self._attr_state_class = description.state_class

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict:
        if self.entity_description.attributes_fn:
            return self.entity_description.attributes_fn(self.coordinator.data)
        return {}


class Fail2banJailSensor(_Fail2banBaseSensor):
    """Capteur numérique pour un jail spécifique."""

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: Fail2banCoordinator,
        entry: ConfigEntry,
        host: str,
        jail: str,
        key: str,
        name: str,
        icon: str,
        unit: str,
    ) -> None:
        super().__init__(coordinator, entry, host)
        self._jail = jail
        self._key = key
        self._attr_name = name
        self._attr_icon = icon
        self._attr_native_unit_of_measurement = unit
        self._attr_unique_id = f"{entry.entry_id}_{jail}_{key}"

    @property
    def native_value(self) -> int:
        jail_data = self.coordinator.data.get("jails_data", {}).get(self._jail, {})
        return jail_data.get(self._key, 0)

    @property
    def extra_state_attributes(self) -> dict:
        return {"jail": self._jail}


class Fail2banJailFileSensor(_Fail2banBaseSensor):
    """Capteur listant les fichiers surveillés par le filtre d'un jail."""

    _attr_icon = "mdi:file-search-outline"

    def __init__(
        self,
        coordinator: Fail2banCoordinator,
        entry: ConfigEntry,
        host: str,
        jail: str,
    ) -> None:
        super().__init__(coordinator, entry, host)
        self._jail = jail
        self._attr_name = f"{jail} - Fichiers surveillés"
        self._attr_unique_id = f"{entry.entry_id}_{jail}_file_list"

    @property
    def native_value(self) -> int:
        """Retourne le nombre de fichiers surveillés."""
        jail_data = self.coordinator.data.get("jails_data", {}).get(self._jail, {})
        return len(jail_data.get("filter_file_list", []))

    @property
    def extra_state_attributes(self) -> dict:
        jail_data = self.coordinator.data.get("jails_data", {}).get(self._jail, {})
        return {
            "jail": self._jail,
            "files": jail_data.get("filter_file_list", []),
        }


class Fail2banJailBannedIPsSensor(_Fail2banBaseSensor):
    """Capteur listant les IPs actuellement bannies pour un jail."""

    _attr_icon = "mdi:ip-lock"
    _attr_native_unit_of_measurement = "IP"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: Fail2banCoordinator,
        entry: ConfigEntry,
        host: str,
        jail: str,
    ) -> None:
        super().__init__(coordinator, entry, host)
        self._jail = jail
        self._attr_name = f"{jail} - Liste IPs bannies"
        self._attr_unique_id = f"{entry.entry_id}_{jail}_banned_ips"

    @property
    def native_value(self) -> int:
        jail_data = self.coordinator.data.get("jails_data", {}).get(self._jail, {})
        return len(jail_data.get("actions_banned_ips", []))

    @property
    def extra_state_attributes(self) -> dict:
        jail_data = self.coordinator.data.get("jails_data", {}).get(self._jail, {})
        return {
            "jail": self._jail,
            "banned_ips": jail_data.get("actions_banned_ips", []),
        }
