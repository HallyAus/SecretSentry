"""Sensor platform for SecretSentry integration."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, Severity
from .coordinator import SecretSentryCoordinator, SecretSentryData


@dataclass(frozen=True, kw_only=True)
class SecretSentrySensorEntityDescription(SensorEntityDescription):
    """Describes SecretSentry sensor entity."""

    value_fn: Callable[[SecretSentryData], int | str | None]
    extra_state_attributes_fn: Callable[[SecretSentryData], dict[str, Any]] | None = (
        None
    )


def _get_total_findings(data: SecretSentryData) -> int:
    """Get total number of findings."""
    return data.total_findings


def _get_high_count(data: SecretSentryData) -> int:
    """Get count of high severity findings."""
    return data.high_count


def _get_med_count(data: SecretSentryData) -> int:
    """Get count of medium severity findings."""
    return data.med_count


def _get_low_count(data: SecretSentryData) -> int:
    """Get count of low severity findings."""
    return data.low_count


def _get_findings_attributes(data: SecretSentryData) -> dict[str, Any]:
    """Get extra attributes for total findings sensor."""
    return {
        "high_count": data.high_count,
        "med_count": data.med_count,
        "low_count": data.low_count,
        "last_scan": data.last_scan.isoformat() if data.last_scan else None,
        "scan_duration_seconds": data.scan_duration,
        "new_high_count": data.new_high_count,
        "resolved_count": data.resolved_count,
        "top_findings": data.get_top_findings(5),
    }


def _get_high_severity_attributes(data: SecretSentryData) -> dict[str, Any]:
    """Get extra attributes for high severity sensor."""
    high_findings = [
        f for f in data.findings if f.severity == Severity.HIGH
    ]
    return {
        "new_high_count": data.new_high_count,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "file": f.file_path,
                "line": f.line,
            }
            for f in high_findings[:10]  # Limit to first 10
        ],
    }


def _get_med_severity_attributes(data: SecretSentryData) -> dict[str, Any]:
    """Get extra attributes for medium severity sensor."""
    med_findings = [
        f for f in data.findings if f.severity == Severity.MED
    ]
    return {
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "file": f.file_path,
                "line": f.line,
            }
            for f in med_findings[:10]  # Limit to first 10
        ],
    }


def _get_low_severity_attributes(data: SecretSentryData) -> dict[str, Any]:
    """Get extra attributes for low severity sensor."""
    low_findings = [
        f for f in data.findings if f.severity in (Severity.LOW, Severity.INFO)
    ]
    return {
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "file": f.file_path,
                "line": f.line,
            }
            for f in low_findings[:10]  # Limit to first 10
        ],
    }


SENSOR_DESCRIPTIONS: tuple[SecretSentrySensorEntityDescription, ...] = (
    SecretSentrySensorEntityDescription(
        key="total_findings",
        translation_key="total_findings",
        native_unit_of_measurement="findings",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:shield-search",
        value_fn=_get_total_findings,
        extra_state_attributes_fn=_get_findings_attributes,
    ),
    SecretSentrySensorEntityDescription(
        key="high_severity_findings",
        translation_key="high_severity_findings",
        native_unit_of_measurement="findings",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:shield-alert",
        value_fn=_get_high_count,
        extra_state_attributes_fn=_get_high_severity_attributes,
    ),
    SecretSentrySensorEntityDescription(
        key="medium_severity_findings",
        translation_key="medium_severity_findings",
        native_unit_of_measurement="findings",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:shield-half-full",
        value_fn=_get_med_count,
        extra_state_attributes_fn=_get_med_severity_attributes,
    ),
    SecretSentrySensorEntityDescription(
        key="low_severity_findings",
        translation_key="low_severity_findings",
        native_unit_of_measurement="findings",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:shield-outline",
        value_fn=_get_low_count,
        extra_state_attributes_fn=_get_low_severity_attributes,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up SecretSentry sensors based on config entry.

    Args:
        hass: Home Assistant instance.
        config_entry: Configuration entry for this integration.
        async_add_entities: Callback to add entities.
    """
    coordinator: SecretSentryCoordinator = hass.data[DOMAIN][
        config_entry.entry_id
    ]

    async_add_entities(
        SecretSentrySensor(coordinator, description)
        for description in SENSOR_DESCRIPTIONS
    )


class SecretSentrySensor(
    CoordinatorEntity[SecretSentryCoordinator], SensorEntity
):
    """Sensor for SecretSentry findings."""

    entity_description: SecretSentrySensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: SecretSentryCoordinator,
        description: SecretSentrySensorEntityDescription,
    ) -> None:
        """Initialize the sensor.

        Args:
            coordinator: The data update coordinator.
            description: Entity description for this sensor.
        """
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{DOMAIN}_{description.key}"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, "secretsentry")},
            "name": "SecretSentry",
            "manufacturer": "SecretSentry",
            "model": "Security Scanner",
            "sw_version": "1.0.0",
        }

    @property
    def native_value(self) -> int | str | None:
        """Return the sensor value."""
        if self.coordinator.data is None:
            return None
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return extra state attributes."""
        if (
            self.coordinator.data is None
            or self.entity_description.extra_state_attributes_fn is None
        ):
            return None
        return self.entity_description.extra_state_attributes_fn(
            self.coordinator.data
        )
