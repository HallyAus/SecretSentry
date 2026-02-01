"""SecretSentry - Local security scanner for Home Assistant.

This integration provides local static scanning for credential leak risks
and insecure exposure settings in your Home Assistant configuration.

IMPORTANT: This integration performs ONLY local scanning. It does NOT:
- Connect to the internet for any scanning purposes
- Enumerate other Home Assistant instances
- Use external services like Shodan or any registry lookups
- Send any data outside your local network
- Perform any network scanning or enumeration

All scanning is performed locally against your /config directory.
The optional external URL self-check ONLY checks YOUR OWN provided URL.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import SecretSentryCoordinator
from .services import async_setup_services, async_unload_services

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up SecretSentry from a config entry.

    Args:
        hass: Home Assistant instance.
        entry: Configuration entry for this integration.

    Returns:
        True if setup was successful.
    """
    coordinator = SecretSentryCoordinator(hass, entry)

    # Perform initial scan
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Set up platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register services
    await async_setup_services(hass, coordinator)

    # Listen for options updates
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    _LOGGER.info(
        "SecretSentry initialized. Found %d security findings (%d high severity).",
        coordinator.data.total_findings if coordinator.data else 0,
        coordinator.data.high_count if coordinator.data else 0,
    )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry.

    Args:
        hass: Home Assistant instance.
        entry: Configuration entry to unload.

    Returns:
        True if unload was successful.
    """
    # Unload platforms
    unload_ok = await hass.config_entries.async_unload_platforms(
        entry, PLATFORMS
    )

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

        # Remove services if no more entries
        if not hass.data[DOMAIN]:
            await async_unload_services(hass)

    return unload_ok


async def _async_update_listener(
    hass: HomeAssistant, entry: ConfigEntry
) -> None:
    """Handle options update.

    Args:
        hass: Home Assistant instance.
        entry: Updated configuration entry.
    """
    await hass.config_entries.async_reload(entry.entry_id)
