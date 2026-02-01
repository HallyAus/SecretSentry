"""Config flow for SecretSentry integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, OptionsFlow, ConfigEntry
from homeassistant.core import callback

_LOGGER = logging.getLogger(__name__)

DOMAIN = "secretsentry"


class SecretSentryConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for SecretSentry."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Handle the initial step."""
        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=vol.Schema({}))
        return self.async_create_entry(title="SecretSentry", data={})

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow for this handler."""
        return SecretSentryOptionsFlowHandler(config_entry)


class SecretSentryOptionsFlowHandler(OptionsFlow):
    """Handle SecretSentry options."""

    def __init__(self, entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self._entry = entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        """Manage the options."""
        # Hardcoded defaults - no imports
        defaults = {
            "privacy_mode_reports": True,
            "enable_log_scan": False,
            "enable_env_hygiene": True,
            "scan_interval": "daily",
            "max_file_size_kb": 512,
            "max_total_scan_mb": 50,
            "max_findings": 500,
        }
        options = {**defaults, **dict(self._entry.options or {})}

        if user_input is None:
            try:
                schema = vol.Schema({
                    vol.Required("privacy_mode_reports", default=options["privacy_mode_reports"]): bool,
                    vol.Required("enable_log_scan", default=options["enable_log_scan"]): bool,
                    vol.Required("enable_env_hygiene", default=options["enable_env_hygiene"]): bool,
                    vol.Required("scan_interval", default=options["scan_interval"]): vol.In(["disabled", "daily", "weekly"]),
                    vol.Required("max_file_size_kb", default=options["max_file_size_kb"]): int,
                    vol.Required("max_total_scan_mb", default=options["max_total_scan_mb"]): int,
                    vol.Required("max_findings", default=options["max_findings"]): int,
                })
                return self.async_show_form(step_id="init", data_schema=schema)
            except Exception:
                _LOGGER.exception("Options flow failed")
                return self.async_show_form(step_id="init", data_schema=vol.Schema({}))

        return self.async_create_entry(title="", data={**options, **user_input})
