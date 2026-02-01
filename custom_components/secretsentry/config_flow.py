"""Config flow for SecretSentry integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, OptionsFlow, ConfigEntry
from homeassistant.core import callback

from .const import DOMAIN, DEFAULT_OPTIONS

_LOGGER = logging.getLogger(__name__)


class SecretSentryConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for SecretSentry."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Handle the initial step."""
        # Keep initial flow simple to avoid crashes.
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
        # Store as _entry to avoid conflict with base class config_entry property
        self._entry = entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        """Manage the options."""
        options = {**DEFAULT_OPTIONS, **dict(self._entry.options or {})}

        def _schema(opts: dict[str, Any]) -> vol.Schema:
            """Build schema with safe defaults."""
            return vol.Schema(
                {
                    vol.Required("privacy_mode_reports", default=bool(opts["privacy_mode_reports"])): bool,
                    vol.Required("enable_log_scan", default=bool(opts["enable_log_scan"])): bool,
                    vol.Required("enable_env_hygiene", default=bool(opts["enable_env_hygiene"])): bool,
                    vol.Required("scan_interval", default=str(opts["scan_interval"])): vol.In(
                        ["disabled", "daily", "weekly"]
                    ),
                    vol.Optional("include_paths", default=list(opts.get("include_paths") or [])): [str],
                    vol.Optional("exclude_paths", default=list(opts.get("exclude_paths") or [])): [str],
                    vol.Required("max_file_size_kb", default=int(opts["max_file_size_kb"])): vol.Coerce(int),
                    vol.Required("max_total_scan_mb", default=int(opts["max_total_scan_mb"])): vol.Coerce(int),
                    vol.Required("max_findings", default=int(opts["max_findings"])): vol.Coerce(int),
                }
            )

        if user_input is None:
            try:
                return self.async_show_form(step_id="init", data_schema=_schema(options))
            except Exception:
                _LOGGER.exception("Options flow schema build failed")
                # Show a minimal fallback form instead of 500.
                return self.async_show_form(
                    step_id="init",
                    data_schema=vol.Schema({}),
                    errors={"base": "unknown"},
                )

        # Sanitize types
        cleaned = {**options, **user_input}
        cleaned["max_file_size_kb"] = int(cleaned["max_file_size_kb"])
        cleaned["max_total_scan_mb"] = int(cleaned["max_total_scan_mb"])
        cleaned["max_findings"] = int(cleaned["max_findings"])
        cleaned["include_paths"] = list(cleaned.get("include_paths") or [])
        cleaned["exclude_paths"] = list(cleaned.get("exclude_paths") or [])

        return self.async_create_entry(title="", data=cleaned)
