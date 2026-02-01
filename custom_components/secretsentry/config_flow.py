"""Config flow for SecretSentry integration.

IMPORTANT: This module must NOT import heavy modules like scanner, coordinator,
or rules at module level. Only import standard HA config flow requirements.
"""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback

from .const import (
    CONF_ENABLE_ENV_HYGIENE,
    CONF_ENABLE_EXTERNAL_CHECK,
    CONF_ENABLE_GIT_CHECKS,
    CONF_ENABLE_LOG_SCAN,
    CONF_ENABLE_SECRET_AGE,
    CONF_ENABLE_SNAPSHOT_SCAN,
    CONF_EXTERNAL_URL,
    CONF_MAX_FILE_SIZE_KB,
    CONF_MAX_FINDINGS,
    CONF_MAX_LOG_LINES,
    CONF_MAX_LOG_SCAN_MB,
    CONF_MAX_TOTAL_SCAN_MB,
    CONF_PRIVACY_MODE_REPORTS,
    CONF_SCAN_INTERVAL,
    DEFAULT_OPTIONS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class SecretSentryConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for SecretSentry."""

    VERSION = 1
    MINOR_VERSION = 0

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step.

        This integration only needs to be set up once, so we check for
        existing entries and create one if none exists.
        """
        # Only allow a single instance
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()

        if user_input is not None:
            return self.async_create_entry(
                title="SecretSentry",
                data={},
                options=dict(DEFAULT_OPTIONS),
            )

        return self.async_show_form(
            step_id="user",
            description_placeholders={
                "title": "SecretSentry",
            },
        )

    async def async_step_import(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle import from configuration.yaml."""
        return await self.async_step_user(user_input)

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: ConfigEntry,
    ) -> SecretSentryOptionsFlowHandler:
        """Get the options flow for this handler."""
        return SecretSentryOptionsFlowHandler(config_entry)


class SecretSentryOptionsFlowHandler(OptionsFlow):
    """Handle SecretSentry options.

    The options flow is what opens when the user clicks the gear icon.
    This must be robust and never crash.
    """

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry
        self._options: dict[str, Any] = {}

    def _get_options(self) -> dict[str, Any]:
        """Get current options merged with defaults."""
        return {**DEFAULT_OPTIONS, **dict(self.config_entry.options or {})}

    def _build_init_schema(self, options: dict[str, Any]) -> vol.Schema:
        """Build the schema for the init step.

        Uses vol.Coerce and vol.In for robustness across HA versions.
        """
        return vol.Schema(
            {
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=options.get(CONF_SCAN_INTERVAL, "daily"),
                ): vol.In(["disabled", "daily", "weekly"]),
                vol.Required(
                    CONF_PRIVACY_MODE_REPORTS,
                    default=options.get(CONF_PRIVACY_MODE_REPORTS, True),
                ): bool,
                vol.Required(
                    CONF_ENABLE_ENV_HYGIENE,
                    default=options.get(CONF_ENABLE_ENV_HYGIENE, True),
                ): bool,
                vol.Required(
                    CONF_ENABLE_LOG_SCAN,
                    default=options.get(CONF_ENABLE_LOG_SCAN, False),
                ): bool,
                vol.Required(
                    CONF_ENABLE_SNAPSHOT_SCAN,
                    default=options.get(CONF_ENABLE_SNAPSHOT_SCAN, False),
                ): bool,
                vol.Required(
                    CONF_ENABLE_GIT_CHECKS,
                    default=options.get(CONF_ENABLE_GIT_CHECKS, False),
                ): bool,
                vol.Required(
                    CONF_ENABLE_SECRET_AGE,
                    default=options.get(CONF_ENABLE_SECRET_AGE, False),
                ): bool,
                vol.Required(
                    CONF_ENABLE_EXTERNAL_CHECK,
                    default=options.get(CONF_ENABLE_EXTERNAL_CHECK, False),
                ): bool,
            }
        )

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the main options.

        This is called when the gear icon is clicked.
        """
        errors: dict[str, str] = {}

        try:
            options = self._get_options()

            if user_input is not None:
                # Store current input for multi-step flow
                self._options = {**options, **user_input}

                # Chain to additional steps if needed
                if user_input.get(CONF_ENABLE_EXTERNAL_CHECK):
                    return await self.async_step_external_url()

                if user_input.get(CONF_ENABLE_LOG_SCAN):
                    return await self.async_step_log_scan()

                return await self.async_step_advanced()

            schema = self._build_init_schema(options)

            return self.async_show_form(
                step_id="init",
                data_schema=schema,
                errors=errors,
            )

        except Exception:
            _LOGGER.exception("Error in options flow init step")
            errors["base"] = "unknown"
            # Return a minimal form on error
            return self.async_show_form(
                step_id="init",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_SCAN_INTERVAL, default="daily"): vol.In(
                            ["disabled", "daily", "weekly"]
                        ),
                    }
                ),
                errors=errors,
            )

    async def async_step_external_url(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure external URL for self-check."""
        errors: dict[str, str] = {}

        try:
            if user_input is not None:
                external_url = user_input.get(CONF_EXTERNAL_URL, "")

                # Validate URL format
                if external_url:
                    from urllib.parse import urlparse

                    try:
                        parsed = urlparse(external_url)
                        if not parsed.scheme or not parsed.netloc:
                            errors["base"] = "invalid_url"
                    except Exception:
                        errors["base"] = "invalid_url"

                if not errors:
                    # Merge and continue
                    self._options = {**self._options, **user_input}
                    if self._options.get(CONF_ENABLE_LOG_SCAN):
                        return await self.async_step_log_scan()
                    return await self.async_step_advanced()

            options = self._get_options()

            return self.async_show_form(
                step_id="external_url",
                data_schema=vol.Schema(
                    {
                        vol.Optional(
                            CONF_EXTERNAL_URL,
                            default=options.get(CONF_EXTERNAL_URL, ""),
                        ): str,
                    }
                ),
                errors=errors,
            )

        except Exception:
            _LOGGER.exception("Error in external URL step")
            self._options[CONF_EXTERNAL_URL] = ""
            return await self.async_step_advanced()

    async def async_step_log_scan(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure log scanning options."""
        try:
            if user_input is not None:
                self._options = {**self._options, **user_input}
                return await self.async_step_advanced()

            options = self._get_options()

            return self.async_show_form(
                step_id="log_scan",
                data_schema=vol.Schema(
                    {
                        vol.Required(
                            CONF_MAX_LOG_SCAN_MB,
                            default=options.get(CONF_MAX_LOG_SCAN_MB, 10),
                        ): vol.Coerce(int),
                        vol.Required(
                            CONF_MAX_LOG_LINES,
                            default=options.get(CONF_MAX_LOG_LINES, 50000),
                        ): vol.Coerce(int),
                    }
                ),
            )

        except Exception:
            _LOGGER.exception("Error in log scan step")
            return await self.async_step_advanced()

    async def async_step_advanced(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure advanced options and finalize."""
        try:
            if user_input is not None:
                # Merge all options and create entry
                final_options = {**self._options, **user_input}
                return self.async_create_entry(title="", data=final_options)

            options = self._get_options()

            return self.async_show_form(
                step_id="advanced",
                data_schema=vol.Schema(
                    {
                        vol.Required(
                            CONF_MAX_FILE_SIZE_KB,
                            default=options.get(CONF_MAX_FILE_SIZE_KB, 512),
                        ): vol.Coerce(int),
                        vol.Required(
                            CONF_MAX_TOTAL_SCAN_MB,
                            default=options.get(CONF_MAX_TOTAL_SCAN_MB, 50),
                        ): vol.Coerce(int),
                        vol.Required(
                            CONF_MAX_FINDINGS,
                            default=options.get(CONF_MAX_FINDINGS, 500),
                        ): vol.Coerce(int),
                    }
                ),
            )

        except Exception:
            _LOGGER.exception("Error in advanced options step")
            # Still create entry with what we have
            return self.async_create_entry(title="", data=self._options)
