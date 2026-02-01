"""Config flow for SecretSentry integration."""
from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import (
    CONF_ADDON_CONFIG_DIRS,
    CONF_ENABLE_ENV_HYGIENE,
    CONF_ENABLE_EXTERNAL_CHECK,
    CONF_ENABLE_GIT_CHECKS,
    CONF_ENABLE_LOG_SCAN,
    CONF_ENABLE_SECRET_AGE,
    CONF_ENABLE_SNAPSHOT_SCAN,
    CONF_ENV_FILES,
    CONF_EXCLUDE_PATHS,
    CONF_EXTERNAL_URL,
    CONF_INCLUDE_PATHS,
    CONF_LOG_SCAN_PATHS,
    CONF_MAX_FILE_SIZE_KB,
    CONF_MAX_FINDINGS,
    CONF_MAX_LOG_LINES,
    CONF_MAX_LOG_SCAN_MB,
    CONF_MAX_TOTAL_SCAN_MB,
    CONF_PRIVACY_MODE_REPORTS,
    CONF_SCAN_INTERVAL,
    DEFAULT_ENABLE_ENV_HYGIENE,
    DEFAULT_ENABLE_LOG_SCAN,
    DEFAULT_ENV_FILES,
    DEFAULT_LOG_SCAN_PATHS,
    DEFAULT_MAX_FILE_SIZE_KB,
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_LOG_LINES,
    DEFAULT_MAX_LOG_SCAN_MB,
    DEFAULT_MAX_TOTAL_SCAN_MB,
    DEFAULT_PRIVACY_MODE_REPORTS,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)


class SecretSentryConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for SecretSentry."""

    VERSION = 1

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
                options={
                    CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL,
                    CONF_PRIVACY_MODE_REPORTS: DEFAULT_PRIVACY_MODE_REPORTS,
                    CONF_ENABLE_ENV_HYGIENE: DEFAULT_ENABLE_ENV_HYGIENE,
                },
            )

        return self.async_show_form(
            step_id="user",
            description_placeholders={
                "title": "SecretSentry",
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: ConfigEntry,
    ) -> SecretSentryOptionsFlow:
        """Get the options flow for this handler."""
        return SecretSentryOptionsFlow(config_entry)


class SecretSentryOptionsFlow(OptionsFlow):
    """Handle SecretSentry options."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry
        self._options: dict[str, Any] = {}

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the main options."""
        if user_input is not None:
            self._options = user_input
            # Check if external URL check needs configuration
            if user_input.get(CONF_ENABLE_EXTERNAL_CHECK):
                return await self.async_step_external_url()

            # Check if log scan needs configuration
            if user_input.get(CONF_ENABLE_LOG_SCAN):
                return await self.async_step_log_scan()

            return self.async_create_entry(title="", data=user_input)

        options = self.config_entry.options

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SCAN_INTERVAL,
                        default=options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                    ): SelectSelector(
                        SelectSelectorConfig(
                            options=[
                                {"value": "disabled", "label": "Disabled"},
                                {"value": "daily", "label": "Daily"},
                                {"value": "weekly", "label": "Weekly"},
                            ],
                            mode=SelectSelectorMode.DROPDOWN,
                        )
                    ),
                    vol.Optional(
                        CONF_ENABLE_SNAPSHOT_SCAN,
                        default=options.get(CONF_ENABLE_SNAPSHOT_SCAN, False),
                    ): BooleanSelector(),
                    vol.Optional(
                        CONF_ENABLE_GIT_CHECKS,
                        default=options.get(CONF_ENABLE_GIT_CHECKS, False),
                    ): BooleanSelector(),
                    vol.Optional(
                        CONF_ENABLE_SECRET_AGE,
                        default=options.get(CONF_ENABLE_SECRET_AGE, False),
                    ): BooleanSelector(),
                    vol.Optional(
                        CONF_ENABLE_EXTERNAL_CHECK,
                        default=options.get(CONF_ENABLE_EXTERNAL_CHECK, False),
                    ): BooleanSelector(),
                    # v3.0: Privacy mode
                    vol.Optional(
                        CONF_PRIVACY_MODE_REPORTS,
                        default=options.get(CONF_PRIVACY_MODE_REPORTS, DEFAULT_PRIVACY_MODE_REPORTS),
                    ): BooleanSelector(),
                    # v3.0: Environment hygiene
                    vol.Optional(
                        CONF_ENABLE_ENV_HYGIENE,
                        default=options.get(CONF_ENABLE_ENV_HYGIENE, DEFAULT_ENABLE_ENV_HYGIENE),
                    ): BooleanSelector(),
                    # v3.0: Log scanning
                    vol.Optional(
                        CONF_ENABLE_LOG_SCAN,
                        default=options.get(CONF_ENABLE_LOG_SCAN, DEFAULT_ENABLE_LOG_SCAN),
                    ): BooleanSelector(),
                }
            ),
        )

    async def async_step_external_url(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure external URL for self-check."""
        errors = {}

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
                # Merge with previous options
                final_options = {**self._options, **user_input}
                # Check if log scan also needs configuration
                if self._options.get(CONF_ENABLE_LOG_SCAN):
                    self._options = final_options
                    return await self.async_step_log_scan()
                return self.async_create_entry(title="", data=final_options)

        options = self.config_entry.options

        return self.async_show_form(
            step_id="external_url",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_EXTERNAL_URL,
                        default=options.get(CONF_EXTERNAL_URL, ""),
                    ): TextSelector(
                        TextSelectorConfig(
                            type=TextSelectorType.URL,
                        )
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_log_scan(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure log scanning options (v3.0)."""
        if user_input is not None:
            # Merge with previous options
            final_options = {**self._options, **user_input}
            return self.async_create_entry(title="", data=final_options)

        options = self.config_entry.options

        return self.async_show_form(
            step_id="log_scan",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_MAX_LOG_SCAN_MB,
                        default=options.get(CONF_MAX_LOG_SCAN_MB, DEFAULT_MAX_LOG_SCAN_MB),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=1,
                            max=100,
                            step=1,
                            mode=NumberSelectorMode.BOX,
                            unit_of_measurement="MB",
                        )
                    ),
                    vol.Optional(
                        CONF_MAX_LOG_LINES,
                        default=options.get(CONF_MAX_LOG_LINES, DEFAULT_MAX_LOG_LINES),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=1000,
                            max=500000,
                            step=1000,
                            mode=NumberSelectorMode.BOX,
                        )
                    ),
                }
            ),
        )

    async def async_step_advanced(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure advanced options."""
        if user_input is not None:
            # Merge with current options
            new_options = {**self.config_entry.options, **user_input}
            return self.async_create_entry(title="", data=new_options)

        options = self.config_entry.options

        return self.async_show_form(
            step_id="advanced",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_MAX_FILE_SIZE_KB,
                        default=options.get(CONF_MAX_FILE_SIZE_KB, DEFAULT_MAX_FILE_SIZE_KB),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=64,
                            max=5120,
                            step=64,
                            mode=NumberSelectorMode.BOX,
                            unit_of_measurement="KB",
                        )
                    ),
                    vol.Optional(
                        CONF_MAX_TOTAL_SCAN_MB,
                        default=options.get(CONF_MAX_TOTAL_SCAN_MB, DEFAULT_MAX_TOTAL_SCAN_MB),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=10,
                            max=500,
                            step=10,
                            mode=NumberSelectorMode.BOX,
                            unit_of_measurement="MB",
                        )
                    ),
                    vol.Optional(
                        CONF_MAX_FINDINGS,
                        default=options.get(CONF_MAX_FINDINGS, DEFAULT_MAX_FINDINGS),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=50,
                            max=2000,
                            step=50,
                            mode=NumberSelectorMode.BOX,
                        )
                    ),
                }
            ),
        )
