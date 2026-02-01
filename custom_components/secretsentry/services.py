"""Service handlers for SecretSentry integration."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv

from .const import (
    DOMAIN,
    SERVICE_EXPORT_REPORT,
    SERVICE_EXPORT_SANITISED,
    SERVICE_RUN_SELFTEST,
    SERVICE_SCAN_NOW,
)

if TYPE_CHECKING:
    from .coordinator import SecretSentryCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_services(
    hass: HomeAssistant,
    coordinator: "SecretSentryCoordinator",
) -> None:
    """Set up SecretSentry services.

    Args:
        hass: Home Assistant instance.
        coordinator: The data update coordinator.
    """

    async def handle_scan_now(call: ServiceCall) -> None:
        """Handle the scan_now service call.

        Triggers an immediate security scan.

        Args:
            call: Service call data.
        """
        _LOGGER.info("Manual security scan triggered via service")
        result = await coordinator.async_scan_now()
        _LOGGER.info(
            "Manual scan complete. Found %d findings (%d high severity).",
            result.total_findings,
            result.high_count,
        )

    async def handle_export_report(call: ServiceCall) -> None:
        """Handle the export_report service call.

        Exports a masked JSON report to /config.

        Args:
            call: Service call data.
        """
        _LOGGER.info("Exporting security report via service")
        report_path = await coordinator.async_export_report()

        # Create persistent notification
        await hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": "SecretSentry Report Exported",
                "message": f"Security report exported to:\n`{report_path}`",
                "notification_id": "secretsentry_export",
            },
        )

    async def handle_export_sanitised(call: ServiceCall) -> None:
        """Handle the export_sanitised_copy service call.

        Creates a sanitised copy of configuration files.

        Args:
            call: Service call data.
        """
        _LOGGER.info("Creating sanitised configuration copy via service")
        output_dir, files_processed, errors = await coordinator.async_export_sanitised()

        # Create persistent notification
        error_msg = ""
        if errors:
            error_msg = f"\n\nErrors ({len(errors)}):\n" + "\n".join(errors[:5])

        await hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": "SecretSentry Sanitised Copy Created",
                "message": (
                    f"Sanitised configuration copy created at:\n`{output_dir}`\n\n"
                    f"Files processed: {files_processed}{error_msg}"
                ),
                "notification_id": "secretsentry_sanitised",
            },
        )

    async def handle_run_selftest(call: ServiceCall) -> None:
        """Handle the run_selftest service call.

        Runs internal self-tests to verify scanner functionality.

        Args:
            call: Service call data.
        """
        _LOGGER.info("Running SecretSentry self-tests via service")

        from .selftest import async_run_selftest

        result = await async_run_selftest(hass)

        # Build notification message
        status = "✅ PASSED" if result.passed else "❌ FAILED"
        message = (
            f"**Status:** {status}\n\n"
            f"**Tests:** {result.passed_tests}/{result.total_tests} passed\n\n"
        )

        if result.assertions:
            message += "**Results:**\n"
            for assertion in result.assertions:
                icon = "✓" if assertion["passed"] else "✗"
                message += f"- {icon} {assertion['test']}\n"

        if result.errors:
            message += f"\n**Errors:**\n"
            for error in result.errors[:5]:
                message += f"- {error}\n"

        await hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": f"SecretSentry Self-Test: {status}",
                "message": message,
                "notification_id": "secretsentry_selftest",
            },
        )

        _LOGGER.info("Self-test complete: %s", result.summary())

    # Register services only if not already registered
    if not hass.services.has_service(DOMAIN, SERVICE_SCAN_NOW):
        hass.services.async_register(
            DOMAIN,
            SERVICE_SCAN_NOW,
            handle_scan_now,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_EXPORT_REPORT):
        hass.services.async_register(
            DOMAIN,
            SERVICE_EXPORT_REPORT,
            handle_export_report,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_EXPORT_SANITISED):
        hass.services.async_register(
            DOMAIN,
            SERVICE_EXPORT_SANITISED,
            handle_export_sanitised,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_RUN_SELFTEST):
        hass.services.async_register(
            DOMAIN,
            SERVICE_RUN_SELFTEST,
            handle_run_selftest,
        )


async def async_unload_services(hass: HomeAssistant) -> None:
    """Unload SecretSentry services.

    Args:
        hass: Home Assistant instance.
    """
    for service in (
        SERVICE_SCAN_NOW,
        SERVICE_EXPORT_REPORT,
        SERVICE_EXPORT_SANITISED,
        SERVICE_RUN_SELFTEST,
    ):
        if hass.services.has_service(DOMAIN, service):
            hass.services.async_remove(DOMAIN, service)
