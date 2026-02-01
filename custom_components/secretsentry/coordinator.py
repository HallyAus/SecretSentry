"""DataUpdateCoordinator for SecretSentry integration."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    CONF_ENABLE_EXTERNAL_CHECK,
    CONF_EXTERNAL_URL,
    CONF_SCAN_INTERVAL,
    DOMAIN,
    SCAN_INTERVALS,
    STORAGE_KEY,
    STORAGE_VERSION,
    Severity,
)
from .scanner import ScanResult, SecretSentryScanner

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry

_LOGGER = logging.getLogger(__name__)


class SecretSentryData:
    """Data class to hold scan results and delta information."""

    def __init__(
        self,
        scan_result: ScanResult,
        new_fingerprints: set[str],
        resolved_fingerprints: set[str],
        external_check_result: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the data class.

        Args:
            scan_result: Result from the scanner.
            new_fingerprints: Fingerprints of new findings.
            resolved_fingerprints: Fingerprints of resolved findings.
            external_check_result: Results from external URL check.
        """
        self.scan_result = scan_result
        self.new_fingerprints = new_fingerprints
        self.resolved_fingerprints = resolved_fingerprints
        self.external_check_result = external_check_result

    @property
    def findings(self):
        """Get findings from scan result."""
        return self.scan_result.findings

    @property
    def total_findings(self) -> int:
        """Get total number of findings."""
        return self.scan_result.total_findings

    @property
    def high_count(self) -> int:
        """Get count of high severity findings."""
        return self.scan_result.high_count

    @property
    def med_count(self) -> int:
        """Get count of medium severity findings."""
        return self.scan_result.med_count

    @property
    def low_count(self) -> int:
        """Get count of low severity findings."""
        return self.scan_result.low_count

    @property
    def new_high_count(self) -> int:
        """Get count of new high severity findings."""
        return len([
            f for f in self.scan_result.findings
            if f.fingerprint in self.new_fingerprints
            and f.severity == Severity.HIGH
        ])

    @property
    def resolved_count(self) -> int:
        """Get count of resolved findings."""
        return len(self.resolved_fingerprints)

    @property
    def last_scan(self) -> datetime:
        """Get timestamp of last scan."""
        return self.scan_result.timestamp

    @property
    def scan_duration(self) -> float:
        """Get duration of last scan."""
        return self.scan_result.scan_duration

    def get_top_findings(self, limit: int = 5) -> list[str]:
        """Get top findings as summary strings.

        Args:
            limit: Maximum number of findings to return.

        Returns:
            List of summary strings (no secrets).
        """
        # Sort by severity (high first)
        severity_order = {Severity.HIGH: 0, Severity.MED: 1, Severity.LOW: 2, Severity.INFO: 3}
        sorted_findings = sorted(
            self.scan_result.findings,
            key=lambda f: severity_order.get(f.severity, 99)
        )
        return [f.summary(80) for f in sorted_findings[:limit]]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        base = self.scan_result.to_dict()
        base["delta"] = {
            "new_fingerprints": list(self.new_fingerprints),
            "resolved_fingerprints": list(self.resolved_fingerprints),
            "new_high_count": self.new_high_count,
            "resolved_count": self.resolved_count,
        }
        if self.external_check_result:
            base["external_self_check"] = self.external_check_result
        return base


class SecretSentryCoordinator(DataUpdateCoordinator[SecretSentryData]):
    """Coordinator for SecretSentry security scanning.

    This coordinator manages periodic security scans of the Home Assistant
    configuration directory and provides the results to sensors.
    """

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the coordinator.

        Args:
            hass: Home Assistant instance.
            config_entry: Configuration entry for this integration.
        """
        # Determine scan interval from options
        interval_key = config_entry.options.get(CONF_SCAN_INTERVAL, "daily")
        interval_seconds = SCAN_INTERVALS.get(interval_key)

        update_interval = None
        if interval_seconds:
            update_interval = timedelta(seconds=interval_seconds)

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=update_interval,
        )
        self.config_entry = config_entry
        self._config_path = hass.config.path()
        self._store = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self._previous_fingerprints: set[str] = set()
        self._loaded_state = False

    async def _async_update_data(self) -> SecretSentryData:
        """Fetch data from scanner.

        This method is called by the coordinator on the update interval.
        The actual scanning is run in the executor to avoid blocking.

        Returns:
            SecretSentryData containing scan results.
        """
        # Load previous state if not loaded
        if not self._loaded_state:
            await self._load_state()

        # Get options for scanner
        options = dict(self.config_entry.options)

        # Run scanner in executor to avoid blocking the event loop
        scan_result = await self.hass.async_add_executor_job(
            self._run_scan, options
        )

        _LOGGER.debug(
            "Scan completed in %.2f seconds. Found %d issues.",
            scan_result.scan_duration,
            scan_result.total_findings,
        )

        # Calculate delta
        current_fingerprints = scan_result.fingerprints
        new_fingerprints = current_fingerprints - self._previous_fingerprints
        resolved_fingerprints = self._previous_fingerprints - current_fingerprints

        # Run external check if enabled
        external_result = None
        if options.get(CONF_ENABLE_EXTERNAL_CHECK):
            external_url = options.get(CONF_EXTERNAL_URL)
            if external_url:
                external_result = await self._run_external_check(external_url)
                # Add external findings to scan result
                if external_result and external_result.get("findings"):
                    scan_result.findings.extend(external_result["findings"])

        # Create data object
        data = SecretSentryData(
            scan_result=scan_result,
            new_fingerprints=new_fingerprints,
            resolved_fingerprints=resolved_fingerprints,
            external_check_result=external_result,
        )

        # Update repairs
        await self._update_repairs(data)

        # Save state
        self._previous_fingerprints = current_fingerprints
        await self._save_state(data)

        return data

    def _run_scan(self, options: dict[str, Any]) -> ScanResult:
        """Run the security scan synchronously.

        This method is executed in the executor pool.

        Args:
            options: Scanner options from config entry.

        Returns:
            ScanResult with all findings.
        """
        scanner = SecretSentryScanner(self._config_path, options)
        return scanner.scan(self._previous_fingerprints)

    async def _run_external_check(
        self, external_url: str
    ) -> dict[str, Any] | None:
        """Run external URL security check.

        Args:
            external_url: The user's external URL to check.

        Returns:
            Dictionary with check results or None on error.
        """
        try:
            from .http_check import check_external_url

            return await check_external_url(self.hass, external_url)
        except Exception as err:
            _LOGGER.warning("External URL check failed: %s", err)
            return {"error": str(err), "findings": []}

    async def _update_repairs(self, data: SecretSentryData) -> None:
        """Update repair issues based on scan results.

        Uses grouped findings to reduce spam and improve readability.
        Creates repair issues with descriptive titles and actionable descriptions.

        Args:
            data: Current scan data.
        """
        from homeassistant.helpers import issue_registry as ir

        from .repairs import (
            create_summary_finding,
            group_findings,
        )

        # Group findings by (rule_id, file_path, key_name)
        grouped = group_findings(data.findings)

        # Get current grouped fingerprints
        current_group_fps = set(grouped.keys())

        # Track which old fingerprints we've seen for migration
        if not hasattr(self, "_last_group_fingerprints"):
            self._last_group_fingerprints: set[str] = set()

        # New groups to create issues for
        new_group_fps = current_group_fps - self._last_group_fingerprints

        # Resolved groups to delete issues for
        resolved_group_fps = self._last_group_fingerprints - current_group_fps

        # Privacy mode for descriptions
        privacy_mode = self.config_entry.options.get("privacy_mode_reports", True)

        # Create issues for new grouped findings
        for group_fp in new_group_fps:
            group = grouped.get(group_fp)
            if not group:
                continue

            try:
                ir.async_create_issue(
                    self.hass,
                    DOMAIN,
                    group_fp,
                    is_fixable=False,
                    is_persistent=True,
                    severity=self._map_severity_to_ir(group.severity),
                    translation_key=group.rule_id.lower(),
                    translation_placeholders={
                        "title": group.format_title(),
                        "file_path": group.file_path,
                        "line": str(group.first_line) if group.first_line else "N/A",
                        "evidence": group.occurrences[0][1] if group.occurrences else "N/A",
                        "recommendation": group.format_description(privacy_mode),
                        "description": group._get_why_text(),
                    },
                )
            except Exception as err:
                _LOGGER.debug("Failed to create repair issue: %s", err)

        # Remove resolved issues
        for group_fp in resolved_group_fps:
            try:
                ir.async_delete_issue(self.hass, DOMAIN, group_fp)
            except Exception as err:
                _LOGGER.debug("Failed to delete repair issue: %s", err)

        # Update/create summary issue
        if data.findings:
            try:
                summary = create_summary_finding(
                    high_count=data.high_count,
                    med_count=data.med_count,
                    low_count=data.low_count,
                    last_scan=data.last_scan.isoformat(),
                    top_titles=data.get_top_findings(5),
                )
                ir.async_create_issue(
                    self.hass,
                    DOMAIN,
                    summary["fingerprint"],
                    is_fixable=False,
                    is_persistent=True,
                    severity=ir.IssueSeverity.WARNING if data.high_count > 0 else ir.IssueSeverity.WARNING,
                    learn_more_url="https://github.com/secretsentry/secretsentry",
                    translation_key="summary",
                    translation_placeholders={
                        "title": summary["title"],
                        "description": summary["description"],
                    },
                )
            except Exception as err:
                _LOGGER.debug("Failed to create summary issue: %s", err)
        else:
            # No findings - remove summary
            try:
                ir.async_delete_issue(self.hass, DOMAIN, "secretsentry_summary")
            except Exception:
                pass

        # Update tracked fingerprints
        self._last_group_fingerprints = current_group_fps

    @staticmethod
    def _map_severity_to_ir(severity: str) -> "ir.IssueSeverity":
        """Map finding severity to issue registry severity.

        Args:
            severity: Finding severity string.

        Returns:
            IssueSeverity enum value.
        """
        from homeassistant.helpers import issue_registry as ir

        mapping = {
            Severity.HIGH: ir.IssueSeverity.ERROR,
            Severity.MED: ir.IssueSeverity.WARNING,
            Severity.LOW: ir.IssueSeverity.WARNING,
            Severity.INFO: ir.IssueSeverity.WARNING,
        }
        return mapping.get(severity, ir.IssueSeverity.WARNING)

    async def _load_state(self) -> None:
        """Load previous scan state from storage."""
        try:
            stored = await self._store.async_load()
            if stored and isinstance(stored, dict):
                fingerprints = stored.get("fingerprints", [])
                self._previous_fingerprints = set(fingerprints)
                _LOGGER.debug(
                    "Loaded %d previous fingerprints from storage",
                    len(self._previous_fingerprints)
                )
        except Exception as err:
            _LOGGER.warning("Failed to load state: %s", err)

        self._loaded_state = True

    async def _save_state(self, data: SecretSentryData) -> None:
        """Save scan state to storage.

        Only stores fingerprints and counts, never raw secrets.

        Args:
            data: Current scan data.
        """
        try:
            state = {
                "fingerprints": list(data.scan_result.fingerprints),
                "counts": {
                    "high": data.high_count,
                    "med": data.med_count,
                    "low": data.low_count,
                },
                "last_scan": data.last_scan.isoformat(),
            }
            await self._store.async_save(state)
        except Exception as err:
            _LOGGER.warning("Failed to save state: %s", err)

    async def async_scan_now(self) -> SecretSentryData:
        """Trigger an immediate scan.

        Returns:
            SecretSentryData containing scan results.
        """
        await self.async_refresh()
        return self.data

    async def async_export_report(self) -> str:
        """Export findings to a JSON report file.

        Returns:
            Path to the exported report file.
        """
        import json
        from pathlib import Path

        from .const import REPORT_FILENAME

        if not self.data:
            await self.async_refresh()

        report_path = Path(self._config_path) / REPORT_FILENAME

        report_data = {
            "config_path": self._config_path,
            **self.data.to_dict(),
        }

        # Write report in executor
        def write_report() -> None:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)

        await self.hass.async_add_executor_job(write_report)

        _LOGGER.info("Security report exported to %s", report_path)
        return str(report_path)

    async def async_export_sanitised(self) -> tuple[str, int, list[str]]:
        """Export sanitised copy of configuration.

        Returns:
            Tuple of (output_dir, files_processed, errors).
        """
        from pathlib import Path

        from .const import SANITISED_DIR
        from .scanner import create_sanitised_copy

        output_dir = str(Path(self._config_path) / SANITISED_DIR)
        options = dict(self.config_entry.options)

        files_processed, errors = await self.hass.async_add_executor_job(
            create_sanitised_copy,
            self._config_path,
            output_dir,
            options,
        )

        _LOGGER.info(
            "Sanitised copy created at %s (%d files)",
            output_dir,
            files_processed
        )

        return output_dir, files_processed, errors
