"""Repairs module for SecretSentry integration.

This module handles creating user-friendly repair issues from scan findings.
It implements integration guessing, finding grouping, and formatted descriptions.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

# Try new location first, fall back to old
try:
    from homeassistant.helpers.issue_registry import RepairsFlow
except ImportError:
    from homeassistant.components.repairs import RepairsFlow

from .const import RuleID, Severity

if TYPE_CHECKING:
    from .rules import Finding

_LOGGER = logging.getLogger(__name__)


# Maximum occurrences to show in a single repair issue
MAX_OCCURRENCES_SHOWN = 5

# Integration keywords to detect from surrounding context
INTEGRATION_KEYWORDS: dict[str, str] = {
    "mqtt:": "MQTT",
    "mqtt_password": "MQTT",
    "rest:": "REST",
    "rest_command:": "REST",
    "telegram_bot:": "Telegram",
    "telegram:": "Telegram",
    "discord:": "Discord",
    "http:": "HTTP",
    "influxdb:": "InfluxDB",
    "database:": "Recorder/DB",
    "recorder:": "Recorder/DB",
    "mysql:": "MySQL",
    "postgres:": "PostgreSQL",
    "mariadb:": "MariaDB",
    "notify:": "Notify",
    "pushover:": "Pushover",
    "google_assistant:": "Google Assistant",
    "alexa:": "Alexa",
    "camera:": "Camera",
    "rtsp:": "Camera",
    "smtp:": "Email",
    "imap:": "Email",
    "api_key:": "API",
    "spotify:": "Spotify",
    "nest:": "Nest",
    "tuya:": "Tuya",
    "xiaomi:": "Xiaomi",
    "homekit:": "HomeKit",
    "zwave:": "Z-Wave",
    "zigbee:": "Zigbee",
}

# Path-based integration detection
PATH_INTEGRATIONS: list[tuple[str, str]] = [
    ("esphome/", "ESPHome"),
    ("esphome.", "ESPHome"),
    ("automations", "Automation"),
    ("automation", "Automation"),
    ("scripts/", "Script"),
    ("script.", "Script"),
    ("packages/", "Package"),
    ("scenes", "Scene"),
    ("lovelace", "Lovelace"),
    ("dashboards", "Dashboard"),
    (".storage/", "Storage"),
    ("custom_components/", "Custom Integration"),
    ("www/", "Web"),
    ("blueprints/", "Blueprint"),
]


def guess_integration(file_path: str, surrounding_lines: list[str] | None = None) -> str:
    """Guess which Home Assistant integration a finding relates to.

    Uses local heuristics only - no network calls or HA API access.

    Args:
        file_path: Relative path to the file.
        surrounding_lines: Optional list of ~20 lines around the finding.

    Returns:
        Integration name or "Config" as fallback.
    """
    # 1. Path-based detection
    file_lower = file_path.lower()
    for pattern, integration in PATH_INTEGRATIONS:
        if pattern in file_lower:
            return integration

    # 2. Scan surrounding lines for integration keywords
    if surrounding_lines:
        context_text = "\n".join(surrounding_lines).lower()
        for keyword, integration in INTEGRATION_KEYWORDS.items():
            if keyword in context_text:
                return integration

    # 3. Check filename itself
    for keyword, integration in INTEGRATION_KEYWORDS.items():
        keyword_clean = keyword.rstrip(":").replace("_", "")
        if keyword_clean in file_lower:
            return integration

    # 4. Fallback
    return "Config"


def create_grouped_fingerprint(
    rule_id: str,
    file_path: str,
    key_name: str | None = None,
) -> str:
    """Create a fingerprint for grouping findings (excludes line number).

    Args:
        rule_id: The rule identifier.
        file_path: Path to the file (relative).
        key_name: Optional key name for grouping (e.g., "username").

    Returns:
        SHA256-based fingerprint string for grouping.
    """
    components = [rule_id, file_path]
    if key_name:
        components.append(key_name.lower())

    combined = ":".join(components)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:16]


@dataclass
class GroupedFinding:
    """Represents a group of related findings for a single repairs issue."""

    rule_id: str
    file_path: str
    key_name: str | None
    severity: Severity
    title_base: str  # Base title without location
    description_base: str
    recommendation: str
    integration: str
    occurrences: list[tuple[int | None, str]]  # (line_number, masked_evidence)
    fingerprint: str = ""
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Generate fingerprint if not provided."""
        if not self.fingerprint:
            self.fingerprint = create_grouped_fingerprint(
                self.rule_id, self.file_path, self.key_name
            )

    @property
    def first_line(self) -> int | None:
        """Get the first line number from occurrences."""
        for line, _ in self.occurrences:
            if line is not None:
                return line
        return None

    def format_title(self) -> str:
        """Format the repairs issue title.

        Format varies by rule type:
        - Inline secrets: "Secrets in <integration>: <key> (in <file>:<line>)"
        - Duplicates: "Duplicate secret value: <type> (in <count> files)"
        - Gitignore: "Git ignore missing: <count> recommended entries"
        - External: "External exposure hint: <summary> (in <file>:<line>)"
        """
        # Location string
        if self.first_line:
            loc = f"{self.file_path}:{self.first_line}"
        else:
            loc = self.file_path

        # Rule-specific title formatting
        if self.rule_id == RuleID.R001_INLINE_SECRET_KEY:
            key_display = self.key_name or "secret"
            title = f"Secrets in {self.integration}: {key_display} (in {loc})"

        elif self.rule_id == RuleID.R005_SECRET_DUPLICATION:
            count = len(self.occurrences)
            secret_type = self.key_name or "secret"
            title = f"Duplicate secret value: {secret_type} (in {count} files)"

        elif self.rule_id in (RuleID.R010_GITIGNORE_MISSING, RuleID.R011_GITIGNORE_WEAK):
            title = f"Git ignore issue: {self.title_base}"

        elif self.rule_id == RuleID.R023_EXPOSED_PORT_HINT:
            title = f"External exposure hint: {self.title_base} (in {loc})"

        elif self.rule_id == RuleID.R008_URL_USERINFO:
            title = f"URL credentials in {self.integration} (in {loc})"

        elif self.rule_id == RuleID.R002_JWT_DETECTED:
            title = f"JWT token in {self.integration} (in {loc})"

        elif self.rule_id == RuleID.R003_PEM_BLOCK:
            title = f"Private key in {self.integration} (in {loc})"

        elif self.rule_id in (RuleID.R090_ENV_FILE_PRESENT, RuleID.R091_ENV_INLINE_SECRET):
            title = f"Environment file issue: {self.title_base} (in {loc})"

        elif self.rule_id == RuleID.R092_DOCKER_COMPOSE_INLINE_SECRET:
            key_display = self.key_name or "secret"
            title = f"Docker secret: {key_display} (in {loc})"

        elif self.rule_id == RuleID.R080_LOG_CONTAINS_SECRET:
            title = f"Secret in log: {self.title_base} (in {loc})"

        else:
            # Generic format
            title = f"{self.title_base} (in {loc})"

        # Truncate to 90 chars
        if len(title) > 90:
            title = title[:87] + "..."

        return title

    def format_description(self, privacy_mode: bool = False) -> str:
        """Format the repairs issue description.

        Creates a scannable description with sections:
        - Context (integration, file, occurrences)
        - Why this matters
        - Fix steps
        - Notes

        Args:
            privacy_mode: Whether to include privacy mode note.

        Returns:
            Formatted description string.
        """
        lines: list[str] = []

        # Context section
        lines.append("Context:")
        lines.append(f"  Integration: {self.integration}")
        lines.append(f"  File: {self.file_path}")

        # Occurrences
        if self.occurrences:
            lines.append("  Occurrences:")
            shown = 0
            for line_num, evidence in self.occurrences:
                if shown >= MAX_OCCURRENCES_SHOWN:
                    remaining = len(self.occurrences) - shown
                    lines.append(f"    + {remaining} more occurrences")
                    break
                if line_num:
                    lines.append(f"    - line {line_num}: {evidence}")
                else:
                    lines.append(f"    - {evidence}")
                shown += 1

        lines.append("")

        # Why this matters
        lines.append("Why this matters:")
        lines.append(f"  {self._get_why_text()}")
        lines.append("")

        # Fix section
        lines.append("Fix:")
        for fix_step in self._get_fix_steps():
            lines.append(f"  - {fix_step}")

        # Notes
        if privacy_mode:
            lines.append("")
            lines.append("Note: IPs/hosts masked in exports (privacy mode enabled).")

        return "\n".join(lines)

    def _get_why_text(self) -> str:
        """Get the 'why this matters' text based on rule type."""
        why_map = {
            RuleID.R001_INLINE_SECRET_KEY: "Hardcoded secrets can leak through version control or backups.",
            RuleID.R002_JWT_DETECTED: "JWTs often contain sensitive claims and can grant unauthorized access.",
            RuleID.R003_PEM_BLOCK: "Private keys allow impersonation and must be stored securely.",
            RuleID.R005_SECRET_DUPLICATION: "Duplicated secrets are harder to rotate and increase blast radius.",
            RuleID.R008_URL_USERINFO: "Credentials in URLs appear in logs, history, and referrer headers.",
            RuleID.R010_GITIGNORE_MISSING: "Without .gitignore, sensitive files may be committed accidentally.",
            RuleID.R011_GITIGNORE_WEAK: "Missing gitignore entries can lead to secret exposure in repos.",
            RuleID.R012_SECRETS_IN_REPO: "Secrets in version control persist in history even after removal.",
            RuleID.R020_HTTP_IP_BAN_DISABLED: "Without IP banning, brute force attacks are more effective.",
            RuleID.R021_TRUSTED_PROXIES_BROAD: "Trusting all IPs defeats reverse proxy security.",
            RuleID.R022_CORS_WILDCARD: "Wildcard CORS allows any website to make authenticated requests.",
            RuleID.R023_EXPOSED_PORT_HINT: "External exposure requires proper security measures.",
            RuleID.R030_WEBHOOK_SHORT: "Short webhook IDs can be brute-forced by attackers.",
            RuleID.R080_LOG_CONTAINS_SECRET: "Secrets in logs can be exposed through log aggregation or sharing.",
            RuleID.R091_ENV_INLINE_SECRET: "Environment files with secrets need proper access controls.",
            RuleID.R092_DOCKER_COMPOSE_INLINE_SECRET: "Hardcoded Docker secrets are visible in configuration.",
        }
        return why_map.get(self.rule_id, self.description_base)

    def _get_fix_steps(self) -> list[str]:
        """Get fix steps based on rule type."""
        if self.rule_id == RuleID.R001_INLINE_SECRET_KEY:
            key = self.key_name or "your_secret"
            return [
                "Move the value to secrets.yaml",
                f"Replace with: !secret {key.lower()}",
                "Restart Home Assistant after changes",
            ]

        if self.rule_id == RuleID.R005_SECRET_DUPLICATION:
            return [
                "Choose a single location in secrets.yaml for this value",
                "Replace all duplicates with !secret reference",
                "Remove the duplicate values",
            ]

        if self.rule_id == RuleID.R008_URL_USERINFO:
            return [
                "Store username and password in secrets.yaml",
                "Construct URL dynamically or use separate fields",
                "Example: mqtt://!secret mqtt_user:!secret mqtt_pass@host",
            ]

        if self.rule_id in (RuleID.R010_GITIGNORE_MISSING, RuleID.R011_GITIGNORE_WEAK):
            return [
                "Create or update .gitignore file",
                "Add: secrets.yaml, .storage/, *.db",
                "Verify with: git status --ignored",
            ]

        if self.rule_id == RuleID.R012_SECRETS_IN_REPO:
            return [
                "Run: git rm --cached secrets.yaml",
                "Add secrets.yaml to .gitignore",
                "Consider rotating all affected secrets",
            ]

        if self.rule_id == RuleID.R080_LOG_CONTAINS_SECRET:
            return [
                "Review application logging configuration",
                "Implement log sanitization for sensitive fields",
                "Consider log rotation and secure storage",
            ]

        # Default recommendation
        return [self.recommendation] if self.recommendation else ["Review and remediate this finding."]


def group_findings(findings: list[Finding]) -> dict[str, GroupedFinding]:
    """Group findings by (rule_id, file_path, key_name) for deduplication.

    Args:
        findings: List of findings from a scan.

    Returns:
        Dictionary mapping grouped fingerprint to GroupedFinding.
    """
    groups: dict[str, GroupedFinding] = {}

    for finding in findings:
        # Extract key name from title if present
        key_name = _extract_key_name(finding)

        # Get surrounding lines for integration guessing (we don't have them here,
        # so we rely on path-based detection primarily)
        integration = guess_integration(finding.file_path)

        # Create group fingerprint (excludes line number)
        group_fp = create_grouped_fingerprint(
            finding.rule_id, finding.file_path, key_name
        )

        if group_fp not in groups:
            groups[group_fp] = GroupedFinding(
                rule_id=finding.rule_id,
                file_path=finding.file_path,
                key_name=key_name,
                severity=finding.severity,
                title_base=finding.title,
                description_base=finding.description,
                recommendation=finding.recommendation,
                integration=integration,
                occurrences=[],
                fingerprint=group_fp,
                tags=finding.tags.copy() if finding.tags else [],
            )

        # Add this occurrence
        groups[group_fp].occurrences.append(
            (finding.line, finding.evidence_masked or "")
        )

    return groups


def _extract_key_name(finding: Finding) -> str | None:
    """Extract the key name from a finding title or evidence.

    Args:
        finding: The finding to extract from.

    Returns:
        Extracted key name or None.
    """
    title = finding.title or ""

    # Pattern: "Inline Secret: <key>"
    match = re.search(r"(?:Inline Secret|Secret in \.[a-z]+):\s*(\w+)", title, re.IGNORECASE)
    if match:
        return match.group(1)

    # Pattern: "Missing Secret: <key>"
    match = re.search(r"Missing Secret:\s*(\w+)", title)
    if match:
        return match.group(1)

    # Pattern: "Secret in docker-compose: <key>"
    match = re.search(r"docker-compose:\s*(\w+)", title, re.IGNORECASE)
    if match:
        return match.group(1)

    # Pattern from evidence: "<key>: ***"
    if finding.evidence_masked:
        match = re.match(r"^(\w+)\s*[:=]", finding.evidence_masked)
        if match:
            return match.group(1)

    return None


def create_summary_finding(
    high_count: int,
    med_count: int,
    low_count: int,
    last_scan: str,
    top_titles: list[str],
) -> dict[str, Any]:
    """Create a summary repairs item data.

    Args:
        high_count: Number of high severity findings.
        med_count: Number of medium severity findings.
        low_count: Number of low severity findings.
        last_scan: Timestamp of last scan.
        top_titles: Top 5 finding titles.

    Returns:
        Dictionary with summary issue data.
    """
    title = f"SecretSentry summary: {high_count}/{med_count}/{low_count} findings"

    description_lines = [
        f"Scan completed: {last_scan}",
        "",
        f"High severity: {high_count}",
        f"Medium severity: {med_count}",
        f"Low/Info severity: {low_count}",
        "",
        "Top findings:",
    ]
    for t in top_titles[:5]:
        description_lines.append(f"  - {t}")

    return {
        "title": title,
        "description": "\n".join(description_lines),
        "severity": "low",
        "fingerprint": "secretsentry_summary",
    }


# Prefix for identifying old-style repair issues for migration
OLD_ISSUE_PREFIX = "secretsentry_v2_"


# =============================================================================
# Repair Flow Handler
# =============================================================================


class SecretSentryRepairFlow(RepairsFlow):
    """Handler for SecretSentry repair flows.

    This flow allows users to acknowledge security findings. Since the
    findings are informational and require manual remediation, the flow
    simply provides information and allows dismissal.
    """

    def __init__(self, issue_id: str) -> None:
        """Initialize the repair flow.

        Args:
            issue_id: The unique identifier for the repair issue.
        """
        self.issue_id = issue_id
        super().__init__()

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Handle the first step of the repair flow.

        This step shows information about the finding and provides
        options for the user.

        Args:
            user_input: User input from the form, if any.

        Returns:
            FlowResult for the next step or completion.
        """
        return self.async_show_menu(
            step_id="init",
            menu_options=["confirm", "ignore"],
            description_placeholders={"issue_id": self.issue_id},
        )

    async def async_step_confirm(
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Handle confirmation that user will fix the issue.

        Args:
            user_input: User input from the form.

        Returns:
            FlowResult completing the flow.
        """
        return self.async_create_entry(
            title="",
            data={},
        )

    async def async_step_ignore(
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Handle user choosing to ignore the issue.

        Args:
            user_input: User input from the form.

        Returns:
            FlowResult aborting the flow.
        """
        return self.async_abort(reason="ignored")


async def async_create_fix_flow(
    hass: HomeAssistant,
    issue_id: str,
    data: dict[str, str] | None,
) -> RepairsFlow:
    """Create a repair flow for a SecretSentry issue.

    This function is called by Home Assistant when a user clicks to
    fix an issue in the repairs dashboard.

    Args:
        hass: Home Assistant instance.
        issue_id: The unique identifier for the repair issue.
        data: Additional data associated with the issue.

    Returns:
        A RepairsFlow instance to handle the repair.
    """
    return SecretSentryRepairFlow(issue_id)
