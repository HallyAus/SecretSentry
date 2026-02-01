"""Rule engine and rule implementations for SecretSentry.

This module contains the base Rule class and all security rule implementations.
Rules must never throw exceptions; they fail safe and return empty findings on errors.
"""
from __future__ import annotations

import logging
import re
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .const import (
    BROAD_PROXY_RANGES,
    RECOMMENDED_GITIGNORE,
    SECRET_AGE_HIGH,
    SECRET_AGE_LOW,
    SECRET_AGE_MED,
    SENSITIVE_KEYS,
    RuleID,
    Severity,
    Tags,
)
from .masking import (
    JWT_PATTERN,
    PEM_BEGIN_PATTERN,
    SECRET_REF_PATTERN,
    URL_USERINFO_PATTERN,
    WEBHOOK_PATTERN,
    calculate_entropy,
    create_fingerprint,
    extract_url_userinfo,
    hash_for_comparison,
    looks_like_secret,
    mask_jwt,
    mask_line,
    mask_pem,
    mask_secret,
    mask_webhook_id,
    redact_url_userinfo,
    truncate_evidence,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

_LOGGER = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a security finding.

    All sensitive data must be masked before storing in evidence_masked.
    The fingerprint must never include raw secret material.
    """

    rule_id: str
    severity: Severity
    confidence: int  # 0-100
    title: str
    description: str
    file_path: str  # relative to /config
    line: int | None
    evidence_masked: str | None
    recommendation: str
    tags: list[str] = field(default_factory=list)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """Generate fingerprint if not provided."""
        if not self.fingerprint:
            self.fingerprint = create_fingerprint(
                self.rule_id,
                self.file_path,
                self.line,
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary for JSON export."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line": self.line,
            "evidence_masked": self.evidence_masked,
            "recommendation": self.recommendation,
            "tags": self.tags,
            "fingerprint": self.fingerprint,
        }

    def summary(self, max_length: int = 100) -> str:
        """Get a short summary string for display."""
        loc = f"{self.file_path}:{self.line}" if self.line else self.file_path
        summary = f"[{self.severity.upper()}] {self.title} in {loc}"
        if len(summary) > max_length:
            return summary[: max_length - 3] + "..."
        return summary


@dataclass
class ScanContext:
    """Context passed to rules during scanning."""

    config_root: Path
    secrets_map: dict[str, str]  # key -> masked/hashed value (never raw)
    secrets_raw_hashes: dict[str, str]  # key -> sha256 of raw value
    used_secret_keys: set[str]
    gitignore_text: str | None
    options: dict[str, Any]
    last_scan_fingerprints: set[str] = field(default_factory=set)

    # Collected during scan
    inline_value_hashes: dict[str, list[tuple[str, int]]] = field(
        default_factory=dict
    )  # hash -> [(file, line), ...]
    secret_usage_map: dict[str, list[tuple[str, int]]] = field(
        default_factory=dict
    )  # key -> [(file, line), ...]


class Rule(ABC):
    """Base class for security rules.

    Rules must not throw exceptions. They should catch errors internally
    and return empty findings lists on failure.
    """

    id: str
    title: str
    severity: Severity
    tags: list[str]

    @abstractmethod
    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Evaluate a file's content for security issues.

        Args:
            file_path: Relative path to the file.
            lines: List of lines in the file.
            context: Scan context with secrets map and options.

        Returns:
            List of findings (may be empty).
        """

    def evaluate_context(self, context: ScanContext) -> list[Finding]:
        """Evaluate the overall context for issues (post-file scan).

        Override this for rules that need to analyze across all files.

        Args:
            context: Scan context after all files processed.

        Returns:
            List of findings (may be empty).
        """
        return []

    def _create_finding(
        self,
        file_path: str,
        line: int | None,
        evidence: str,
        confidence: int = 80,
        description: str | None = None,
        recommendation: str | None = None,
        fingerprint_key: str | None = None,
    ) -> Finding:
        """Helper to create a finding with rule defaults."""
        return Finding(
            rule_id=self.id,
            severity=self.severity,
            confidence=confidence,
            title=self.title,
            description=description or f"{self.title} detected.",
            file_path=file_path,
            line=line,
            evidence_masked=truncate_evidence(mask_line(evidence)),
            recommendation=recommendation or "Review and remediate this finding.",
            tags=self.tags.copy(),
            fingerprint=create_fingerprint(
                self.id, file_path, line, fingerprint_key
            ),
        )


# =============================================================================
# Group 1: Credential Leak Linting
# =============================================================================


class R001InlineSecretKey(Rule):
    """Detect inline secrets in configuration files."""

    id = RuleID.R001_INLINE_SECRET_KEY
    title = "Inline Secret Detected"
    severity = Severity.HIGH
    tags = [Tags.SECRETS]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Detect sensitive keys with hardcoded values."""
        findings: list[Finding] = []

        # Skip secrets.yaml itself
        if file_path == "secrets.yaml":
            return findings

        try:
            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()

                # Skip comments and empty lines
                if not stripped or stripped.startswith("#"):
                    continue

                # Check each sensitive key pattern
                for key_pattern, key_severity, confidence_boost in SENSITIVE_KEYS:
                    # Match patterns like "api_key: value" or "api_key=value"
                    pattern = rf"\b({re.escape(key_pattern)})\s*[:=]\s*(.+)"
                    match = re.search(pattern, line, re.IGNORECASE)

                    if not match:
                        continue

                    key_name = match.group(1)
                    value_part = match.group(2).strip()

                    # Skip if using !secret reference
                    if value_part.startswith("!secret"):
                        secret_key_match = SECRET_REF_PATTERN.search(value_part)
                        if secret_key_match:
                            context.used_secret_keys.add(secret_key_match.group(1))
                        continue

                    # Skip if it's a placeholder, empty, or template
                    if self._is_skip_value(value_part):
                        continue

                    # Strip quotes for analysis
                    clean_value = value_part.strip("'\"")

                    # Skip env var references
                    if clean_value.startswith("${") or clean_value.startswith("$"):
                        continue

                    # Check if value looks like a secret
                    is_secret, value_confidence = looks_like_secret(clean_value)
                    if not is_secret and len(clean_value) < 8:
                        continue

                    # Calculate final confidence
                    confidence = min(
                        100, 40 + confidence_boost + (value_confidence // 3)
                    )

                    # Track for duplication detection
                    value_hash = hash_for_comparison(clean_value)
                    if value_hash not in context.inline_value_hashes:
                        context.inline_value_hashes[value_hash] = []
                    context.inline_value_hashes[value_hash].append(
                        (file_path, line_num)
                    )

                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=key_severity,
                            confidence=confidence,
                            title=f"Inline Secret: {key_name}",
                            description=(
                                f"The key '{key_name}' contains a hardcoded value "
                                "instead of using a !secret reference."
                            ),
                            file_path=file_path,
                            line=line_num,
                            evidence_masked=f"{key_name}: {mask_secret(clean_value)}",
                            recommendation=(
                                f"Move the value to secrets.yaml and use "
                                f"'!secret {key_name.lower()}' instead."
                            ),
                            tags=self.tags.copy(),
                            fingerprint=create_fingerprint(
                                self.id, file_path, line_num, key_name.lower()
                            ),
                        )
                    )
                    break  # Only one finding per line

        except Exception as err:
            _LOGGER.debug("R001 error scanning %s: %s", file_path, err)

        return findings

    @staticmethod
    def _is_skip_value(value: str) -> bool:
        """Check if value should be skipped."""
        skip_values = ('""', "''", "", "null", "~", "None", "[]", "{}")
        if value in skip_values:
            return True
        # Template expressions
        if "{{" in value or "{%" in value:
            return True
        # YAML anchors/aliases
        if value.startswith("*") or value.startswith("&"):
            return True
        return False


class R002JWTDetected(Rule):
    """Detect JWT tokens in configuration files."""

    id = RuleID.R002_JWT_DETECTED
    title = "JWT Token Detected"
    severity = Severity.HIGH
    tags = [Tags.SECRETS]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Detect JWT tokens in file content."""
        findings: list[Finding] = []

        # Skip secrets.yaml
        if file_path == "secrets.yaml":
            return findings

        try:
            for line_num, line in enumerate(lines, start=1):
                for match in JWT_PATTERN.finditer(line):
                    token = match.group(0)
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=90,
                            title="JWT Token Detected",
                            description=(
                                "A JSON Web Token (JWT) was found in the configuration. "
                                "JWTs often contain sensitive claims and should be stored securely."
                            ),
                            file_path=file_path,
                            line=line_num,
                            evidence_masked=mask_jwt(token),
                            recommendation=(
                                "Move the JWT to secrets.yaml and use a !secret reference."
                            ),
                            tags=self.tags.copy(),
                            fingerprint=create_fingerprint(
                                self.id, file_path, line_num
                            ),
                        )
                    )
        except Exception as err:
            _LOGGER.debug("R002 error scanning %s: %s", file_path, err)

        return findings


class R003PEMBlock(Rule):
    """Detect PEM private key blocks."""

    id = RuleID.R003_PEM_BLOCK
    title = "PEM Private Key Detected"
    severity = Severity.HIGH
    tags = [Tags.SECRETS]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Detect PEM private key blocks."""
        findings: list[Finding] = []

        try:
            for line_num, line in enumerate(lines, start=1):
                if PEM_BEGIN_PATTERN.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=95,
                            title="PEM Private Key Block",
                            description=(
                                "A PEM-encoded private key was detected. Private keys "
                                "should never be stored in configuration files."
                            ),
                            file_path=file_path,
                            line=line_num,
                            evidence_masked=mask_pem(line),
                            recommendation=(
                                "Store private keys in a secure location outside the "
                                "config directory with restricted permissions."
                            ),
                            tags=self.tags.copy(),
                            fingerprint=create_fingerprint(
                                self.id, file_path, line_num
                            ),
                        )
                    )
        except Exception as err:
            _LOGGER.debug("R003 error scanning %s: %s", file_path, err)

        return findings


class R004SecretRefMissing(Rule):
    """Detect !secret references that don't exist in secrets.yaml."""

    id = RuleID.R004_SECRET_REF_MISSING
    title = "Missing Secret Reference"
    severity = Severity.MED
    tags = [Tags.SECRETS]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Collect !secret references for later validation."""
        # This rule collects data; findings are generated in evaluate_context
        try:
            for line_num, line in enumerate(lines, start=1):
                for match in SECRET_REF_PATTERN.finditer(line):
                    secret_key = match.group(1)
                    context.used_secret_keys.add(secret_key)

                    # Track usage locations
                    if secret_key not in context.secret_usage_map:
                        context.secret_usage_map[secret_key] = []
                    context.secret_usage_map[secret_key].append(
                        (file_path, line_num)
                    )
        except Exception as err:
            _LOGGER.debug("R004 error scanning %s: %s", file_path, err)

        return []

    def evaluate_context(self, context: ScanContext) -> list[Finding]:
        """Check for missing secret references after all files scanned."""
        findings: list[Finding] = []

        try:
            available_keys = set(context.secrets_map.keys())

            for key in context.used_secret_keys:
                if key not in available_keys:
                    # Get first usage location
                    locations = context.secret_usage_map.get(key, [])
                    if locations:
                        file_path, line_num = locations[0]
                    else:
                        file_path, line_num = "unknown", None

                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=95,
                            title=f"Missing Secret: {key}",
                            description=(
                                f"The secret key '{key}' is referenced but not defined "
                                "in secrets.yaml."
                            ),
                            file_path=file_path,
                            line=line_num,
                            evidence_masked=f"!secret {key}",
                            recommendation=(
                                f"Add '{key}' to your secrets.yaml file with the appropriate value."
                            ),
                            tags=self.tags.copy(),
                            fingerprint=create_fingerprint(
                                self.id, file_path, line_num, key
                            ),
                        )
                    )
        except Exception as err:
            _LOGGER.debug("R004 context evaluation error: %s", err)

        return findings


class R005SecretDuplication(Rule):
    """Detect duplicate inline secret values across files."""

    id = RuleID.R005_SECRET_DUPLICATION
    title = "Duplicate Secret Value"
    severity = Severity.MED
    tags = [Tags.SECRETS]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """This rule uses data collected by R001."""
        return []

    def evaluate_context(self, context: ScanContext) -> list[Finding]:
        """Check for duplicate secret values after all files scanned."""
        findings: list[Finding] = []

        try:
            for value_hash, locations in context.inline_value_hashes.items():
                if len(locations) > 1:
                    # Format location list (without exposing the value)
                    loc_strs = [f"{f}:{l}" for f, l in locations[:5]]
                    if len(locations) > 5:
                        loc_strs.append(f"...and {len(locations) - 5} more")

                    first_file, first_line = locations[0]

                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=85,
                            title="Duplicate Secret Value Detected",
                            description=(
                                f"The same secret value appears in {len(locations)} locations. "
                                "This suggests the value should be in secrets.yaml."
                            ),
                            file_path=first_file,
                            line=first_line,
                            evidence_masked=f"Value duplicated in: {', '.join(loc_strs)}",
                            recommendation=(
                                "Store this value once in secrets.yaml and use !secret references."
                            ),
                            tags=self.tags.copy(),
                            fingerprint=create_fingerprint(
                                self.id, first_file, first_line, value_hash[:8]
                            ),
                        )
                    )
        except Exception as err:
            _LOGGER.debug("R005 context evaluation error: %s", err)

        return findings


# =============================================================================
# v3.0: R008 - URL Userinfo Detection
# =============================================================================


class R008URLUserinfo(Rule):
    """Detect credentials embedded in URLs (userinfo)."""

    id = RuleID.R008_URL_USERINFO
    title = "URL Contains Credentials"
    severity = Severity.HIGH
    tags = [Tags.SECRETS, Tags.URL]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Detect URLs with embedded credentials (scheme://user:pass@host)."""
        findings: list[Finding] = []

        # Skip secrets.yaml
        if file_path == "secrets.yaml":
            return findings

        try:
            for line_num, line in enumerate(lines, start=1):
                for match in URL_USERINFO_PATTERN.finditer(line):
                    # Extract components but never store raw password
                    scheme = match.group(1)
                    username = match.group(2)
                    host = match.group(4)

                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=95,
                            title="Credentials in URL",
                            description=(
                                f"A URL contains embedded credentials in the userinfo section. "
                                f"This exposes the password in configuration and logs."
                            ),
                            file_path=file_path,
                            line=line_num,
                            evidence_masked=f"{scheme}{mask_secret(username, 2, 0, 4)}:***@{host}",
                            recommendation=(
                                "Move the credentials to secrets.yaml and construct "
                                "the URL dynamically, or use environment variables."
                            ),
                            tags=self.tags.copy(),
                            fingerprint=create_fingerprint(
                                self.id, file_path, line_num, host
                            ),
                        )
                    )
        except Exception as err:
            _LOGGER.debug("R008 error scanning %s: %s", file_path, err)

        return findings


# =============================================================================
# Group 2: Git Hygiene
# =============================================================================


class R010GitignoreMissing(Rule):
    """Detect missing .gitignore when .git exists."""

    id = RuleID.R010_GITIGNORE_MISSING
    title = "Gitignore Missing"
    severity = Severity.MED
    tags = [Tags.GIT]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """This rule evaluates in context only."""
        return []

    def evaluate_context(self, context: ScanContext) -> list[Finding]:
        """Check for missing .gitignore."""
        findings: list[Finding] = []

        try:
            git_dir = context.config_root / ".git"
            gitignore = context.config_root / ".gitignore"

            if git_dir.exists() and not gitignore.exists():
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=90,
                        title="Git Repository Without .gitignore",
                        description=(
                            "A .git directory exists but no .gitignore file was found. "
                            "This may lead to accidentally committing sensitive files."
                        ),
                        file_path=".gitignore",
                        line=None,
                        evidence_masked=".git exists but .gitignore missing",
                        recommendation=(
                            f"Create a .gitignore file with at least: "
                            f"{', '.join(RECOMMENDED_GITIGNORE)}"
                        ),
                        tags=self.tags.copy(),
                    )
                )
        except Exception as err:
            _LOGGER.debug("R010 error: %s", err)

        return findings


class R011GitignoreWeak(Rule):
    """Detect .gitignore missing recommended entries."""

    id = RuleID.R011_GITIGNORE_WEAK
    title = "Gitignore Missing Entries"
    severity = Severity.MED
    tags = [Tags.GIT]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """This rule evaluates in context only."""
        return []

    def evaluate_context(self, context: ScanContext) -> list[Finding]:
        """Check .gitignore for missing entries."""
        findings: list[Finding] = []

        if not context.gitignore_text:
            return findings

        try:
            gitignore_lines = [
                line.strip()
                for line in context.gitignore_text.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

            missing: list[str] = []
            for entry in RECOMMENDED_GITIGNORE:
                entry_found = False
                for line in gitignore_lines:
                    # Exact match or pattern match
                    if line == entry or line == entry.rstrip("/"):
                        entry_found = True
                        break
                    # Glob patterns
                    if line.endswith("*") and entry.startswith(line[:-1]):
                        entry_found = True
                        break
                if not entry_found:
                    missing.append(entry)

            if missing:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=85,
                        title="Gitignore Missing Recommended Entries",
                        description=(
                            f"The .gitignore is missing {len(missing)} recommended entries "
                            "that protect sensitive files from being committed."
                        ),
                        file_path=".gitignore",
                        line=None,
                        evidence_masked=f"Missing: {', '.join(missing)}",
                        recommendation=(
                            f"Add the following to .gitignore: {', '.join(missing)}"
                        ),
                        tags=self.tags.copy(),
                    )
                )
        except Exception as err:
            _LOGGER.debug("R011 error: %s", err)

        return findings


class R012SecretsInRepo(Rule):
    """Detect if secrets.yaml might be tracked in git."""

    id = RuleID.R012_SECRETS_IN_REPO
    title = "Secrets File May Be Tracked"
    severity = Severity.HIGH
    tags = [Tags.GIT, Tags.SECRETS]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """This rule evaluates in context only."""
        return []

    def evaluate_context(self, context: ScanContext) -> list[Finding]:
        """Check if secrets.yaml might be tracked in git."""
        findings: list[Finding] = []

        try:
            git_dir = context.config_root / ".git"
            secrets_file = context.config_root / "secrets.yaml"

            if not git_dir.exists() or not secrets_file.exists():
                return findings

            # Check if secrets.yaml is in .gitignore
            secrets_ignored = False
            if context.gitignore_text:
                for line in context.gitignore_text.splitlines():
                    line = line.strip()
                    if line == "secrets.yaml" or line == "secrets.yaml*":
                        secrets_ignored = True
                        break

            # If git subprocess checks enabled, verify tracking status
            if context.options.get("enable_git_subprocess_checks"):
                try:
                    result = subprocess.run(
                        ["git", "ls-files", "--error-unmatch", "secrets.yaml"],
                        cwd=str(context.config_root),
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        # File is tracked!
                        findings.append(
                            Finding(
                                rule_id=self.id,
                                severity=Severity.HIGH,
                                confidence=100,
                                title="secrets.yaml Is Tracked in Git",
                                description=(
                                    "The secrets.yaml file is currently tracked by git. "
                                    "Your secrets may be exposed in the repository history."
                                ),
                                file_path="secrets.yaml",
                                line=None,
                                evidence_masked="git ls-files confirms tracking",
                                recommendation=(
                                    "Run 'git rm --cached secrets.yaml' to untrack the file, "
                                    "add it to .gitignore, and consider rotating all secrets."
                                ),
                                tags=self.tags.copy(),
                            )
                        )
                        return findings
                except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                    pass

            # Heuristic check if git checks not enabled
            if not secrets_ignored:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=Severity.MED,
                        confidence=70,
                        title="secrets.yaml Not in .gitignore",
                        description=(
                            "The secrets.yaml file is not listed in .gitignore. "
                            "It may be tracked or at risk of being committed."
                        ),
                        file_path="secrets.yaml",
                        line=None,
                        evidence_masked="secrets.yaml not found in .gitignore",
                        recommendation=(
                            "Add 'secrets.yaml' to .gitignore and verify it's not tracked."
                        ),
                        tags=self.tags.copy(),
                    )
                )
        except Exception as err:
            _LOGGER.debug("R012 error: %s", err)

        return findings


# =============================================================================
# Group 3: Exposure / Proxy / HTTP Hardening
# =============================================================================


class R020HTTPIPBanDisabled(Rule):
    """Detect disabled or weak IP ban settings."""

    id = RuleID.R020_HTTP_IP_BAN_DISABLED
    title = "HTTP IP Ban Disabled"
    severity = Severity.MED
    tags = [Tags.HTTP]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Check HTTP configuration for IP ban settings."""
        findings: list[Finding] = []

        if file_path != "configuration.yaml":
            return findings

        try:
            import yaml

            content = "\n".join(lines)
            config = yaml.safe_load(content)

            if not isinstance(config, dict):
                return findings

            http_config = config.get("http")
            if not http_config or not isinstance(http_config, dict):
                return findings

            issues: list[str] = []

            # Check ip_ban_enabled
            if http_config.get("ip_ban_enabled") is False:
                issues.append("ip_ban_enabled is false")

            # Check login_attempts_threshold
            threshold = http_config.get("login_attempts_threshold")
            if threshold is None:
                issues.append("login_attempts_threshold not set")
            elif isinstance(threshold, int) and threshold < 0:
                issues.append("login_attempts_threshold is disabled (<0)")

            if issues:
                # Find http: line
                line_num = 1
                for idx, line in enumerate(lines, start=1):
                    if line.strip().startswith("http:"):
                        line_num = idx
                        break

                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=85,
                        title="HTTP Security Settings Weak",
                        description=(
                            "The HTTP integration has weak brute-force protection. "
                            f"Issues: {'; '.join(issues)}"
                        ),
                        file_path=file_path,
                        line=line_num,
                        evidence_masked="; ".join(issues),
                        recommendation=(
                            "Set ip_ban_enabled: true and login_attempts_threshold "
                            "to a positive value (e.g., 5)."
                        ),
                        tags=self.tags.copy(),
                    )
                )
        except Exception as err:
            _LOGGER.debug("R020 error: %s", err)

        return findings


class R021TrustedProxiesBroad(Rule):
    """Detect overly broad trusted_proxies."""

    id = RuleID.R021_TRUSTED_PROXIES_BROAD
    title = "Overly Broad Trusted Proxies"
    severity = Severity.HIGH
    tags = [Tags.HTTP, Tags.PROXY]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Check for overly broad trusted_proxies."""
        findings: list[Finding] = []

        if file_path != "configuration.yaml":
            return findings

        try:
            import yaml

            content = "\n".join(lines)
            config = yaml.safe_load(content)

            if not isinstance(config, dict):
                return findings

            http_config = config.get("http")
            if not http_config or not isinstance(http_config, dict):
                return findings

            trusted_proxies = http_config.get("trusted_proxies", [])
            if not trusted_proxies:
                return findings

            if isinstance(trusted_proxies, str):
                trusted_proxies = [trusted_proxies]

            broad_found: list[str] = []
            for proxy in trusted_proxies:
                proxy_str = str(proxy).strip()
                if proxy_str in BROAD_PROXY_RANGES:
                    broad_found.append(proxy_str)

            if broad_found:
                # Find line number
                line_num = 1
                for idx, line in enumerate(lines, start=1):
                    if "trusted_proxies" in line:
                        line_num = idx
                        break

                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=95,
                        title="Trusted Proxies Allow All IPs",
                        description=(
                            f"The trusted_proxies setting includes: {', '.join(broad_found)}. "
                            "This trusts ALL IP addresses and defeats proxy security."
                        ),
                        file_path=file_path,
                        line=line_num,
                        evidence_masked=f"trusted_proxies includes: {', '.join(broad_found)}",
                        recommendation=(
                            "Restrict trusted_proxies to specific proxy IPs only."
                        ),
                        tags=self.tags.copy(),
                    )
                )
        except Exception as err:
            _LOGGER.debug("R021 error: %s", err)

        return findings


class R022CORSWildcard(Rule):
    """Detect wildcard CORS configuration."""

    id = RuleID.R022_CORS_WILDCARD
    title = "CORS Wildcard Origin"
    severity = Severity.HIGH
    tags = [Tags.HTTP]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Check for wildcard CORS origins."""
        findings: list[Finding] = []

        if file_path != "configuration.yaml":
            return findings

        try:
            import yaml

            content = "\n".join(lines)
            config = yaml.safe_load(content)

            if not isinstance(config, dict):
                return findings

            http_config = config.get("http")
            if not http_config or not isinstance(http_config, dict):
                return findings

            cors_origins = http_config.get("cors_allowed_origins", [])
            if not cors_origins:
                return findings

            if isinstance(cors_origins, str):
                cors_origins = [cors_origins]

            wildcard_found = False
            for origin in cors_origins:
                if origin == "*" or origin == "null":
                    wildcard_found = True
                    break

            if wildcard_found:
                line_num = 1
                for idx, line in enumerate(lines, start=1):
                    if "cors_allowed_origins" in line:
                        line_num = idx
                        break

                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=95,
                        title="CORS Allows All Origins",
                        description=(
                            "The cors_allowed_origins includes '*' which allows "
                            "any website to make authenticated requests."
                        ),
                        file_path=file_path,
                        line=line_num,
                        evidence_masked="cors_allowed_origins: *",
                        recommendation=(
                            "Specify exact allowed origins instead of using wildcards."
                        ),
                        tags=self.tags.copy(),
                    )
                )
        except Exception as err:
            _LOGGER.debug("R022 error: %s", err)

        return findings


class R023ExposedPortHint(Rule):
    """Detect hints of exposed ports/URLs."""

    id = RuleID.R023_EXPOSED_PORT_HINT
    title = "Possible External Exposure"
    severity = Severity.LOW
    tags = [Tags.HTTP, Tags.EXTERNAL]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Detect external URL patterns suggesting exposure."""
        findings: list[Finding] = []

        try:
            patterns = [
                (r"external_url\s*:", "external_url configured"),
                (r"base_url\s*:.*:8123", "base_url with port 8123"),
                (r"https?://[^/]*:8123", "URL with port 8123"),
            ]

            for line_num, line in enumerate(lines, start=1):
                for pattern, desc in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(
                            Finding(
                                rule_id=self.id,
                                severity=self.severity,
                                confidence=50,
                                title="External Exposure Hint",
                                description=(
                                    f"Configuration suggests external access: {desc}. "
                                    "Ensure proper security measures are in place."
                                ),
                                file_path=file_path,
                                line=line_num,
                                evidence_masked=truncate_evidence(mask_line(line.strip())),
                                recommendation=(
                                    "If exposing externally, use HTTPS, strong auth, "
                                    "and consider a reverse proxy."
                                ),
                                tags=self.tags.copy(),
                            )
                        )
                        break
        except Exception as err:
            _LOGGER.debug("R023 error: %s", err)

        return findings


# =============================================================================
# Group 4: Webhook Hygiene
# =============================================================================


class R030WebhookShort(Rule):
    """Detect short or weak webhook IDs."""

    id = RuleID.R030_WEBHOOK_SHORT
    title = "Weak Webhook ID"
    severity = Severity.MED
    tags = [Tags.WEBHOOK, Tags.SECRETS]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Detect short or low-entropy webhook IDs."""
        findings: list[Finding] = []

        try:
            for line_num, line in enumerate(lines, start=1):
                for match in WEBHOOK_PATTERN.finditer(line):
                    webhook_id = match.group(1)

                    # Check length
                    if len(webhook_id) < 16:
                        severity = Severity.HIGH if len(webhook_id) < 10 else Severity.MED
                    else:
                        # Check entropy
                        entropy = calculate_entropy(webhook_id)
                        if entropy < 3.0:
                            severity = Severity.MED
                        else:
                            continue  # Acceptable webhook

                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=severity,
                            confidence=80,
                            title="Weak Webhook ID",
                            description=(
                                f"Webhook ID is {'short' if len(webhook_id) < 16 else 'low entropy'} "
                                "and may be guessable."
                            ),
                            file_path=file_path,
                            line=line_num,
                            evidence_masked=f"/api/webhook/{mask_webhook_id(webhook_id)}",
                            recommendation=(
                                "Use a longer, randomly generated webhook ID "
                                "(at least 32 characters recommended)."
                            ),
                            tags=self.tags.copy(),
                            fingerprint=create_fingerprint(
                                self.id, file_path, line_num, webhook_id[:4]
                            ),
                        )
                    )
        except Exception as err:
            _LOGGER.debug("R030 error: %s", err)

        return findings


# =============================================================================
# Group 5: Storage Sensitivity
# =============================================================================


class R040StorageDirPresent(Rule):
    """Advisory about .storage directory."""

    id = RuleID.R040_STORAGE_DIR_PRESENT
    title = "Storage Directory Advisory"
    severity = Severity.LOW
    tags = [Tags.STORAGE]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """This rule evaluates in context only."""
        return []

    def evaluate_context(self, context: ScanContext) -> list[Finding]:
        """Check .storage directory status."""
        findings: list[Finding] = []

        try:
            storage_dir = context.config_root / ".storage"
            if not storage_dir.exists():
                return findings

            git_dir = context.config_root / ".git"
            if git_dir.exists():
                # Check if storage is ignored (covered by R011)
                return findings

            # Only show if not a git repo (advisory)
            findings.append(
                Finding(
                    rule_id=self.id,
                    severity=Severity.INFO,
                    confidence=60,
                    title="Storage Directory Contains Sensitive Data",
                    description=(
                        "The .storage directory contains authentication tokens, "
                        "device keys, and other sensitive data."
                    ),
                    file_path=".storage",
                    line=None,
                    evidence_masked=".storage directory present",
                    recommendation=(
                        "Never share the .storage directory. If backing up, "
                        "ensure backups are encrypted."
                    ),
                    tags=self.tags.copy(),
                )
            )
        except Exception as err:
            _LOGGER.debug("R040 error: %s", err)

        return findings


# =============================================================================
# Group 6: Snapshot Leak Detection
# =============================================================================


class R050SnapshotContainsSecrets(Rule):
    """Detect secrets in backup archives."""

    id = RuleID.R050_SNAPSHOT_CONTAINS_SECRETS
    title = "Snapshot Contains Secrets"
    severity = Severity.HIGH
    tags = [Tags.BACKUP, Tags.SECRETS]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """This rule is handled specially in scanner for archives."""
        return []


# =============================================================================
# Group 7: Secret Age
# =============================================================================


class R060SecretAge(Rule):
    """Check secret age based on metadata comments."""

    id = RuleID.R060_SECRET_AGE
    title = "Old Secret"
    severity = Severity.MED
    tags = [Tags.SECRETS, Tags.AGE]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Check for old secrets based on metadata."""
        if not context.options.get("enable_secret_age"):
            return []

        if file_path != "secrets.yaml":
            return []

        findings: list[Finding] = []

        try:
            date_pattern = re.compile(
                r"#\s*(?:created|rotated)\s*:\s*(\d{4}-\d{2}-\d{2})"
            )

            current_key: str | None = None

            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()

                # Track current secret key
                if ":" in stripped and not stripped.startswith("#"):
                    current_key = stripped.split(":")[0].strip()
                    continue

                # Look for date metadata
                match = date_pattern.search(stripped)
                if match and current_key:
                    try:
                        date_str = match.group(1)
                        secret_date = datetime.strptime(date_str, "%Y-%m-%d")
                        age_days = (datetime.now() - secret_date).days

                        if age_days >= SECRET_AGE_HIGH:
                            severity = Severity.HIGH
                            desc = f"over {SECRET_AGE_HIGH // 365} years"
                        elif age_days >= SECRET_AGE_MED:
                            severity = Severity.MED
                            desc = f"over {SECRET_AGE_MED // 30} months"
                        elif age_days >= SECRET_AGE_LOW:
                            severity = Severity.LOW
                            desc = f"over {SECRET_AGE_LOW // 30} months"
                        else:
                            continue

                        findings.append(
                            Finding(
                                rule_id=self.id,
                                severity=severity,
                                confidence=75,
                                title=f"Secret '{current_key}' is {desc} old",
                                description=(
                                    f"The secret '{current_key}' was created/rotated "
                                    f"on {date_str} ({age_days} days ago)."
                                ),
                                file_path=file_path,
                                line=line_num,
                                evidence_masked=f"{current_key}: created {date_str}",
                                recommendation=(
                                    "Consider rotating this secret to maintain security."
                                ),
                                tags=self.tags.copy(),
                                fingerprint=create_fingerprint(
                                    self.id, file_path, line_num, current_key
                                ),
                            )
                        )
                    except ValueError:
                        pass
        except Exception as err:
            _LOGGER.debug("R060 error: %s", err)

        return findings


# =============================================================================
# v3.0 Group 9: Log Scanning
# =============================================================================


class R080LogContainsSecret(Rule):
    """Detect secrets leaked into log files."""

    id = RuleID.R080_LOG_CONTAINS_SECRET
    title = "Secret in Log File"
    severity = Severity.HIGH
    tags = [Tags.LOGS, Tags.SECRETS]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Detect secrets in log file content.

        This rule is called from scanner.scan_logs() which streams lines.
        """
        findings: list[Finding] = []

        try:
            for line_num, line in enumerate(lines, start=1):
                # Check for JWT
                if JWT_PATTERN.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=90,
                            title="JWT Token in Log",
                            description="A JWT token was found in a log file.",
                            file_path=file_path,
                            line=line_num,
                            evidence_masked=truncate_evidence(mask_line(line.strip())),
                            recommendation=(
                                "Ensure logging does not capture authentication tokens. "
                                "Review application logging configuration."
                            ),
                            tags=self.tags.copy(),
                            fingerprint=create_fingerprint(
                                self.id, file_path, line_num
                            ),
                        )
                    )
                    continue

                # Check for PEM
                if PEM_BEGIN_PATTERN.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=95,
                            title="Private Key in Log",
                            description="A PEM private key header was found in a log file.",
                            file_path=file_path,
                            line=line_num,
                            evidence_masked=mask_pem(line),
                            recommendation=(
                                "Private keys should never appear in logs. "
                                "Review what is being logged."
                            ),
                            tags=self.tags.copy(),
                            fingerprint=create_fingerprint(
                                self.id, file_path, line_num
                            ),
                        )
                    )
                    continue

                # Check for URL userinfo
                if URL_USERINFO_PATTERN.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=90,
                            title="URL Credentials in Log",
                            description="A URL with embedded credentials was found in a log file.",
                            file_path=file_path,
                            line=line_num,
                            evidence_masked=truncate_evidence(redact_url_userinfo(line.strip())),
                            recommendation=(
                                "URLs with credentials should not be logged. "
                                "Consider sanitizing URLs before logging."
                            ),
                            tags=self.tags.copy(),
                            fingerprint=create_fingerprint(
                                self.id, file_path, line_num
                            ),
                        )
                    )
                    continue

                # Check for inline secrets patterns
                for key_pattern, key_severity, _ in SENSITIVE_KEYS[:10]:  # Top patterns
                    pattern = rf"\b{re.escape(key_pattern)}\s*[=:]\s*['\"]?([^'\"\\s]+)"
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        value = match.group(1)
                        is_secret, _ = looks_like_secret(value)
                        if is_secret:
                            findings.append(
                                Finding(
                                    rule_id=self.id,
                                    severity=key_severity,
                                    confidence=75,
                                    title=f"Possible {key_pattern} in Log",
                                    description=f"A potential {key_pattern} value was logged.",
                                    file_path=file_path,
                                    line=line_num,
                                    evidence_masked=truncate_evidence(
                                        f"{key_pattern}={mask_secret(value)}"
                                    ),
                                    recommendation=(
                                        "Avoid logging sensitive values. "
                                        "Use structured logging with secret redaction."
                                    ),
                                    tags=self.tags.copy(),
                                    fingerprint=create_fingerprint(
                                        self.id, file_path, line_num, key_pattern
                                    ),
                                )
                            )
                            break

        except Exception as err:
            _LOGGER.debug("R080 error scanning %s: %s", file_path, err)

        return findings


# =============================================================================
# v3.0 Group 10: Environment Hygiene
# =============================================================================


class R090EnvFilePresent(Rule):
    """Advisory about .env files present."""

    id = RuleID.R090_ENV_FILE_PRESENT
    title = ".env File Present"
    severity = Severity.LOW
    tags = [Tags.ENV]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Check if this is a .env file."""
        if not file_path.endswith(".env"):
            return []

        return [
            Finding(
                rule_id=self.id,
                severity=self.severity,
                confidence=80,
                title=".env File Found",
                description=(
                    f"An environment file '{file_path}' was found. "
                    "These files often contain secrets and should be protected."
                ),
                file_path=file_path,
                line=None,
                evidence_masked=f".env file: {file_path}",
                recommendation=(
                    "Ensure .env files are in .gitignore and have restricted permissions. "
                    "Consider using Home Assistant secrets.yaml instead."
                ),
                tags=self.tags.copy(),
            )
        ]


class R091EnvInlineSecret(Rule):
    """Detect inline secrets in .env files."""

    id = RuleID.R091_ENV_INLINE_SECRET
    title = "Secret in .env File"
    severity = Severity.MED
    tags = [Tags.ENV, Tags.SECRETS]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Detect secrets in .env files."""
        if not file_path.endswith(".env"):
            return []

        findings: list[Finding] = []

        try:
            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()

                # Skip comments and empty lines
                if not stripped or stripped.startswith("#"):
                    continue

                # Match KEY=VALUE pattern
                match = re.match(r'^([A-Z_][A-Z0-9_]*)\s*=\s*(.+)$', stripped, re.IGNORECASE)
                if not match:
                    continue

                key_name = match.group(1)
                value = match.group(2).strip("'\"")

                # Check if key suggests a secret
                key_lower = key_name.lower()
                for sensitive_key, key_severity, _ in SENSITIVE_KEYS:
                    if sensitive_key in key_lower:
                        is_secret, _ = looks_like_secret(value)
                        if is_secret or len(value) >= 8:
                            findings.append(
                                Finding(
                                    rule_id=self.id,
                                    severity=key_severity,
                                    confidence=80,
                                    title=f"Secret in .env: {key_name}",
                                    description=(
                                        f"The .env file contains '{key_name}' which appears to be a secret."
                                    ),
                                    file_path=file_path,
                                    line=line_num,
                                    evidence_masked=f"{key_name}={mask_secret(value)}",
                                    recommendation=(
                                        "Ensure this .env file is not committed to version control. "
                                        "Consider migrating to Home Assistant secrets.yaml."
                                    ),
                                    tags=self.tags.copy(),
                                    fingerprint=create_fingerprint(
                                        self.id, file_path, line_num, key_name
                                    ),
                                )
                            )
                        break

        except Exception as err:
            _LOGGER.debug("R091 error scanning %s: %s", file_path, err)

        return findings


class R092DockerComposeInlineSecret(Rule):
    """Detect inline secrets in docker-compose files."""

    id = RuleID.R092_DOCKER_COMPOSE_INLINE_SECRET
    title = "Secret in docker-compose"
    severity = Severity.MED
    tags = [Tags.DOCKER, Tags.SECRETS]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Detect secrets in docker-compose files."""
        if not file_path.endswith(("docker-compose.yml", "docker-compose.yaml")):
            return []

        findings: list[Finding] = []

        try:
            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()

                # Skip comments
                if stripped.startswith("#"):
                    continue

                # Check for sensitive environment variables
                for key_pattern, key_severity, _ in SENSITIVE_KEYS:
                    # Match patterns like "- PASSWORD=value" or "PASSWORD: value"
                    patterns = [
                        rf'-\s*{re.escape(key_pattern)}\s*=\s*(.+)',
                        rf'{re.escape(key_pattern)}\s*:\s*(.+)',
                    ]
                    for pattern in patterns:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip("'\"")

                            # Skip if it's an env var reference
                            if value.startswith("${") or value.startswith("$"):
                                continue

                            is_secret, _ = looks_like_secret(value)
                            if is_secret or len(value) >= 8:
                                findings.append(
                                    Finding(
                                        rule_id=self.id,
                                        severity=key_severity,
                                        confidence=80,
                                        title=f"Secret in docker-compose: {key_pattern}",
                                        description=(
                                            f"docker-compose contains hardcoded '{key_pattern}'."
                                        ),
                                        file_path=file_path,
                                        line=line_num,
                                        evidence_masked=f"{key_pattern}={mask_secret(value)}",
                                        recommendation=(
                                            "Use environment variable substitution (${VAR}) "
                                            "with a .env file instead of hardcoding secrets."
                                        ),
                                        tags=self.tags.copy(),
                                        fingerprint=create_fingerprint(
                                            self.id, file_path, line_num, key_pattern
                                        ),
                                    )
                                )
                            break

        except Exception as err:
            _LOGGER.debug("R092 error scanning %s: %s", file_path, err)

        return findings


class R093AddonConfigExportRisk(Rule):
    """Detect potential export risks in add-on configurations."""

    id = RuleID.R093_ADDON_CONFIG_EXPORT_RISK
    title = "Add-on Config Export Risk"
    severity = Severity.LOW
    tags = [Tags.ADDON, Tags.SECRETS]

    def evaluate_file_text(
        self,
        file_path: str,
        lines: list[str],
        context: ScanContext,
    ) -> list[Finding]:
        """Check add-on config directories for secrets.

        Only scans directories explicitly provided by user.
        """
        findings: list[Finding] = []

        # Get user-provided addon config dirs
        addon_dirs = context.options.get("addon_config_dirs", [])
        if not addon_dirs:
            return findings

        # Check if this file is in an addon config dir
        in_addon_dir = False
        for addon_dir in addon_dirs:
            if file_path.startswith(addon_dir) or file_path.startswith(f"{addon_dir}/"):
                in_addon_dir = True
                break

        if not in_addon_dir:
            return findings

        try:
            for line_num, line in enumerate(lines, start=1):
                # Check for sensitive keys
                for key_pattern, key_severity, _ in SENSITIVE_KEYS:
                    pattern = rf"\b{re.escape(key_pattern)}\s*[:=]\s*(.+)"
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        value = match.group(1).strip("'\"")
                        is_secret, _ = looks_like_secret(value)
                        if is_secret:
                            findings.append(
                                Finding(
                                    rule_id=self.id,
                                    severity=Severity.MED if key_severity == Severity.HIGH else Severity.LOW,
                                    confidence=70,
                                    title=f"Add-on Config Secret: {key_pattern}",
                                    description=(
                                        f"Add-on configuration contains '{key_pattern}' which may be exported."
                                    ),
                                    file_path=file_path,
                                    line=line_num,
                                    evidence_masked=f"{key_pattern}={mask_secret(value)}",
                                    recommendation=(
                                        "Be cautious when exporting or sharing add-on configurations. "
                                        "Secrets may be included in exports or backups."
                                    ),
                                    tags=self.tags.copy(),
                                    fingerprint=create_fingerprint(
                                        self.id, file_path, line_num, key_pattern
                                    ),
                                )
                            )
                            break

        except Exception as err:
            _LOGGER.debug("R093 error scanning %s: %s", file_path, err)

        return findings


# =============================================================================
# Rule Registry
# =============================================================================


def get_all_rules() -> list[Rule]:
    """Get instances of all available rules."""
    return [
        R001InlineSecretKey(),
        R002JWTDetected(),
        R003PEMBlock(),
        R004SecretRefMissing(),
        R005SecretDuplication(),
        R008URLUserinfo(),  # v3.0
        R010GitignoreMissing(),
        R011GitignoreWeak(),
        R012SecretsInRepo(),
        R020HTTPIPBanDisabled(),
        R021TrustedProxiesBroad(),
        R022CORSWildcard(),
        R023ExposedPortHint(),
        R030WebhookShort(),
        R040StorageDirPresent(),
        R060SecretAge(),
        R080LogContainsSecret(),  # v3.0
        R090EnvFilePresent(),  # v3.0
        R091EnvInlineSecret(),  # v3.0
        R092DockerComposeInlineSecret(),  # v3.0
        R093AddonConfigExportRisk(),  # v3.0
    ]
