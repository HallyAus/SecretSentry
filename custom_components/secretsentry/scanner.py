"""Scanner module for SecretSentry integration.

This module implements the main scanning logic that coordinates rules
and file traversal. All filesystem operations run in an executor.
"""
from __future__ import annotations

import fnmatch
import logging
import re
import tarfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .const import (
    ARCHIVE_EXTENSIONS,
    CONF_ADDON_CONFIG_DIRS,
    CONF_ENABLE_ENV_HYGIENE,
    CONF_ENABLE_LOG_SCAN,
    CONF_ENV_FILES,
    CONF_LOG_SCAN_PATHS,
    CONF_MAX_LOG_LINES,
    CONF_MAX_LOG_SCAN_MB,
    CONF_PRIVACY_MODE_REPORTS,
    DEFAULT_ADDON_CONFIG_DIRS,
    DEFAULT_ENABLE_ENV_HYGIENE,
    DEFAULT_ENABLE_LOG_SCAN,
    DEFAULT_ENV_FILES,
    DEFAULT_EXCLUDE_DIRS,
    DEFAULT_EXCLUDE_PATTERNS,
    DEFAULT_LOG_SCAN_PATHS,
    DEFAULT_MAX_FILE_SIZE_KB,
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_LOG_LINES,
    DEFAULT_MAX_LOG_SCAN_MB,
    DEFAULT_MAX_TOTAL_SCAN_MB,
    DEFAULT_PRIVACY_MODE_REPORTS,
    DEFAULT_SNAPSHOT_MEMBER_SIZE,
    DEFAULT_SNAPSHOT_TOTAL_SIZE,
    SCANNABLE_EXTENSIONS,
    RuleID,
    Severity,
)
from .masking import (
    JWT_PATTERN,
    PEM_BEGIN_PATTERN,
    REDACTED_PLACEHOLDER,
    URL_USERINFO_PATTERN,
    PrivacyTokenizer,
    apply_privacy_to_dict,
    hash_for_comparison,
    looks_like_secret,
    mask_secret,
    redact_url_userinfo,
    redact_value_in_line,
)
from .rules import (
    Finding,
    R080LogContainsSecret,
    ScanContext,
    get_all_rules,
)

if TYPE_CHECKING:
    from collections.abc import Generator

_LOGGER = logging.getLogger(__name__)


class ScanResult:
    """Contains the results of a security scan."""

    def __init__(
        self,
        findings: list[Finding],
        scanned_files: int,
        scanned_bytes: int,
        scan_duration: float,
        errors: list[str],
        secret_inventory: dict[str, Any],
    ) -> None:
        """Initialize scan result.

        Args:
            findings: List of security findings.
            scanned_files: Number of files scanned.
            scanned_bytes: Total bytes scanned.
            scan_duration: Duration in seconds.
            errors: List of error messages.
            secret_inventory: Inventory of secrets.
        """
        self.findings = findings
        self.scanned_files = scanned_files
        self.scanned_bytes = scanned_bytes
        self.scan_duration = scan_duration
        self.errors = errors
        self.secret_inventory = secret_inventory
        self.timestamp = datetime.now()

    @property
    def total_findings(self) -> int:
        """Get total number of findings."""
        return len(self.findings)

    @property
    def high_count(self) -> int:
        """Get count of high severity findings."""
        return len([f for f in self.findings if f.severity == Severity.HIGH])

    @property
    def med_count(self) -> int:
        """Get count of medium severity findings."""
        return len([f for f in self.findings if f.severity == Severity.MED])

    @property
    def low_count(self) -> int:
        """Get count of low severity findings."""
        return len([f for f in self.findings if f.severity in (Severity.LOW, Severity.INFO)])

    @property
    def fingerprints(self) -> set[str]:
        """Get set of all finding fingerprints."""
        return {f.fingerprint for f in self.findings}

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON export."""
        return {
            "generated_at": self.timestamp.isoformat(),
            "scan_duration_seconds": self.scan_duration,
            "scanned_files": self.scanned_files,
            "scanned_bytes": self.scanned_bytes,
            "counts_by_severity": {
                "high": self.high_count,
                "med": self.med_count,
                "low": self.low_count,
            },
            "findings": [f.to_dict() for f in self.findings],
            "secret_inventory": self.secret_inventory,
            "errors": self.errors[:10],  # Limit errors in export
        }


class SecretSentryScanner:
    """Scanner for detecting security issues in Home Assistant configuration."""

    def __init__(
        self,
        config_path: str,
        options: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the scanner.

        Args:
            config_path: Path to the Home Assistant config directory.
            options: Scanner options from config entry.
        """
        self.config_path = Path(config_path)
        self.options = options or {}
        self._rules = get_all_rules()
        self._log_rule = R080LogContainsSecret()  # v3.0: dedicated log rule
        self._errors: list[str] = []

    def scan(
        self,
        last_fingerprints: set[str] | None = None,
    ) -> ScanResult:
        """Run the security scan.

        This method should be called from an executor.

        Args:
            last_fingerprints: Fingerprints from previous scan for delta.

        Returns:
            ScanResult with all findings.
        """
        start_time = datetime.now()
        self._errors = []

        # Initialize context
        context = self._create_context(last_fingerprints or set())

        # Collect all findings
        findings: list[Finding] = []
        scanned_files = 0
        scanned_bytes = 0

        max_file_size = self.options.get(
            "max_file_size_kb", DEFAULT_MAX_FILE_SIZE_KB
        ) * 1024
        max_total_bytes = self.options.get(
            "max_total_scan_mb", DEFAULT_MAX_TOTAL_SCAN_MB
        ) * 1024 * 1024
        max_findings = self.options.get("max_findings", DEFAULT_MAX_FINDINGS)

        # Scan regular files
        for file_path in self._get_scannable_files():
            if len(findings) >= max_findings:
                _LOGGER.warning(
                    "Maximum findings (%d) reached, stopping scan", max_findings
                )
                break

            if scanned_bytes >= max_total_bytes:
                _LOGGER.warning(
                    "Maximum scan size (%d MB) reached", max_total_bytes // (1024 * 1024)
                )
                break

            try:
                file_size = file_path.stat().st_size
                if file_size > max_file_size:
                    _LOGGER.debug("Skipping large file: %s", file_path)
                    continue

                rel_path = str(file_path.relative_to(self.config_path))
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                # Run each rule on the file
                for rule in self._rules:
                    try:
                        rule_findings = rule.evaluate_file_text(
                            rel_path, lines, context
                        )
                        findings.extend(rule_findings)
                    except Exception as err:
                        _LOGGER.debug(
                            "Rule %s error on %s: %s", rule.id, rel_path, err
                        )

                scanned_files += 1
                scanned_bytes += file_size

            except PermissionError:
                self._errors.append(f"Permission denied: {file_path}")
            except OSError as err:
                self._errors.append(f"Error reading {file_path}: {err}")
            except Exception as err:
                _LOGGER.debug("Unexpected error scanning %s: %s", file_path, err)

        # v3.0: Scan environment files if enabled
        if self.options.get(CONF_ENABLE_ENV_HYGIENE, DEFAULT_ENABLE_ENV_HYGIENE):
            env_findings = self._scan_env_files(context, max_findings - len(findings))
            findings.extend(env_findings)

        # Scan archives if enabled
        if self.options.get("enable_snapshot_scan"):
            archive_findings = self._scan_archives(context, max_findings - len(findings))
            findings.extend(archive_findings)

        # v3.0: Scan logs if enabled
        if self.options.get(CONF_ENABLE_LOG_SCAN, DEFAULT_ENABLE_LOG_SCAN):
            log_findings = self._scan_logs(context, max_findings - len(findings))
            findings.extend(log_findings)

        # Run context-level evaluations
        for rule in self._rules:
            try:
                context_findings = rule.evaluate_context(context)
                findings.extend(context_findings)
            except Exception as err:
                _LOGGER.debug("Rule %s context error: %s", rule.id, err)

        # Build secret inventory
        secret_inventory = self._build_secret_inventory(context)

        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()

        _LOGGER.info(
            "Scan complete: %d files, %d findings in %.2fs",
            scanned_files,
            len(findings),
            scan_duration,
        )

        return ScanResult(
            findings=findings[:max_findings],
            scanned_files=scanned_files,
            scanned_bytes=scanned_bytes,
            scan_duration=scan_duration,
            errors=self._errors,
            secret_inventory=secret_inventory,
        )

    def _create_context(
        self,
        last_fingerprints: set[str],
    ) -> ScanContext:
        """Create the scan context.

        Args:
            last_fingerprints: Fingerprints from previous scan.

        Returns:
            Initialized ScanContext.
        """
        # Load secrets.yaml from multiple locations
        secrets_map: dict[str, str] = {}
        secrets_raw_hashes: dict[str, str] = {}

        # List of secrets.yaml locations to check
        secrets_paths = [
            self.config_path / "secrets.yaml",
            self.config_path / "esphome" / "secrets.yaml",
        ]

        for secrets_path in secrets_paths:
            if secrets_path.exists():
                try:
                    import yaml

                    content = secrets_path.read_text(encoding="utf-8")
                    parsed = yaml.safe_load(content)
                    if isinstance(parsed, dict):
                        for key, value in parsed.items():
                            if isinstance(value, str):
                                # Store masked version and hash only
                                secrets_map[key] = mask_secret(value)
                                secrets_raw_hashes[key] = hash_for_comparison(value)
                            else:
                                secrets_map[key] = str(type(value))
                    _LOGGER.debug("Loaded secrets from %s", secrets_path)
                except Exception as err:
                    _LOGGER.warning("Failed to load %s: %s", secrets_path, err)
                    self._errors.append(f"Failed to load {secrets_path}: {err}")

        # Load .gitignore
        gitignore_text: str | None = None
        gitignore_path = self.config_path / ".gitignore"
        if gitignore_path.exists():
            try:
                gitignore_text = gitignore_path.read_text(encoding="utf-8")
            except Exception as err:
                _LOGGER.debug("Failed to load .gitignore: %s", err)

        return ScanContext(
            config_root=self.config_path,
            secrets_map=secrets_map,
            secrets_raw_hashes=secrets_raw_hashes,
            used_secret_keys=set(),
            gitignore_text=gitignore_text,
            options=self.options,
            last_scan_fingerprints=last_fingerprints,
        )

    def _get_scannable_files(self) -> Generator[Path, None, None]:
        """Get all files that should be scanned.

        Yields:
            Path objects for each file to scan.
        """
        # Get custom include/exclude paths
        include_paths = self.options.get("include_paths", [])
        exclude_paths = self.options.get("exclude_paths", [])

        # Combine with defaults
        exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)
        for path in exclude_paths:
            exclude_dirs.add(path)

        def should_skip(path: Path) -> bool:
            """Check if path should be skipped."""
            try:
                rel_path = path.relative_to(self.config_path)
            except ValueError:
                return True

            parts = rel_path.parts

            # Check directory exclusions
            for part in parts[:-1]:  # Check parent dirs
                if part in exclude_dirs:
                    return True

            # Check file pattern exclusions
            filename = path.name
            for pattern in DEFAULT_EXCLUDE_PATTERNS:
                if fnmatch.fnmatch(filename, pattern):
                    return True

            return False

        # Scan based on include paths or default to config root
        scan_roots = [self.config_path]
        if include_paths:
            scan_roots = [
                self.config_path / p
                for p in include_paths
                if (self.config_path / p).exists()
            ]

        for scan_root in scan_roots:
            if not scan_root.exists():
                continue

            if scan_root.is_file():
                yield scan_root
                continue

            try:
                for path in scan_root.rglob("*"):
                    if not path.is_file():
                        continue

                    if should_skip(path):
                        continue

                    # Check extension
                    suffix = path.suffix.lower()
                    if suffix not in SCANNABLE_EXTENSIONS:
                        continue

                    yield path
            except PermissionError:
                self._errors.append(f"Permission denied scanning: {scan_root}")
            except Exception as err:
                _LOGGER.debug("Error scanning directory %s: %s", scan_root, err)

    def _scan_env_files(
        self,
        context: ScanContext,
        max_findings: int,
    ) -> list[Finding]:
        """Scan environment files (.env, docker-compose.yml).

        v3.0: Added environment hygiene checks.

        Args:
            context: Scan context.
            max_findings: Maximum findings to return.

        Returns:
            List of findings from env files.
        """
        findings: list[Finding] = []
        env_files = self.options.get(CONF_ENV_FILES, DEFAULT_ENV_FILES)

        for env_file in env_files:
            if len(findings) >= max_findings:
                break

            file_path = self.config_path / env_file
            if not file_path.exists():
                continue

            try:
                rel_path = env_file
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                # Run rules on env file
                for rule in self._rules:
                    if len(findings) >= max_findings:
                        break
                    try:
                        rule_findings = rule.evaluate_file_text(rel_path, lines, context)
                        findings.extend(rule_findings[:max_findings - len(findings)])
                    except Exception as err:
                        _LOGGER.debug("Error scanning env file %s: %s", env_file, err)

            except Exception as err:
                _LOGGER.debug("Error reading env file %s: %s", env_file, err)

        return findings

    def _scan_logs(
        self,
        context: ScanContext,
        max_findings: int,
    ) -> list[Finding]:
        """Scan log files for secrets (v3.0).

        Streams lines to avoid loading entire log into memory.

        Args:
            context: Scan context.
            max_findings: Maximum findings to return.

        Returns:
            List of findings from log files.
        """
        findings: list[Finding] = []
        log_paths = self.options.get(CONF_LOG_SCAN_PATHS, DEFAULT_LOG_SCAN_PATHS)
        max_log_mb = self.options.get(CONF_MAX_LOG_SCAN_MB, DEFAULT_MAX_LOG_SCAN_MB)
        max_log_lines = self.options.get(CONF_MAX_LOG_LINES, DEFAULT_MAX_LOG_LINES)
        max_log_bytes = max_log_mb * 1024 * 1024

        for log_path in log_paths:
            if len(findings) >= max_findings:
                break

            full_path = self.config_path / log_path
            if not full_path.exists():
                continue

            try:
                file_size = full_path.stat().st_size
                if file_size > max_log_bytes:
                    _LOGGER.debug("Log file %s exceeds max size, skipping", log_path)
                    continue

                # Stream log file line by line
                lines_read = 0
                batch_lines: list[str] = []
                batch_start_line = 1

                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    for line_num, line in enumerate(f, start=1):
                        if len(findings) >= max_findings:
                            break
                        if lines_read >= max_log_lines:
                            break

                        lines_read += 1
                        batch_lines.append(line.rstrip("\n\r"))

                        # Process in batches of 1000 lines
                        if len(batch_lines) >= 1000:
                            batch_findings = self._log_rule.evaluate_file_text(
                                log_path, batch_lines, context
                            )
                            # Adjust line numbers for batch
                            for bf in batch_findings:
                                if bf.line:
                                    bf.line = batch_start_line + bf.line - 1
                            findings.extend(batch_findings[:max_findings - len(findings)])
                            batch_start_line = line_num + 1
                            batch_lines = []

                    # Process remaining lines
                    if batch_lines and len(findings) < max_findings:
                        batch_findings = self._log_rule.evaluate_file_text(
                            log_path, batch_lines, context
                        )
                        for bf in batch_findings:
                            if bf.line:
                                bf.line = batch_start_line + bf.line - 1
                        findings.extend(batch_findings[:max_findings - len(findings)])

            except Exception as err:
                _LOGGER.debug("Error scanning log %s: %s", log_path, err)

        return findings

    def _scan_archives(
        self,
        context: ScanContext,
        max_findings: int,
    ) -> list[Finding]:
        """Scan backup archives for secrets.

        Args:
            context: Scan context.
            max_findings: Maximum findings to return.

        Returns:
            List of findings from archives.
        """
        findings: list[Finding] = []

        # Look for archives in backup directories
        backup_dirs = ["backups", "backup"]
        for backup_dir in backup_dirs:
            backup_path = self.config_path / backup_dir
            if not backup_path.exists():
                continue

            try:
                for archive_path in backup_path.rglob("*"):
                    if len(findings) >= max_findings:
                        break

                    suffix = "".join(archive_path.suffixes).lower()
                    if not any(suffix.endswith(ext) for ext in ARCHIVE_EXTENSIONS):
                        continue

                    try:
                        archive_findings = self._scan_single_archive(
                            archive_path, context
                        )
                        findings.extend(archive_findings)
                    except Exception as err:
                        _LOGGER.debug("Error scanning archive %s: %s", archive_path, err)
            except PermissionError:
                self._errors.append(f"Permission denied scanning: {backup_path}")

        return findings

    def _scan_single_archive(
        self,
        archive_path: Path,
        context: ScanContext,
    ) -> list[Finding]:
        """Scan a single archive file.

        Args:
            archive_path: Path to the archive.
            context: Scan context.

        Returns:
            List of findings.
        """
        findings: list[Finding] = []
        rel_archive = str(archive_path.relative_to(self.config_path))
        total_read = 0
        max_member_size = DEFAULT_SNAPSHOT_MEMBER_SIZE
        max_total_size = DEFAULT_SNAPSHOT_TOTAL_SIZE

        def check_content(member_name: str, content: str) -> None:
            """Check archive member content for secrets."""
            lines = content.splitlines()
            for line_num, line in enumerate(lines, start=1):
                # Check for JWT
                if JWT_PATTERN.search(line):
                    findings.append(
                        Finding(
                            rule_id=RuleID.R050_SNAPSHOT_CONTAINS_SECRETS,
                            severity=Severity.HIGH,
                            confidence=90,
                            title="JWT in Backup Archive",
                            description=f"Archive contains JWT in {member_name}",
                            file_path=rel_archive,
                            line=None,
                            evidence_masked=f"JWT found in {member_name}",
                            recommendation="Ensure backups are encrypted and access-controlled.",
                            tags=["backup", "secrets"],
                        )
                    )
                    return  # One finding per member is enough

                # Check for PEM
                if PEM_BEGIN_PATTERN.search(line):
                    findings.append(
                        Finding(
                            rule_id=RuleID.R050_SNAPSHOT_CONTAINS_SECRETS,
                            severity=Severity.HIGH,
                            confidence=95,
                            title="Private Key in Backup Archive",
                            description=f"Archive contains private key in {member_name}",
                            file_path=rel_archive,
                            line=None,
                            evidence_masked=f"PEM key found in {member_name}",
                            recommendation="Ensure backups are encrypted and access-controlled.",
                            tags=["backup", "secrets"],
                        )
                    )
                    return

                # v3.0: Check for URL userinfo
                if URL_USERINFO_PATTERN.search(line):
                    findings.append(
                        Finding(
                            rule_id=RuleID.R050_SNAPSHOT_CONTAINS_SECRETS,
                            severity=Severity.HIGH,
                            confidence=90,
                            title="URL Credentials in Backup Archive",
                            description=f"Archive contains URL with credentials in {member_name}",
                            file_path=rel_archive,
                            line=None,
                            evidence_masked=f"URL with userinfo in {member_name}",
                            recommendation="Ensure backups are encrypted and access-controlled.",
                            tags=["backup", "secrets"],
                        )
                    )
                    return

        try:
            suffix = "".join(archive_path.suffixes).lower()

            if suffix.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    for info in zf.infolist():
                        if total_read >= max_total_size:
                            break
                        if info.file_size > max_member_size:
                            continue
                        if info.is_dir():
                            continue

                        # Only check text-like files
                        name_lower = info.filename.lower()
                        if not any(name_lower.endswith(ext) for ext in SCANNABLE_EXTENSIONS):
                            continue

                        try:
                            content = zf.read(info.filename).decode("utf-8", errors="ignore")
                            total_read += len(content)
                            check_content(info.filename, content)
                        except Exception:
                            pass

            elif ".tar" in suffix:
                with tarfile.open(archive_path, "r:*") as tf:
                    for member in tf.getmembers():
                        if total_read >= max_total_size:
                            break
                        if member.size > max_member_size:
                            continue
                        if not member.isfile():
                            continue

                        name_lower = member.name.lower()
                        if not any(name_lower.endswith(ext) for ext in SCANNABLE_EXTENSIONS):
                            continue

                        try:
                            f = tf.extractfile(member)
                            if f:
                                content = f.read().decode("utf-8", errors="ignore")
                                total_read += len(content)
                                check_content(member.name, content)
                        except Exception:
                            pass

        except Exception as err:
            _LOGGER.debug("Archive scan error for %s: %s", archive_path, err)

        return findings

    def _build_secret_inventory(self, context: ScanContext) -> dict[str, Any]:
        """Build the secret inventory for reporting.

        Args:
            context: Scan context after scanning.

        Returns:
            Secret inventory dictionary.
        """
        defined_keys = set(context.secrets_map.keys())
        used_keys = context.used_secret_keys
        unused_keys = defined_keys - used_keys
        missing_keys = used_keys - defined_keys

        # Build blast radius (capped)
        blast_radius: dict[str, list[str]] = {}
        for key, locations in context.secret_usage_map.items():
            # Cap at 10 locations per key
            blast_radius[key] = [f"{f}:{l}" for f, l in locations[:10]]
            if len(locations) > 10:
                blast_radius[key].append(f"...and {len(locations) - 10} more")

        return {
            "used_secret_keys": sorted(used_keys)[:100],
            "unused_secret_keys": sorted(unused_keys)[:50],
            "missing_secret_keys": sorted(missing_keys)[:50],
            "blast_radius": dict(list(blast_radius.items())[:50]),
        }


def create_sanitised_copy(
    config_path: str,
    output_dir: str,
    options: dict[str, Any] | None = None,
) -> tuple[int, list[str]]:
    """Create a sanitised copy of configuration files.

    This replaces detected secrets with ***REDACTED***.
    v3.0: Also redacts URL userinfo and applies privacy mode.

    Args:
        config_path: Path to the config directory.
        output_dir: Path for the sanitised output.
        options: Scanner options.

    Returns:
        Tuple of (files_processed, error_list).
    """
    options = options or {}
    config_root = Path(config_path)
    output_root = Path(output_dir)

    # v3.0: Initialize privacy tokenizer if privacy mode is on
    privacy_mode = options.get(CONF_PRIVACY_MODE_REPORTS, DEFAULT_PRIVACY_MODE_REPORTS)
    tokenizer = PrivacyTokenizer() if privacy_mode else None

    # Create output directory
    output_root.mkdir(parents=True, exist_ok=True)

    # Write warning README
    readme_content = """# SecretSentry Sanitised Configuration Copy

**WARNING**: This directory contains a sanitised copy of your Home Assistant
configuration. Detected secrets have been replaced with ***REDACTED***.

However, this sanitisation is best-effort and may not catch all secrets.
Review carefully before sharing.

Generated: {timestamp}
""".format(timestamp=datetime.now().isoformat())

    (output_root / "README_SANITISED.md").write_text(readme_content)

    scanner = SecretSentryScanner(config_path, options)
    files_processed = 0
    errors: list[str] = []

    # Patterns to redact
    sensitive_patterns = [
        # Key-value patterns
        (
            r'(\b(?:api_key|apikey|token|password|secret|bearer|authorization|client_secret|private_key|access_token|refresh_token|auth_token|webhook|mqtt_password|db_password|database_url|redis_password|mysql_password|postgres_password|encryption_key|jwt_secret)\s*[:=]\s*)["\']?([^"\'\s\n]+)["\']?',
            r'\1"***REDACTED***"',
        ),
        # JWT tokens
        (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+', '***REDACTED_JWT***'),
        # Webhook IDs (partial)
        (r'(/api/webhook/)[A-Za-z0-9_-]{8,}', r'\1***REDACTED***'),
    ]

    for file_path in scanner._get_scannable_files():
        try:
            rel_path = file_path.relative_to(config_root)
            output_path = output_root / rel_path

            # Create parent directories
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Read and sanitise content
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            # Apply redaction patterns
            sanitised = content
            for pattern, replacement in sensitive_patterns:
                sanitised = re.sub(pattern, replacement, sanitised, flags=re.IGNORECASE)

            # v3.0: Redact URL userinfo
            sanitised = redact_url_userinfo(sanitised)

            # v3.0: Apply privacy mode if enabled
            if tokenizer:
                sanitised = tokenizer.apply_privacy_mode(sanitised)

            # Write sanitised file
            output_path.write_text(sanitised, encoding="utf-8")
            files_processed += 1

        except PermissionError:
            errors.append(f"Permission denied: {file_path}")
        except Exception as err:
            errors.append(f"Error processing {file_path}: {err}")

    return files_processed, errors


def export_report_with_privacy(
    scan_result: ScanResult,
    options: dict[str, Any],
) -> dict[str, Any]:
    """Export scan result with privacy mode applied.

    v3.0: New function for privacy-aware exports.

    Args:
        scan_result: The scan result to export.
        options: Options including privacy_mode_reports.

    Returns:
        Dictionary ready for JSON export.
    """
    result_dict = scan_result.to_dict()

    privacy_mode = options.get(CONF_PRIVACY_MODE_REPORTS, DEFAULT_PRIVACY_MODE_REPORTS)
    if privacy_mode:
        tokenizer = PrivacyTokenizer()
        result_dict = apply_privacy_to_dict(result_dict, tokenizer)

    return result_dict
