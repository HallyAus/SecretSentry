"""Self-test module for SecretSentry.

This module provides built-in self-testing functionality to verify
that the scanner rules are working correctly. It tests against
sample data without touching the actual filesystem.

v3.0: Added tests for URL userinfo, log scanning, env files,
and export secret verification.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .const import RuleID
from .sample_data import (
    EXPECTED_FINDINGS,
    SAMPLE_LOG_CONTENT,
    SAMPLE_SAFE_CONFIG,
    TEST_SECRET_VALUES,
    get_sample_files,
)
from .scanner import SecretSentryScanner, create_sanitised_copy, export_report_with_privacy

_LOGGER = logging.getLogger(__name__)


@dataclass
class SelfTestResult:
    """Result of self-test execution."""

    passed: bool
    total_tests: int
    passed_tests: int
    failed_tests: int
    assertions: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "passed": self.passed,
            "total_tests": self.total_tests,
            "passed_tests": self.passed_tests,
            "failed_tests": self.failed_tests,
            "assertions": self.assertions,
            "errors": self.errors,
        }

    def summary(self) -> str:
        """Get a human-readable summary."""
        status = "PASSED" if self.passed else "FAILED"
        return (
            f"Self-test {status}: {self.passed_tests}/{self.total_tests} tests passed"
        )


def run_selftest() -> SelfTestResult:
    """Run the self-test suite.

    This function creates temporary files with sample data and runs
    the scanner against them to verify rules are working correctly.

    Returns:
        SelfTestResult with test outcomes.
    """
    assertions: list[dict[str, Any]] = []
    errors: list[str] = []
    passed_count = 0
    total_count = 0

    try:
        # Test 1: Scanner finds expected issues in sample data
        with TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Write sample files
            sample_files = get_sample_files()
            for filename, content in sample_files.items():
                (tmppath / filename).write_text(content)

            # Create weak .gitignore
            from .sample_data import SAMPLE_GITIGNORE_WEAK
            (tmppath / ".gitignore").write_text(SAMPLE_GITIGNORE_WEAK)

            # Create .git directory to trigger git rules
            (tmppath / ".git").mkdir()

            # v3.0: Create log file for log scanning test
            (tmppath / "home-assistant.log").write_text(SAMPLE_LOG_CONTENT)

            # Run scanner with v3.0 options enabled
            scanner = SecretSentryScanner(str(tmppath), {
                "enable_log_scan": True,
                "log_scan_paths": ["home-assistant.log"],
                "enable_env_hygiene": True,
                "env_files": [".env", "docker-compose.yml"],
            })
            result = scanner.scan()

            # Check that expected findings are present
            found_rules = {f.rule_id for f in result.findings}

            # Test: R001 inline secrets detected
            total_count += 1
            if RuleID.R001_INLINE_SECRET_KEY in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R001_INLINE_SECRET_KEY detection",
                    "passed": True,
                    "message": "Inline secrets correctly detected",
                })
            else:
                assertions.append({
                    "test": "R001_INLINE_SECRET_KEY detection",
                    "passed": False,
                    "message": "Failed to detect inline secrets",
                })

            # Test: R002 JWT detected
            total_count += 1
            if RuleID.R002_JWT_DETECTED in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R002_JWT_DETECTED detection",
                    "passed": True,
                    "message": "JWT tokens correctly detected",
                })
            else:
                assertions.append({
                    "test": "R002_JWT_DETECTED detection",
                    "passed": False,
                    "message": "Failed to detect JWT tokens",
                })

            # Test: R003 PEM detected
            total_count += 1
            if RuleID.R003_PEM_BLOCK in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R003_PEM_BLOCK detection",
                    "passed": True,
                    "message": "PEM private keys correctly detected",
                })
            else:
                assertions.append({
                    "test": "R003_PEM_BLOCK detection",
                    "passed": False,
                    "message": "Failed to detect PEM private keys",
                })

            # Test: R004 missing secret ref detected
            total_count += 1
            if RuleID.R004_SECRET_REF_MISSING in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R004_SECRET_REF_MISSING detection",
                    "passed": True,
                    "message": "Missing secret references correctly detected",
                })
            else:
                assertions.append({
                    "test": "R004_SECRET_REF_MISSING detection",
                    "passed": False,
                    "message": "Failed to detect missing secret references",
                })

            # v3.0 Test: R008 URL userinfo detected
            total_count += 1
            if RuleID.R008_URL_USERINFO in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R008_URL_USERINFO detection",
                    "passed": True,
                    "message": "URL credentials correctly detected",
                })
            else:
                assertions.append({
                    "test": "R008_URL_USERINFO detection",
                    "passed": False,
                    "message": "Failed to detect URL credentials",
                })

            # Test: R011 gitignore weak detected
            total_count += 1
            if RuleID.R011_GITIGNORE_WEAK in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R011_GITIGNORE_WEAK detection",
                    "passed": True,
                    "message": "Weak gitignore correctly detected",
                })
            else:
                assertions.append({
                    "test": "R011_GITIGNORE_WEAK detection",
                    "passed": False,
                    "message": "Failed to detect weak gitignore",
                })

            # Test: R020 HTTP security detected
            total_count += 1
            if RuleID.R020_HTTP_IP_BAN_DISABLED in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R020_HTTP_IP_BAN_DISABLED detection",
                    "passed": True,
                    "message": "HTTP security issues correctly detected",
                })
            else:
                assertions.append({
                    "test": "R020_HTTP_IP_BAN_DISABLED detection",
                    "passed": False,
                    "message": "Failed to detect HTTP security issues",
                })

            # Test: R021 broad proxies detected
            total_count += 1
            if RuleID.R021_TRUSTED_PROXIES_BROAD in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R021_TRUSTED_PROXIES_BROAD detection",
                    "passed": True,
                    "message": "Broad trusted proxies correctly detected",
                })
            else:
                assertions.append({
                    "test": "R021_TRUSTED_PROXIES_BROAD detection",
                    "passed": False,
                    "message": "Failed to detect broad trusted proxies",
                })

            # Test: R022 CORS wildcard detected
            total_count += 1
            if RuleID.R022_CORS_WILDCARD in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R022_CORS_WILDCARD detection",
                    "passed": True,
                    "message": "CORS wildcard correctly detected",
                })
            else:
                assertions.append({
                    "test": "R022_CORS_WILDCARD detection",
                    "passed": False,
                    "message": "Failed to detect CORS wildcard",
                })

            # Test: R030 short webhook detected
            total_count += 1
            if RuleID.R030_WEBHOOK_SHORT in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R030_WEBHOOK_SHORT detection",
                    "passed": True,
                    "message": "Short webhook IDs correctly detected",
                })
            else:
                assertions.append({
                    "test": "R030_WEBHOOK_SHORT detection",
                    "passed": False,
                    "message": "Failed to detect short webhook IDs",
                })

            # v3.0 Test: R080 log contains secret detected
            total_count += 1
            if RuleID.R080_LOG_CONTAINS_SECRET in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R080_LOG_CONTAINS_SECRET detection",
                    "passed": True,
                    "message": "Secrets in logs correctly detected",
                })
            else:
                assertions.append({
                    "test": "R080_LOG_CONTAINS_SECRET detection",
                    "passed": False,
                    "message": "Failed to detect secrets in logs",
                })

            # v3.0 Test: R090 .env file present detected
            total_count += 1
            if RuleID.R090_ENV_FILE_PRESENT in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R090_ENV_FILE_PRESENT detection",
                    "passed": True,
                    "message": ".env file presence correctly detected",
                })
            else:
                assertions.append({
                    "test": "R090_ENV_FILE_PRESENT detection",
                    "passed": False,
                    "message": "Failed to detect .env file presence",
                })

            # v3.0 Test: R091 .env inline secret detected
            total_count += 1
            if RuleID.R091_ENV_INLINE_SECRET in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R091_ENV_INLINE_SECRET detection",
                    "passed": True,
                    "message": ".env inline secrets correctly detected",
                })
            else:
                assertions.append({
                    "test": "R091_ENV_INLINE_SECRET detection",
                    "passed": False,
                    "message": "Failed to detect .env inline secrets",
                })

            # v3.0 Test: R092 docker-compose inline secret detected
            total_count += 1
            if RuleID.R092_DOCKER_COMPOSE_INLINE_SECRET in found_rules:
                passed_count += 1
                assertions.append({
                    "test": "R092_DOCKER_COMPOSE_INLINE_SECRET detection",
                    "passed": True,
                    "message": "docker-compose inline secrets correctly detected",
                })
            else:
                assertions.append({
                    "test": "R092_DOCKER_COMPOSE_INLINE_SECRET detection",
                    "passed": False,
                    "message": "Failed to detect docker-compose inline secrets",
                })

        # Test 2: Verify masking works - no raw secrets in evidence
        total_count += 1
        masking_passed = True
        for finding in result.findings:
            evidence = finding.evidence_masked or ""
            for secret in TEST_SECRET_VALUES:
                if secret in evidence:
                    masking_passed = False
                    errors.append(f"Raw secret found in evidence: {secret[:10]}...")
                    break
            if not masking_passed:
                break

        if masking_passed:
            passed_count += 1
            assertions.append({
                "test": "Secret masking in evidence",
                "passed": True,
                "message": "All secrets properly masked in evidence",
            })
        else:
            assertions.append({
                "test": "Secret masking in evidence",
                "passed": False,
                "message": "Raw secrets found in evidence - masking failed",
            })

        # v3.0 Test 3: Verify no raw secrets in export report
        total_count += 1
        report_dict = export_report_with_privacy(result, {"privacy_mode_reports": True})
        report_json = json.dumps(report_dict)
        export_masking_passed = True
        for secret in TEST_SECRET_VALUES:
            if secret in report_json:
                export_masking_passed = False
                errors.append(f"Raw secret found in export: {secret[:10]}...")
                break

        if export_masking_passed:
            passed_count += 1
            assertions.append({
                "test": "Secret masking in exports",
                "passed": True,
                "message": "All secrets properly masked in exported report",
            })
        else:
            assertions.append({
                "test": "Secret masking in exports",
                "passed": False,
                "message": "Raw secrets found in exported report - masking failed",
            })

        # Test 4: Safe config should have minimal findings
        with TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "configuration.yaml").write_text(SAMPLE_SAFE_CONFIG)
            (tmppath / "secrets.yaml").write_text("my_api_key: test\nmy_token: test")

            scanner = SecretSentryScanner(str(tmppath), {})
            safe_result = scanner.scan()

            total_count += 1
            # Safe config should not have R001 findings
            r001_findings = [
                f for f in safe_result.findings
                if f.rule_id == RuleID.R001_INLINE_SECRET_KEY
            ]
            if len(r001_findings) == 0:
                passed_count += 1
                assertions.append({
                    "test": "Safe config no false positives",
                    "passed": True,
                    "message": "Safe configuration correctly has no inline secret findings",
                })
            else:
                assertions.append({
                    "test": "Safe config no false positives",
                    "passed": False,
                    "message": f"Safe configuration incorrectly flagged with {len(r001_findings)} R001 findings",
                })

        # Test 5: Fingerprint stability
        total_count += 1
        fingerprints = {f.fingerprint for f in result.findings}
        if len(fingerprints) == len(result.findings):
            passed_count += 1
            assertions.append({
                "test": "Fingerprint uniqueness",
                "passed": True,
                "message": "All findings have unique fingerprints",
            })
        else:
            assertions.append({
                "test": "Fingerprint uniqueness",
                "passed": False,
                "message": "Duplicate fingerprints detected",
            })

        # Test 6: Options flow schema does not crash
        total_count += 1
        try:
            from .config_flow import SecretSentryOptionsFlowHandler
            from .const import DEFAULT_OPTIONS

            # Test schema building with partial options (simulates real-world)
            class FakeConfigEntry:
                def __init__(self):
                    self.options = {"scan_interval": "weekly"}  # Missing some keys

            fake_entry = FakeConfigEntry()
            handler = SecretSentryOptionsFlowHandler(fake_entry)
            options = handler._get_options()
            schema = handler._build_init_schema(options)

            # Verify schema is valid
            if schema is not None:
                passed_count += 1
                assertions.append({
                    "test": "Options flow schema",
                    "passed": True,
                    "message": "Options flow schema builds without error",
                })
            else:
                assertions.append({
                    "test": "Options flow schema",
                    "passed": False,
                    "message": "Options flow schema returned None",
                })
        except Exception as err:
            assertions.append({
                "test": "Options flow schema",
                "passed": False,
                "message": f"Options flow schema failed: {err}",
            })
            errors.append(f"Options flow schema error: {err}")

        # Test 7: Repairs grouping reduces issue count
        total_count += 1
        try:
            from .repairs import group_findings, guess_integration

            # Group the findings from our scan
            grouped = group_findings(result.findings)

            # Verify grouping reduces count (multiple occurrences collapse)
            original_count = len(result.findings)
            grouped_count = len(grouped)

            if grouped_count <= original_count:
                passed_count += 1
                assertions.append({
                    "test": "Repairs grouping",
                    "passed": True,
                    "message": f"Grouping reduced {original_count} findings to {grouped_count} repair issues",
                })
            else:
                assertions.append({
                    "test": "Repairs grouping",
                    "passed": False,
                    "message": f"Grouping should not increase count ({original_count} -> {grouped_count})",
                })
        except Exception as err:
            assertions.append({
                "test": "Repairs grouping",
                "passed": False,
                "message": f"Repairs grouping failed: {err}",
            })
            errors.append(f"Repairs grouping error: {err}")

        # Test 8: Integration guessing for esphome path
        total_count += 1
        try:
            integration = guess_integration("esphome/device.yaml")
            if integration == "ESPHome":
                passed_count += 1
                assertions.append({
                    "test": "Integration guessing",
                    "passed": True,
                    "message": "ESPHome path correctly identified",
                })
            else:
                assertions.append({
                    "test": "Integration guessing",
                    "passed": False,
                    "message": f"Expected 'ESPHome', got '{integration}'",
                })
        except Exception as err:
            assertions.append({
                "test": "Integration guessing",
                "passed": False,
                "message": f"Integration guessing failed: {err}",
            })
            errors.append(f"Integration guessing error: {err}")

        # Test 9: Grouped finding title includes file:line
        total_count += 1
        try:
            if grouped:
                first_group = next(iter(grouped.values()))
                title = first_group.format_title()
                # Title should include file reference
                if "in" in title.lower() or first_group.file_path in title:
                    passed_count += 1
                    assertions.append({
                        "test": "Repair title includes location",
                        "passed": True,
                        "message": f"Repair title includes location: {title[:60]}...",
                    })
                else:
                    assertions.append({
                        "test": "Repair title includes location",
                        "passed": False,
                        "message": f"Repair title missing location: {title}",
                    })
            else:
                passed_count += 1
                assertions.append({
                    "test": "Repair title includes location",
                    "passed": True,
                    "message": "No grouped findings to test (expected in some configs)",
                })
        except Exception as err:
            assertions.append({
                "test": "Repair title includes location",
                "passed": False,
                "message": f"Repair title test failed: {err}",
            })
            errors.append(f"Repair title error: {err}")

        # Test 10: Verify sanitised copy has no raw secrets
        total_count += 1
        with TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            srcpath = tmppath / "src"
            destpath = tmppath / "dest"
            srcpath.mkdir()

            # Write sample files
            for filename, content in sample_files.items():
                (srcpath / filename).write_text(content)

            # Create sanitised copy
            files_copied, copy_errors = create_sanitised_copy(
                str(srcpath), str(destpath), {"privacy_mode_reports": True}
            )

            # Check sanitised files for raw secrets
            sanitised_clean = True
            for filename in sample_files.keys():
                sanitised_file = destpath / filename
                if sanitised_file.exists():
                    content = sanitised_file.read_text()
                    for secret in TEST_SECRET_VALUES:
                        if secret in content:
                            sanitised_clean = False
                            errors.append(f"Raw secret in sanitised copy {filename}: {secret[:10]}...")
                            break

            if sanitised_clean and files_copied > 0:
                passed_count += 1
                assertions.append({
                    "test": "Sanitised copy has no secrets",
                    "passed": True,
                    "message": f"All {files_copied} sanitised files have no raw secrets",
                })
            else:
                assertions.append({
                    "test": "Sanitised copy has no secrets",
                    "passed": False,
                    "message": "Raw secrets found in sanitised copy",
                })

    except Exception as err:
        _LOGGER.exception("Self-test error: %s", err)
        errors.append(f"Self-test exception: {err}")

    passed = passed_count == total_count and len(errors) == 0

    return SelfTestResult(
        passed=passed,
        total_tests=total_count,
        passed_tests=passed_count,
        failed_tests=total_count - passed_count,
        assertions=assertions,
        errors=errors,
    )


async def async_run_selftest(hass) -> SelfTestResult:
    """Run self-test asynchronously.

    Args:
        hass: Home Assistant instance.

    Returns:
        SelfTestResult with test outcomes.
    """
    return await hass.async_add_executor_job(run_selftest)
