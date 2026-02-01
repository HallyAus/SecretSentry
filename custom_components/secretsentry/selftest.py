"""Self-test module for SecretSentry.

This module provides built-in self-testing functionality to verify
that the scanner rules are working correctly. It tests against
sample data without touching the actual filesystem.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .const import RuleID
from .sample_data import (
    EXPECTED_FINDINGS,
    SAMPLE_SAFE_CONFIG,
    TEST_SECRET_VALUES,
    get_sample_files,
)
from .scanner import SecretSentryScanner

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

            # Run scanner
            scanner = SecretSentryScanner(str(tmppath), {})
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

        # Test 2: Verify masking works
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
                "test": "Secret masking",
                "passed": True,
                "message": "All secrets properly masked in evidence",
            })
        else:
            assertions.append({
                "test": "Secret masking",
                "passed": False,
                "message": "Raw secrets found in evidence - masking failed",
            })

        # Test 3: Safe config should have minimal findings
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

        # Test 4: Fingerprint stability
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
