"""External URL security checks for SecretSentry.

This module provides optional external URL self-checks that verify
the user's own Home Assistant instance is properly secured.

IMPORTANT: This module ONLY checks the user-provided URL.
It does not scan, enumerate, or probe any other systems.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from .const import HTTP_CHECK_MAX_CONTENT, HTTP_CHECK_TIMEOUT, RuleID, Severity
from .rules import Finding

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)


async def check_external_url(
    hass: "HomeAssistant",
    external_url: str,
) -> dict[str, Any]:
    """Perform security checks on user's external URL.

    This function checks the user's own external URL for common
    security misconfigurations. It only accesses the URL provided
    by the user and does not scan or enumerate any other systems.

    Args:
        hass: Home Assistant instance.
        external_url: The user's external URL to check.

    Returns:
        Dictionary containing check results and any findings.
    """
    import aiohttp

    findings: list[Finding] = []
    results: dict[str, Any] = {
        "url": external_url,
        "checks_performed": [],
        "findings": findings,
    }

    # Validate URL format
    try:
        parsed = urlparse(external_url)
        if not parsed.scheme or not parsed.netloc:
            results["error"] = "Invalid URL format"
            return results
    except Exception as err:
        results["error"] = f"URL parsing error: {err}"
        return results

    # Check for HTTPS
    if parsed.scheme != "https":
        findings.append(
            Finding(
                rule_id=RuleID.R070_EXTERNAL_URL_WEAK_TLS,
                severity=Severity.MED,
                confidence=95,
                title="External URL Not Using HTTPS",
                description=(
                    f"The external URL '{external_url}' uses HTTP instead of HTTPS. "
                    "Traffic to this URL is not encrypted."
                ),
                file_path="external_url",
                line=None,
                evidence_masked=f"URL scheme: {parsed.scheme}",
                recommendation="Configure HTTPS with a valid SSL certificate.",
                tags=["external", "tls"],
            )
        )
        results["checks_performed"].append("tls_check")

    # Perform HTTP checks with strict timeout
    timeout = aiohttp.ClientTimeout(total=HTTP_CHECK_TIMEOUT)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Check base URL
            results["checks_performed"].append("base_url_check")
            try:
                async with session.head(
                    external_url,
                    allow_redirects=True,
                    ssl=False,  # Don't fail on self-signed certs
                ) as response:
                    results["base_url_status"] = response.status
                    results["base_url_accessible"] = response.status < 500
            except aiohttp.ClientError as err:
                results["base_url_error"] = str(err)
                results["base_url_accessible"] = False

            # Check /api/ endpoint (should require auth)
            api_url = external_url.rstrip("/") + "/api/"
            results["checks_performed"].append("api_auth_check")

            try:
                async with session.get(
                    api_url,
                    allow_redirects=False,
                    ssl=False,
                ) as response:
                    results["api_status"] = response.status

                    # If we get 200, the API might be exposed without auth
                    if response.status == 200:
                        # Read limited content to check
                        content = await response.content.read(HTTP_CHECK_MAX_CONTENT)
                        content_str = content.decode("utf-8", errors="ignore")

                        # Check if this looks like actual API content
                        if "message" in content_str or "{" in content_str:
                            findings.append(
                                Finding(
                                    rule_id=RuleID.R071_API_EXPOSED,
                                    severity=Severity.HIGH,
                                    confidence=80,
                                    title="API Endpoint May Be Exposed",
                                    description=(
                                        f"The API endpoint at {api_url} returned 200 OK "
                                        "without authentication. This may expose sensitive data."
                                    ),
                                    file_path="external_url",
                                    line=None,
                                    evidence_masked=f"API returned status 200",
                                    recommendation=(
                                        "Ensure API endpoints require authentication. "
                                        "Check your reverse proxy configuration."
                                    ),
                                    tags=["external", "http"],
                                )
                            )
                    elif response.status in (401, 403):
                        results["api_auth_required"] = True

            except aiohttp.ClientError as err:
                results["api_error"] = str(err)

    except Exception as err:
        _LOGGER.warning("External URL check error: %s", err)
        results["error"] = str(err)

    results["findings"] = [f.to_dict() for f in findings]
    return results
