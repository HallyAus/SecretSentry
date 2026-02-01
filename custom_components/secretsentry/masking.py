"""Secret masking utilities for SecretSentry.

This module provides utilities for masking sensitive data to ensure
secrets are never exposed in logs, reports, or UI elements.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Final

# Masking constants
MASK_CHAR: Final = "*"
MIN_VISIBLE_CHARS: Final = 4
MAX_MASK_LENGTH: Final = 20
REDACTED_PLACEHOLDER: Final = "***REDACTED***"

# Patterns for detecting secrets in text
JWT_PATTERN: Final = re.compile(
    r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+"
)
PEM_BEGIN_PATTERN: Final = re.compile(
    r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?(?:PRIVATE|ENCRYPTED)\s+KEY-----"
)
PEM_END_PATTERN: Final = re.compile(
    r"-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?(?:PRIVATE|ENCRYPTED)\s+KEY-----"
)
SECRET_REF_PATTERN: Final = re.compile(r"!secret\s+(\S+)")
WEBHOOK_PATTERN: Final = re.compile(r"/api/webhook/([A-Za-z0-9_-]+)")

# Pattern to detect values that look like secrets (high entropy strings)
SECRET_VALUE_PATTERN: Final = re.compile(
    r'^[A-Za-z0-9+/=_-]{16,}$'
)


def mask_secret(
    value: str,
    visible_start: int = MIN_VISIBLE_CHARS,
    visible_end: int = 0,
    max_mask: int = MAX_MASK_LENGTH,
) -> str:
    """Mask a secret value, showing only specified characters.

    Args:
        value: The secret value to mask.
        visible_start: Number of characters to show at the start.
        visible_end: Number of characters to show at the end.
        max_mask: Maximum number of mask characters to use.

    Returns:
        Masked string with asterisks replacing hidden characters.
    """
    if not value:
        return MASK_CHAR * 4

    length = len(value)

    if length <= visible_start + visible_end:
        return MASK_CHAR * min(length, 4)

    hidden_length = length - visible_start - visible_end
    mask_length = min(hidden_length, max_mask)

    start_part = value[:visible_start] if visible_start > 0 else ""
    end_part = value[-visible_end:] if visible_end > 0 else ""

    return f"{start_part}{MASK_CHAR * mask_length}{end_part}"


def mask_jwt(token: str) -> str:
    """Mask a JWT token, preserving structure indication.

    Args:
        token: The JWT token to mask.

    Returns:
        Masked JWT showing only header type hint.
    """
    if not token:
        return "jwt:****"

    parts = token.split(".")
    if len(parts) != 3:
        return f"jwt:{mask_secret(token, 4, 0, 8)}"

    # Try to extract header type
    try:
        import base64
        import json

        # Add padding if needed
        header_b64 = parts[0]
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding

        header = json.loads(base64.urlsafe_b64decode(header_b64))
        alg = header.get("alg", "?")
        return f"jwt:{alg}:****"
    except Exception:
        return f"jwt:len{len(token)}:****"


def mask_pem(line: str) -> str:
    """Mask a PEM key line.

    Args:
        line: The PEM line to mask.

    Returns:
        Masked PEM header indication.
    """
    if "BEGIN" in line and "PRIVATE" in line:
        return "-----BEGIN PRIVATE KEY----- [CONTENT REDACTED]"
    if "BEGIN" in line and "KEY" in line:
        return line.split("-----")[1].strip() + " [REDACTED]"
    return "[PEM KEY CONTENT REDACTED]"


def mask_webhook_id(webhook_id: str) -> str:
    """Mask a webhook ID, showing only first 4 characters.

    Args:
        webhook_id: The webhook ID to mask.

    Returns:
        Masked webhook ID.
    """
    if not webhook_id:
        return "****"

    if len(webhook_id) <= 4:
        return MASK_CHAR * len(webhook_id)

    return f"{webhook_id[:4]}{MASK_CHAR * min(len(webhook_id) - 4, 12)}"


def mask_line(
    line: str,
    known_secrets: list[str] | None = None,
) -> str:
    """Mask any potential secrets in a line of text.

    Args:
        line: The line of text to mask.
        known_secrets: Optional list of known secret values to mask.

    Returns:
        Line with secrets masked.
    """
    masked = line

    # Mask JWT tokens
    for match in JWT_PATTERN.finditer(masked):
        token = match.group(0)
        masked = masked.replace(token, mask_jwt(token))

    # Mask webhook IDs
    for match in WEBHOOK_PATTERN.finditer(masked):
        webhook_id = match.group(1)
        masked = masked.replace(
            f"/api/webhook/{webhook_id}",
            f"/api/webhook/{mask_webhook_id(webhook_id)}"
        )

    # Mask quoted values that look like secrets
    quoted_pattern = re.compile(r'["\']([^"\']{8,})["\']')
    for match in quoted_pattern.finditer(line):
        value = match.group(1)
        if SECRET_VALUE_PATTERN.match(value):
            masked = masked.replace(
                match.group(0),
                f'"{mask_secret(value)}"'
            )

    # Mask known secrets
    if known_secrets:
        for secret in known_secrets:
            if secret and len(secret) > 4 and secret in masked:
                masked = masked.replace(secret, mask_secret(secret))

    return masked


def calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string.

    Higher entropy indicates more randomness, suggesting a secret.

    Args:
        value: The string to analyze.

    Returns:
        Entropy value (bits per character).
    """
    if not value:
        return 0.0

    # Count character frequencies
    freq: dict[str, int] = {}
    for char in value:
        freq[char] = freq.get(char, 0) + 1

    # Calculate entropy
    length = len(value)
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)

    return entropy


def looks_like_secret(value: str, min_length: int = 8) -> tuple[bool, int]:
    """Determine if a value looks like a secret based on heuristics.

    Args:
        value: The value to check.
        min_length: Minimum length to consider.

    Returns:
        Tuple of (is_likely_secret, confidence_score 0-100).
    """
    if not value or len(value) < min_length:
        return False, 0

    # Strip quotes if present
    stripped = value.strip("'\"")
    if not stripped:
        return False, 0

    confidence = 0

    # Length scoring
    length = len(stripped)
    if length >= 32:
        confidence += 25
    elif length >= 20:
        confidence += 15
    elif length >= 12:
        confidence += 10

    # Entropy scoring
    entropy = calculate_entropy(stripped)
    if entropy >= 4.5:
        confidence += 30
    elif entropy >= 4.0:
        confidence += 20
    elif entropy >= 3.5:
        confidence += 10

    # Pattern scoring
    if SECRET_VALUE_PATTERN.match(stripped):
        confidence += 20

    # Contains mixed case and numbers
    has_upper = any(c.isupper() for c in stripped)
    has_lower = any(c.islower() for c in stripped)
    has_digit = any(c.isdigit() for c in stripped)
    if has_upper and has_lower and has_digit:
        confidence += 15

    # Contains special characters common in tokens
    if any(c in stripped for c in "_-"):
        confidence += 5

    # Negative indicators
    # Looks like a URL
    if stripped.startswith(("http://", "https://", "ftp://")):
        confidence -= 30

    # Looks like a path
    if stripped.startswith("/") or "\\" in stripped:
        confidence -= 20

    # Contains spaces (unlikely to be a secret)
    if " " in stripped:
        confidence -= 40

    # Common non-secret patterns
    non_secret_patterns = [
        r"^\d+\.\d+\.\d+",  # Version numbers
        r"^[a-z]+\.[a-z]+",  # Domain-like
        r"^true$|^false$|^null$|^none$",  # Boolean/null
    ]
    for pattern in non_secret_patterns:
        if re.match(pattern, stripped, re.IGNORECASE):
            confidence -= 30

    confidence = max(0, min(100, confidence))
    return confidence >= 40, confidence


def hash_for_comparison(value: str) -> str:
    """Create a hash of a value for comparison without storing the raw value.

    This is used for detecting duplicate secrets across files.

    Args:
        value: The value to hash.

    Returns:
        SHA256 hash of the value.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_fingerprint(
    rule_id: str,
    file_path: str,
    line: int | None,
    key: str | None = None,
) -> str:
    """Create a stable fingerprint for a finding.

    The fingerprint never includes raw secret material.

    Args:
        rule_id: The rule identifier.
        file_path: Path to the file (relative).
        line: Line number or None.
        key: Optional additional key for uniqueness (NOT a secret value).

    Returns:
        SHA256-based fingerprint string.
    """
    components = [rule_id, file_path, str(line or 0)]
    if key:
        components.append(key)

    combined = ":".join(components)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:16]


def redact_value_in_line(line: str, value: str) -> str:
    """Replace a specific value in a line with the redacted placeholder.

    Args:
        line: The line of text.
        value: The value to redact.

    Returns:
        Line with value replaced by placeholder.
    """
    if not value or not line:
        return line

    # Try to replace with quotes preserved
    for quote in ('"', "'", ""):
        pattern = f"{quote}{re.escape(value)}{quote}"
        if re.search(pattern, line):
            return re.sub(
                pattern,
                f"{quote}{REDACTED_PLACEHOLDER}{quote}" if quote else REDACTED_PLACEHOLDER,
                line
            )

    return line.replace(value, REDACTED_PLACEHOLDER)
