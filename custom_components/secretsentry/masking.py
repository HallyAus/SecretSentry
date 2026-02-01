"""Secret masking utilities for SecretSentry.

This module provides utilities for masking sensitive data to ensure
secrets are never exposed in logs, reports, or UI elements.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Final
from urllib.parse import urlparse, urlunparse

# Masking constants
MASK_CHAR: Final = "*"
MIN_VISIBLE_CHARS: Final = 4
MAX_MASK_LENGTH: Final = 20
REDACTED_PLACEHOLDER: Final = "***REDACTED***"
REDACTED_URL_CREDS: Final = "***:***"

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

# v3.0: URL with userinfo pattern (scheme://user:pass@host)
URL_USERINFO_PATTERN: Final = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^:@/\s]+):([^@/\s]+)@([^\s/]+)"
)

# Pattern to detect values that look like secrets (high entropy strings)
SECRET_VALUE_PATTERN: Final = re.compile(
    r'^[A-Za-z0-9+/=_-]{16,}$'
)

# v3.0: Private IP patterns for privacy mode
PRIVATE_IP_PATTERN: Final = re.compile(
    r'\b(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # 10.x.x.x
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'  # 172.16-31.x.x
    r'192\.168\.\d{1,3}\.\d{1,3}|'  # 192.168.x.x
    r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}'  # 127.x.x.x
    r')\b'
)

# v3.0: Hostname/domain pattern for tokenization
HOSTNAME_PATTERN: Final = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
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


def redact_url_userinfo(url: str) -> str:
    """Redact credentials from a URL with userinfo.

    Detects URLs in format scheme://user:pass@host and replaces
    the credentials with ***:***.

    Args:
        url: The URL or text containing URLs to redact.

    Returns:
        URL with credentials redacted.
    """
    if not url:
        return url

    def replace_userinfo(match: re.Match) -> str:
        scheme = match.group(1)
        host = match.group(4)
        return f"{scheme}{REDACTED_URL_CREDS}@{host}"

    return URL_USERINFO_PATTERN.sub(replace_userinfo, url)


def extract_url_userinfo(url: str) -> tuple[str, str] | None:
    """Extract username and password from a URL with userinfo.

    Args:
        url: The URL to analyze.

    Returns:
        Tuple of (username, password) or None if no userinfo.
    """
    match = URL_USERINFO_PATTERN.search(url)
    if match:
        return (match.group(2), match.group(3))
    return None


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

    # v3.0: Mask URL userinfo first
    masked = redact_url_userinfo(masked)

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
    # Looks like a URL (but check for userinfo)
    if stripped.startswith(("http://", "https://", "ftp://")):
        # If it has userinfo, it's still a secret concern
        if extract_url_userinfo(stripped):
            confidence += 20
        else:
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


# =============================================================================
# v3.0: Privacy Mode Utilities
# =============================================================================


class PrivacyTokenizer:
    """Tokenizer for consistent hostname/IP masking within an export run.

    Creates consistent tokens for hostnames and IPs so that relationships
    between findings can be preserved while actual values are hidden.
    """

    def __init__(self) -> None:
        """Initialize the tokenizer."""
        self._hostname_map: dict[str, str] = {}
        self._ip_map: dict[str, str] = {}
        self._hostname_counter = 0
        self._ip_counter = 0

    def tokenize_hostname(self, hostname: str) -> str:
        """Get consistent token for a hostname.

        Args:
            hostname: The hostname to tokenize.

        Returns:
            Consistent token for this hostname.
        """
        if hostname not in self._hostname_map:
            self._hostname_counter += 1
            self._hostname_map[hostname] = f"host_{self._hostname_counter}"
        return self._hostname_map[hostname]

    def tokenize_ip(self, ip: str) -> str:
        """Get consistent token for a private IP.

        Args:
            ip: The IP address to tokenize.

        Returns:
            Consistent token for this IP.
        """
        if ip not in self._ip_map:
            self._ip_counter += 1
            self._ip_map[ip] = f"private_ip_{self._ip_counter}"
        return self._ip_map[ip]

    def apply_privacy_mode(self, text: str) -> str:
        """Apply privacy mode to text, masking IPs and tokenizing hostnames.

        Does NOT remove file names or line numbers.

        Args:
            text: The text to process.

        Returns:
            Text with private IPs masked and hostnames tokenized.
        """
        if not text:
            return text

        result = text

        # Mask private IPs with consistent tokens
        for match in PRIVATE_IP_PATTERN.finditer(text):
            ip = match.group(0)
            result = result.replace(ip, self.tokenize_ip(ip))

        # Tokenize hostnames (but not file paths or common words)
        for match in HOSTNAME_PATTERN.finditer(text):
            hostname = match.group(0)
            # Skip common TLDs that might be false positives
            if hostname.endswith(('.yaml', '.json', '.yml', '.env', '.txt', '.py')):
                continue
            # Skip localhost
            if hostname == 'localhost':
                continue
            result = result.replace(hostname, self.tokenize_hostname(hostname))

        return result


def apply_privacy_to_dict(
    data: dict,
    tokenizer: PrivacyTokenizer,
    skip_keys: set[str] | None = None,
) -> dict:
    """Apply privacy mode recursively to a dictionary.

    Args:
        data: Dictionary to process.
        tokenizer: PrivacyTokenizer instance for consistent tokenization.
        skip_keys: Keys to skip (like 'file_path', 'line').

    Returns:
        New dictionary with privacy mode applied.
    """
    skip_keys = skip_keys or {'file_path', 'line', 'rule_id', 'fingerprint', 'severity'}
    result = {}

    for key, value in data.items():
        if key in skip_keys:
            result[key] = value
        elif isinstance(value, str):
            result[key] = tokenizer.apply_privacy_mode(value)
        elif isinstance(value, dict):
            result[key] = apply_privacy_to_dict(value, tokenizer, skip_keys)
        elif isinstance(value, list):
            result[key] = [
                apply_privacy_to_dict(item, tokenizer, skip_keys) if isinstance(item, dict)
                else tokenizer.apply_privacy_mode(item) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            result[key] = value

    return result


def truncate_evidence(evidence: str, max_length: int = 200) -> str:
    """Truncate evidence string to maximum length.

    Args:
        evidence: The evidence string.
        max_length: Maximum allowed length.

    Returns:
        Truncated evidence with ellipsis if needed.
    """
    if not evidence or len(evidence) <= max_length:
        return evidence

    return evidence[:max_length - 3] + "..."
