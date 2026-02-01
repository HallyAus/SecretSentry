"""Constants for the SecretSentry integration."""
from __future__ import annotations

from enum import StrEnum
from typing import Final

DOMAIN: Final = "secretsentry"

# Storage keys
STORAGE_KEY: Final = f"{DOMAIN}_state"
STORAGE_VERSION: Final = 1

# Configuration keys
CONF_SCAN_INTERVAL: Final = "scan_interval"
CONF_ENABLE_SNAPSHOT_SCAN: Final = "enable_snapshot_scan"
CONF_ENABLE_GIT_CHECKS: Final = "enable_git_subprocess_checks"
CONF_ENABLE_SECRET_AGE: Final = "enable_secret_age"
CONF_ENABLE_EXTERNAL_CHECK: Final = "enable_external_url_self_check"
CONF_EXTERNAL_URL: Final = "external_url"
CONF_INCLUDE_PATHS: Final = "include_paths"
CONF_EXCLUDE_PATHS: Final = "exclude_paths"
CONF_MAX_FILE_SIZE_KB: Final = "max_file_size_kb"
CONF_MAX_TOTAL_SCAN_MB: Final = "max_total_scan_mb"
CONF_MAX_FINDINGS: Final = "max_findings"

# Default configuration values
DEFAULT_SCAN_INTERVAL: Final = "daily"  # disabled, daily, weekly
DEFAULT_MAX_FILE_SIZE_KB: Final = 512
DEFAULT_MAX_TOTAL_SCAN_MB: Final = 50
DEFAULT_MAX_FINDINGS: Final = 500
DEFAULT_SNAPSHOT_MEMBER_SIZE: Final = 256 * 1024  # 256KB per archive member
DEFAULT_SNAPSHOT_TOTAL_SIZE: Final = 5 * 1024 * 1024  # 5MB total for archive scanning

# Scan interval options (in seconds)
SCAN_INTERVALS: Final[dict[str, int | None]] = {
    "disabled": None,
    "daily": 86400,
    "weekly": 604800,
}

# Attributes
ATTR_FINDINGS: Final = "findings"
ATTR_LAST_SCAN: Final = "last_scan"
ATTR_SCAN_DURATION: Final = "scan_duration"
ATTR_MED_COUNT: Final = "med_count"
ATTR_LOW_COUNT: Final = "low_count"
ATTR_NEW_HIGH_COUNT: Final = "new_high_count"
ATTR_RESOLVED_COUNT: Final = "resolved_count"
ATTR_TOP_FINDINGS: Final = "top_findings"

# Services
SERVICE_SCAN_NOW: Final = "scan_now"
SERVICE_EXPORT_REPORT: Final = "export_report"
SERVICE_EXPORT_SANITISED: Final = "export_sanitised_copy"
SERVICE_RUN_SELFTEST: Final = "run_selftest"

# File paths
REPORT_FILENAME: Final = "secretsentry_report.json"
SANITISED_DIR: Final = "secretsentry_sanitised"

# Secret age thresholds (days)
SECRET_AGE_LOW: Final = 180
SECRET_AGE_MED: Final = 365
SECRET_AGE_HIGH: Final = 730


class Severity(StrEnum):
    """Severity levels for findings."""

    HIGH = "high"
    MED = "med"
    LOW = "low"
    INFO = "info"


class RuleID(StrEnum):
    """Rule identifiers for scanner."""

    # Group 1: Credential leak linting
    R001_INLINE_SECRET_KEY = "R001"
    R002_JWT_DETECTED = "R002"
    R003_PEM_BLOCK = "R003"
    R004_SECRET_REF_MISSING = "R004"
    R005_SECRET_DUPLICATION = "R005"

    # Group 2: Git hygiene
    R010_GITIGNORE_MISSING = "R010"
    R011_GITIGNORE_WEAK = "R011"
    R012_SECRETS_IN_REPO = "R012"

    # Group 3: Exposure / proxy / http hardening
    R020_HTTP_IP_BAN_DISABLED = "R020"
    R021_TRUSTED_PROXIES_BROAD = "R021"
    R022_CORS_WILDCARD = "R022"
    R023_EXPOSED_PORT_HINT = "R023"

    # Group 4: Webhook hygiene
    R030_WEBHOOK_SHORT = "R030"

    # Group 5: Storage sensitivity
    R040_STORAGE_DIR_PRESENT = "R040"

    # Group 6: Snapshot leak detection
    R050_SNAPSHOT_CONTAINS_SECRETS = "R050"

    # Group 7: Rotation / age metadata
    R060_SECRET_AGE = "R060"

    # Group 8: External URL checks
    R070_EXTERNAL_URL_WEAK_TLS = "R070"
    R071_API_EXPOSED = "R071"


# Sensitive keys to check for inline secrets (R001)
# Tuple of (key_pattern, severity, confidence_boost)
SENSITIVE_KEYS: Final[tuple[tuple[str, Severity, int], ...]] = (
    ("api_key", Severity.HIGH, 20),
    ("apikey", Severity.HIGH, 20),
    ("token", Severity.HIGH, 15),
    ("access_token", Severity.HIGH, 25),
    ("refresh_token", Severity.HIGH, 25),
    ("bearer", Severity.HIGH, 25),
    ("client_secret", Severity.HIGH, 25),
    ("password", Severity.HIGH, 20),
    ("passwd", Severity.HIGH, 20),
    ("private_key", Severity.HIGH, 30),
    ("webhook", Severity.MED, 15),
    ("mqtt_password", Severity.HIGH, 25),
    ("auth", Severity.MED, 10),
    ("authorization", Severity.HIGH, 20),
    ("client_id", Severity.MED, 5),
    ("username", Severity.LOW, 0),
    ("secret", Severity.HIGH, 20),
    ("secret_key", Severity.HIGH, 25),
    ("app_secret", Severity.HIGH, 25),
    ("consumer_secret", Severity.HIGH, 25),
    ("api_token", Severity.HIGH, 20),
    ("auth_token", Severity.HIGH, 20),
    ("credential", Severity.HIGH, 15),
    ("credentials", Severity.HIGH, 15),
)

# Recommended .gitignore entries
RECOMMENDED_GITIGNORE: Final[tuple[str, ...]] = (
    "secrets.yaml",
    ".storage/",
    "*.db",
    "*.sqlite",
    "backups/",
    "backup/",
)

# Broad proxy ranges to flag
BROAD_PROXY_RANGES: Final[tuple[str, ...]] = (
    "0.0.0.0/0",
    "::/0",
    "0.0.0.0",
    "::",
)

# File patterns to scan
SCANNABLE_EXTENSIONS: Final[tuple[str, ...]] = (
    ".yaml",
    ".yml",
    ".json",
    ".env",
    ".conf",
    ".txt",
)

# Archive extensions for snapshot scanning
ARCHIVE_EXTENSIONS: Final[tuple[str, ...]] = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".zip",
)

# Directories to skip during scanning
DEFAULT_EXCLUDE_DIRS: Final[tuple[str, ...]] = (
    ".storage",
    "deps",
    "tts",
    "www",
    "media",
    "backups",
    "backup",
    "logs",
    "__pycache__",
    ".git",
)

# File patterns to skip
DEFAULT_EXCLUDE_PATTERNS: Final[tuple[str, ...]] = (
    "*.db",
    "*.log",
    "*.sqlite",
    "*.tar",
    "*.tar.gz",
    "*.tgz",
    "*.zip",
)

# Tags for findings
class Tags(StrEnum):
    """Tags for categorizing findings."""

    SECRETS = "secrets"
    GIT = "git"
    PROXY = "proxy"
    HTTP = "http"
    BACKUP = "backup"
    WEBHOOK = "webhook"
    STORAGE = "storage"
    AGE = "age"
    EXTERNAL = "external"
    TLS = "tls"


# External check timeouts
HTTP_CHECK_TIMEOUT: Final = 10  # seconds
HTTP_CHECK_MAX_CONTENT: Final = 1024  # bytes to read for response check
