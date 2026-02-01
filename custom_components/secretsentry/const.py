"""Constants for the SecretSentry integration."""
from __future__ import annotations

from enum import StrEnum
from typing import Final

DOMAIN: Final = "secretsentry"

# Storage keys
STORAGE_KEY: Final = f"{DOMAIN}_state"
STORAGE_VERSION: Final = 2

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

# v3.0: Log scanning options
CONF_ENABLE_LOG_SCAN: Final = "enable_log_scan"
CONF_LOG_SCAN_PATHS: Final = "log_scan_paths"
CONF_MAX_LOG_SCAN_MB: Final = "max_log_scan_mb"
CONF_MAX_LOG_LINES: Final = "max_log_lines"

# v3.0: Environment hygiene options
CONF_ENABLE_ENV_HYGIENE: Final = "enable_env_hygiene"
CONF_ENV_FILES: Final = "env_files"
CONF_ADDON_CONFIG_DIRS: Final = "addon_config_dirs"

# v3.0: Privacy mode option
CONF_PRIVACY_MODE_REPORTS: Final = "privacy_mode_reports"

# Default configuration values
DEFAULT_SCAN_INTERVAL: Final = "daily"  # disabled, daily, weekly
DEFAULT_MAX_FILE_SIZE_KB: Final = 512
DEFAULT_MAX_TOTAL_SCAN_MB: Final = 50
DEFAULT_MAX_FINDINGS: Final = 500
DEFAULT_SNAPSHOT_MEMBER_SIZE: Final = 256 * 1024  # 256KB per archive member
DEFAULT_SNAPSHOT_TOTAL_SIZE: Final = 5 * 1024 * 1024  # 5MB total for archive scanning

# v3.0: Log scanning defaults
DEFAULT_ENABLE_LOG_SCAN: Final = False  # Off by default
DEFAULT_LOG_SCAN_PATHS: Final = ["home-assistant.log"]
DEFAULT_MAX_LOG_SCAN_MB: Final = 10
DEFAULT_MAX_LOG_LINES: Final = 50000

# v3.0: Environment hygiene defaults
DEFAULT_ENABLE_ENV_HYGIENE: Final = True  # On by default
DEFAULT_ENV_FILES: Final = [".env", "docker-compose.yml", "docker-compose.yaml"]
DEFAULT_ADDON_CONFIG_DIRS: Final = []  # Empty by default, user must specify

# v3.0: Privacy mode default
DEFAULT_PRIVACY_MODE_REPORTS: Final = True  # On by default

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
    R008_URL_USERINFO = "R008"  # v3.0: URL with userinfo

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

    # Group 9: Log scanning (v3.0)
    R080_LOG_CONTAINS_SECRET = "R080"

    # Group 10: Environment hygiene (v3.0)
    R090_ENV_FILE_PRESENT = "R090"
    R091_ENV_INLINE_SECRET = "R091"
    R092_DOCKER_COMPOSE_INLINE_SECRET = "R092"
    R093_ADDON_CONFIG_EXPORT_RISK = "R093"


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
    # v3.0: Additional Docker/env sensitive keys
    ("db_password", Severity.HIGH, 25),
    ("database_url", Severity.HIGH, 20),
    ("redis_password", Severity.HIGH, 25),
    ("mysql_password", Severity.HIGH, 25),
    ("postgres_password", Severity.HIGH, 25),
    ("encryption_key", Severity.HIGH, 30),
    ("jwt_secret", Severity.HIGH, 30),
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
    LOGS = "logs"  # v3.0
    ENV = "env"  # v3.0
    DOCKER = "docker"  # v3.0
    ADDON = "addon"  # v3.0
    URL = "url"  # v3.0


# External check timeouts
HTTP_CHECK_TIMEOUT: Final = 10  # seconds
HTTP_CHECK_MAX_CONTENT: Final = 1024  # bytes to read for response check

# v3.0: Privacy mode tokenization prefix
PRIVACY_TOKEN_PREFIX: Final = "host_"
PRIVACY_IP_MASK: Final = "x.x.x.x"

# Default options dictionary for config entry options
# Used to merge with user options to ensure all keys exist
DEFAULT_OPTIONS: Final[dict[str, any]] = {
    CONF_SCAN_INTERVAL: "daily",
    CONF_PRIVACY_MODE_REPORTS: True,
    CONF_ENABLE_ENV_HYGIENE: True,
    CONF_ENABLE_LOG_SCAN: False,
    CONF_ENABLE_SNAPSHOT_SCAN: False,
    CONF_ENABLE_GIT_CHECKS: False,
    CONF_ENABLE_SECRET_AGE: False,
    CONF_ENABLE_EXTERNAL_CHECK: False,
    CONF_EXTERNAL_URL: "",
    CONF_MAX_FILE_SIZE_KB: 512,
    CONF_MAX_TOTAL_SCAN_MB: 50,
    CONF_MAX_FINDINGS: 500,
    CONF_MAX_LOG_SCAN_MB: 10,
    CONF_MAX_LOG_LINES: 50000,
}
