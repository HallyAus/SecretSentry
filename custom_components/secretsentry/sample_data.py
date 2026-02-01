"""Sample data for SecretSentry self-tests.

This module contains sample configuration "files" as strings that are used
for testing the scanner rules. The samples include various security issues
that the scanner should detect.

IMPORTANT: These are test samples only. The "secrets" here are fake
and used only to verify the scanner works correctly.
"""
from __future__ import annotations

from typing import Final

from .const import RuleID

# Sample configuration.yaml with various issues
SAMPLE_CONFIGURATION_YAML: Final = """
# Sample Home Assistant configuration for testing

homeassistant:
  name: Test Home
  unit_system: metric
  time_zone: UTC
  external_url: https://example.com:8123

http:
  ip_ban_enabled: false
  cors_allowed_origins:
    - "*"
  trusted_proxies:
    - 0.0.0.0/0

# Inline secret (R001)
some_integration:
  api_key: FAKE_TEST_KEY_abc123def456ghi789jkl012mno345
  token: FAKE_TOKEN_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  password: "SuperSecretPassword123!"

# Another inline secret
mqtt:
  broker: localhost
  username: mqtt_user
  password: mqtt_secret_password

# Missing secret reference (R004)
another_integration:
  api_key: !secret nonexistent_api_key

# v3.0: URL with userinfo (R008)
external_service:
  url: http://admin:FakeSecretPass123@test.local:8080/api
"""

# Sample with JWT token (R002)
SAMPLE_JWT_CONFIG: Final = """
# Configuration with JWT token

auth_provider:
  # This JWT should be detected
  token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
"""

# Sample with PEM key (R003)
SAMPLE_PEM_CONFIG: Final = """
# Configuration with PEM private key

ssl:
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpQIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7Lx9AGlqLcGPL3Gry
    [... key content would continue here ...]
    -----END RSA PRIVATE KEY-----
"""

# Sample automation with short webhook (R030)
SAMPLE_WEBHOOK_CONFIG: Final = """
# Automation with short webhook ID

automation:
  - alias: "Test Automation"
    trigger:
      - platform: webhook
        webhook_id: abc123
    action:
      - service: light.turn_on
        target:
          entity_id: light.living_room
"""

# Sample secrets.yaml (for reference, scanner skips this for inline detection)
SAMPLE_SECRETS_YAML: Final = """
# Secrets file with age metadata

# created: 2020-01-01
old_api_key: this_is_very_old_secret

# created: 2023-06-15
newer_secret: this_is_newer

mqtt_password: mqtt_pass_value
"""

# Sample .gitignore (weak)
SAMPLE_GITIGNORE_WEAK: Final = """
# Partial gitignore
*.pyc
__pycache__/
"""

# Sample .gitignore (good)
SAMPLE_GITIGNORE_GOOD: Final = """
# Good gitignore
secrets.yaml
.storage/
*.db
*.sqlite
backups/
backup/
*.pyc
__pycache__/
"""

# v3.0: Sample .env file with secrets (R090, R091)
SAMPLE_ENV_FILE: Final = """
# Docker environment file

# Database credentials
DB_PASSWORD=FakeDbPass123456
MYSQL_ROOT_PASSWORD=FakeRootPass789
POSTGRES_PASSWORD=FakePgKey456789

# API keys
API_KEY=FAKE_API_xxxxxxxxxxxxxxxxxxxxxx
JWT_SECRET=FakeJwtSecretValue123

# Non-sensitive values
DEBUG=true
LOG_LEVEL=info
"""

# v3.0: Sample docker-compose.yml with inline secrets (R092)
SAMPLE_DOCKER_COMPOSE: Final = """
version: '3.8'

services:
  homeassistant:
    image: ghcr.io/home-assistant/home-assistant:stable
    environment:
      - TZ=UTC
    volumes:
      - ./config:/config
    restart: unless-stopped

  mosquitto:
    image: eclipse-mosquitto
    environment:
      - MQTT_PASSWORD=FakeMqttPass123
    ports:
      - 1883:1883

  mariadb:
    image: mariadb:latest
    environment:
      MYSQL_ROOT_PASSWORD: FakeDbRootSecret456
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
    volumes:
      - db_data:/var/lib/mysql

volumes:
  db_data:
"""

# v3.0: Sample log line with JWT (R080)
SAMPLE_LOG_CONTENT: Final = """
2024-01-15 10:23:45.123 INFO (MainThread) [homeassistant.core] Starting Home Assistant
2024-01-15 10:23:46.456 WARNING (MainThread) [custom_component.test] Auth token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNTE2MjM5MDIyfQ.FAKE_test_signature
2024-01-15 10:23:47.789 INFO (MainThread) [homeassistant.setup] Setup completed
2024-01-15 10:23:48.012 DEBUG (MainThread) [aiohttp.access] Connecting to http://user:FakeLogPass123@internal.test:8080/api
"""

# v3.0: Sample URL with userinfo (R008)
SAMPLE_URL_USERINFO_CONFIG: Final = """
# Configuration with URL containing credentials

camera:
  - platform: generic
    stream_source: rtsp://admin:FakeCamPass123@192.168.1.50:554/stream1
    name: Front Door Camera

notify:
  - platform: smtp
    server: smtp://mailuser:FakeMailPass456@smtp.test.local:587
"""


# Expected findings for the samples
EXPECTED_FINDINGS: Final[list[dict[str, str | int | list[str]]]] = [
    # From SAMPLE_CONFIGURATION_YAML
    {
        "rule_id": RuleID.R020_HTTP_IP_BAN_DISABLED,
        "file": "configuration.yaml",
        "approximate_line": 12,
    },
    {
        "rule_id": RuleID.R022_CORS_WILDCARD,
        "file": "configuration.yaml",
        "approximate_line": 13,
    },
    {
        "rule_id": RuleID.R021_TRUSTED_PROXIES_BROAD,
        "file": "configuration.yaml",
        "approximate_line": 16,
    },
    {
        "rule_id": RuleID.R001_INLINE_SECRET_KEY,
        "file": "configuration.yaml",
        "approximate_line": 20,
        "key": "api_key",
    },
    {
        "rule_id": RuleID.R001_INLINE_SECRET_KEY,
        "file": "configuration.yaml",
        "approximate_line": 21,
        "key": "token",
    },
    {
        "rule_id": RuleID.R001_INLINE_SECRET_KEY,
        "file": "configuration.yaml",
        "approximate_line": 22,
        "key": "password",
    },
    {
        "rule_id": RuleID.R001_INLINE_SECRET_KEY,
        "file": "configuration.yaml",
        "approximate_line": 28,
        "key": "password",
    },
    {
        "rule_id": RuleID.R004_SECRET_REF_MISSING,
        "file": "configuration.yaml",
        "key": "nonexistent_api_key",
    },
    # v3.0: URL userinfo finding
    {
        "rule_id": RuleID.R008_URL_USERINFO,
        "file": "configuration.yaml",
        "approximate_line": 33,
    },
    # From SAMPLE_JWT_CONFIG
    {
        "rule_id": RuleID.R002_JWT_DETECTED,
        "file": "jwt_config.yaml",
        "approximate_line": 5,
    },
    # From SAMPLE_PEM_CONFIG
    {
        "rule_id": RuleID.R003_PEM_BLOCK,
        "file": "pem_config.yaml",
        "approximate_line": 6,
    },
    # From SAMPLE_WEBHOOK_CONFIG
    {
        "rule_id": RuleID.R030_WEBHOOK_SHORT,
        "file": "webhook_config.yaml",
        "approximate_line": 8,
    },
    # v3.0: From SAMPLE_ENV_FILE
    {
        "rule_id": RuleID.R091_ENV_INLINE_SECRET,
        "file": ".env",
        "key": "DB_PASSWORD",
    },
    # v3.0: From SAMPLE_DOCKER_COMPOSE
    {
        "rule_id": RuleID.R092_DOCKER_COMPOSE_INLINE_SECRET,
        "file": "docker-compose.yml",
        "key": "MQTT_PASSWORD",
    },
    # v3.0: From SAMPLE_URL_USERINFO_CONFIG
    {
        "rule_id": RuleID.R008_URL_USERINFO,
        "file": "url_userinfo_config.yaml",
    },
]


# Test data that should NOT trigger findings (negative tests)
SAMPLE_SAFE_CONFIG: Final = """
# Safe configuration using secrets properly

homeassistant:
  name: Safe Home

http:
  ip_ban_enabled: true
  login_attempts_threshold: 5

# Properly using secrets
some_integration:
  api_key: !secret my_api_key
  token: !secret my_token

# Template value (should not trigger)
sensor:
  platform: template
  sensors:
    test:
      value_template: "{{ states('sensor.temperature') }}"
"""

# Fake secret values used in tests (for masking verification)
# These are the raw secret values that should NEVER appear in evidence or exports
TEST_SECRET_VALUES: Final[list[str]] = [
    "FAKE_TEST_KEY_abc123def456ghi789jkl012mno345",
    "FAKE_TOKEN_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "SuperSecretPassword123!",
    "mqtt_secret_password",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    # v3.0: URL userinfo secrets
    "FakeSecretPass123",
    "FakeCamPass123",
    "FakeMailPass456",
    # v3.0: .env file secrets
    "FakeDbPass123456",
    "FakeRootPass789",
    "FakePgKey456789",
    "FAKE_API_xxxxxxxxxxxxxxxxxxxxxx",
    "FakeJwtSecretValue123",
    # v3.0: docker-compose secrets
    "FakeMqttPass123",
    "FakeDbRootSecret456",
    # v3.0: log file secrets
    "FakeLogPass123",
]


def get_sample_files() -> dict[str, str]:
    """Get all sample files as a dictionary.

    Returns:
        Dictionary mapping filename to content.
    """
    return {
        "configuration.yaml": SAMPLE_CONFIGURATION_YAML,
        "jwt_config.yaml": SAMPLE_JWT_CONFIG,
        "pem_config.yaml": SAMPLE_PEM_CONFIG,
        "webhook_config.yaml": SAMPLE_WEBHOOK_CONFIG,
        "secrets.yaml": SAMPLE_SECRETS_YAML,
        # v3.0: New sample files
        ".env": SAMPLE_ENV_FILE,
        "docker-compose.yml": SAMPLE_DOCKER_COMPOSE,
        "url_userinfo_config.yaml": SAMPLE_URL_USERINFO_CONFIG,
    }


def get_expected_findings() -> list[dict]:
    """Get expected findings for test verification.

    Returns:
        List of expected finding dictionaries.
    """
    return EXPECTED_FINDINGS.copy()


def get_log_sample() -> str:
    """Get sample log content for log scanning tests.

    v3.0: New function for log scanning tests.

    Returns:
        Sample log content string.
    """
    return SAMPLE_LOG_CONTENT
