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
TEST_SECRET_VALUES: Final[list[str]] = [
    "FAKE_TEST_KEY_abc123def456ghi789jkl012mno345",
    "FAKE_TOKEN_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "SuperSecretPassword123!",
    "mqtt_secret_password",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
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
    }


def get_expected_findings() -> list[dict]:
    """Get expected findings for test verification.

    Returns:
        List of expected finding dictionaries.
    """
    return EXPECTED_FINDINGS.copy()
