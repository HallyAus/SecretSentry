# SecretSentry

![SecretSentry](logo.png)

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support-yellow?style=for-the-badge&logo=buy-me-a-coffee)](https://buymeacoffee.com/printforge)
[![Add to Home Assistant](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=HallyAus&repository=SecretSentry&category=integration)

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

🛰️ *Like free internet? [Get one free month of Starlink!](https://starlink.com/residential?referral=RC-2455784-77014-69&app_source=share)*

**Local security scanner for Home Assistant configurations.**

SecretSentry scans your Home Assistant configuration directory for potential security issues, including exposed credentials, insecure settings, git hygiene problems, and missing security best practices.

## Security Model

**SecretSentry is LOCAL ONLY.** Your secrets never leave your system.

| Feature | Guarantee |
|---------|-----------|
| **Local Execution** | All scanning runs locally on your HA instance |
| **No Telemetry** | Zero analytics, tracking, or data collection |
| **No Outbound** | No connections except optional external URL self-check (YOUR URL only) |
| **Secret Masking** | Raw secrets NEVER logged, stored, or displayed |
| **Privacy Mode** | Reports can mask private IPs and tokenize hostnames |

See [SECURITY.md](SECURITY.md) for complete security documentation.

## Features

### v3.0 Highlights

- **Log Scanning**: Detect secrets leaked into log files
- **Environment Hygiene**: Scan .env and docker-compose.yml for secrets
- **URL Userinfo Detection**: Find credentials embedded in URLs (scheme://user:pass@host)
- **Privacy Mode**: Mask IPs and tokenize hostnames in exported reports
- **Enhanced Self-Test**: Verify masking in evidence, exports, and sanitised copies

### Core Features

- **20+ Security Rules**: Comprehensive checks across 10 categories
- **Delta Scanning**: Track new and resolved findings between scans
- **Repairs Integration**: Findings appear in Home Assistant's Repairs dashboard
- **Evidence Masking**: All secrets are automatically masked in logs and reports
- **Snapshot Scanning**: Optionally scan backup archives for leaked secrets
- **Git Hygiene Checks**: Verify secrets aren't committed to repositories
- **Secret Age Tracking**: Detect old secrets that need rotation
- **External URL Self-Check**: Verify your own instance's HTTPS and auth status
- **Built-in Self-Test**: Verify the scanner is working correctly
- **Sanitised Export**: Create redacted copies of configuration for sharing

## Installation

### HACS Installation (Recommended)

1. Open HACS in Home Assistant
2. Click on "Integrations"
3. Click the three dots menu in the top right
4. Select "Custom repositories"
5. Add the repository URL and select "Integration" as the category
6. Click "Add"
7. Search for "SecretSentry" and install it
8. Restart Home Assistant
9. Go to Settings → Devices & Services → Add Integration → Search for "SecretSentry"

### Manual Installation

1. Download the `custom_components/secretsentry` folder from this repository
2. Copy it to your Home Assistant `config/custom_components/` directory
3. Restart Home Assistant
4. Go to Settings → Devices & Services → Add Integration → Search for "SecretSentry"

## Configuration Options

### Basic Options

- **Scan Interval**: Disabled, Daily, or Weekly
- **Privacy Mode Reports**: Mask private IPs and hostnames in exports (default: ON)
- **Environment Hygiene**: Scan .env and docker-compose files (default: ON)
- **Log Scanning**: Scan log files for leaked secrets (default: OFF)
- **Scan Backup Archives**: Scan .tar and .zip files in backup directories
- **Enable Git Subprocess Checks**: Check if secrets.yaml is tracked in git
- **Check Secret Age Metadata**: Detect old secrets based on date comments
- **Enable External URL Self-Check**: Check your own external URL for issues

### Advanced Options

- **Maximum File Size**: Skip files larger than this (default: 512KB)
- **Maximum Total Scan Size**: Stop scanning after this total (default: 50MB)
- **Maximum Findings**: Limit total findings per scan (default: 500)
- **Maximum Log Size**: Limit for log file scanning (default: 10MB)
- **Maximum Log Lines**: Stop after this many log lines (default: 50000)

## Security Rules

### Group 1: Credential Leak Detection

| Rule | Severity | Description |
|------|----------|-------------|
| R001 | HIGH | Inline secrets (api_key, token, password, etc.) |
| R002 | HIGH | JWT tokens in configuration |
| R003 | HIGH | PEM private key blocks |
| R004 | MED | Missing !secret references |
| R005 | MED | Duplicate secret values |
| R008 | HIGH | URL with credentials (user:pass@host) |

### Group 2: Git Hygiene

| Rule | Severity | Description |
|------|----------|-------------|
| R010 | MED | Missing .gitignore |
| R011 | MED | Weak .gitignore (missing critical entries) |
| R012 | HIGH | secrets.yaml tracked in git |

### Group 3: HTTP/Proxy Security

| Rule | Severity | Description |
|------|----------|-------------|
| R020 | MED | IP ban disabled |
| R021 | HIGH | Broad trusted proxies (0.0.0.0/0) |
| R022 | HIGH | CORS wildcard origin |
| R023 | LOW | External exposure hints |

### Group 4: Webhooks

| Rule | Severity | Description |
|------|----------|-------------|
| R030 | MED | Short or predictable webhook IDs |

### Group 5: Storage Security

| Rule | Severity | Description |
|------|----------|-------------|
| R040 | LOW | .storage directory advisory |

### Group 6: Snapshot/Backup Scanning

| Rule | Severity | Description |
|------|----------|-------------|
| R050 | HIGH | Secrets in backup archives |

### Group 7: Secret Age

| Rule | Severity | Description |
|------|----------|-------------|
| R060 | MED | Old secrets needing rotation |

### Group 8: External URL Checks

| Rule | Severity | Description |
|------|----------|-------------|
| R070 | HIGH | External URL not using HTTPS |
| R071 | HIGH | External API accessible without auth |

### Group 9: Log Scanning (v3.0)

| Rule | Severity | Description |
|------|----------|-------------|
| R080 | HIGH | Secrets leaked into log files |

### Group 10: Environment Hygiene (v3.0)

| Rule | Severity | Description |
|------|----------|-------------|
| R090 | LOW | .env file present (advisory) |
| R091 | MED/HIGH | Secrets in .env files |
| R092 | MED | Secrets in docker-compose.yml |
| R093 | LOW/MED | Add-on config export risk |

## Services

### `secretsentry.scan_now`
Triggers an immediate security scan.

### `secretsentry.export_report`
Exports a masked JSON report to `/config/secretsentry_report.json`.

### `secretsentry.export_sanitised_copy`
Creates a sanitised copy of configuration files with secrets replaced by `***REDACTED***`. Output is saved to `/config/secretsentry_sanitised/`.

### `secretsentry.run_selftest`
Runs internal self-tests to verify the scanner is working correctly. Tests include:
- All rule detection
- Secret masking in evidence
- Secret masking in exports
- Sanitised copy verification

## Sensors

### Total Security Findings
`sensor.secretsentry_total_findings`

**Attributes:**
- `med_count`: Medium severity count
- `low_count`: Low severity count
- `last_scan`: Timestamp of the last scan
- `scan_duration_seconds`: How long the scan took
- `new_high_count`: High findings since last scan
- `resolved_count`: Findings fixed since last scan
- `top_findings`: Top 5 most important findings

### High Severity Findings
`sensor.secretsentry_high_severity_findings`

## Privacy Mode

When `privacy_mode_reports` is enabled (default: ON), exported reports and sanitised copies will:

- Replace private IPs with tokens (`private_ip_1`, `private_ip_2`, etc.)
- Tokenize hostnames consistently within an export
- Preserve file paths and line numbers for debugging
- Maintain consistent tokens so relationships are visible

This allows sharing reports without exposing your network topology.

## Example Automations

### Notify on New High Severity Findings

```yaml
automation:
  - alias: "Notify on new security findings"
    trigger:
      - platform: state
        entity_id: sensor.secretsentry_high_severity_findings
    condition:
      - condition: template
        value_template: >
          {{ state_attr('sensor.secretsentry_total_findings', 'new_high_count') | int > 0 }}
    action:
      - service: notify.mobile_app
        data:
          title: "Security Alert"
          message: >
            SecretSentry found {{ state_attr('sensor.secretsentry_total_findings', 'new_high_count') }}
            new high severity security issues.
```

## Troubleshooting

### Config Flow 500 Error

If clicking the gear icon (options) shows "Config flow could not be loaded: 500":

1. Check Settings -> System -> Logs and search for "secretsentry" or "config_flow"
2. Common cause is import errors in config_flow.py
3. Try removing and re-adding the integration
4. Restart Home Assistant after any updates

### Running Self-Test

Use the `secretsentry.run_selftest` service to verify the scanner is working correctly. This tests all rules against known sample data and verifies masking is functioning.

### Findings Not Appearing

1. Check if the scan has completed (look at `last_scan` attribute)
2. Verify file permissions allow Home Assistant to read config files
3. Check Home Assistant logs for any scanner errors
4. Run the self-test service to verify scanner functionality

### False Positives

Some findings may be intentional. You can:
1. Acknowledge them in the Repairs dashboard
2. Move the values to `secrets.yaml` even if not strictly necessary

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) if available.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.

## Disclaimer

SecretSentry is a security scanning tool that helps identify potential issues but does not guarantee complete security. Always follow security best practices and regularly review your Home Assistant configuration.
