# SecretSentry

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)

**Local security scanner for Home Assistant configurations.**

SecretSentry scans your Home Assistant configuration directory for potential security issues, including exposed credentials, insecure settings, git hygiene problems, and missing security best practices.

## Important Safety Note

**SecretSentry performs ONLY local scanning.** It does NOT:

- Connect to the internet for any scanning purposes
- Enumerate other Home Assistant instances
- Use external services like Shodan or any registry lookups
- Send any data outside your local network
- Perform any network scanning or enumeration

All scanning is performed locally against your `/config` directory. Your secrets and configuration data never leave your system.

The **only** network feature is the optional "External URL Self-Check" which checks YOUR OWN configured external URL - no other systems are ever contacted.

## Features

- **15+ Security Rules**: Comprehensive checks across 8 categories
- **Delta Scanning**: Track new and resolved findings between scans
- **Repairs Integration**: Findings appear in Home Assistant's Repairs dashboard
- **Evidence Masking**: All secrets are automatically masked in logs and reports
- **Snapshot Scanning**: Optionally scan backup archives for leaked secrets
- **Git Hygiene Checks**: Verify secrets aren't committed to repositories
- **Secret Age Tracking**: Detect old secrets that need rotation
- **External URL Self-Check**: Verify your own instance's HTTPS and auth status
- **Built-in Self-Test**: Verify the scanner is working correctly
- **Sanitised Export**: Create redacted copies of configuration for sharing
- **Two Sensors**: Monitor total findings and high-severity findings
- **Export Reports**: Generate masked JSON reports for review

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

After setup, configure options through the integration's configuration page:

### Basic Options

- **Scan Interval**: How often to scan (5 minutes to 24 hours, default: 1 hour)
- **Scan Backup Archives**: Scan .tar and .zip files in backup directories
- **Enable Git Subprocess Checks**: Check if secrets.yaml is tracked in git
- **Check Secret Age Metadata**: Detect old secrets based on date comments
- **Enable External URL Self-Check**: Check your own external URL for issues

### Advanced Options

- **Maximum File Size**: Skip files larger than this (default: 5MB)
- **Maximum Total Scan Size**: Stop scanning after this total (default: 100MB)
- **Maximum Findings**: Limit total findings per scan (default: 500)

## Security Rules

### Group 1: Credential Leak Detection

#### R001: Inline Secrets Detected
**Severity: High**

Detects sensitive configuration keys (api_key, token, password, client_secret, private_key, bearer, webhook, etc.) that contain hardcoded values instead of using `!secret` references.

```yaml
# BAD - will be flagged
api_key: abc123secretkey

# GOOD - uses secret reference
api_key: !secret my_api_key
```

#### R002: JWT Token Detected
**Severity: High**

Detects JSON Web Tokens (JWTs) in configuration files.

#### R003: PEM Private Key Detected
**Severity: High**

Detects PEM-encoded private key blocks in configuration files.

#### R004: Missing Secret Reference
**Severity: Medium**

Detects `!secret` references that point to keys not defined in `secrets.yaml`.

#### R005: Secret Duplication
**Severity: Medium**

Flags when the same secret value appears in multiple places, increasing leak risk.

### Group 2: Git Hygiene

#### R010: Gitignore Missing
**Severity: Medium**

No `.gitignore` file found in config directory.

#### R011: Gitignore Weak
**Severity: Medium**

`.gitignore` is missing critical entries like `secrets.yaml`, `.storage/`, or `*.db`.

#### R012: Secrets Tracked in Git
**Severity: High**

`secrets.yaml` is being tracked by git (requires git subprocess checks enabled).

### Group 3: HTTP/Proxy Security

#### R020: IP Ban Disabled
**Severity: Medium**

`ip_ban_enabled` is set to false in HTTP configuration.

#### R021: Login Attempts Threshold Missing
**Severity: Low**

No `login_attempts_threshold` configured for rate limiting.

#### R022: Broad Trusted Proxies
**Severity: High**

Overly permissive `trusted_proxies` like `0.0.0.0/0` that trust all IPs.

#### R023: SSL Not Enforced
**Severity: Medium**

External access configured without SSL enforcement.

### Group 4: Webhooks

#### R030: Unprotected Webhooks
**Severity: Medium**

Webhook IDs that are too short or predictable.

### Group 5: Storage Security

#### R040: Plaintext Credentials in Storage
**Severity: High**

Credentials stored in plaintext in `.storage/` files.

### Group 6: Snapshot/Backup Scanning

#### R050: Secrets in Backup Archives
**Severity: High**

Secrets found in backup .tar or .zip files (requires snapshot scanning enabled).

### Group 7: Secret Age

#### R060: Stale Secrets
**Severity: Low**

Secrets older than 365 days based on date comments in secrets.yaml.

### Group 8: External URL Checks

#### R070: External URL Not HTTPS
**Severity: High**

Your external URL is not using HTTPS.

#### R071: External API Unauthenticated
**Severity: High**

Your external URL's API endpoint is accessible without authentication.

## Sensors

### Total Security Findings
`sensor.secretsentry_total_findings`

Shows the total number of security findings across all severity levels.

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

Shows the count of high severity findings.

**Attributes:**
- `new_high_count`: New high findings since last scan
- `findings`: List of high severity findings (limited to first 10)

## Services

### `secretsentry.scan_now`

Triggers an immediate security scan.

```yaml
service: secretsentry.scan_now
```

### `secretsentry.export_report`

Exports a masked JSON report to `/config/secretsentry_report.json`.

```yaml
service: secretsentry.export_report
```

### `secretsentry.export_sanitised_copy`

Creates a sanitised copy of configuration files with secrets replaced by `***REDACTED***`. Output is saved to `/config/secretsentry_sanitised/`.

```yaml
service: secretsentry.export_sanitised_copy
```

### `secretsentry.run_selftest`

Runs internal self-tests to verify the scanner is working correctly. Results are displayed as a persistent notification.

```yaml
service: secretsentry.run_selftest
```

## Repairs Integration

All findings appear in Home Assistant's Repairs dashboard (Settings → System → Repairs). Each finding includes:

- Rule ID and severity
- File path and line number
- Masked evidence (secrets are never shown in plain text)
- Remediation recommendations

When you fix an issue and the next scan runs, the repair issue is automatically removed.

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
            new high severity security issues. Check the Repairs dashboard.
```

### Weekly Security Scan with Report

```yaml
automation:
  - alias: "Weekly security scan"
    trigger:
      - platform: time
        at: "03:00:00"
    condition:
      - condition: time
        weekday:
          - sun
    action:
      - service: secretsentry.scan_now
      - delay: "00:01:00"
      - service: secretsentry.export_report
```

## Privacy & Security

- All scanning is performed locally
- No data is sent to external services
- Secrets are automatically masked in all outputs using entropy-based detection
- Reports contain only masked evidence
- The only network connection is the optional external URL self-check of YOUR OWN instance
- Fingerprints are used for stable finding identification without exposing content

## Troubleshooting

### Running Self-Test

Use the `secretsentry.run_selftest` service to verify the scanner is working correctly. This tests all rules against known sample data and verifies masking is functioning.

### Findings Not Appearing

1. Check if the scan has completed (look at `last_scan` attribute)
2. Verify file permissions allow Home Assistant to read config files
3. Check Home Assistant logs for any scanner errors
4. Run the self-test service to verify scanner functionality

### False Positives

Some findings may be intentional (e.g., test configurations). You can:
1. Acknowledge them in the Repairs dashboard
2. Move the values to `secrets.yaml` even if not strictly necessary

### Scan Taking Too Long

- Large configuration directories may take longer
- Files in `.storage`, `deps`, and other excluded directories are automatically skipped
- Configure the maximum file size and total scan size limits in options
- Disable snapshot scanning if you have many large backup files

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

SecretSentry is a security scanning tool that helps identify potential issues but does not guarantee complete security. Always follow security best practices and regularly review your Home Assistant configuration.
