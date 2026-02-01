# Security Policy

## SecretSentry Security Model

SecretSentry is designed with a **local-only, privacy-first** approach to configuration security scanning.

### Core Security Principles

1. **Local Execution Only**
   - All scanning happens locally on your Home Assistant instance
   - No configuration data is ever sent to external servers
   - No telemetry, analytics, or usage tracking

2. **No Outbound Connections**
   - The only optional outbound connection is the **External URL Self-Check**
   - This checks YOUR OWN external URL only (if configured)
   - This is disabled by default and requires explicit opt-in

3. **Secret Masking Guarantees**
   - Raw secrets are NEVER logged, stored, or displayed
   - All evidence in findings uses masked values (e.g., `api_****...`)
   - JWT tokens show only algorithm, not payload or signature
   - Private keys show only type indicator, no key material
   - URL credentials are redacted (scheme://***:***@host)

4. **Privacy Mode for Reports**
   - When enabled (default: ON), exported reports mask:
     - Private IP addresses (replaced with tokens like `private_ip_1`)
     - Hostnames/domains (tokenized consistently within export)
   - File paths and line numbers are preserved for debugging

5. **Filesystem Safety**
   - Scanner runs in executor (non-blocking)
   - Respects file size limits (configurable)
   - Automatic caps on total scan size and findings count
   - Log scanning uses streaming to avoid memory issues

### What SecretSentry Does NOT Do

- Does NOT scan the internet or external systems
- Does NOT use Shodan, Censys, or any external scanning services
- Does NOT enumerate your network
- Does NOT send any data anywhere
- Does NOT modify your configuration files
- Does NOT store raw secret values

## Reporting Security Issues

If you discover a security vulnerability in SecretSentry:

1. **Do NOT open a public issue**
2. Email the maintainers directly with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
3. Allow reasonable time for a fix before public disclosure

## Security Best Practices

When using SecretSentry:

1. **Review findings carefully** before sharing sanitised copies
2. **Rotate exposed secrets** immediately when detected
3. **Use secrets.yaml** for all sensitive values
4. **Keep .gitignore** properly configured
5. **Encrypt backups** that contain configuration data

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.x     | :white_check_mark: |
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for security-related changes and updates.
