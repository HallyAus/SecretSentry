# Changelog

All notable changes to SecretSentry will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.6] - 2025-02-03

### Added

- **Options Menu**: New menu-based options flow with:
  - **Configure Settings**: Access all configuration options
  - **Scan Now**: Trigger an immediate security scan from the UI
  - **Clear All Repairs**: Remove all SecretSentry repair issues (useful for stuck issues)

### Fixed

- **Repair Persistence**: Fixed issue where resolved findings weren't removed from Repairs dashboard
  - Now persists repair fingerprints to storage
  - Properly cleans up resolved issues after rescan
- **Config Flow 500 Error**: Fixed OptionsFlow config_entry property conflict in modern HA versions

## [3.0.0] - 2024-01-XX

### Added

#### Log Scanning (Quarantine Logs Detection)
- New rule **R080_LOG_CONTAINS_SECRET**: Detects secrets leaked into log files
- Options: `enable_log_scan` (default: OFF), `log_scan_paths`, `max_log_scan_mb`, `max_log_lines`
- Streaming line-by-line processing with strict caps
- Detects JWT, PEM, URL userinfo, and inline secrets in logs

#### Environment Hygiene Checks
- New rule **R090_ENV_FILE_PRESENT**: Advisory for .env files
- New rule **R091_ENV_INLINE_SECRET**: Detects secrets in .env files (med/high)
- New rule **R092_DOCKER_COMPOSE_INLINE_SECRET**: Detects secrets in docker-compose (med)
- New rule **R093_ADDON_CONFIG_EXPORT_RISK**: Checks add-on config directories (user-specified)
- Options: `enable_env_hygiene` (default: ON), `env_files`, `addon_config_dirs`

#### URL Userinfo Detection
- New rule **R008_URL_USERINFO**: Detects scheme://user:pass@host patterns (high severity)
- New masking helper `redact_url_userinfo()` applied to evidence and exports
- URL credentials redacted in sanitised copies

#### Privacy Mode for Reports
- New option `privacy_mode_reports` (default: ON)
- Private IPs masked with consistent tokens (e.g., `private_ip_1`)
- Hostnames tokenized consistently within export
- File paths and line numbers preserved

#### Packaging and Trust
- Added SECURITY.md with security model documentation
- Added LICENSE (MIT)
- Added CHANGELOG.md
- Updated README with security guarantees

### Changed

- Self-test now verifies no raw secrets in evidence, exports, or sanitised copies
- Sample data includes test cases for all new rules
- Sensitive key patterns expanded for Docker/database credentials

### Security

- All new rules follow masking-first design
- No raw secrets ever logged or stored
- Evidence always truncated to max 200 characters

## [2.0.0] - 2024-01-XX

### Added

- 15+ security rules across 8 categories
- Built-in self-test service
- Sanitised configuration export
- Delta scanning (new/resolved findings)
- Evidence masking with entropy detection
- Fingerprinting for stable finding identification
- External URL self-check (optional)
- Comprehensive options flow

### Changed

- Complete rewrite of scanner architecture
- Modular rule engine design
- Improved secret detection accuracy

## [1.0.0] - 2024-01-XX

### Added

- Initial release
- Basic secret scanning (7 rules)
- DataUpdateCoordinator for periodic scans
- Repairs integration
- Two sensors (total and high severity findings)
- Scan now and export report services
