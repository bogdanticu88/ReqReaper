# Changelog

All notable changes to ReqReaper will be documented in this file.

## [0.1.0] - 2026-02-20

### Added
- Initial release of ReqReaper API Security Framework.
- Modular plugin system for tool orchestration.
- Integration with `httpx`, `nmap`, `nuclei`, `testssl.sh`, `zap-cli`, `ffuf`, `kiterunner`, `sqlmap`, `k6`, and OpenAPI parsing.
- Centralized DataManager with SQLite backend and automated CSV exports.
- Robust configuration validation with JSON schema and allowlist enforcement.
- Safe preflight mode (`--dry-run`) for validation and tool discovery.
- Professional console UI with rich progress indicators and execution summaries.
- Basic HTML report generation.
- Unit test suite for parsers and normalization logic.
- Documentation including README.md and ROADMAP.md.
