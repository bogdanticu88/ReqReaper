# Changelog

All notable changes to ReqReaper will be documented in this file.

## [0.1.0] - 2026-02-20

### Added
- Initial release of the ReqReaper API Security Framework.
- Modular plugin system for tool orchestration and data normalization.
- Integration with standard security tools:
  - Discovery: `httpx`, `nmap`
  - Vulnerability: `nuclei`, `testssl.sh`, `zap-cli`
  - Fuzzing & Enumeration: `ffuf`, `kiterunner`
  - Injection: `sqlmap`
  - Load Testing: `k6`
  - API Specific: `OpenAPI` parsing
- Centralized DataManager with SQLite backend and automated CSV exports.
- Robust configuration validation with JSON schema and allowlist enforcement.
- Safe preflight mode (`--dry-run`) for validation and tool discovery.
- Professional console UI with rich progress indicators and execution
  summaries.
- Basic HTML report generation for high-level findings.
- Unit test suite for parsers and data normalization logic.
- Comprehensive documentation: README.md, ROADMAP.md, and CHANGELOG.md.
