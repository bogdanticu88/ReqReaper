# Changelog

All notable changes to ReqReaper will be documented in this file.

## [0.2.0] - 2026-02-21

### Fixed
- **XSS vulnerability in HTML report**: All database-sourced values are now escaped with
  `html.escape()` before being written into the report template.
- **SQLMap module always skipping**: Removed an internal `enable_sqli` config gate that was
  never set and caused the module to return early on every execution. Module gating is handled
  exclusively by the orchestrator via CLI flags.
- **Silent error swallowing in `run_command()`**: Timeout, missing binary (`FileNotFoundError`),
  and unexpected exceptions are now logged at the appropriate level (`warning`, `error`) instead
  of being silently discarded.
- **TLS module not parsing findings**: `testssl.sh` JSON output is now fully parsed. Findings
  are extracted with severity mapping (`CRITICAL` → `critical`, `HIGH` → `high`, etc.) and
  written to the database. Informational `OK` results are filtered out.
- **Auth headers not passed to tools**: `httpx`, `nuclei`, and `ffuf` now append the configured
  `auth.header_name` / `auth.header_value` as a `-H` flag when building tool commands.
- **No timeout on OpenAPI HTTP requests**: `requests.get()` in the OpenAPI module now uses the
  configured `timeout` value, preventing indefinite hangs.
- **OpenAPI module only supported JSON specs**: Both URL-fetched and file-based specs now try
  JSON first and fall back to YAML, covering the majority of real-world API specs.

### Added
- **JWT module**: Native Python module for JWT security analysis. Collects tokens from configured
  auth headers, response headers, and response body. Flags weak algorithms (`none`, `HS256`),
  missing `exp`, `aud`, and `iss` claims. Findings are written to the `findings` table and a
  local `jwt_findings.csv`. Registered under the `Vulnerability` module group.
- **Auth header passthrough in OpenAPI module**: OpenAPI spec fetches now include the configured
  auth header for specs served behind authentication.

### Changed
- **Refactored module selection logic**: Extracted a `select_modules()` function to replace
  duplicated conditional blocks in both the dry-run and execution paths. Ensures consistent
  behaviour and a single place to update when adding new modules.
- **requirements.txt**: Removed unused `sqlite-utils` dependency. Added minimum version pins
  for all dependencies (`rich>=13.0.0`, `pyyaml>=6.0.0`, `requests>=2.28.0`,
  `jsonschema>=4.0.0`, `pytest>=7.0.0`).

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
