# ReqReaper Roadmap

## Completed

### v0.1.0
- **Core Orchestration Engine:** CLI interface, configuration management, and
  modular plugin system.
- **Data Normalization Layer:** Standardized SQLite backend with automated
  CSV exports.
- **Allowlist & Preflight:** Robust host enforcement and tool availability
  validation.
- **Reporting:** Basic HTML report generation with severity summaries.
- **Testing:** Unit test suite for parsers and data management.
- **Functional Modules:**
  - `httpx`: Discovery and tech fingerprinting.
  - `nmap`: Port scanning and service detection.
  - `nuclei`: Template-based vulnerability scanning.
  - `testssl.sh`: TLS/SSL configuration auditing.
  - `zap-cli`: OWASP ZAP baseline security scans.
  - `ffuf`: Directory and endpoint fuzzing.
  - `kiterunner`: API endpoint discovery.
  - `sqlmap`: Automated SQL injection testing.
  - `k6`: Performance and stress testing.
  - `OpenAPI`: Definition parsing and extraction.

### v0.2.0
- **JWT Analysis Module:** Native Python implementation. Collects tokens from
  auth headers, response headers, and response body. Flags weak algorithms
  (`none`, `HS256`), missing `exp`/`aud`/`iss` claims. No external binary required.
- **TLS Finding Extraction:** Full parsing of `testssl.sh` JSON output with
  severity mapping. Actual findings are now stored in the database rather than
  a placeholder path reference.
- **Auth Header Passthrough:** Configured auth headers are now forwarded to
  `httpx`, `nuclei`, `ffuf`, and OpenAPI spec fetches.
- **OpenAPI YAML Support:** Spec fetches and file inputs now support both JSON
  and YAML formats.
- **Error Visibility:** `run_command()` now logs timeouts, missing binaries, and
  unexpected errors rather than silently returning `None`.
- **XSS Fix in HTML Report:** All database-sourced values are HTML-escaped before
  being written into the report template.
- **Code Quality:** Extracted `select_modules()` to eliminate duplicated module
  selection logic across dry-run and execution paths.

## In Progress

- **Database Deep Integration:** Full per-request/response storage for all
  modules for auditing.
- **Artifact Consolidation:** Improving evidence linking in HTML reports and
  cross-referencing findings across modules.

## Planned

- **Extended Discovery:** Integration of `katana`, `gau`, and `waybackurls`.
- **Advanced Fuzzing:** Support for `wfuzz` and `arjun` for parameter discovery.
- **Load Testing Expansion:** Integration of `vegeta`, `wrk`, and `hey`.
- **Dynamic HTML Reports:** Interactive reporting dashboard with severity
  filtering and search.
- **Nmap Result Parsing:** Extract open ports and service banners from nmap XML
  output into the database.

## Future Ideas

- **GraphQL Interrogation:** Specialized module for GraphQL schema introspection
  and testing.
- **Mass Assignment Detection:** Automated testing for object injection and mass
  assignment vulnerabilities.
- **IDOR Testing:** Semi-automated module for identifying potential IDOR
  endpoints through multi-user session analysis.
- **Authentication Proxy:** Integration with Burp Suite or ZAP proxy for manual
  and automated traffic interception.
