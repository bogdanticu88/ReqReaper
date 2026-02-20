# ReqReaper Roadmap

## Completed
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

## In Progress
- **Database Deep Integration:** Full per-request/response storage for all
  modules for auditing.
- **Enhanced JWT Analysis:** Native logic for common JWT misconfigurations and
  token tampering.
- **Artifact Consolidation:** Improving evidence linking in HTML reports.

## Planned
- **Extended Discovery:** Integration of `katana`, `gau`, and `waybackurls`.
- **Advanced Fuzzing:** Support for `wfuzz` and `arjun` for parameter discovery.
- **Load Testing Expansion:** Integration of `vegeta`, `wrk`, and `hey`.
- **Dynamic HTML Reports:** Interactive reporting dashboard with severity
  filtering and search.

## Future Ideas
- **GraphQL Interrogation:** Specialized module for GraphQL schema introspection
  and testing.
- **Mass Assignment Detection:** Automated testing for object injection and mass
  assignment vulnerabilities.
- **IDOR Testing:** Semi-automated module for identifying potential IDOR
  endpoints through multi-user session analysis.
- **Authentication Proxy:** Integration with Burp Suite or ZAP proxy for manual
  and automated traffic interception.
