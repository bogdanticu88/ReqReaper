# ReqReaper

ReqReaper is a modular orchestration framework for API security testing, designed to automate the execution of standard red-team tools and normalize their output for analysis.

by Bogdan Ticu

## Current Status

ReqReaper is currently in an active development phase. The core orchestration engine and the following modules are functional:

- **Reconnaissance:**
  - `httpx`: Service discovery and technology fingerprinting.
  - `nmap`: Port scanning and service version detection.
- **Vulnerability Scanning:**
  - `nuclei`: Template-based vulnerability scanning.
  - `testssl.sh`: Comprehensive TLS/SSL configuration auditing.
  - `zap-cli`: Baseline OWASP ZAP security scans.
- **Fuzzing & Enumeration:**
  - `ffuf`: Directory and endpoint fuzzing.
  - `kiterunner`: API endpoint discovery using kiterunner routes.
- **Injection:**
  - `sqlmap`: Automated SQL injection testing (requires `--enable-sqli`).
- **Load Testing:**
  - `k6`: Automated performance and stress testing (requires `--enable-load`).
- **API Specific:**
  - `OpenAPI`: Definition parsing and endpoint extraction from URLs or local files.

## Architecture

- **Orchestrator:** Python-based engine that manages module execution, allowlist enforcement, and artifact generation.
- **Module System:** Abstracted plugin system where each module handles tool execution, raw output capture, and CSV normalization.
- **Data Persistence:**
  - **SQLite:** Centralized database (`reqreaper.db`) initialized with schema for findings and requests.
  - **CSV:** Normalized data exports for each module.
  - **Raw:** Unmodified output from all external tools.

## Known Limitations

- **Database Integration:** While the SQLite database is initialized, current module implementations primarily focus on CSV normalization. Deep integration for per-request storage is in progress.
- **Reporting:** The HTML report currently provides a high-level execution summary; detailed findings are primarily available in the `normalized/` CSV artifacts.
- **Tool Dependencies:** ReqReaper acts as an orchestrator and requires the underlying tools (e.g., `httpx`, `nuclei`, `nmap`) to be pre-installed and available in the system PATH.
- **JWT Module:** Currently provides basic base64 decoding logic; full `jwt-tool` integration is planned.

## Roadmap

Planned features and tool integrations:
- **Additional Discovery Tools:** `katana`, `gau`, `waybackurls`.
- **Enhanced Fuzzing:** `wfuzz`, `arjun`.
- **Load Testing Expansion:** `vegeta`, `wrk`, `hey`.
- **Full Database Sync:** Real-time synchronization of all module findings into the SQLite backend.
- **Advanced Reporting:** Dynamic HTML reports with severity-based filtering and evidence embedding.

## Supported Environments

- **Primary:** Kali Linux Rolling (2024.x+)
- **Secondary:** Debian-based distributions with security tools installed via `apt` or manual binary placement.
- **Python:** 3.11 or higher.

## Installation

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Ensure required external tools are installed:
   ```bash
   sudo apt install httpx nmap nuclei ffuf kiterunner sqlmap zaproxy k6 testssl.sh
   ```

## Usage

Define targets and allowed hosts in `config.yaml`, then execute:

```bash
python3 reqreaper.py --config config.yaml [FLAGS]
```

## Example Execution

### Command
```bash
python3 reqreaper.py --config config.yaml --full
```

### Console Output Snippet
```text
[*] Initialization complete. Run ID: 550e8400-e29b-41d4-a716-446655440000
[*] Target Scope: 2 hosts
[*] Running OpenAPI Analysis...
[*] Executing Discovery:HTTPX...
[+] Discovery:HTTPX completed
[*] Executing Discovery:Nmap...
[+] Discovery:Nmap completed
[*] Executing Vulnerability:Nuclei...
[+] Vulnerability:Nuclei completed

Execution Summary
Artifacts Directory: /home/user/ReqReaper/artifacts/run_20260220_120000

Findings by Severity
Severity  Count
HIGH          2
MEDIUM        5
LOW          12
```

### Example Findings Table (Normalized CSV)
| Tool   | Severity | Title                        | Endpoint                        | Confidence |
|--------|----------|------------------------------|---------------------------------|------------|
| nuclei | HIGH     | Exposed Git Repository       | https://api.example.com/.git/   | high       |
| nuclei | MEDIUM   | Information Disclosure       | https://api.example.com/        | high       |
| nuclei | LOW      | Missing Security Header      | https://api.example.com/        | high       |

Full samples can be found in `docs/sample_run/`.

### Flags

- `--config`: (Required) Path to the YAML configuration file.
- `--safe`: Disables dangerous modules (default behavior).
- `--full`: Enables all discovery and vulnerability modules.
- `--enable-load`: Explicitly enables load testing modules.
- `--enable-fuzz`: Explicitly enables directory/endpoint fuzzing.
- `--enable-sqli`: Explicitly enables SQL injection testing.
- `--quiet`: Suppresses informational logs.
- `--no-color`: Disables ANSI color output.

## Legal Warning

ReqReaper is for authorized security testing only. Use of this tool against targets without explicit, written permission is illegal. The developer assumes no liability for damages or legal consequences resulting from misuse of this software.
