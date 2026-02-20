# ReqReaper

ReqReaper is a modular orchestration framework for API security testing, designed
to automate the execution of standard red-team tools and normalize their output
for analysis.

By Bogdan Ticu

## Current Status

ReqReaper provides a core orchestration engine and several functional modules for
reconnaissance, vulnerability scanning, and fuzzing. It is built to streamline the
workflow of API security assessments by wrapping disparate tools into a unified
execution and data model.

- **Reconnaissance:** `httpx`, `nmap`
- **Vulnerability Scanning:** `nuclei`, `testssl.sh`, `zap-cli`
- **Fuzzing & Enumeration:** `ffuf`, `kiterunner`
- **Injection:** `sqlmap`
- **Load Testing:** `k6`
- **API Specific:** `OpenAPI` parsing

For a detailed list of implemented features and planned updates, see the
[ROADMAP.md](ROADMAP.md) file.

## Architecture

- **Orchestrator:** Python-based engine that manages module execution,
  allowlist enforcement, and artifact generation.
- **Module System:** Abstracted plugin system where each module handles tool
  execution, raw output capture, and CSV normalization.
- **Data Persistence:**
  - **SQLite:** Centralized database (`reqreaper.db`) for findings and requests.
  - **CSV:** Normalized data exports for each module.
  - **Raw:** Unmodified output from all external tools stored for audit.

## Known Limitations

- **Database Integration:** Current module implementations primarily focus on
  CSV normalization; deep per-request storage is in progress.
- **Reporting:** HTML report provides a high-level execution summary; detailed
  findings are primarily available in the `normalized/` CSV artifacts.
- **Tool Dependencies:** Requires underlying tools (e.g., `httpx`, `nuclei`) to
  be pre-installed in the system PATH.

## Supported Environments

- **Primary:** Kali Linux Rolling (2024.x+)
- **Secondary:** Debian-based distributions with security tools installed.
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

Full samples can be found in the `docs/sample_run/` directory.

### Flags

- `--config`: (Required) Path to the YAML configuration file.
- `--dry-run`: Safe preflight: validate config and check tools.
- `--safe`: Disables dangerous modules (default behavior).
- `--full`: Enables all discovery and vulnerability modules.
- `--enable-load`: Explicitly enables load testing modules.
- `--enable-fuzz`: Explicitly enables directory/endpoint fuzzing.
- `--enable-sqli`: Explicitly enables SQL injection testing.
- `--quiet`: Suppresses informational logs.
- `--no-color`: Disables ANSI color output.
- `--version`: Displays the application version.

## Legal Warning

ReqReaper is for authorized security testing only. Use of this tool against
targets without explicit, written permission is illegal. The developer assumes
no liability for damages or legal consequences resulting from misuse of this
software.
