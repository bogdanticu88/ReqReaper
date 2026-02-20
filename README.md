# ReqReaper

ReqReaper is a modular orchestration framework designed for automated API security
testing. It integrates industry-standard security tools into a unified workflow,
providing standardized data models, normalized CSV exports, and comprehensive 
audit trails for authorized red-team engagements.

By Bogdan Ticu

## Quickstart

Start a security assessment in three commands:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Perform a safe preflight check
python3 reqreaper.py --config config/example.yaml --dry-run

# 3. Execute the full assessment
python3 reqreaper.py --config config/example.yaml
```

## What it generates

Every execution produces a timestamped artifact directory containing:

- `artifacts/run_<timestamp>/raw`: Unmodified output from every executed tool.
- `artifacts/run_<timestamp>/normalized`: Standardized CSV exports (endpoints, findings, etc.).
- `artifacts/run_<timestamp>/report/report.html`: High-level summary of the assessment.
- `artifacts/run_<timestamp>/reqreaper.db`: A complete SQLite database of all results and audit trails.

## Example output

### Startup Banner
```text
██████╗ ███████╗ ██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝█████╗  ██║   ██║██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██╔══██╗██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██║███████╗╚██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝

                        v0.1.0 | by Bogdan Ticu
```

### Console Execution
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

## Modules

### Implemented now
- **Reconnaissance:** `httpx`, `nmap`
- **Vulnerability Scanning:** `nuclei`, `testssl.sh`, `zap-cli`
- **Fuzzing & Enumeration:** `ffuf`, `kiterunner`
- **Injection:** `sqlmap`
- **Load Testing:** `k6`
- **API Specific:** `OpenAPI` parsing

### Planned
For upcoming tool integrations and features, see the [ROADMAP.md](ROADMAP.md).

## Legal

**AUTHORIZED USE ONLY.** This tool is intended for use by security professionals 
during authorized security assessments. Unauthorized testing against systems 
without explicit permission is illegal. The author assumes no liability for 
misuse or any damages caused by this software.
