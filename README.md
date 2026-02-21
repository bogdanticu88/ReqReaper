# ReqReaper

ReqReaper is a modular orchestration framework designed for automated API security
testing. It integrates industry-standard security tools into a unified workflow,
providing standardized data models, normalized CSV exports, and comprehensive
audit trails for authorized red-team engagements.

By Bogdan Ticu

## Quickstart

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Perform a safe preflight check
python3 reqreaper.py --config config/example.yaml --dry-run

# 3. Execute the full assessment
python3 reqreaper.py --config config/example.yaml

# 4. Run a simulated demo (no tools required)
python3 reqreaper.py --demo
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `--config` | Path to YAML configuration file |
| `--dry-run` | Validate config and check tool availability without executing |
| `--demo` | Run a simulated execution for preview purposes |
| `--full` | Enable all non-destructive modules in one pass |
| `--safe` | Restrict `--full` to passive modules only |
| `--enable-fuzz` | Enable fuzzing modules (`ffuf`, `kiterunner`) |
| `--enable-sqli` | Enable SQL injection testing (`sqlmap`) |
| `--enable-load` | Enable load testing (`k6`) |
| `--quiet` | Suppress console output |
| `--no-color` | Disable color output |
| `--version` | Print version and exit |

## Configuration

All scan behaviour is controlled through a YAML config file. See `config/example.yaml` for a full reference.

Key fields:

```yaml
targets:
  - https://api.example.com

allowed_hosts:
  - api.example.com        # Allowlist enforced — targets not listed here are rejected

auth:
  header_name: "Authorization"
  header_value: "Bearer <token>"   # Passed to httpx, nuclei, ffuf, and OpenAPI fetches

openapi_url: "https://api.example.com/openapi.json"   # JSON or YAML specs supported

timeout: 30
```

## Modules

### Implemented

| Category | Tools |
|----------|-------|
| Reconnaissance | `httpx`, `nmap` |
| Vulnerability Scanning | `nuclei`, `testssl.sh`, `zap-cli` |
| JWT Analysis | Native Python — no binary required |
| Fuzzing & Enumeration | `ffuf`, `kiterunner` |
| Injection | `sqlmap` |
| Load Testing | `k6` |
| API Parsing | OpenAPI (JSON + YAML) |

### JWT Analysis

The JWT module runs as part of the vulnerability group without requiring any
external binary. It collects tokens from configured auth headers, HTTP response
headers, and response body fields, then checks for:

- Algorithm `none` (critical — token is unsigned)
- Weak symmetric algorithms (`HS256`, `HS1`)
- Missing `exp` claim (token never expires)
- Missing `aud` / `iss` claims

Findings are written to the `findings` table and exported to `jwt_findings.csv`.

### Planned

For upcoming integrations and features, see [ROADMAP.md](ROADMAP.md).

## What it generates

Every execution produces a timestamped artifact directory:

```
artifacts/run_<timestamp>/
├── raw/                  # Unmodified output from each tool
├── normalized/           # Standardized CSV exports per table
│   ├── endpoints.csv
│   ├── findings.csv
│   ├── jwt_findings.csv
│   ├── tls_findings.csv
│   └── ...
├── report/
│   └── report.html       # High-level HTML summary
└── reqreaper.db          # Full SQLite audit database
```

## Example output

### Startup Banner
```text
██████╗ ███████╗ ██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝█████╗  ██║   ██║██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██╔══██╗██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██║███████╗╚██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝

                        v0.2.0 | by Bogdan Ticu
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
[*] Executing Vulnerability:TLS...
[+] Vulnerability:TLS completed
[*] Executing Vulnerability:JWT...
[+] Vulnerability:JWT completed

Execution Summary
Artifacts Directory: /home/user/ReqReaper/artifacts/run_20260221_120000

Findings by Severity
Severity  Count
CRITICAL      1
HIGH          3
MEDIUM        5
LOW           9
```

## Legal

**AUTHORIZED USE ONLY.** This tool is intended for use by security professionals
during authorized security assessments. Unauthorized testing against systems
without explicit permission is illegal. The author assumes no liability for
misuse or any damages caused by this software.
