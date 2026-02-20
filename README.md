# ReqReaper

**API Security Automation Framework**

ReqReaper is a professional-grade red team orchestration tool for API security testing. It automates discovery, enumeration, vulnerability scanning, and reporting for authorized security assessments.

Built by Bogdan Ticu.

## Features

- **Automated Discovery:** Integrates `httpx`, `nmap`, `katana`, `gau`, `waybackurls`.
- **Vulnerability Scanning:** Orchestrates `nuclei`, `ZAP`, `sqlmap`, `kiterunner`.
- **Fuzzing & Stress Testing:** Supports `ffuf`, `wfuzz`, `k6`, `vegeta`.
- **Modular Architecture:** Plugin-based system for easy extension.
- **Reporting:** Generates professional HTML reports and normalized CSV exports.
- **Safety Controls:** Strict allowlist enforcement and safe-mode defaults.

## Architecture

ReqReaper uses a modular Python architecture with a SQLite backend.
1.  **Orchestrator:** Manages execution flow and concurrency.
2.  **Modules:** Wrappers for external security tools.
3.  **Database:** Stores all findings, requests, and endpoints.
4.  **Reporter:** Generates actionable artifacts.

## Installation

### Prerequisites

- Python 3.11+
- Kali Linux (recommended) or Linux environment with security tools installed.

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Install External Tools (Kali Linux)

Ensure the following tools are in your PATH:
`httpx`, `nmap`, `nuclei`, `ffuf`, `kiterunner`, `sqlmap`, `zap-cli` (or `zaproxy`), `k6`.

## Usage

1.  **Configure:** Copy `config/example.yaml` to `config.yaml` and edit targets.
    *CRITICAL: Ensure `allowed_hosts` includes all your targets.*

2.  **Run:**

```bash
python3 reqreaper.py --config config.yaml
```

### CLI Options

- `--config`: Path to configuration file.
- `--safe`: Enable safe mode (disables dangerous modules).
- `--full`: Run all enabled modules including extensive scans.
- `--enable-load`: Enable load/stress testing modules.
- `--enable-fuzz`: Enable fuzzing modules.
- `--enable-sqli`: Enable SQL injection modules.
- `--quiet`: Minimal output.
- `--no-color`: Disable colored output.

## Output

Artifacts are stored in `artifacts/run_<timestamp>/`.
- `report/`: HTML report.
- `normalized/`: CSV exports (findings, endpoints).
- `raw/`: Raw tool outputs.
- `reqreaper.db`: SQLite database.

## Legal Disclaimer

**AUTHORIZED USE ONLY.**

This tool is designed for security professionals and researchers to test systems they own or have explicit permission to test. Unauthorized use against systems is illegal. The author assumes no liability for misuse.
