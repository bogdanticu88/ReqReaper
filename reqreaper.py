import argparse
import yaml
import os
import sys
import datetime
import sqlite3
import csv
import shutil
import uuid
import time
import logging
import html

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.logging import RichHandler
from jsonschema import validate, ValidationError

# Versioning
__version__ = "0.1.0"

# Import modules
from banner import banner
from modules.httpx_module import HttpxModule
from modules.nmap_module import NmapModule
from modules.tls_module import TLSModule
from modules.kiterunner_module import KiterunnerModule
from modules.ffuf_module import FfufModule
from modules.zap_module import ZapModule
from modules.nuclei_module import NucleiModule
from modules.sqlmap_module import SqlmapModule
from modules.openapi_module import OpenApiModule
from modules.stress_k6_module import StressK6Module
from modules.jwt_module import JwtModule

# Configuration Schema
CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "targets": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string"},
        },
        "allowed_hosts": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string"},
        },
        "output_directory": {"type": "string"},
        "openapi_url": {"type": "string"},
        "openapi_file": {"type": "string"},
        "safe_mode": {"type": "boolean"},
        "concurrency": {"type": "integer", "minimum": 1, "maximum": 50},
        "rate_limit_per_second": {"type": "integer", "minimum": 1, "maximum": 1000},
        "timeout": {"type": "integer", "minimum": 1, "maximum": 3600},
        "modules": {
            "type": "object",
            "properties": {
                "discovery": {"type": "object", "required": ["enabled"]},
                "vulnerability": {"type": "object", "required": ["enabled"]},
                "fuzzing": {"type": "object", "required": ["enabled"]},
                "injection": {"type": "object", "required": ["enabled"]},
                "stress": {"type": "object", "required": ["enabled"]},
            },
            "required": ["discovery", "vulnerability"],
            "additionalProperties": False,
        },
        "auth": {
            "type": "object",
            "properties": {
                "header_name": {"type": "string"},
                "header_value": {"type": "string"},
            },
        },
        "log_level": {
            "type": "string",
            "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        },
    },
    "required": ["targets", "allowed_hosts", "modules"],
}


class DataManager:
    """Manages SQLite database operations and CSV exports."""

    def __init__(self, db_path, run_id, output_dir):
        self.db_path = db_path
        self.run_id = run_id
        self.output_dir = output_dir
        self.normalized_dir = os.path.join(output_dir, "normalized")
        os.makedirs(self.normalized_dir, exist_ok=True)
        self.init_db()

    def init_db(self):
        """Initializes the SQLite database with the required schema."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Consistent Schema Definition
        c.execute("""CREATE TABLE IF NOT EXISTS targets 
               (id INTEGER PRIMARY KEY, run_id TEXT, url TEXT, host TEXT, 
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")

        c.execute("""CREATE TABLE IF NOT EXISTS endpoints 
               (id INTEGER PRIMARY KEY, run_id TEXT, url TEXT, method TEXT, 
                source_tool TEXT, status_code INTEGER, 
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")

        c.execute("""CREATE TABLE IF NOT EXISTS requests 
               (id INTEGER PRIMARY KEY, run_id TEXT, method TEXT, url TEXT, 
                status INTEGER, response_time REAL, 
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")

        c.execute("""CREATE TABLE IF NOT EXISTS findings 
               (id INTEGER PRIMARY KEY, run_id TEXT, tool TEXT, severity TEXT, 
                title TEXT, endpoint TEXT, evidence_path TEXT, confidence TEXT, 
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")

        c.execute("""CREATE TABLE IF NOT EXISTS tls_findings 
               (id INTEGER PRIMARY KEY, run_id TEXT, host TEXT, finding TEXT, 
                severity TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")

        c.execute("""CREATE TABLE IF NOT EXISTS load_results 
               (id INTEGER PRIMARY KEY, run_id TEXT, target TEXT, rps REAL, 
                p95_latency REAL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")

        conn.commit()
        conn.close()

    def add_data(self, table, data):
        """Inserts multiple rows of data into a specified table."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        for item in data:
            item["run_id"] = self.run_id
            keys = ", ".join(item.keys())
            placeholders = ", ".join(["?"] * len(item))
            query = f"INSERT INTO {table} ({keys}) VALUES ({placeholders})"
            c.execute(query, list(item.values()))

        conn.commit()
        conn.close()

    def export_all_to_csv(self):
        """Exports all database tables to individual CSV files."""
        tables = [
            "targets",
            "endpoints",
            "requests",
            "findings",
            "tls_findings",
            "load_results",
        ]
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        for table in tables:
            c.execute(f"SELECT * FROM {table} WHERE run_id = ?", (self.run_id,))
            rows = c.fetchall()
            if not rows:
                continue

            csv_path = os.path.join(self.normalized_dir, f"{table}.csv")
            with open(csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                for row in rows:
                    writer.writerow(dict(row))

        conn.close()


def setup_logger(console, args):
    """Configures the logging system with rich output."""
    logging.basicConfig(
        level="ERROR" if args.quiet else "INFO",
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, markup=True)],
    )
    return logging.getLogger("reqreaper")


def validate_config(config, logger):
    """Performs comprehensive validation of the configuration object."""
    # 1. Schema Validation
    try:
        validate(instance=config, schema=CONFIG_SCHEMA)
    except ValidationError as e:
        path = " -> ".join([str(p) for p in e.path])
        logger.error(f"[bold red][!] Configuration Error at {path}:[/] {e.message}")
        return False

    # 2. Host Validation
    allowed = set(config.get("allowed_hosts", []))
    for target in config.get("targets", []):
        try:
            host = target.split("//")[-1].split("/")[0].split(":")[0]
            if host not in allowed:
                logger.error(
                    f"[bold red][!] Allowlist Violation:[/] Target '{target}' "
                    f"(host: {host}) is not in allowed_hosts."
                )
                return False
        except Exception:
            logger.error(f"[bold red][!] Invalid Target Format:[/] '{target}'")
            return False

    # 3. Module Integrity
    valid_module_groups = {
        "discovery",
        "vulnerability",
        "fuzzing",
        "injection",
        "stress",
    }
    config_modules = set(config.get("modules", {}).keys())
    invalid_groups = config_modules - valid_module_groups
    if invalid_groups:
        logger.error(
            f"[bold red][!] Invalid Module Groups in config:[/] "
            f"{', '.join(invalid_groups)}"
        )
        return False

    return True


def select_modules(config, args):
    """Returns (planned, skipped) based on config and CLI flags.

    planned: list of module name strings
    skipped: list of (module name, reason) tuples
    """
    planned = []
    skipped = []

    if config["modules"]["discovery"]["enabled"]:
        planned.extend(["Discovery:HTTPX", "Discovery:Nmap"])
    else:
        skipped.append(("Discovery", "Disabled in config"))

    if config["modules"]["vulnerability"]["enabled"]:
        planned.extend(["Vulnerability:Nuclei", "Vulnerability:TLS", "Vulnerability:ZAP", "Vulnerability:JWT"])
    else:
        skipped.append(("Vulnerability", "Disabled in config"))

    if args.enable_fuzz or (args.full and not args.safe):
        planned.extend(["Fuzzing:Ffuf", "Fuzzing:Kiterunner"])
    else:
        skipped.append(("Fuzzing", "Flag not provided"))

    if args.enable_sqli or (args.full and not args.safe):
        planned.append("Injection:SQLMap")
    else:
        skipped.append(("Injection", "Flag not provided"))

    if args.enable_load:
        planned.append("Load:K6")
    else:
        skipped.append(("Load", "Flag not provided"))

    return planned, skipped


def preflight_tools_check(console, modules_config):
    """Checks for the presence of required external binaries."""
    table = Table(title="Preflight Tool Availability Check")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Path", style="dim")

    required_tools = set()
    for mod_name, mod_cfg in modules_config.items():
        if mod_cfg.get("enabled"):
            for tool in mod_cfg.get("tools", []):
                binary_name = tool
                if tool == "zap":
                    binary_name = "zap-cli"
                elif tool == "tls":
                    binary_name = "testssl.sh"
                elif tool == "kiterunner":
                    binary_name = "kr"
                required_tools.add(binary_name)

    all_ok = True
    for tool in sorted(list(required_tools)):
        path = shutil.which(tool)
        if path:
            table.add_row(tool, "[green]OK[/]", path)
        else:
            table.add_row(tool, "[red]MISSING[/]", "Not Found")
            all_ok = False

    console.print(table)
    return all_ok


def generate_report(output_dir, db_path, run_id):
    """Generates a static HTML report from the execution findings."""
    report_path = os.path.join(output_dir, "report", "report.html")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,))
    findings = c.fetchall()
    conn.close()

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ReqReaper Security Report</title>
        <style>
            body { font-family: sans-serif; background: #1a1a1a; color: #e0e0e0; }
            .container { width: 80%; margin: auto; padding: 20px; }
            h1 { color: #ff4444; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid #444; padding: 10px; text-align: left; }
            th { background: #333; }
            tr:nth-child(even) { background: #222; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>ReqReaper Security Assessment</h1>
            <p>Run ID: {run_id}</p>
            <p>Generated: {timestamp}</p>
            <h2>Findings Summary</h2>
            <table>
                <tr>
                    <th>Tool</th>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Endpoint</th>
                    <th>Details/Evidence</th>
                </tr>
                {rows}
            </table>
        </div>
    </body>
    </html>
    """

    rows_html = ""
    for f in findings:
        rows_html += (
            f"<tr><td>{html.escape(str(f['tool']))}</td>"
            f"<td>{html.escape(str(f['severity']))}</td>"
            f"<td>{html.escape(str(f['title']))}</td>"
            f"<td>{html.escape(str(f['endpoint']))}</td>"
            f"<td>{html.escape(str(f['evidence_path']))}</td></tr>"
        )

    final_html = html_template.format(
        run_id=run_id, timestamp=datetime.datetime.now(), rows=rows_html
    )

    with open(report_path, "w") as f:
        f.write(final_html)


def run_demo(console):
    """Simulates a realistic ReqReaper execution flow for demonstration purposes."""
    banner(console, __version__)

    console.print("[*] Loading configuration...")
    time.sleep(1)
    run_id = str(uuid.uuid4())
    console.print(f"[*] Initialization complete. Run ID: {run_id}")
    console.print(
        "[*] Target Scope: 2 hosts (https://api.example.com, https://example.com)"
    )
    time.sleep(1)

    # Tool Availability Table
    table = Table(title="Preflight Tool Availability Check")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Path", style="dim")
    table.add_row("httpx", "[green]OK[/]", "/usr/bin/httpx")
    table.add_row("nmap", "[green]OK[/]", "/usr/bin/nmap")
    table.add_row("nuclei", "[green]OK[/]", "/usr/bin/nuclei")
    table.add_row("zap-cli", "[red]MISSING[/]", "Not Found")
    table.add_row("sqlmap", "[green]OK[/]", "/usr/bin/sqlmap")
    console.print(table)
    time.sleep(1)

    # Execution Simulation
    demo_modules = [
        ("Discovery:HTTPX", "RUN", 12, "0.45s", "-"),
        ("Discovery:Nmap", "RUN", 4, "2.12s", "-"),
        ("Vulnerability:Nuclei", "RUN", 3, "1.89s", "-"),
        ("Vulnerability:ZAP", "SKIP", 0, "0s", "Tool 'zap-cli' not found"),
        ("Injection:SQLMap", "RUN", 1, "3.45s", "-"),
    ]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        for name, status, findings, duration, notes in demo_modules:
            if status == "SKIP":
                console.print(f"[*] Skipping {name}: {notes}")
                continue

            task_id = progress.add_task(
                description=f"[*] Executing {name}...", total=None
            )
            time.sleep(float(duration[:-1]))  # Simulate duration
            progress.update(task_id, description=f"[green][+] {name} completed[/]")

    # Artifact generation simulation
    console.print("[*] Synchronizing database to CSV...")
    time.sleep(1)
    console.print("[*] Generating HTML artifacts...")
    time.sleep(1)

    # Final Summary
    output_dir = os.path.join("artifacts", "run_demo")
    os.makedirs(os.path.join(output_dir, "normalized"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "report"), exist_ok=True)

    # Create dummy files
    for f in ["normalized/findings.csv", "report/report.html", "reqreaper.db"]:
        with open(os.path.join(output_dir, f), "w") as fd:
            fd.write("Demo Artifact")

    console.print("\n[bold]Execution Summary[/]")
    console.print(f"Artifacts Directory: {os.path.abspath(output_dir)}")

    sev_table = Table(title="Findings by Severity", box=None)
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count", justify="right")
    sev_table.add_row("[red]HIGH[/]", "2")
    sev_table.add_row("[yellow]MEDIUM[/]", "5")
    sev_table.add_row("[blue]LOW[/]", "13")
    console.print(sev_table)

    res_table = Table(title="Module Execution Detail", box=None)
    res_table.add_column("Module", style="cyan")
    res_table.add_column("Status")
    res_table.add_column("Findings", justify="right")
    res_table.add_column("Duration", justify="right")
    res_table.add_column("Notes", style="dim")

    for name, status, findings, duration, notes in demo_modules:
        status_color = "green" if status == "RUN" else "yellow"
        res_table.add_row(
            name, f"[{status_color}]{status}[/]", str(findings), duration, notes
        )

    console.print(res_table)
    console.print(f"\n[bold green][+] ReqReaper session finished.[/]\n")


def main():
    parser = argparse.ArgumentParser(description="ReqReaper API Security Framework")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    parser.add_argument(
        "--version", action="version", version=f"ReqReaper {__version__}"
    )
    parser.add_argument("--safe", action="store_true", help="Enable safe mode")
    parser.add_argument("--full", action="store_true", help="Enable full scan")
    parser.add_argument(
        "--enable-load", action="store_true", help="Enable load testing"
    )
    parser.add_argument("--enable-fuzz", action="store_true", help="Enable fuzzing")
    parser.add_argument(
        "--enable-sqli", action="store_true", help="Enable SQL injection"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Safe preflight: validate config"
    )
    parser.add_argument(
        "--demo", action="store_true", help="Run in demo mode (simulated execution)"
    )

    args = parser.parse_args()

    console = Console(no_color=args.no_color, quiet=args.quiet)
    logger = setup_logger(console, args)

    if args.demo:
        run_demo(console)
        sys.exit(0)

    if not args.config:
        parser.print_help()
        sys.exit(1)

    banner(console, __version__)

    # 1. Initialization
    if not os.path.exists(args.config):
        logger.error(f"Configuration file '{args.config}' not found.")
        sys.exit(1)

    try:
        with open(args.config, "r") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error parsing YAML: {e}")
        sys.exit(1)

    # 2. Validation
    if not validate_config(config, logger):
        sys.exit(2)

    tools_ok = preflight_tools_check(console, config["modules"])

    # 3. Dry-Run Logic
    planned_modules, skipped_info = select_modules(config, args)

    if args.dry_run:
        plan_table = Table(title="Planned Module Execution (Dry-Run)", box=None)
        plan_table.add_column("Module", style="cyan")
        plan_table.add_column("Action")
        plan_table.add_column("Reason", style="dim")

        for mod in planned_modules:
            plan_table.add_row(mod, "[green]WILL RUN[/]", "-")
        for mod, reason in skipped_info:
            plan_table.add_row(mod, "[yellow]WILL SKIP[/]", reason)

        console.print(plan_table)
        if tools_ok:
            console.print("\n[bold green][+] Preflight successful![/]")
            sys.exit(0)
        else:
            console.print("\n[bold yellow][!] Preflight warning: Missing tools.[/]")
            sys.exit(4)

    if not tools_ok:
        if not args.quiet:
            logger.warning("[*] Some tools are missing. Proceeding with available.")

    # 4. Execution Setup
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = str(uuid.uuid4())
    output_dir = os.path.join(
        config.get("output_directory", "artifacts"), f"run_{timestamp}"
    )
    os.makedirs(output_dir, exist_ok=True)

    db_path = os.path.join(output_dir, "reqreaper.db")
    dm = DataManager(db_path, run_id, output_dir)

    target_data = []
    for t in config["targets"]:
        host = (
            t.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        )
        target_data.append({"url": t, "host": host})
    dm.add_data("targets", target_data)

    valid_targets = config["targets"]
    console.print(f"[bold green][*] Initialization complete. Run ID: {run_id}[/]")
    console.print(f"[*] Target Scope: {len(valid_targets)} hosts")

    # 5. Module Orchestration
    if config.get("openapi_url") or config.get("openapi_file"):
        console.print("[*] Running OpenAPI Analysis...")
        openapi_mod = OpenApiModule(config, output_dir, db_path)
        openapi_mod.dm = dm
        try:
            openapi_mod.run(
                url=config.get("openapi_url"), file_path=config.get("openapi_file")
            )
        except Exception as e:
            logger.error(f"OpenAPI Analysis failed: {e}")

    mod_instances = {
        "Discovery:HTTPX": HttpxModule(config, output_dir, db_path),
        "Discovery:Nmap": NmapModule(config, output_dir, db_path),
        "Vulnerability:Nuclei": NucleiModule(config, output_dir, db_path),
        "Vulnerability:TLS": TLSModule(config, output_dir, db_path),
        "Vulnerability:ZAP": ZapModule(config, output_dir, db_path),
        "Vulnerability:JWT": JwtModule(config, output_dir, db_path),
        "Fuzzing:Ffuf": FfufModule(config, output_dir, db_path),
        "Fuzzing:Kiterunner": KiterunnerModule(config, output_dir, db_path),
        "Injection:SQLMap": SqlmapModule(config, output_dir, db_path),
        "Load:K6": StressK6Module(config, output_dir, db_path),
    }

    active_module_names, _ = select_modules(config, args)
    modules_to_run = [
        (name, mod_instances[name]) for name in active_module_names
    ]

    for _, mod in mod_instances.items():
        mod.dm = dm

    execution_results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        disable=args.quiet,
    ) as progress:
        for name, module in modules_to_run:
            if not module.is_available():
                reason = f"Tool '{module.required_tool}' not found"
                if not args.quiet:
                    logger.warning(f"[*] Skipping {name}: {reason}")
                execution_results.append(
                    {
                        "name": name,
                        "status": "SKIP",
                        "findings": 0,
                        "duration": "0s",
                        "notes": reason,
                    }
                )
                continue

            task_id = progress.add_task(
                description=f"[*] Executing {name}...", total=None
            )
            start_time = time.time()
            try:
                module.run(valid_targets)
                duration = time.time() - start_time
                progress.update(task_id, description=f"[green][+] {name} completed[/]")
                execution_results.append(
                    {
                        "name": name,
                        "status": "RUN",
                        "findings": module.findings_count,
                        "duration": f"{duration:.2f}s",
                        "notes": "-",
                    }
                )
            except Exception as e:
                duration = time.time() - start_time
                progress.update(task_id, description=f"[red][!] {name} failed: {e}[/]")
                execution_results.append(
                    {
                        "name": name,
                        "status": "FAIL",
                        "findings": 0,
                        "duration": f"{duration:.2f}s",
                        "notes": str(e),
                    }
                )

    # 6. Finalization
    if not args.quiet:
        console.print("[*] Synchronizing database to CSV...")
    dm.export_all_to_csv()

    if not args.quiet:
        console.print("[*] Generating HTML artifacts...")
    generate_report(output_dir, db_path, run_id)

    # 7. Final Summary
    console.print("\n[bold]Execution Summary[/]")
    console.print(f"Artifacts Directory: {os.path.abspath(output_dir)}")

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        "SELECT severity, COUNT(*) FROM findings WHERE run_id = ? GROUP BY severity",
        (run_id,),
    )
    sev_counts = c.fetchall()
    conn.close()

    if sev_counts:
        sev_table = Table(title="Findings by Severity", box=None)
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")
        for sev, count in sev_counts:
            color = (
                "red"
                if sev.lower() in ["high", "critical"]
                else "yellow" if sev.lower() == "medium" else "blue"
            )
            sev_table.add_row(f"[{color}]{sev.upper()}[/]", str(count))
        console.print(sev_table)

    res_table = Table(title="Module Execution Detail", box=None)
    res_table.add_column("Module", style="cyan")
    res_table.add_column("Status")
    res_table.add_column("Findings", justify="right")
    res_table.add_column("Duration", justify="right")
    res_table.add_column("Notes", style="dim")

    for res in execution_results:
        status_color = (
            "green"
            if res["status"] == "RUN"
            else "yellow" if res["status"] == "SKIP" else "red"
        )
        res_table.add_row(
            res["name"],
            f"[{status_color}]{res['status']}[/]",
            str(res["findings"]),
            res["duration"],
            res["notes"],
        )

    console.print(res_table)
    console.print("\n[bold green][+] ReqReaper session finished.[/]\n")


if __name__ == "__main__":
    main()
