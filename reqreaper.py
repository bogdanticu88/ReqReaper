import argparse
import yaml
import os
import sys
import datetime
import sqlite3
import csv
import shutil
import uuid
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.logging import RichHandler
from jsonschema import validate, ValidationError
import logging

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

# Configuration Schema
CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "targets": {"type": "array", "items": {"type": "string"}},
        "allowed_hosts": {"type": "array", "items": {"type": "string"}},
        "output_directory": {"type": "string"},
        "openapi_url": {"type": "string"},
        "openapi_file": {"type": "string"},
        "safe_mode": {"type": "boolean"},
        "concurrency": {"type": "integer", "minimum": 1},
        "rate_limit_per_second": {"type": "integer", "minimum": 1},
        "timeout": {"type": "integer", "minimum": 1},
        "modules": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean"},
                    "tools": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["enabled"]
            }
        },
        "auth": {
            "type": "object",
            "properties": {
                "header_name": {"type": "string"},
                "header_value": {"type": "string"}
            }
        },
        "log_level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]}
    },
    "required": ["targets", "allowed_hosts", "modules"]
}

class DataManager:
    def __init__(self, db_path, run_id, output_dir):
        self.db_path = db_path
        self.run_id = run_id
        self.output_dir = output_dir
        self.normalized_dir = os.path.join(output_dir, "normalized")
        os.makedirs(self.normalized_dir, exist_ok=True)
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Consistent Schema
        c.execute('''CREATE TABLE IF NOT EXISTS targets 
                     (id INTEGER PRIMARY KEY, run_id TEXT, url TEXT, host TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS endpoints 
                     (id INTEGER PRIMARY KEY, run_id TEXT, url TEXT, method TEXT, source_tool TEXT, status_code INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS requests 
                     (id INTEGER PRIMARY KEY, run_id TEXT, method TEXT, url TEXT, status INTEGER, response_time REAL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS findings 
                     (id INTEGER PRIMARY KEY, run_id TEXT, tool TEXT, severity TEXT, title TEXT, endpoint TEXT, evidence_path TEXT, confidence TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS tls_findings 
                     (id INTEGER PRIMARY KEY, run_id TEXT, host TEXT, finding TEXT, severity TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS load_results 
                     (id INTEGER PRIMARY KEY, run_id TEXT, target TEXT, rps REAL, p95_latency REAL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        conn.commit()
        conn.close()

    def add_data(self, table, data):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Ensure run_id is in data
        for item in data:
            item['run_id'] = self.run_id
            keys = ', '.join(item.keys())
            placeholders = ', '.join(['?'] * len(item))
            c.execute(f"INSERT INTO {table} ({keys}) VALUES ({placeholders})", list(item.values()))
            
        conn.commit()
        conn.close()

    def export_all_to_csv(self):
        tables = ["targets", "endpoints", "requests", "findings", "tls_findings", "load_results"]
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        for table in tables:
            c.execute(f"SELECT * FROM {table} WHERE run_id = ?", (self.run_id,))
            rows = c.fetchall()
            if not rows:
                continue
                
            csv_path = os.path.join(self.normalized_dir, f"{table}.csv")
            with open(csv_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                for row in rows:
                    writer.writerow(dict(row))
                    
        conn.close()

def setup_logger(console, args):
    logging.basicConfig(
        level="ERROR" if args.quiet else "INFO",
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, markup=True)]
    )
    return logging.getLogger("reqreaper")

def validate_config(config, logger):
    try:
        validate(instance=config, schema=CONFIG_SCHEMA)
        return True
    except ValidationError as e:
        logger.error(f"[bold red]Configuration Validation Error:[/] {e.message}")
        return False

def check_allowlist(targets, allowed_hosts, logger):
    invalid_targets = []
    for t in targets:
        host = t.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if host not in allowed_hosts:
            invalid_targets.append(t)
    
    if invalid_targets:
        for t in invalid_targets:
            logger.error(f"[bold red]Allowlist Violation:[/] Target '{t}' host not in allowed_hosts.")
        return False
    return True

def preflight_tools_check(console, modules_config):
    table = Table(title="Preflight Tool Availability Check")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Path", style="dim")

    required_tools = set()
    for mod_name, mod_cfg in modules_config.items():
        if mod_cfg.get('enabled'):
            for tool in mod_cfg.get('tools', []):
                binary_name = tool
                if tool == "zap": binary_name = "zap-cli"
                elif tool == "tls": binary_name = "testssl.sh"
                elif tool == "kiterunner": binary_name = "kr"
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
    report_path = os.path.join(output_dir, "report", "report.html")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,))
    findings = c.fetchall()
    conn.close()

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ReqReaper Security Report</title>
        <style>
            body {{ font-family: sans-serif; background: #1a1a1a; color: #e0e0e0; }}
            .container {{ width: 80%; margin: auto; padding: 20px; }}
            h1 {{ color: #ff4444; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #444; padding: 10px; text-align: left; }}
            th {{ background: #333; }}
            tr:nth-child(even) {{ background: #222; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>ReqReaper Security Assessment</h1>
            <p>Run ID: {run_id}</p>
            <p>Generated: {datetime.datetime.now()}</p>
            <h2>Findings Summary</h2>
            <table>
                <tr><th>Tool</th><th>Severity</th><th>Title</th><th>Endpoint</th><th>Details/Evidence</th></tr>
    """
    
    for f in findings:
        html += f"<tr><td>{f['tool']}</td><td>{f['severity']}</td><td>{f['title']}</td><td>{f['endpoint']}</td><td>{f['evidence_path']}</td></tr>"
        
    html += """
            </table>
        </div>
    </body>
    </html>
    """
    
    with open(report_path, 'w') as f:
        f.write(html)

def main():
    parser = argparse.ArgumentParser(description="ReqReaper API Security Framework")
    parser.add_argument("--config", help="Path to configuration file", required=True)
    parser.add_argument("--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode")
    parser.add_argument("--full", action="store_true", help="Enable full scan")
    parser.add_argument("--enable-load", action="store_true", help="Enable load testing")
    parser.add_argument("--enable-fuzz", action="store_true", help="Enable fuzzing")
    parser.add_argument("--enable-sqli", action="store_true", help="Enable SQL injection")
    parser.add_argument("--dry-run", action="store_true", help="Safe preflight: validate config and check tools")
    
    args = parser.parse_args()
    
    console = Console(no_color=args.no_color, quiet=args.quiet)
    logger = setup_logger(console, args)
    
    banner(console)
    
    if not os.path.exists(args.config):
        logger.error(f"Configuration file '{args.config}' not found.")
        sys.exit(1)
        
    try:
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error parsing YAML: {e}")
        sys.exit(1)

    if not validate_config(config, logger):
        sys.exit(2)

    if not check_allowlist(config['targets'], config['allowed_hosts'], logger):
        sys.exit(3)

    tools_ok = preflight_tools_check(console, config['modules'])
    
    if args.dry_run:
        if tools_ok:
            console.print("\n[bold green]Preflight successful![/]")
            sys.exit(0)
        else:
            console.print("\n[bold yellow]Preflight warning:[/] Missing tools.")
            sys.exit(4)

    if not tools_ok:
         logger.error("Critical Error: Tools missing.")
         sys.exit(4)
         
    # Setup Output
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = str(uuid.uuid4())
    output_dir = os.path.join(config.get("output_directory", "artifacts"), f"run_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    
    db_path = os.path.join(output_dir, "reqreaper.db")
    dm = DataManager(db_path, run_id, output_dir)
    
    # Store targets
    target_data = []
    for t in config['targets']:
        host = t.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        target_data.append({"url": t, "host": host})
    dm.add_data("targets", target_data)

    valid_targets = config['targets']
    console.print(f"[bold green][*] Initialization complete. Run ID: {run_id}[/]")
    console.print(f"[*] Target Scope: {len(valid_targets)} hosts")
    
    # Module Execution
    modules_to_run = []
    skipped_modules = []
    
    # OpenAPI Analysis
    if config.get('openapi_url') or config.get('openapi_file'):
        console.print("[*] Running OpenAPI Analysis...")
        openapi_mod = OpenApiModule(config, output_dir, db_path)
        openapi_mod.dm = dm
        try:
            openapi_mod.run(url=config.get('openapi_url'), file_path=config.get('openapi_file'))
        except Exception as e:
            logger.error(f"OpenAPI Analysis failed: {e}")

    # Instantiate modules
    mod_instances = {
        "Discovery:HTTPX": HttpxModule(config, output_dir, db_path),
        "Discovery:Nmap": NmapModule(config, output_dir, db_path),
        "Vulnerability:Nuclei": NucleiModule(config, output_dir, db_path),
        "Vulnerability:TLS": TLSModule(config, output_dir, db_path),
        "Vulnerability:ZAP": ZapModule(config, output_dir, db_path),
        "Fuzzing:Ffuf": FfufModule(config, output_dir, db_path),
        "Fuzzing:Kiterunner": KiterunnerModule(config, output_dir, db_path),
        "Injection:SQLMap": SqlmapModule(config, output_dir, db_path),
        "Load:K6": StressK6Module(config, output_dir, db_path)
    }

    for name, mod in mod_instances.items():
        mod.dm = dm

    # Selection Logic
    if config['modules']['discovery']['enabled']:
        modules_to_run.append(("Discovery:HTTPX", mod_instances["Discovery:HTTPX"]))
        modules_to_run.append(("Discovery:Nmap", mod_instances["Discovery:Nmap"]))
    else:
        skipped_modules.append(("Discovery", "Disabled in config"))
        
    if config['modules']['vulnerability']['enabled']:
        modules_to_run.append(("Vulnerability:Nuclei", mod_instances["Vulnerability:Nuclei"]))
        modules_to_run.append(("Vulnerability:TLS", mod_instances["Vulnerability:TLS"]))
        modules_to_run.append(("Vulnerability:ZAP", mod_instances["Vulnerability:ZAP"]))
    else:
        skipped_modules.append(("Vulnerability", "Disabled in config"))

    if args.enable_fuzz:
        modules_to_run.append(("Fuzzing:Ffuf", mod_instances["Fuzzing:Ffuf"]))
        modules_to_run.append(("Fuzzing:Kiterunner", mod_instances["Fuzzing:Kiterunner"]))
    elif args.full and not args.safe:
        modules_to_run.append(("Fuzzing:Ffuf", mod_instances["Fuzzing:Ffuf"]))
        modules_to_run.append(("Fuzzing:Kiterunner", mod_instances["Fuzzing:Kiterunner"]))
    else:
        skipped_modules.append(("Fuzzing", "Flag not provided"))

    if args.enable_sqli or (args.full and not args.safe):
        modules_to_run.append(("Injection:SQLMap", mod_instances["Injection:SQLMap"]))
    else:
        skipped_modules.append(("Injection", "Flag not provided"))
        
    if args.enable_load:
         modules_to_run.append(("Load:K6", mod_instances["Load:K6"]))
    else:
        skipped_modules.append(("Load", "Flag not provided"))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        disable=args.quiet
    ) as progress:
        for name, module in modules_to_run:
            task_id = progress.add_task(description=f"[*] Executing {name}...", total=None)
            try:
                module.run(valid_targets)
                progress.update(task_id, description=f"[green][+] {name} completed[/]")
            except Exception as e:
                progress.update(task_id, description=f"[red][!] {name} failed: {e}[/]")
                
    # Final CSV Export
    if not args.quiet: console.print("[*] Synchronizing database to CSV...")
    dm.export_all_to_csv()
    
    # Final Reporting
    if not args.quiet: console.print("[*] Generating HTML artifacts...")
    generate_report(output_dir, db_path, run_id)
    
    # Execution Summary
    console.print("\n[bold]Execution Summary[/]")
    console.print(f"Artifacts Directory: {os.path.abspath(output_dir)}")
    
    # Severity Counts
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT severity, COUNT(*) FROM findings WHERE run_id = ? GROUP BY severity", (run_id,))
    sev_counts = c.fetchall()
    conn.close()

    if sev_counts:
        sev_table = Table(title="Findings by Severity", box=None)
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")
        for sev, count in sev_counts:
            color = "red" if sev.lower() in ["high", "critical"] else "yellow" if sev.lower() == "medium" else "blue"
            sev_table.add_row(f"[{color}]{sev.upper()}[/]", str(count))
        console.print(sev_table)
    else:
        console.print("[*] No security findings recorded.")

    # Module Status Table
    status_table = Table(title="Module Status", box=None)
    status_table.add_column("Module", style="cyan")
    status_table.add_column("Status")
    status_table.add_column("Reason", style="dim")

    for name, _ in modules_to_run:
        status_table.add_row(name, "[green]RUN[/]", "-")
    for name, reason in skipped_modules:
        status_table.add_row(name, "[yellow]SKIP[/]", reason)
        
    console.print(status_table)
    console.print(f"\n[bold green][+] ReqReaper session finished.[/]\n")

if __name__ == "__main__":
    main()
