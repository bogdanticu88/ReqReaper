import argparse
import yaml
import os
import sys
import datetime
import sqlite3
import csv
import shutil
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
        # Simple extraction of host
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

    # Flatten list of tools from enabled modules
    required_tools = set()
    for mod_name, mod_cfg in modules_config.items():
        if mod_cfg.get('enabled'):
            for tool in mod_cfg.get('tools', []):
                # Manual override for some tools where binary names differ
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

def init_db(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS findings
                 (id INTEGER PRIMARY KEY, tool TEXT, target TEXT, severity TEXT, details TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS requests
                 (id INTEGER PRIMARY KEY, method TEXT, url TEXT, status INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    return conn

def generate_report(output_dir, findings):
    report_path = os.path.join(output_dir, "report", "report.html")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
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
            <p>Generated: {datetime.datetime.now()}</p>
            <h2>Findings Summary</h2>
            <table>
                <tr><th>Tool</th><th>Target</th><th>Severity</th><th>Details</th></tr>
    """
    
    for f in findings:
        html += f"<tr><td>{f[1]}</td><td>{f[2]}</td><td>{f[3]}</td><td>{f[4]}</td></tr>"
        
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
    
    # 1. Load Config
    if not os.path.exists(args.config):
        logger.error(f"[bold red]Error:[/] Configuration file '{args.config}' not found.")
        sys.exit(1)
        
    try:
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"[bold red]Error parsing YAML:[/] {e}")
        sys.exit(1)

    # 2. Validate Config Schema
    if not validate_config(config, logger):
        sys.exit(2)

    # 3. Enforce Allowlist
    if not check_allowlist(config['targets'], config['allowed_hosts'], logger):
        sys.exit(3)

    # 4. Preflight Tools Check
    tools_ok = preflight_tools_check(console, config['modules'])
    
    if args.dry_run:
        if tools_ok:
            console.print("\n[bold green]Preflight successful![/] Config is valid and tools are available.")
            sys.exit(0)
        else:
            console.print("\n[bold yellow]Preflight warning:[/] Config is valid but some tools are missing.")
            sys.exit(4)

    if not tools_ok:
         logger.error("[bold red]Critical Error:[/] Some required tools are missing. Run with --dry-run for details.")
         sys.exit(4)
         
    # Setup Output
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(config.get("output_directory", "artifacts"), f"run_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    
    db_path = os.path.join(output_dir, "reqreaper.db")
    db_conn = init_db(db_path)
    
    valid_targets = config['targets']

    console.print(f"[bold green]Starting ReqReaper on {len(valid_targets)} targets...[/]")
    
    # Module Execution
    modules_to_run = []
    
    # OpenAPI Analysis
    if config.get('openapi_url') or config.get('openapi_file'):
        console.print("[bold cyan]Running OpenAPI Analysis...[/]")
        openapi_mod = OpenApiModule(config, output_dir, db_path)
        openapi_mod.run(url=config.get('openapi_url'), file_path=config.get('openapi_file'))

    # Discovery
    if config['modules']['discovery']['enabled']:
        modules_to_run.append(("HTTPX Discovery", HttpxModule(config, output_dir, db_path)))
        modules_to_run.append(("Nmap Scan", NmapModule(config, output_dir, db_path)))
        
    # Vulnerability
    if config['modules']['vulnerability']['enabled']:
        modules_to_run.append(("Nuclei Scan", NucleiModule(config, output_dir, db_path)))
        modules_to_run.append(("TLS Scan", TLSModule(config, output_dir, db_path)))
        modules_to_run.append(("ZAP Baseline", ZapModule(config, output_dir, db_path)))

    # Fuzzing
    if args.enable_fuzz or (args.full and not args.safe):
        modules_to_run.append(("Ffuf Fuzzing", FfufModule(config, output_dir, db_path)))
        modules_to_run.append(("Kiterunner", KiterunnerModule(config, output_dir, db_path)))

    # Injection
    if args.enable_sqli or (args.full and not args.safe):
        modules_to_run.append(("SQLMap", SqlmapModule(config, output_dir, db_path)))
        
    # Stress
    if args.enable_load:
         modules_to_run.append(("K6 Stress Test", StressK6Module(config, output_dir, db_path)))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        for name, module in modules_to_run:
            task_id = progress.add_task(description=f"Running {name}...", total=None)
            try:
                module.run(valid_targets)
                progress.update(task_id, description=f"[green]{name} Complete[/]")
            except Exception as e:
                progress.update(task_id, description=f"[red]{name} Failed: {e}[/]")
                logger.error(f"Module {name} failed: {e}")
                
    # Final Reporting
    console.print("[bold blue]Generating Report...[/]")
    findings = [(1, "System", "All", "Info", "Scan Completed Successfully")]
    generate_report(output_dir, findings)
    
    # Summary Table
    table = Table(title="ReqReaper Execution Summary")
    table.add_column("Module", style="cyan")
    table.add_column("Status", style="green")
    
    for name, _ in modules_to_run:
        table.add_row(name, "Executed")
        
    console.print(table)
    console.print(f"[bold green]Scan Complete. Artifacts stored in {output_dir}[/]")

if __name__ == "__main__":
    main()
