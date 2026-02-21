from .base import BaseModule
import os
import json
import logging

logger = logging.getLogger("reqreaper")

# testssl.sh severity labels to normalized values
SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "OK": "info",
    "NOT ok": "medium",
    "WARN": "low",
}


class TLSModule(BaseModule):
    def __init__(self, config, output_dir, db_path):
        super().__init__(config, output_dir, db_path)
        self.required_tool = "testssl.sh"

    def run(self, targets):
        scan_outputs = []
        for target in targets:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            output_file = os.path.join(self.raw_output_dir, f"tls_{domain}.json")

            cmd = ["testssl.sh", "--jsonfile", output_file, "--quiet", domain]
            self.run_command(cmd, "testssl.sh")
            scan_outputs.append({"domain": domain, "output_file": output_file})

        self.parse_results(scan_outputs)
        return scan_outputs

    def parse_results(self, data):
        normalized = []
        for item in data:
            output_file = item["output_file"]
            domain = item["domain"]

            if not os.path.exists(output_file):
                logger.warning(f"[testssl.sh] No output file found for {domain}")
                continue

            try:
                with open(output_file, "r") as f:
                    findings = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"[testssl.sh] Failed to parse output for {domain}: {e}")
                continue

            # testssl.sh JSON is a list of finding objects
            if not isinstance(findings, list):
                findings = findings.get("scanResult", [{}])[0].get("findings", [])

            for entry in findings:
                severity_raw = entry.get("severity", "INFO")
                severity = SEVERITY_MAP.get(severity_raw.upper(), "info")

                # Skip purely informational OK results
                if severity_raw.upper() in ("OK",):
                    continue

                finding_text = entry.get("finding", "")
                finding_id = entry.get("id", "unknown")

                normalized.append(
                    {
                        "host": domain,
                        "finding": f"[{finding_id}] {finding_text}",
                        "severity": severity,
                    }
                )

        self.findings_count = len(normalized)
        if self.dm and normalized:
            self.dm.add_data("tls_findings", normalized)
