from .base import BaseModule
import os
import csv
import shutil

class ZapModule(BaseModule):
    def __init__(self, config, output_dir, db_path):
        super().__init__(config, output_dir, db_path)
        self.required_tool = "zap-cli"

    def run(self, targets):
        results = []
        for target in targets:
            report_file = os.path.join(self.raw_output_dir, f"zap_{target.replace('/', '_')}.html")
            cmd = [
                "zap-cli",
                "quick-scan",
                "--spider",
                "--recursive",
                "--scanners", "all",
                target
            ]
            self.run_command(cmd, "zap-cli")
            
            report_cmd = [
                "zap-cli",
                "report",
                "-o", report_file,
                "-f", "html"
            ]
            self.run_command(report_cmd, "zap-cli")
            results.append({"target": target, "report": report_file})

        self.parse_results(results)
        return results

    def parse_results(self, data):
        self.findings_count = len(data)
        normalized = []
        for item in data:
            normalized.append({
                "tool": "zap",
                "severity": "info",
                "title": "ZAP Baseline Scan",
                "endpoint": item['target'],
                "evidence_path": item['report'],
                "confidence": "medium"
            })
        if self.dm:
            self.dm.add_data("findings", normalized)
