from .base import BaseModule
import os
import csv
import json

class SqlmapModule(BaseModule):
    def __init__(self, config, output_dir, db_path):
        super().__init__(config, output_dir, db_path)
        self.required_tool = "sqlmap"

    def run(self, targets):
        if not self.config.get("enable_sqli", False):
            return "SQLi testing disabled"

        results = []
        for target in targets:
            output_dir = os.path.join(self.raw_output_dir, f"sqlmap_{target.replace('/', '_')}")
            os.makedirs(output_dir, exist_ok=True)
            
            cmd = [
                "sqlmap",
                "-u", target,
                "--batch",
                "--output-dir", output_dir
            ]
            self.run_command(cmd, "sqlmap")
            results.append({"target": target, "output_dir": output_dir})

        self.parse_results(results)
        return results

    def parse_results(self, data):
        self.findings_count = len(data)
        normalized = []
        for item in data:
            normalized.append({
                "tool": "sqlmap",
                "severity": "high",
                "title": "SQL Injection Analysis",
                "endpoint": item['target'],
                "evidence_path": item['output_dir'],
                "confidence": "high"
            })
        if self.dm:
            self.dm.add_data("findings", normalized)
