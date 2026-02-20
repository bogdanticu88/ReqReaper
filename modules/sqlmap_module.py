from .base import BaseModule
import os
import csv
import json

class SqlmapModule(BaseModule):
    def run(self, targets):
        if not self.check_tool("sqlmap"):
            return "sqlmap not found"

        results = []
        for target in targets:
            # Dangerous - verify config allows
            if not self.config.get("enable_sqli", False):
                return "SQLi testing disabled"

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
        normalized_file = os.path.join(self.normalized_output_dir, "sqlmap_runs.csv")
        with open(normalized_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for item in data:
                writer.writerow([item.get('target'), item.get('output_dir')])
