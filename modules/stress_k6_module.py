from .base import BaseModule
import os
import csv
import json

class StressK6Module(BaseModule):
    def __init__(self, config, output_dir, db_path):
        super().__init__(config, output_dir, db_path)
        self.required_tool = "k6"

    def run(self, targets):
        results = []
        for target in targets:
            output_file = os.path.join(self.raw_output_dir, f"k6_{target.replace('/', '_')}.json")
            script_content = f"""
import http from 'k6/http';
import {{ sleep }} from 'k6';

export default function () {{
  http.get('{target}');
  sleep(1);
}}
"""
            script_path = os.path.join(self.output_dir, f"load_test_{target.replace('/', '_')}.js")
            with open(script_path, 'w') as f:
                f.write(script_content)

            cmd = [
                "k6",
                "run",
                "--out", f"json={output_file}",
                script_path
            ]
            self.run_command(cmd, "k6")
            results.append({"target": target, "output": output_file})

        self.parse_results(results)
        return results

    def parse_results(self, data):
        self.findings_count = len(data)
        normalized = []
        for item in data:
            normalized.append({
                "target": item['target'],
                "rps": 0,
                "p95_latency": 0
            })
        if self.dm:
            self.dm.add_data("load_results", normalized)
