from .base import BaseModule
import os
import csv
import json

class StressK6Module(BaseModule):
    def run(self, targets):
        if not self.check_tool("k6"):
            return "k6 not found"

        results = []
        for target in targets:
            output_file = os.path.join(self.raw_output_dir, f"k6_{target.replace('/', '_')}.json")
            
            # Simple k6 script generation
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
        normalized_file = os.path.join(self.normalized_output_dir, "load_test_results.csv")
        with open(normalized_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Target", "Output File"])
            for item in data:
                writer.writerow([item['target'], item['output']])
