from .base import BaseModule
import os
import csv
import json

class HttpxModule(BaseModule):
    def run(self, targets):
        if not self.check_tool("httpx"):
            return "Httpx not found"

        results = []
        for target in targets:
            output_file = os.path.join(self.raw_output_dir, f"httpx_{target.replace('/', '_')}.json")
            cmd = [
                "httpx",
                "-u", target,
                "-status-code",
                "-tech-detect",
                "-json",
                "-o", output_file
            ]
            self.run_command(cmd, "httpx")
            
            if os.path.exists(output_file):
                data = self.load_raw_results(output_file)
                results.extend(data)
        
        self.parse_results(results)
        return results

    def load_raw_results(self, filepath):
        results = []
        with open(filepath, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    results.append(data)
                except:
                    pass
        return results

    def normalize_data(self, data):
        normalized = []
        for item in data:
            normalized.append([
                item.get('url'),
                item.get('status_code'),
                ",".join(item.get('tech', []))
            ])
        return normalized

    def parse_results(self, data):
        normalized_file = os.path.join(self.normalized_output_dir, "endpoints.csv")
        normalized_rows = self.normalize_data(data)
        with open(normalized_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerows(normalized_rows)
