from .base import BaseModule
import os
import csv
import json

class HttpxModule(BaseModule):
    def __init__(self, config, output_dir, db_path):
        super().__init__(config, output_dir, db_path)
        self.required_tool = "httpx"

    def run(self, targets):
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
            normalized.append({
                "url": item.get('url'),
                "method": "GET",
                "source_tool": "httpx",
                "status_code": item.get('status_code')
            })
        return normalized

    def parse_results(self, data):
        normalized_data = self.normalize_data(data)
        self.findings_count = len(normalized_data)
        if self.dm:
            self.dm.add_data("endpoints", normalized_data)
