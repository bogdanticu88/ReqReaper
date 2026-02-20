from .base import BaseModule
import os
import csv
import json

class KiterunnerModule(BaseModule):
    def run(self, targets):
        if not self.check_tool("kr"):
            return "Kiterunner not found"

        results = []
        for target in targets:
            output_file = os.path.join(self.raw_output_dir, f"kr_{target.replace('/', '_')}.json")
            
            cmd = [
                "kr",
                "scan",
                target,
                "-w", "/usr/share/kiterunner/routes-large.kite", # Default path
                "-o", "json",
                "--output", output_file
            ]
            self.run_command(cmd, "kr")
            
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        results.append(data)
                except:
                    pass
            
        self.parse_results(results)
        return results

    def parse_results(self, data):
        normalized_file = os.path.join(self.normalized_output_dir, "endpoints_kiterunner.csv")
        with open(normalized_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for item in data:
                # Assuming simple structure
                writer.writerow([item.get('url'), item.get('status')])
