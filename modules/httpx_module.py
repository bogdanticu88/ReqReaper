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
            
            # Parse
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            results.append(data)
                        except:
                            pass
        
        self.parse_results(results)
        return results

    def parse_results(self, data):
        normalized_file = os.path.join(self.normalized_output_dir, "endpoints.csv")
        with open(normalized_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for item in data:
                writer.writerow([item.get('url'), item.get('status_code'), item.get('tech')])
