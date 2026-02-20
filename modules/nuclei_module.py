from .base import BaseModule
import os
import csv
import json

class NucleiModule(BaseModule):
    def run(self, targets):
        if not self.check_tool("nuclei"):
            return "Nuclei not found"

        results = []
        for target in targets:
            output_file = os.path.join(self.raw_output_dir, f"nuclei_{target.replace('/', '_')}.json")
            
            cmd = [
                "nuclei",
                "-u", target,
                "-json",
                "-o", output_file,
                "-silent"
            ]
            self.run_command(cmd, "nuclei")
            
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            data = json.loads(line)
                            results.append(data)
                except:
                    pass
            
        self.parse_results(results)
        return results

    def parse_results(self, data):
        normalized_file = os.path.join(self.normalized_output_dir, "nuclei_findings.csv")
        with open(normalized_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for item in data:
                writer.writerow([
                    item.get('template-id'),
                    item.get('info', {}).get('severity'),
                    item.get('matched-at')
                ])
