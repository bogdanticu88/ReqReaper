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
        normalized = []
        for item in data:
            normalized.append({
                "tool": "nuclei",
                "severity": item.get('info', {}).get('severity', 'unknown'),
                "title": item.get('info', {}).get('name', 'N/A'),
                "endpoint": item.get('matched-at', 'N/A'),
                "evidence_path": item.get('template-id', 'N/A'),
                "confidence": "high"
            })
        if self.dm:
            self.dm.add_data("findings", normalized)
