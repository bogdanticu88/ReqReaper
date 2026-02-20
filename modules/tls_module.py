from .base import BaseModule
import os
import csv
import subprocess

class TLSModule(BaseModule):
    def run(self, targets):
        if not self.check_tool("testssl.sh"):
            return "testssl.sh not found"

        results = []
        for target in targets:
            domain = target.replace("https://", "").split("/")[0]
            output_file = os.path.join(self.raw_output_dir, f"tls_{domain}.json")
            
            cmd = [
                "testssl.sh",
                "--jsonfile", output_file,
                domain
            ]
            self.run_command(cmd, "testssl.sh")
            
            # Simple result capture
            results.append({"domain": domain, "output": output_file})
            
        self.parse_results(results)
        return results

    def parse_results(self, data):
        normalized_file = os.path.join(self.normalized_output_dir, "tls_findings.csv")
        with open(normalized_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for item in data:
                writer.writerow([item.get('domain'), item.get('output')])
