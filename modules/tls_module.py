from .base import BaseModule
import os
import csv
import subprocess

class TLSModule(BaseModule):
    def __init__(self, config, output_dir, db_path):
        super().__init__(config, output_dir, db_path)
        self.required_tool = "testssl.sh"

    def run(self, targets):
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
            results.append({"domain": domain, "output": output_file})
            
        self.parse_results(results)
        return results

    def parse_results(self, data):
        self.findings_count = len(data)
        normalized = []
        for item in data:
            normalized.append({
                "run_id": "", # Added by DataManager
                "host": item['domain'],
                "finding": f"TLS scan report: {item['output']}",
                "severity": "info"
            })
        if self.dm:
            self.dm.add_data("tls_findings", normalized)
