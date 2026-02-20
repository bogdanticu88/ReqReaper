from .base import BaseModule
import os
import csv
import shutil

class NmapModule(BaseModule):
    def run(self, targets):
        if not self.check_tool("nmap"):
            return "Nmap not found"

        results = []
        for target in targets:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            output_xml = os.path.join(self.raw_output_dir, f"nmap_{domain}.xml")
            
            cmd = [
                "nmap",
                "-sC",
                "-sV",
                "-p-",
                "-oX", output_xml,
                domain
            ]
            self.run_command(cmd, "nmap")
            results.append({"domain": domain, "output": output_xml})
            
        self.parse_results(results)
        return results

    def parse_results(self, data):
        normalized_file = os.path.join(self.normalized_output_dir, "nmap_hosts.csv")
        with open(normalized_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for item in data:
                writer.writerow([item.get('domain'), item.get('output')])
