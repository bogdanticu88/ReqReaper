from .base import BaseModule
import os


class NmapModule(BaseModule):
    def __init__(self, config, output_dir, db_path):
        super().__init__(config, output_dir, db_path)
        self.required_tool = "nmap"

    def run(self, targets):
        results = []
        for target in targets:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            output_xml = os.path.join(self.raw_output_dir, f"nmap_{domain}.xml")

            cmd = ["nmap", "-sC", "-sV", "-p-", "-oX", output_xml, domain]
            self.run_command(cmd, "nmap")
            results.append({"domain": domain, "output": output_xml})

        self.parse_results(results)
        return results

    def parse_results(self, data):
        # Placeholder for nmap XML parsing to count findings (ports)
        self.findings_count = len(data)  # Simple count of hosts for now
