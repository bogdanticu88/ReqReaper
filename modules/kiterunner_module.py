from .base import BaseModule
import os
import json


class KiterunnerModule(BaseModule):
    def __init__(self, config, output_dir, db_path):
        super().__init__(config, output_dir, db_path)
        self.required_tool = "kr"

    def run(self, targets):
        results = []
        for target in targets:
            output_file = os.path.join(
                self.raw_output_dir, f"kr_{target.replace('/', '_')}.json"
            )
            cmd = [
                "kr",
                "scan",
                target,
                "-w",
                "/usr/share/kiterunner/routes-large.kite",
                "-o",
                "json",
                "--output",
                output_file,
            ]
            self.run_command(cmd, "kr")

            if os.path.exists(output_file):
                try:
                    with open(output_file, "r") as f:
                        data = json.load(f)
                        results.append(data)
                except Exception:
                    pass

        self.parse_results(results)
        return results

    def parse_results(self, data):
        self.findings_count = len(data)
        normalized = []
        for item in data:
            normalized.append(
                {
                    "url": item.get("url"),
                    "method": "GET",
                    "source_tool": "kiterunner",
                    "status_code": item.get("status"),
                }
            )
        if self.dm:
            self.dm.add_data("endpoints", normalized)
