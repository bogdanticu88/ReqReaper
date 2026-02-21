from .base import BaseModule
import os
import json


class FfufModule(BaseModule):
    def __init__(self, config, output_dir, db_path):
        super().__init__(config, output_dir, db_path)
        self.required_tool = "ffuf"

    def _auth_args(self):
        auth = self.config.get("auth", {})
        name = auth.get("header_name")
        value = auth.get("header_value")
        if name and value:
            return ["-H", f"{name}: {value}"]
        return []

    def run(self, targets, wordlist="/usr/share/wordlists/dirb/common.txt"):
        results = []
        for target in targets:
            output_file = os.path.join(
                self.raw_output_dir, f"ffuf_{target.replace('/', '_')}.json"
            )
            cmd = [
                "ffuf",
                "-w",
                wordlist,
                "-u",
                f"{target}/FUZZ",
                "-o",
                output_file,
                "-of",
                "json",
                "-mc",
                "200,301,302,401,403",
            ] + self._auth_args()
            self.run_command(cmd, "ffuf")

            if os.path.exists(output_file):
                try:
                    with open(output_file, "r") as f:
                        data = json.load(f)
                        if "results" in data:
                            results.extend(data["results"])
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
                    "source_tool": "ffuf",
                    "status_code": item.get("status"),
                }
            )
        if self.dm:
            self.dm.add_data("endpoints", normalized)
