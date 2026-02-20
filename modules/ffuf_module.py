from .base import BaseModule
import os
import csv
import json

class FfufModule(BaseModule):
    def run(self, targets, wordlist="/usr/share/wordlists/dirb/common.txt"):
        if not self.check_tool("ffuf"):
            return "ffuf not found"

        results = []
        for target in targets:
            output_file = os.path.join(self.raw_output_dir, f"ffuf_{target.replace('/', '_')}.json")
            
            cmd = [
                "ffuf",
                "-w", wordlist,
                "-u", f"{target}/FUZZ",
                "-o", output_file,
                "-of", "json",
                "-mc", "200,301,302,401,403"
            ]
            self.run_command(cmd, "ffuf")
            
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        if 'results' in data:
                            results.extend(data['results'])
                except:
                    pass
            
        self.parse_results(results)
        return results

    def parse_results(self, data):
        normalized_file = os.path.join(self.normalized_output_dir, "fuzzing_findings.csv")
        with open(normalized_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for item in data:
                writer.writerow([item.get('url'), item.get('status'), item.get('length')])
