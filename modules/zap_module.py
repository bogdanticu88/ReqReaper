from .base import BaseModule
import os
import csv
import shutil

class ZapModule(BaseModule):
    def run(self, targets):
        if not self.check_tool("zap-cli"):
            return "zap-cli not found"

        results = []
        for target in targets:
            report_file = os.path.join(self.raw_output_dir, f"zap_{target.replace('/', '_')}.html")
            
            # Simplified ZAP baseline
            cmd = [
                "zap-cli",
                "quick-scan",
                "--spider",
                "--recursive",
                "--scanners", "all",
                target
            ]
            self.run_command(cmd, "zap-cli")
            
            # Report generation
            report_cmd = [
                "zap-cli",
                "report",
                "-o", report_file,
                "-f", "html"
            ]
            self.run_command(report_cmd, "zap-cli")
            
            results.append({"target": target, "report": report_file})

        self.parse_results(results)
        return results

    def parse_results(self, data):
        normalized_file = os.path.join(self.normalized_output_dir, "zap_summaries.csv")
        with open(normalized_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for item in data:
                writer.writerow([item.get('target'), item.get('report')])
