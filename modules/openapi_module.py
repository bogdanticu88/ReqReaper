from .base import BaseModule
import os
import csv
import json
import requests

class OpenApiModule(BaseModule):
    def run(self, url=None, file_path=None):
        if not url and not file_path:
            return "No OpenAPI source provided"

        spec = {}
        if url:
            try:
                response = requests.get(url)
                spec = response.json()
            except Exception as e:
                return f"Failed to fetch OpenAPI: {e}"
        elif file_path:
            try:
                with open(file_path, 'r') as f:
                    spec = json.load(f)
            except Exception as e:
                return f"Failed to read OpenAPI file: {e}"

        endpoints = []
        if 'paths' in spec:
            for path, methods in spec['paths'].items():
                for method in methods:
                    endpoints.append({
                        "path": path,
                        "method": method.upper()
                    })
        
        self.parse_results(endpoints)
        return endpoints

    def parse_results(self, data):
        normalized_file = os.path.join(self.normalized_output_dir, "openapi_endpoints.csv")
        with open(normalized_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Path", "Method"])
            for item in data:
                writer.writerow([item['path'], item['method']])
