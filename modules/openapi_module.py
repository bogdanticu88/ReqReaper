from .base import BaseModule
import os
import json
import requests

class OpenApiModule(BaseModule):
    def __init__(self, config, output_dir, db_path):
        super().__init__(config, output_dir, db_path)
        self.required_tool = None # Native Python

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

        endpoints = self.extract_endpoints(spec)
        self.parse_results(endpoints)
        return endpoints

    def extract_endpoints(self, spec):
        endpoints = []
        if 'paths' in spec:
            for path, methods in spec['paths'].items():
                for method in methods:
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                        endpoints.append({
                            "path": path,
                            "method": method.upper()
                        })
        return endpoints

    def parse_results(self, data):
        normalized = []
        for item in data:
            normalized.append({
                "url": item['path'],
                "method": item['method'],
                "source_tool": "openapi",
                "status_code": 0
            })
        self.findings_count = len(normalized)
        if self.dm:
            self.dm.add_data("endpoints", normalized)
