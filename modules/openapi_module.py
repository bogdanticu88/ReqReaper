from .base import BaseModule
import json
import logging
import requests
import yaml

logger = logging.getLogger("reqreaper")


def _parse_spec(content, content_type=""):
    """Try JSON first, fall back to YAML."""
    try:
        return json.loads(content)
    except (json.JSONDecodeError, TypeError):
        pass
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ValueError(f"Could not parse spec as JSON or YAML: {e}")


class OpenApiModule(BaseModule):
    def __init__(self, config, output_dir, db_path):
        super().__init__(config, output_dir, db_path)
        self.required_tool = None  # Native Python

    def run(self, url=None, file_path=None):
        if not url and not file_path:
            return "No OpenAPI source provided"

        spec = {}
        timeout = self.config.get("timeout", 30)

        if url:
            try:
                auth = self.config.get("auth", {})
                headers = {}
                if auth.get("header_name") and auth.get("header_value"):
                    headers[auth["header_name"]] = auth["header_value"]
                response = requests.get(url, timeout=timeout, headers=headers)
                response.raise_for_status()
                spec = _parse_spec(response.text, response.headers.get("content-type", ""))
            except requests.RequestException as e:
                logger.error(f"[openapi] Failed to fetch spec from {url}: {e}")
                return f"Failed to fetch OpenAPI: {e}"
            except ValueError as e:
                logger.error(f"[openapi] {e}")
                return str(e)
        elif file_path:
            try:
                with open(file_path, "r") as f:
                    content = f.read()
                spec = _parse_spec(content)
            except OSError as e:
                logger.error(f"[openapi] Failed to read file {file_path}: {e}")
                return f"Failed to read OpenAPI file: {e}"
            except ValueError as e:
                logger.error(f"[openapi] {e}")
                return str(e)

        endpoints = self.extract_endpoints(spec)
        self.parse_results(endpoints)
        return endpoints

    def extract_endpoints(self, spec):
        endpoints = []
        if "paths" in spec:
            for path, methods in spec["paths"].items():
                for method in methods:
                    if method.lower() in [
                        "get",
                        "post",
                        "put",
                        "delete",
                        "patch",
                        "options",
                        "head",
                    ]:
                        endpoints.append({"path": path, "method": method.upper()})
        return endpoints

    def parse_results(self, data):
        normalized = []
        for item in data:
            normalized.append(
                {
                    "url": item["path"],
                    "method": item["method"],
                    "source_tool": "openapi",
                    "status_code": 0,
                }
            )
        self.findings_count = len(normalized)
        if self.dm:
            self.dm.add_data("endpoints", normalized)
