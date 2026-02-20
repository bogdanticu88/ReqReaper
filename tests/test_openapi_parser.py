import os
import json
from modules.openapi_module import OpenApiModule


def test_openapi_endpoint_extraction():
    module = OpenApiModule(config={}, output_dir="tmp", db_path="tmp.db")
    fixture_path = os.path.join(
        os.path.dirname(__file__), "fixtures/openapi_sample.json"
    )

    with open(fixture_path, "r") as f:
        spec = json.load(f)

    endpoints = module.extract_endpoints(spec)
    assert len(endpoints) == 3

    paths = [e["path"] for e in endpoints]
    assert "/users" in paths
    assert "/auth/login" in paths

    # Check methods
    user_methods = [e["method"] for e in endpoints if e["path"] == "/users"]
    assert "GET" in user_methods
    assert "POST" in user_methods


def test_openapi_malformed_spec():
    module = OpenApiModule(config={}, output_dir="tmp", db_path="tmp.db")
    endpoints = module.extract_endpoints({})
    assert endpoints == []
