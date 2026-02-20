import pytest
import json
import os
from modules.httpx_module import HttpxModule
from modules.openapi_module import OpenApiModule

def test_httpx_normalization():
    # Mock config and directories
    module = HttpxModule(config={}, output_dir="tmp", db_path="tmp.db")
    
    # Load fixture
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures/httpx_sample.jsonl")
    raw_data = module.load_raw_results(fixture_path)
    
    # Normalize
    normalized = module.normalize_data(raw_data)
    
    assert len(normalized) == 2
    assert normalized[0]['url'] == "https://api.example.com/v1/user"
    assert normalized[0]['status_code'] == 200
    assert normalized[0]['source_tool'] == "httpx"

def test_openapi_extraction():
    module = OpenApiModule(config={}, output_dir="tmp", db_path="tmp.db")
    
    # Load fixture
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures/openapi_sample.json")
    with open(fixture_path, 'r') as f:
        spec = json.load(f)
        
    endpoints = module.extract_endpoints(spec)
    
    assert len(endpoints) == 3
    paths = [e['path'] for e in endpoints]
    assert "/users" in paths
    assert "/auth/login" in paths
    
    methods = [e['method'] for e in endpoints if e['path'] == "/users"]
    assert "GET" in methods
    assert "POST" in methods
