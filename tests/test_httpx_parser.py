import pytest
import os
import json
from modules.httpx_module import HttpxModule

def test_httpx_load_raw_results():
    module = HttpxModule(config={}, output_dir="tmp", db_path="tmp.db")
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures/httpx_sample.jsonl")
    
    results = module.load_raw_results(fixture_path)
    assert len(results) == 2
    assert results[0]['url'] == "https://api.example.com/v1/user"
    assert results[1]['status_code'] == 401

def test_httpx_normalize_data():
    module = HttpxModule(config={}, output_dir="tmp", db_path="tmp.db")
    sample_data = [
        {"url": "http://test.com", "status_code": 200, "tech": ["Apache"]},
        {"url": "http://test.com/api", "status_code": 404, "tech": []}
    ]
    
    normalized = module.normalize_data(sample_data)
    assert len(normalized) == 2
    assert normalized[0]['url'] == "http://test.com"
    assert normalized[0]['status_code'] == 200
    assert normalized[0]['source_tool'] == "httpx"
    assert normalized[1]['status_code'] == 404
