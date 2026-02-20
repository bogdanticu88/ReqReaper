import pytest
import os
import sqlite3
import csv
from reqreaper import DataManager

def test_datamanager_init_db(tmp_path):
    db_path = tmp_path / "test_reaper.db"
    run_id = "test-run-123"
    dm = DataManager(str(db_path), run_id, str(tmp_path))
    
    # Check tables
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in c.fetchall()]
    conn.close()
    
    assert "targets" in tables
    assert "endpoints" in tables
    assert "findings" in tables

def test_datamanager_add_and_export(tmp_path):
    db_path = tmp_path / "test_reaper.db"
    run_id = "test-run-456"
    dm = DataManager(str(db_path), run_id, str(tmp_path))
    
    # Add sample data
    dm.add_data("endpoints", [
        {"url": "https://api.test/v1", "method": "GET", "source_tool": "test", "status_code": 200}
    ])
    
    # Export CSV
    dm.export_all_to_csv()
    
    csv_path = tmp_path / "normalized" / "endpoints.csv"
    assert csv_path.exists()
    
    with open(csv_path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]['url'] == "https://api.test/v1"
        assert rows[0]['run_id'] == run_id
