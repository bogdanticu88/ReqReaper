from abc import ABC, abstractmethod
import subprocess
import shutil
import json
import os
import time

class BaseModule(ABC):
    def __init__(self, config, output_dir, db_path):
        self.config = config
        self.output_dir = output_dir
        self.db_path = db_path
        self.dm = None # Will be injected by orchestrator
        self.raw_output_dir = os.path.join(output_dir, "raw")
        self.normalized_output_dir = os.path.join(output_dir, "normalized")
        self.required_tool = None # To be defined by subclasses
        self.findings_count = 0
        self.duration = 0
        os.makedirs(self.raw_output_dir, exist_ok=True)
        os.makedirs(self.normalized_output_dir, exist_ok=True)

    def is_available(self):
        if not self.required_tool:
            return True
        return shutil.which(self.required_tool) is not None

    def run_command(self, cmd, tool_name):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get("timeout", 60) * 10 
            )
            return result
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            return None

    @abstractmethod
    def run(self, targets):
        pass

    @abstractmethod
    def parse_results(self, data):
        pass
