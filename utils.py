#!/usr/bin/env python3
"""
Utility functions for logging, file operations, and performance metrics.
Enhanced to support encryption policy loading from JSON and YAML.
"""

import logging
import os
from pathlib import Path
import hashlib
from datetime import datetime
import sys
import threading
import json
import time

try:
    import yaml
except ImportError:
    yaml = None

def setup_logging(log_level: str = "INFO"):
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler("application.log")],
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("cryptography").setLevel(logging.WARNING)

def load_encryption_policy(policy_file: str) -> dict:
    path = Path(policy_file)
    if path.suffix in [".yaml", ".yml"]:
        if yaml is None:
            raise ImportError("PyYAML is required for YAML policy files.")
        with open(policy_file, "r") as f:
            policy = yaml.safe_load(f)
    else:
        with open(policy_file, "r") as f:
            policy = json.load(f)
    return policy

def apply_encryption_policy(file_path: str, current_algorithm: str, policy: dict) -> str:
    p = Path(file_path)
    for rule in policy.get("policies", []):
        if "file_extension" in rule and p.suffix.lower() == rule["file_extension"].lower():
            return rule.get("algorithm", current_algorithm)
        if "max_size" in rule:
            if p.stat().st_size <= rule["max_size"]:
                return rule.get("algorithm", current_algorithm)
    return policy.get("default_algorithm", current_algorithm)

def calculate_file_hash(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def get_file_metadata(file_path: str) -> dict:
    p = Path(file_path)
    stats = p.stat()
    return {
        "name": p.name,
        "size": stats.st_size,
        "created": datetime.fromtimestamp(stats.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
        "hash": calculate_file_hash(file_path),
    }

def create_backup(file_path: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = f"{file_path}.backup.{timestamp}"
    Path(file_path).rename(backup_path)
    return backup_path

def restore_from_backup(backup_path: str, original_path: str):
    Path(backup_path).rename(original_path)

def clean_up_backup(backup_path: str):
    try:
        Path(backup_path).unlink()
    except Exception as e:
        logging.warning(f"Failed to remove backup file {backup_path}: {e}")

class AuditLogger:
    def __init__(self):
        self.audit_file = "audit.log"
    def log_operation(self, operation, file_path):
        with open(self.audit_file, "a") as f:
            f.write(f"{datetime.now().isoformat()} - {operation} - {file_path}\n")

class FileHandler:
    def validate_path(self, path: str) -> bool:
        try:
            p = Path(path)
            if p.exists():
                return True
            return p.parent.exists()
        except Exception:
            return False

    def walk_directory(self, dir_path: str):
        p = Path(dir_path)
        for f in p.rglob("*"):
            if f.is_file():
                yield f

from rich.progress import Progress

class ProgressBar:
    def __init__(self, total, desc="Processing"):
        self.progress = Progress()
        self.task_id = self.progress.add_task(desc, total=total)
        # Start the progress display in a thread.
        self.thread = threading.Thread(target=self.progress.start, daemon=True)
        self.thread.start()

    def update(self, advance=1):
        self.progress.update(self.task_id, advance=advance)

    def close(self):
        self.progress.stop()
        self.thread.join(timeout=1)

def start_metrics_server(port: int):
    from threading import Thread
    def run_server():
        # Dummy metrics server implementation
        print(f"Metrics server running on port {port}")
        while True:
            time.sleep(60)
    t = Thread(target=run_server, daemon=True)
    t.start()
