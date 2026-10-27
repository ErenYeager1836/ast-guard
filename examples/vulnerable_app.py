"""
Intentionally vulnerable sample application for demonstrating ast-guard detections.

WARNING: For testing and demonstration only. Contains deliberate security flaws.
Target: Localhost demonstration environment only.
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess
import tempfile
import yaml


def vulnerable_db_query(user_id: str):
    # AG-101: SQL Injection via f-string interpolation
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)


def vulnerable_system_command(target_host: str):
    # AG-102: Command Injection via os.system and shell=True
    os.system("ping -c 1 " + target_host)
    subprocess.run(f"traceroute {target_host}", shell=True, check=True)


def vulnerable_deserialization(payload: bytes):
    # AG-103: Insecure Deserialization via pickle and unsafe yaml
    obj = pickle.loads(payload)
    cfg = yaml.load("user: admin\nrole: root")
    return obj, cfg


def vulnerable_crypto(password: str):
    # AG-104: Broken Cryptographic Hash (MD5) without usedforsecurity=False
    return hashlib.md5(password.encode()).hexdigest()


def vulnerable_dynamic_execution(user_input: str):
    # AG-105: Dangerous Dynamic Code Execution via eval()
    return eval(user_input)


def vulnerable_temp_file():
    # AG-106: Insecure Temporary File Creation (TOCTOU Race Condition)
    temp_path = tempfile.mktemp()
    return temp_path


def vulnerable_debug_server():
    # AG-107: Insecure Debug Mode and All-Interface Binding
    class MockApp:
        def run(self, host, debug, port):
            pass

    app = MockApp()
    app.run(host="0.0.0.0", debug=True, port=5000)


def vulnerable_credentials():
    # AG-108: Hardcoded high-entropy API key constant in source code
    # Synthetic mock key for demonstration
    api_key = "a9f8b7c6d5e4f3a2b1c0d9e8f7a6b5c4"
    return api_key
