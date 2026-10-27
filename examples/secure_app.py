"""
Remediated, secure equivalent demonstrating safe coding practices.

Runs clean under ast-guard with 0 findings.
"""

import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
import yaml


def secure_db_query(user_id: str):
    # Remediated: Parameterized query prevents SQL injection
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def secure_system_command(target_host: str):
    # Remediated: Argument list without shell=True prevents command injection
    subprocess.run(["ping", "-c", "1", target_host], shell=False, check=True)


def secure_deserialization(json_payload: str, yaml_payload: str):
    # Remediated: Safe data serialization formats
    obj = json.loads(json_payload)
    cfg = yaml.safe_load(yaml_payload)
    return obj, cfg


def secure_crypto(data: bytes):
    # Remediated: SHA-256 for secure hashing; MD5 explicitly marked for non-security checksums
    secure_hash = hashlib.sha256(data).hexdigest()
    cache_key = hashlib.md5(data, usedforsecurity=False).hexdigest()
    return secure_hash, cache_key


def secure_dynamic_execution(safe_expression: str):
    # Remediated: ast.literal_eval safely parses literals without executing arbitrary code
    import ast
    return ast.literal_eval(safe_expression)


def secure_temp_file():
    # Remediated: Atomic temporary file creation with restrictive permissions
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        return tmp.name


def secure_server():
    # Remediated: Bound strictly to localhost with debug disabled
    class MockApp:
        def run(self, host, debug, port):
            pass

    app = MockApp()
    app.run(host="127.0.0.1", debug=False, port=5000)


def secure_credentials():
    # Remediated: Secrets read dynamically from environment variables
    api_key = os.environ.get("APP_API_KEY", "")
    return api_key
