"""
Unit tests for all ast-guard security rules.

Verifies true-positive detection of vulnerable constructs and confirms that
safe idioms (parameterized queries, shell=False, usedforsecurity=False, SafeLoader)
do not produce false positives.
"""

import ast
import unittest
from pathlib import Path

from ast_guard.context import RuleContext
from ast_guard.models import Severity
from ast_guard.rules.command_injection import CommandInjectionRule
from ast_guard.rules.crypto import WeakCryptoRule
from ast_guard.rules.debug_binding import InsecureDebugBindingRule
from ast_guard.rules.deserialization import InsecureDeserializationRule
from ast_guard.rules.eval_exec import EvalExecRule
from ast_guard.rules.secrets import HardcodedSecretRule
from ast_guard.rules.sqli import SQLInjectionRule
from ast_guard.rules.tempfile_mktemp import InsecureTempfileRule


def run_rule_on_code(rule, code: str):
    """Helper to parse a code snippet and evaluate a rule across all matching nodes."""
    tree = ast.parse(code)
    context = RuleContext(file_path=Path("sample.py"), source_code=code, tree=tree)
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, rule.target_node_types):
            res = rule.check_node(node, context)
            if res:
                findings.extend(res)
    return findings


class TestSQLInjectionRule(unittest.TestCase):
    def setUp(self):
        self.rule = SQLInjectionRule()

    def test_sqli_fstring_triggers(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "AG-101")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_sqli_assigned_variable_triggers(self):
        code = 'q = f"SELECT * FROM users WHERE id = {user_id}"\ncursor.execute(q)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "AG-101")
        self.assertIn("variable 'q'", findings[0].message)

    def test_sqli_percent_formatting_triggers(self):
        code = 'cursor.execute("SELECT * FROM users WHERE name = \'%s\'" % name)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)

    def test_sqli_format_method_triggers(self):
        code = 'db.execute("SELECT * FROM items WHERE category = {}".format(cat))'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)

    def test_sqli_concat_triggers(self):
        code = 'conn.execute("SELECT * FROM accounts WHERE id = " + acc_id)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)

    def test_parameterized_query_safe(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)

    def test_static_literal_query_safe(self):
        code = 'cursor.execute("SELECT id, name FROM users LIMIT 10")'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)


class TestCommandInjectionRule(unittest.TestCase):
    def setUp(self):
        self.rule = CommandInjectionRule()

    def test_os_system_triggers(self):
        code = 'os.system("ping " + host)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "AG-102")

    def test_os_popen_triggers(self):
        code = 'os.popen("ls -la")'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)

    def test_subprocess_shell_true_triggers(self):
        code = 'subprocess.run(cmd, shell=True, check=True)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)

    def test_subprocess_shell_false_safe(self):
        code = 'subprocess.run(["ping", "-c", "1", host], shell=False, check=True)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)

    def test_subprocess_default_shell_safe(self):
        code = 'subprocess.Popen(["ls", "-l"])'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)


class TestDeserializationRule(unittest.TestCase):
    def setUp(self):
        self.rule = InsecureDeserializationRule()

    def test_pickle_loads_triggers(self):
        code = 'data = pickle.loads(user_input)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "AG-103")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_yaml_load_unsafe_triggers(self):
        code = 'cfg = yaml.load(raw_yaml)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)

    def test_yaml_safe_load_is_safe(self):
        code = 'cfg = yaml.safe_load(raw_yaml)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)

    def test_yaml_load_with_safe_loader_is_safe(self):
        code = 'cfg = yaml.load(raw_yaml, Loader=yaml.SafeLoader)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)


class TestWeakCryptoRule(unittest.TestCase):
    def setUp(self):
        self.rule = WeakCryptoRule()

    def test_hashlib_md5_triggers(self):
        code = 'h = hashlib.md5(b"password").hexdigest()'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "AG-104")

    def test_hashlib_sha1_triggers(self):
        code = 'h = hashlib.sha1(data).digest()'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)

    def test_hashlib_new_md5_triggers(self):
        code = 'h = hashlib.new("md5")'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)

    def test_hashlib_md5_usedforsecurity_false_safe(self):
        code = 'h = hashlib.md5(b"data", usedforsecurity=False).hexdigest()'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)

    def test_hashlib_sha256_safe(self):
        code = 'h = hashlib.sha256(b"password").hexdigest()'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)


class TestEvalExecRule(unittest.TestCase):
    def setUp(self):
        self.rule = EvalExecRule()

    def test_eval_triggers(self):
        code = 'res = eval(user_expression)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "AG-105")

    def test_exec_triggers(self):
        code = 'exec(payload)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)

    def test_literal_eval_safe(self):
        code = 'data = ast.literal_eval(safe_str)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)


class TestTempfileRule(unittest.TestCase):
    def setUp(self):
        self.rule = InsecureTempfileRule()

    def test_mktemp_triggers(self):
        code = 'path = tempfile.mktemp()'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "AG-106")

    def test_named_temporary_file_safe(self):
        code = 'with tempfile.NamedTemporaryFile() as tmp: pass'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)


class TestDebugBindingRule(unittest.TestCase):
    def setUp(self):
        self.rule = InsecureDebugBindingRule()

    def test_debug_true_triggers(self):
        code = 'app.run(debug=True, port=5000)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "AG-107")

    def test_all_interfaces_binding_triggers(self):
        code = 'app.run(host="0.0.0.0", port=8000)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)

    def test_debug_false_localhost_safe(self):
        code = 'app.run(host="127.0.0.1", debug=False, port=5000)'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)


class TestHardcodedSecretRule(unittest.TestCase):
    def setUp(self):
        self.rule = HardcodedSecretRule()

    def test_api_key_high_entropy_triggers(self):
        code = 'api_key = "a8f7c9e0d1b2a3c4d5e6f7a8b9c0d1e2"'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "AG-108")
        # Ensure finding masks the secret value
        self.assertIn("a8f...1e2", findings[0].message)

    def test_jwt_secret_triggers(self):
        code = 'JWT_SECRET: str = "super_high_entropy_signing_token_998811"'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 1)

    def test_placeholder_password_ignored(self):
        code = 'password = "changeme"'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)

    def test_non_sensitive_variable_ignored(self):
        code = 'description = "a8f7c9e0d1b2a3c4d5e6f7a8b9c0d1e2"'
        findings = run_rule_on_code(self.rule, code)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
