"""
Unit tests for pre-commit hook configurations.
"""

import unittest
from pathlib import Path

import yaml


class TestPreCommit(unittest.TestCase):
    def setUp(self):
        self.repo_root = Path(__file__).parent.parent

    def test_pre_commit_hooks_yaml_validity(self):
        hooks_file = self.repo_root / ".pre-commit-hooks.yaml"
        self.assertTrue(hooks_file.exists(), ".pre-commit-hooks.yaml must exist")

        content = hooks_file.read_text(encoding="utf-8")
        data = yaml.safe_load(content)

        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 1)

        hook = data[0]
        self.assertEqual(hook.get("id"), "ast-guard")
        self.assertEqual(hook.get("entry"), "ast-guard")
        self.assertEqual(hook.get("language"), "python")
        self.assertIn("python", hook.get("types", []))

    def test_pre_commit_config_yaml_validity(self):
        config_file = self.repo_root / ".pre-commit-config.yaml"
        self.assertTrue(config_file.exists(), ".pre-commit-config.yaml must exist")

        content = config_file.read_text(encoding="utf-8")
        data = yaml.safe_load(content)

        self.assertIsInstance(data, dict)
        self.assertIn("repos", data)
        repos = data["repos"]
        self.assertGreaterEqual(len(repos), 1)


if __name__ == "__main__":
    unittest.main()
