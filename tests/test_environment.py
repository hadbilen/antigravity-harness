"""
tests/test_environment.py — Test Multi-Environment Governance & Registry
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""


from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)

import json
import tempfile
import unittest
from pathlib import Path

from guard.environment import AgentEnvironment, EnvironmentRegistry


class TestEnvironmentRegistry(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.config_file = self.root / ".harness" / "environments.json"
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.registry = EnvironmentRegistry(config_path=self.config_file, workspace_dir=self.root)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_antigravity_environment_seeded(self):
        envs = self.registry.list_environments()
        self.assertGreaterEqual(len(envs), 1)
        ag_env = self.registry.get_environment("antigravity")
        self.assertIsNotNone(ag_env)
        self.assertEqual(ag_env.id, "antigravity")
        self.assertEqual(ag_env.policy, "enforced")
        self.assertIn("GEMINI.md", ag_env.governance_paths)

    def test_add_and_remove_environment(self):
        custom = AgentEnvironment(
            id="custom_agent",
            name="Custom Autonomous Agent",
            platform_type="custom",
            root_path=str(self.root / ".custom"),
            governance_paths=["AGENT.md", "rules.json"],
            policy="monitored",
        )
        self.registry.register_environment(custom)
        retrieved = self.registry.get_environment("custom_agent")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.policy, "monitored")

        # Persistence verification
        new_registry = EnvironmentRegistry(config_path=self.config_file, workspace_dir=self.root)
        persisted = new_registry.get_environment("custom_agent")
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted.name, "Custom Autonomous Agent")

        # Removal
        self.assertTrue(self.registry.unregister_environment("custom_agent"))
        self.assertIsNone(self.registry.get_environment("custom_agent"))

    def test_update_policy(self):
        self.assertTrue(self.registry.set_policy("antigravity", "monitored"))
        ag_env = self.registry.get_environment("antigravity")
        self.assertEqual(ag_env.policy, "monitored")

        with self.assertRaises(ValueError):
            self.registry.set_policy("antigravity", "invalid_policy")

    def test_discover_environments(self):
        # Create simulated agent directories within self.root
        claude_dir = self.root / ".claude"
        claude_dir.mkdir()
        (claude_dir / "CLAUDE.md").write_text("# Claude Config", encoding="utf-8")
        (self.root / "CLAUDE.md").write_text("# Claude Root Config", encoding="utf-8")

        cursor_dir = self.root / ".cursor"
        cursor_dir.mkdir()
        (self.root / ".cursorrules").write_text("# Cursor Rules", encoding="utf-8")

        aider_conf = self.root / ".aider.conf.yml"
        aider_conf.write_text("model: gpt-4", encoding="utf-8")

        discovered = self.registry.discover_environments(workspace_dir=self.root, register=True)
        discovered_types = {e.platform_type for e in discovered}

        self.assertIn("claude", discovered_types)
        self.assertIn("cursor", discovered_types)
        self.assertIn("aider", discovered_types)

    def test_governance_seams_isolation(self):
        """Verify that get_governance_paths strictly yields governance files, not source code."""
        claude_dir = self.root / ".claude"
        claude_dir.mkdir()
        gov_file = self.root / "CLAUDE.md"
        gov_file.write_text("# Governance", encoding="utf-8")

        code_file = self.root / "random_code.py"
        code_file.write_text("print('hello')", encoding="utf-8")

        env = AgentEnvironment(
            id="claude_test",
            name="Claude Test",
            platform_type="claude",
            root_path=str(self.root),
            governance_paths=["CLAUDE.md"],
            policy="enforced",
        )
        self.registry.register_environment(env)

        paths = env.get_governance_paths(existing_only=True)
        resolved_paths = [p.resolve() for p in paths]

        self.assertIn(gov_file.resolve(), resolved_paths)
        self.assertNotIn(code_file.resolve(), resolved_paths)


if __name__ == "__main__":
    unittest.main()
