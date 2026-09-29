"""
tests/test_v140_meta.py — Self-audit checks added in 1.4.0: slash commands referenced by the
instruction set must be provided by a skill.
"""

from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before anything else is imported)

import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.meta_audit import MetaAuditEngine

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestSlashCommandResolution(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="agy_meta_"))
        (self.root / "skills" / "tool").mkdir(parents=True)
        (self.root / "agents").mkdir()
        (self.root / "skills" / "tool" / "SKILL.md").write_text(
            "---\nname: tool\ndescription: Does a thing. Invoke with /tool or /tool-fast.\n---\n\n"
            "# Tool\n\n## Invocation\n* `/tool --deep` for deep mode\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _warnings(self):
        engine = MetaAuditEngine(self.root)
        engine.pass2_cross_references()
        return [f for f in engine.findings if "Slash command" in f.message]

    def test_declared_commands_resolve(self):
        (self.root / "GEMINI.md").write_text("Use `/tool` or `/tool-fast`; paths like `/home/user/x` are not commands.\n",
                                             encoding="utf-8")
        self.assertEqual(self._warnings(), [])

    def test_dangling_command_is_reported_with_its_line(self):
        (self.root / "GEMINI.md").write_text("line one\nHand off to `/goal` when done.\n", encoding="utf-8")
        found = self._warnings()
        self.assertEqual(len(found), 1)
        self.assertIn("/goal", found[0].message)
        self.assertTrue(found[0].target.endswith("GEMINI.md:2"))

    def test_text_between_code_spans_is_not_a_command(self):
        (self.root / "GEMINI.md").write_text("pipe `curl`/`wget`/log output through filters\n", encoding="utf-8")
        self.assertEqual(self._warnings(), [])

    def test_repository_has_no_dangling_commands(self):
        engine = MetaAuditEngine(REPO_ROOT)
        engine.pass2_cross_references()
        self.assertEqual([f"{f.target}: {f.message}" for f in engine.findings if "Slash command" in f.message], [])


if __name__ == "__main__":
    unittest.main()
