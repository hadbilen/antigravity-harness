"""
tests/test_meta_audit.py — Test Autonomous Meta-Consistency & Self-Audit Engine
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.meta_audit import MetaAuditEngine, REPO_ROOT


class TestMetaAuditEngine(unittest.TestCase):
    def test_clean_repo_passes_all_checks(self):
        """Current repository must pass all 5 self-audit passes with zero critical and zero warnings."""
        engine = MetaAuditEngine(repo_root=REPO_ROOT)
        findings = engine.run_all_passes()
        criticals = [f for f in findings if f.severity == "CRITICAL"]
        warnings = [f for f in findings if f.severity == "WARNING"]

        self.assertEqual(len(criticals), 0, f"Unexpected critical findings: {criticals}")
        self.assertEqual(len(warnings), 0, f"Unexpected warning findings: {warnings}")

    def test_pass1_detects_missing_frontmatter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            skills_dir = root / "skills" / "bad_skill"
            skills_dir.mkdir(parents=True)
            # Create a skill file without YAML frontmatter
            (skills_dir / "SKILL.md").write_text("# Bad Skill\nNo frontmatter here.", encoding="utf-8")

            engine = MetaAuditEngine(repo_root=root)
            engine.pass1_schema_validation()

            crit = [f for f in engine.findings if f.severity == "CRITICAL"]
            self.assertGreaterEqual(len(crit), 1)
            self.assertIn("frontmatter", crit[0].message.lower())

    def test_pass2_detects_broken_cross_references(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # Create a GEMINI.md referencing non-existent subagent and non-existent template
            doc = root / "GEMINI.md"
            doc.write_text("Mandatory dispatch of `unreal-auditor` subagent using templates/unreal.template.md.", encoding="utf-8")

            engine = MetaAuditEngine(repo_root=root)
            engine.pass2_cross_references()

            crit = [f for f in engine.findings if f.severity == "CRITICAL"]
            self.assertGreaterEqual(len(crit), 1)
            target_messages = [f.message for f in crit]
            self.assertTrue(any("unreal-auditor" in m or "unreal.template.md" in m for m in target_messages))

    def test_pass3_detects_unbounded_vibe_and_harness_collision(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            skills_dir = root / "skills"
            (skills_dir / "vibecoder").mkdir(parents=True)
            (skills_dir / "harness").mkdir(parents=True)

            # Omit mutual exclusion barrier
            (skills_dir / "vibecoder" / "SKILL.md").write_text(
                "---\nname: vibecoder\ndescription: Rapid prototype\n---\n# Vibecoder\nNo mutex here.",
                encoding="utf-8",
            )
            (skills_dir / "harness" / "SKILL.md").write_text(
                "---\nname: harness\ndescription: Autonomous harness\n---\n# Harness\nEngineering.",
                encoding="utf-8",
            )

            engine = MetaAuditEngine(repo_root=root)
            engine.pass3_directive_collision_and_mutex()

            col = [f for f in engine.findings if "vibecoder" in f.target.lower()]
            self.assertGreaterEqual(len(col), 1)
            self.assertIn("mutual exclusion", col[0].message.lower())


if __name__ == "__main__":
    unittest.main()
