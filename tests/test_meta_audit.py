"""
tests/test_meta_audit.py — Test Autonomous Meta-Consistency & Self-Audit Engine
Part of Plumbwork (https://github.com/hadbilen/plumbwork)
Zero external dependencies: uses strictly the Python standard library.
"""


from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)

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

    def test_pass2_flags_oversized_skill_md_above_40kb(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok_skill = root / "skills" / "ok-skill"
            big_skill = root / "skills" / "big-skill"
            ok_skill.mkdir(parents=True)
            big_skill.mkdir(parents=True)
            (ok_skill / "SKILL.md").write_text(
                "---\nname: ok-skill\ndescription: Small skill.\n---\n" + ("a" * 1024),
                encoding="utf-8",
            )
            (big_skill / "SKILL.md").write_text(
                "---\nname: big-skill\ndescription: Oversized skill.\n---\n" + ("b" * 41500),
                encoding="utf-8",
            )

            engine = MetaAuditEngine(repo_root=root)
            engine.pass2_cross_references()

            size_warns = [
                f for f in engine.findings
                if f.severity == "WARNING" and "40 KB" in f.message
            ]
            self.assertEqual(len(size_warns), 1, engine.findings)
            self.assertIn("big-skill/SKILL.md", size_warns[0].target)

        # Live skills/harness/SKILL.md stays within the W2 28 KB progressive-disclosure target
        self.assertLessEqual((REPO_ROOT / "skills" / "harness" / "SKILL.md").stat().st_size, 28672)

    def test_pass2_validates_upstream_watchdog_session_start_registration(self):
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # Missing SessionStart under upstream-watchdog -> CRITICAL
            (root / "hooks.json").write_text(
                json.dumps(
                    {
                        "upstream-watchdog": {
                            "PreInvocation": [{"type": "command", "command": "python3 w.py"}]
                        },
                        "harness-gate": {
                            "PreInvocation": [{"type": "command", "command": "python3 h.py"}],
                            "PreToolUse": [{"type": "command", "command": "python3 h.py", "matcher": "run_command"}],
                            "Stop": [{"type": "command", "command": "python3 h.py"}],
                        },
                    }
                ),
                encoding="utf-8",
            )
            eng_missing = MetaAuditEngine(repo_root=root)
            eng_missing.pass2_cross_references()
            self.assertTrue(
                any(
                    f.severity == "CRITICAL" and "upstream-watchdog.SessionStart" in f.message
                    for f in eng_missing.findings
                ),
                eng_missing.findings,
            )

            # Both SessionStart and legacy PreInvocation -> WARNING
            (root / "hooks.json").write_text(
                json.dumps(
                    {
                        "upstream-watchdog": {
                            "SessionStart": [{"type": "command", "command": "python3 w.py"}],
                            "PreInvocation": [{"type": "command", "command": "python3 w.py"}],
                        },
                        "harness-gate": {
                            "PreInvocation": [{"type": "command", "command": "python3 h.py"}],
                            "PreToolUse": [{"type": "command", "command": "python3 h.py", "matcher": "run_command"}],
                            "Stop": [{"type": "command", "command": "python3 h.py"}],
                        },
                    }
                ),
                encoding="utf-8",
            )
            eng_dup = MetaAuditEngine(repo_root=root)
            eng_dup.pass2_cross_references()
            self.assertTrue(
                any(
                    f.severity == "WARNING" and "legacy upstream-watchdog.PreInvocation" in f.message
                    for f in eng_dup.findings
                ),
                eng_dup.findings,
            )


if __name__ == "__main__":
    unittest.main()
