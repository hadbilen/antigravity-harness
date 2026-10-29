"""
tests/test_meta_audit_commands.py — Self-audit checks for slash commands, frontmatter, and
skill mutual exclusion: slash commands referenced by the instruction set must be provided by a skill.
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

    def test_body_declared_command_absent_from_frontmatter_is_flagged(self):
        (self.root / "skills" / "tool" / "SKILL.md").write_text(
            "---\nname: tool\ndescription: Does a thing. Invoke with /tool.\n---\n\n"
            "# Tool\n\n## Triggers and Invocations\n* Slash Commands: `/tool`, `/run-gate`.\n", encoding="utf-8")
        found = self._warnings()
        self.assertEqual(len(found), 1)
        self.assertIn("/run-gate", found[0].message)

    def test_split_layout_resolves_code_paths_against_runtime(self):
        (self.root / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")
        (self.root / "DESIGN.md").write_text("Self-audit uses `scripts/meta_audit.py` and `tests/test_protection.py`.\n",
                                             encoding="utf-8")
        engine = MetaAuditEngine(self.root)
        engine.pass2_cross_references()
        broken = [f for f in engine.findings if "Referenced repository path" in f.message]
        self.assertEqual(broken, [])

    def test_pass3_rejects_do_not_stop_as_deactivation_condition(self):
        (self.root / "skills" / "unlazy").mkdir(parents=True)
        (self.root / "skills" / "unlazy" / "SKILL.md").write_text(
            "---\nname: unlazy\ndescription: Tier 3 engine.\n---\n\n"
            "# Unlazy\n\n## Mutual Exclusion\n"
            "* Trigger exclusively on Tier 3 tasks alongside `harness`; do not stop until it is done.\n",
            encoding="utf-8")
        engine = MetaAuditEngine(self.root)
        engine.pass3_directive_collision_and_mutex()
        warnings = [f for f in engine.findings if "unlazy" in f.target]
        self.assertEqual(len(warnings), 1)
        self.assertIn("deactivation", warnings[0].message)

    def test_marathon_and_sweetspot_skills_validate_and_enforce_mutex(self):
        engine = MetaAuditEngine(REPO_ROOT)
        engine.pass1_schema_validation()
        engine.pass2_cross_references()
        engine.pass3_directive_collision_and_mutex()
        relevant = [
            f"{f.target}: {f.message}"
            for f in engine.findings
            if "marathon" in f.target or "sweetspot" in f.target
        ]
        self.assertEqual(relevant, [])
        declared = engine._declared_slash_commands()
        self.assertIn("/marathon", declared)
        self.assertIn("/sweetspot", declared)
        self.assertIn("/optimize", declared)

    def test_pass1_requires_agent_access_and_pass2_checks_subagent_references(self):
        (self.root / "agents").mkdir(parents=True, exist_ok=True)
        (self.root / "agents" / "custom-auditor.md").write_text(
            "---\nname: custom-auditor\ndescription: Custom auditor.\n---\n# Body\n",
            encoding="utf-8",
        )
        (self.root / "skills" / "tool" / "SKILL.md").write_text(
            "---\nname: tool\ndescription: Tool skill. Invoke with /tool.\n---\n"
            "Dispatch `nonexistent-verifier` subagent before delivery.\n",
            encoding="utf-8",
        )
        engine = MetaAuditEngine(self.root)
        engine.pass1_schema_validation()
        engine.pass2_cross_references()
        msgs = [f.message for f in engine.findings]
        self.assertTrue(any("missing 'access' field" in m for m in msgs), msgs)
        self.assertTrue(any("nonexistent-verifier" in m for m in msgs), msgs)

    def test_cursor_emitter_rewrites_relative_skill_links(self):
        from porter.emitters.cursor import CursorEmitter
        from porter.models import UniversalManifest

        manifest = UniversalManifest(
            version="2.0.0",
            constitution={"raw": "# Constitution\n"},
            design_contract={"raw": ""},
            skills=[
                {
                    "name": "demo",
                    "description": "Demo skill",
                    "raw": "See [Ref](references/guide.md) and `scripts/run.py`.\n",
                    "content": "See [Ref](references/guide.md) and `scripts/run.py`.\n",
                    "subfiles": {
                        "references/guide.md": "# Guide\n",
                        "scripts/run.py": "print(1)\n",
                    },
                }
            ],
            agents=[],
        )
        out = self.root / "cursor_out"
        CursorEmitter.emit(manifest, out)
        mdc = (out / ".cursor" / "rules" / "skill-demo.mdc").read_text(encoding="utf-8")
        self.assertIn("(.cursor/skills/demo/references/guide.md)", mdc)
        self.assertIn("`.cursor/skills/demo/scripts/run.py`", mdc)

    def test_pass7_trigger_specificity_and_hooks_subagent_check(self):
        # Full repository passes Pass 7 with zero warnings
        repo_engine = MetaAuditEngine(REPO_ROOT)
        repo_engine.pass7_trigger_specificity()
        self.assertEqual(repo_engine.findings, [])

        # Synthetic skill without negative boundary triggers Pass 7 warning
        engine = MetaAuditEngine(self.root)
        engine.pass7_trigger_specificity()
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("negative trigger boundary", engine.findings[0].message)

        # Synthetic guard/agy_hooks.py referencing a missing repo subagent is flagged by Pass 2
        (self.root / "agents" / "real-auditor.md").write_text(
            "---\nname: real-auditor\ndescription: Real.\naccess: read-only\n---\n# Real\n",
            encoding="utf-8",
        )
        (self.root / "guard").mkdir(parents=True, exist_ok=True)
        (self.root / "guard" / "agy_hooks.py").write_text(
            'ECOSYSTEM_ROUTING_HINTS = (\n'
            '  ("r1", None, "Subagent `ghost-auditor` (`invoke_subagent`)"),\n'
            '  ("r2", None, "Built-in Subagent `image-generator` (`invoke_subagent`)"),\n'
            ')\n',
            encoding="utf-8",
        )
        engine2 = MetaAuditEngine(self.root)
        engine2.pass2_cross_references()
        hook_msgs = [f.message for f in engine2.findings if f.target == "guard/agy_hooks.py"]
        self.assertEqual(len(hook_msgs), 1, hook_msgs)
        self.assertIn("ghost-auditor", hook_msgs[0])

    def test_pass1_flags_deprecated_v1_tool_names(self):
        with tempfile.TemporaryDirectory(prefix="agy_meta_p1_") as tmp_dir:
            base = Path(tmp_dir)

            # 1a. Skill SKILL.md referencing deprecated v1 tools -> CRITICAL
            r_skill = base / "skill_md"
            (r_skill / "skills" / "demo").mkdir(parents=True)
            (r_skill / "skills" / "demo" / "SKILL.md").write_text(
                "---\nname: demo\ndescription: Demo skill. Not for unrelated tasks.\n---\n"
                "# Demo\nUse `view_file` and `write_to_file` on files.\n",
                encoding="utf-8",
            )
            eng_skill = MetaAuditEngine(r_skill)
            eng_skill.pass1_schema_validation()
            crit_skill = [f for f in eng_skill.findings if f.severity == "CRITICAL"]
            self.assertTrue(any("view_file" in f.message for f in crit_skill), eng_skill.findings)
            self.assertTrue(any("write_to_file" in f.message for f in crit_skill), eng_skill.findings)

            # 1b. Skill reference subfile skills/demo/references/ref.md -> CRITICAL
            r_ref = base / "skill_ref"
            (r_ref / "skills" / "demo" / "references").mkdir(parents=True)
            (r_ref / "skills" / "demo" / "SKILL.md").write_text(
                "---\nname: demo\ndescription: Demo skill. Not for unrelated tasks.\n---\n"
                "# Demo\nUse `read_file` and `write_file`.\n",
                encoding="utf-8",
            )
            (r_ref / "skills" / "demo" / "references" / "ref.md").write_text(
                "# Reference\nLegacy call to `view_file` or `write_to_file`.\n",
                encoding="utf-8",
            )
            eng_ref = MetaAuditEngine(r_ref)
            eng_ref.pass1_schema_validation()
            crit_ref = [f for f in eng_ref.findings if f.severity == "CRITICAL"]
            self.assertTrue(
                any("skills/demo/references/ref.md" in f.target and "view_file" in f.message for f in crit_ref),
                eng_ref.findings,
            )
            self.assertTrue(
                any("skills/demo/references/ref.md" in f.target and "write_to_file" in f.message for f in crit_ref),
                eng_ref.findings,
            )

            # 1c. Non-read-only agent (`access: read-exec`) referencing view_file / write_to_file -> CRITICAL
            r_exec = base / "agent_exec"
            (r_exec / "agents").mkdir(parents=True)
            (r_exec / "agents" / "demo-worker.md").write_text(
                "---\nname: demo-worker\ndescription: Worker profile.\naccess: read-exec\n---\n"
                "# Worker\nCalls `view_file` and `write_to_file`.\n",
                encoding="utf-8",
            )
            eng_exec = MetaAuditEngine(r_exec)
            eng_exec.pass1_schema_validation()
            crit_exec = [f for f in eng_exec.findings if f.severity == "CRITICAL"]
            self.assertTrue(any("view_file" in f.message for f in crit_exec), eng_exec.findings)
            self.assertTrue(any("write_to_file" in f.message for f in crit_exec), eng_exec.findings)

            # 2. Read-only agent (`access: read-only`) with dual `read_file` and `view_file` guidance -> 0 CRITICAL
            r_ro = base / "agent_ro"
            (r_ro / "agents").mkdir(parents=True)
            (r_ro / "agents" / "demo-auditor.md").write_text(
                "---\nname: demo-auditor\ndescription: Read-only auditor.\naccess: read-only\n---\n"
                "# Demo Auditor\nUse `read_file` (or `view_file` where read-only subagent aliases apply).\n",
                encoding="utf-8",
            )
            eng_ro = MetaAuditEngine(r_ro)
            eng_ro.pass1_schema_validation()
            crit_ro = [f for f in eng_ro.findings if f.severity == "CRITICAL"]
            self.assertEqual(crit_ro, [])

            # 3. PyYAML-only flow-mapping frontmatter (`meta: {a: 1}`) rejected by porter.frontmatter -> CRITICAL
            r_flow = base / "flow_fm"
            (r_flow / "skills" / "demo").mkdir(parents=True)
            (r_flow / "skills" / "demo" / "SKILL.md").write_text(
                "---\nname: demo\ndescription: Demo skill. Not for unrelated tasks.\nmeta: {a: 1}\n---\n# Demo\n",
                encoding="utf-8",
            )
            eng_flow = MetaAuditEngine(r_flow)
            eng_flow.pass1_schema_validation()
            crit_flow = [f for f in eng_flow.findings if f.severity == "CRITICAL"]
            self.assertTrue(any("skills/demo/SKILL.md" in f.target for f in crit_flow), eng_flow.findings)

    def test_pass2_validates_hooks_matcher_anchors_and_sections(self):
        with tempfile.TemporaryDirectory(prefix="agy_meta_p2_") as tmp_dir:
            base = Path(tmp_dir)

            # 1. hooks.json PreToolUse matcher drift from PRE_TOOL_USE_MATCHER_TOOLS -> CRITICAL
            r_hooks = base / "matcher_drift"
            (r_hooks / "guard").mkdir(parents=True)
            (r_hooks / "guard.py").write_text("# guard entrypoint\n", encoding="utf-8")
            (r_hooks / "guard" / "agy_hooks.py").write_text(
                'PRE_TOOL_USE_MATCHER_TOOLS = ("run_command", "write_file")\n',
                encoding="utf-8",
            )
            (r_hooks / "hooks.json").write_text(
                '{"harness-gate": {"PreToolUse": [{"matcher": "run_command", "hooks": []}]}}\n',
                encoding="utf-8",
            )
            eng_hooks = MetaAuditEngine(r_hooks)
            eng_hooks.pass2_cross_references()
            crit_hooks = [f for f in eng_hooks.findings if f.severity == "CRITICAL"]
            self.assertTrue(
                any(f.target == "hooks.json" and "PRE_TOOL_USE_MATCHER_TOOLS" in f.message for f in crit_hooks),
                eng_hooks.findings,
            )

            # 2. Broken Markdown #nonexistent-anchor link -> CRITICAL
            r_anc = base / "broken_anchor"
            r_anc.mkdir(parents=True)
            (r_anc / "guard.py").write_text("# guard entrypoint\n", encoding="utf-8")
            (r_anc / "GEMINI.md").write_text(
                "# Constitution\n\n## 1. Real Section\n\nSee [Missing](#nonexistent-anchor) for details.\n",
                encoding="utf-8",
            )
            eng_anc = MetaAuditEngine(r_anc)
            eng_anc.pass2_cross_references()
            crit_anc = [f for f in eng_anc.findings if f.severity == "CRITICAL"]
            self.assertTrue(
                any("#nonexistent-anchor" in f.message for f in crit_anc),
                eng_anc.findings,
            )

            # 3a. Direct nonexistent section reference (`GEMINI.md §99.9`) -> CRITICAL
            r_sec1 = base / "broken_sec_direct"
            r_sec1.mkdir(parents=True)
            (r_sec1 / "guard.py").write_text("# guard entrypoint\n", encoding="utf-8")
            (r_sec1 / "GEMINI.md").write_text("# Constitution\n\n## 1. Discourse\n\nRule text.\n", encoding="utf-8")
            (r_sec1 / "DESIGN.md").write_text(
                "# Design\n\n## 1. Layout\n\nFollow `GEMINI.md` §99.9 strictly.\n",
                encoding="utf-8",
            )
            eng_sec1 = MetaAuditEngine(r_sec1)
            eng_sec1.pass2_cross_references()
            crit_sec1 = [f for f in eng_sec1.findings if f.severity == "CRITICAL"]
            self.assertTrue(any("99.9" in f.message for f in crit_sec1), eng_sec1.findings)

            # 3b. Prose line with `.md` earlier (`"Per GEMINI.md, see §99.9"`) -> CRITICAL
            r_sec2 = base / "broken_sec_prose"
            r_sec2.mkdir(parents=True)
            (r_sec2 / "guard.py").write_text("# guard entrypoint\n", encoding="utf-8")
            (r_sec2 / "GEMINI.md").write_text("# Constitution\n\n## 1. Discourse\n\nRule text.\n", encoding="utf-8")
            (r_sec2 / "DESIGN.md").write_text(
                "# Design\n\n## 1. Layout\n\nPer GEMINI.md, see §99.9\n",
                encoding="utf-8",
            )
            eng_sec2 = MetaAuditEngine(r_sec2)
            eng_sec2.pass2_cross_references()
            crit_sec2 = [f for f in eng_sec2.findings if f.severity == "CRITICAL"]
            self.assertTrue(any("99.9" in f.message for f in crit_sec2), eng_sec2.findings)

    def test_pass7_detects_pre_invocation_inject_steps_collision(self):
        from unittest import mock

        with tempfile.TemporaryDirectory(prefix="agy_meta_p7_") as tmp_dir:
            root = Path(tmp_dir)
            (root / "guard.py").write_text("# guard entrypoint\n", encoding="utf-8")
            (root / "skills" / "demo").mkdir(parents=True)
            (root / "skills" / "demo" / "SKILL.md").write_text(
                "---\nname: demo\ndescription: Demo skill. Invoke with /demo. Not for unrelated tasks.\n---\n# Demo\n",
                encoding="utf-8",
            )
            (root / "guard").mkdir(parents=True)
            (root / "guard" / "agy_hooks.py").write_text(
                "import re\n"
                'SKILL_HINTS = (("demo", "skills/demo/SKILL.md", re.compile(r"(?:^|(?<=\\s))/demo\\b"), "Demo"),)\n'
                "ECOSYSTEM_ROUTING_HINTS = ()\n"
                "def handle_pre_invocation(payload):\n"
                '    prompt = str((payload or {}).get("prompt") or "")\n'
                '    if "Inspect src/demo/worker.py" in prompt:\n'
                '        return {"injectSteps": [{"ephemeralMessage": "[Harness Skill Hint]\\nLoad skills/demo/SKILL.md"}]}\n'
                "    return {}\n",
                encoding="utf-8",
            )

            def _mock_pre_inv(payload):
                prompt = str((payload or {}).get("prompt") or "")
                if "Inspect src/demo/worker.py" in prompt:
                    return {"injectSteps": [{"ephemeralMessage": "[Harness Skill Hint]\nLoad skills/demo/SKILL.md"}]}
                return {}

            with mock.patch("guard.agy_hooks.handle_pre_invocation", side_effect=_mock_pre_inv):
                eng = MetaAuditEngine(root)
                eng.pass7_trigger_specificity()

            crits = [f for f in eng.findings if f.severity == "CRITICAL"]
            self.assertTrue(
                any("src/demo/worker.py" in f.message for f in crits),
                eng.findings,
            )


if __name__ == "__main__":
    unittest.main()

