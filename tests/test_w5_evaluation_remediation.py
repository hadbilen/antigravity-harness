"""
tests/test_w5_evaluation_remediation.py — Regression suite for Window 5 (E-01..E-10)
Evaluation Report (2026-11-15) Remediation & Hardening.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import hermetic

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guard import agy_hooks, doctor  # noqa: E402
from guard.environment import AgentEnvironment, EnvironmentRegistry  # noqa: E402
from guard.test_boundary import TestBoundaryGuard  # noqa: E402


HOST_FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "host"


class TestW5EvaluationRemediation(unittest.TestCase):
    """Covers E-01 through E-09 from the 2026-11-15 Evaluation Report."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="w5-eval-"))
        self.home = self.tmp / "home"
        self.home.mkdir(parents=True, exist_ok=True)
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "XDG_STATE_HOME": str(self.tmp / "state"),
                "XDG_DATA_HOME": str(self.tmp / "data"),
                "ANTIGRAVITY_CONFIG_DIR": str(self.home / ".gemini" / "config"),
            },
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        hermetic.force_rmtree(self.tmp)

    def _init_git_ws(self, name: str = "ws") -> Path:
        ws = self.tmp / name
        ws.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q"], cwd=ws, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=ws, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=ws, check=True)
        (ws / "app.py").write_text("def calc():\n    return 5\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=ws, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=ws, check=True)
        return ws

    def test_e01_stop_gate_blacklist_runs_on_all_normal_reasons_and_skips_abnormal(self) -> None:
        fixture = json.loads((HOST_FIXTURES_DIR / "stop_termination_reasons.json").read_text(encoding="utf-8"))
        tautology_diff = (
            "diff --git a/tests/test_sample.py b/tests/test_sample.py\n"
            "--- a/tests/test_sample.py\n"
            "+++ b/tests/test_sample.py\n"
            "@@ -1,2 +1,3 @@\n"
            " def test_ok():\n"
            "+    assert True\n"
        )
        for idx, normal_reason in enumerate(fixture["normalTerminationReasons"]):
            res = agy_hooks.handle_stop(
                {
                    "conversationId": f"conv-norm-{idx}",
                    "terminationReason": normal_reason,
                    "diffText": tautology_diff,
                }
            )
            self.assertEqual(
                res.get("decision"),
                "continue",
                f"Expected Stop gate to run and block tautology for normal reason {normal_reason!r}",
            )
            self.assertIn("Tautological test assertion", res.get("reason", ""))

        # Non-normal stop reasons must exit cleanly ({}) and preserve in_flight state on disk
        ws = self._init_git_ws("ws_stop_preserve")
        agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-abnorm",
                "workspacePaths": [str(ws)],
                "toolCall": {"name": "write_file", "args": {"Path": str(ws / "app.py"), "Content": "x = 1\n"}},
            }
        )
        for abnormal_reason in fixture["nonNormalTerminationReasons"]:
            res_ab = agy_hooks.handle_stop(
                {
                    "conversationId": "conv-abnorm",
                    "terminationReason": abnormal_reason,
                    "workspacePaths": [str(ws)],
                    "diffText": tautology_diff,
                }
            )
            self.assertEqual(res_ab, {}, f"Expected empty dict for non-normal reason {abnormal_reason!r}")

        flight_data = json.loads((agy_hooks.state_dir() / "flight_recorder.json").read_text(encoding="utf-8"))
        ws_entry = flight_data.get(str(ws.resolve()), {})
        self.assertEqual(ws_entry.get("status"), "in_flight")

        # Subsequent normal stop ("model_stop") reconciles flight_recorder to turn_complete
        res_clean = agy_hooks.handle_stop(
            {
                "conversationId": "conv-abnorm",
                "terminationReason": "model_stop",
                "workspacePaths": [str(ws)],
                "diffText": "",
            }
        )
        self.assertEqual(res_clean, {})
        flight_after = json.loads((agy_hooks.state_dir() / "flight_recorder.json").read_text(encoding="utf-8"))
        self.assertEqual(flight_after.get(str(ws.resolve()), {}).get("status"), "turn_complete")

    def test_e02_last_user_input_extraction_and_host_fixture_replay_and_recording(self) -> None:
        text1, step1 = agy_hooks._extract_latest_user_prompt(
            {"lastUserInput": "  /diagnosing-bugs check crash  ", "stepIdx": 4}
        )
        self.assertEqual(text1, "/diagnosing-bugs check crash")
        self.assertEqual(step1, 4)

        text2, _ = agy_hooks._extract_latest_user_prompt({"last_user_input": "refactor this module"})
        self.assertEqual(text2, "refactor this module")

        preinv_fx = json.loads((HOST_FIXTURES_DIR / "pre_invocation_host.json").read_text(encoding="utf-8"))
        res_preinv = agy_hooks.dispatch_hook(preinv_fx["hookEventName"], preinv_fx["payload"])
        inject = res_preinv.get("injectSteps", [])
        inject_msg = inject[0].get("systemMessage", {}) if inject else {}
        inject_text = inject_msg.get("systemMessage", "") if isinstance(inject_msg, dict) else str(inject_msg)
        self.assertIn("diagnosing-bugs", inject_text, res_preinv)

        pretool_fx = json.loads((HOST_FIXTURES_DIR / "pre_tool_use_host.json").read_text(encoding="utf-8"))
        with mock.patch.dict(os.environ, {"AGY_RECORD_HOST_FIXTURES": "1"}):
            res_pretool = agy_hooks.dispatch_hook(
                pretool_fx["hookEventName"],
                {**pretool_fx["payload"], "apiKey": "secret-token-123"},
            )
        self.assertEqual(res_pretool, {"decision": "allow"})
        recorded_file = agy_hooks.state_dir() / "host_fixtures" / "latest_pretooluse.json"
        self.assertTrue(recorded_file.is_file())
        recorded = json.loads(recorded_file.read_text(encoding="utf-8"))
        self.assertEqual(recorded["payload"].get("apiKey"), "<redacted>")

    def test_e03_intra_turn_fast_path_and_lazy_regex_compilation(self) -> None:
        import importlib.util

        watcher_path = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
        spec = importlib.util.spec_from_file_location("upstream_watcher_w5", watcher_path)
        assert spec and spec.loader
        uw_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(uw_mod)

        self.assertEqual(uw_mod.run_hook({"invocationNum": 2}), {})
        self.assertEqual(uw_mod.run_hook({"invocation_num": 3}), {})

        ws = self._init_git_ws("ws_fastpath")
        # Turn 1: initial invocation sets __workspace_checked__ and __last_sig__
        res1 = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-fast",
                "invocationNum": 1,
                "stepIdx": 1,
                "lastUserInput": "Lütfen bu hatayı ayıkla ve kök nedeni bul.",
                "workspacePaths": [str(ws)],
            }
        )
        self.assertIn("injectSteps", res1)

        # Intra-turn step (invocationNum=2, same prompt signature): skips workspace recovery & regex scan
        with mock.patch("guard.agy_hooks._detect_workspace_recovery_hint") as m_rec:
            res2 = agy_hooks.handle_pre_invocation(
                {
                    "conversationId": "conv-fast",
                    "invocationNum": 2,
                    "stepIdx": 1,
                    "lastUserInput": "Lütfen bu hatayı ayıkla ve kök nedeni bul.",
                    "workspacePaths": [str(ws)],
                }
            )
            self.assertEqual(res2, {})
            m_rec.assert_not_called()

        # Verify _LazyRegex delays compilation while SKILL_HINTS and ECOSYSTEM_ROUTING_HINTS remain re.Pattern
        lazy_rx = agy_hooks._LazyRegex(r"^hello_\d+$")
        self.assertIsNone(lazy_rx._compiled)
        self.assertIsNotNone(lazy_rx.match("hello_42"))
        self.assertIsInstance(lazy_rx._compiled, re.Pattern)
        for _, _, s_rx, _ in agy_hooks.SKILL_HINTS:
            self.assertIsInstance(s_rx, re.Pattern)
        for _, r_rx, _ in agy_hooks.ECOSYSTEM_ROUTING_HINTS:
            self.assertIsInstance(r_rx, re.Pattern)

    def test_e04_top_level_gemini_md_shield_and_workspace_hooks_collision_gate(self) -> None:
        # 1. Direct write or shell mutation to ~/.gemini/GEMINI.md or ~/.gemini/AGENTS.md -> deny
        for target in ("~/.gemini/GEMINI.md", "~/.gemini/AGENTS.md"):
            res_w = agy_hooks.handle_pre_tool_use(
                {
                    "modelName": "gemini-4-argon-high",
                    "effort": "high",
                    "toolCall": {"name": "write_file", "args": {"Path": target, "Content": "# hijacked\n"}},
                }
            )
            self.assertEqual(res_w.get("decision"), "deny", target)
            self.assertIn("Harness Governance Shield", res_w.get("reason", ""))

        for cmd in (
            "echo 'x' >> ~/.gemini/GEMINI.md",
            "rm -f ~/.gemini/AGENTS.md",
            "python3 -c \"from pathlib import Path; (Path.home() / '.gemini' / 'GEMINI.md').write_text('x')\"",
        ):
            res_c = agy_hooks.handle_pre_tool_use(
                {
                    "modelName": "gemini-4-argon-high",
                    "effort": "high",
                    "toolCall": {"name": "run_command", "args": {"CommandLine": cmd}},
                }
            )
            self.assertEqual(res_c.get("decision"), "deny", cmd)

        # 2. Writing to workspace .agents/hooks.json with content or workspace scope -> force_ask
        ws = self._init_git_ws("ws_hooks_col")
        res_hooks = agy_hooks.handle_pre_tool_use(
            {
                "modelName": "gemini-4-argon-high",
                "effort": "high",
                "workspacePaths": [str(ws)],
                "toolCall": {
                    "name": "write_file",
                    "args": {
                        "Path": str(ws / ".agents" / "hooks.json"),
                        "Content": '{"harness-gate": {"enabled": false}}',
                    },
                },
            }
        )
        self.assertEqual(res_hooks.get("decision"), "force_ask")
        self.assertIn(".agents/hooks.json", res_hooks.get("reason", ""))

        # 3. guard/doctor.py warns on top-level .gemini/GEMINI.md and colliding .agents/hooks.json
        gemini_dir = self.home / ".gemini"
        cfg_root = gemini_dir / "config"
        cfg_root.mkdir(parents=True, exist_ok=True)
        (cfg_root / "GEMINI.md").write_text("# canonical\n", encoding="utf-8")
        (gemini_dir / "GEMINI.md").write_text("# shadow\n", encoding="utf-8")
        ws_agents = ws / ".agents"
        ws_agents.mkdir(parents=True, exist_ok=True)
        (ws_agents / "hooks.json").write_text('{"harness-gate": {}}', encoding="utf-8")

        reg = EnvironmentRegistry()
        env = AgentEnvironment(
            id="antigravity",
            name="Antigravity Global Config",
            platform_type="antigravity",
            root_path=str(cfg_root),
            policy="enforced",
            is_global=True,
        )
        ws_env = AgentEnvironment(
            id="ws-proj",
            name="Workspace Project",
            platform_type="antigravity",
            root_path=str(ws),
            policy="monitored",
            is_global=False,
        )
        with mock.patch.object(reg, "list_environments", return_value=[env, ws_env]):
            doc_rep = doctor.diagnose(env, reg, sentinel_active=True)
        self.assertTrue(
            any("Top-level" in w and "GEMINI.md" in w for w in doc_rep.warnings),
            doc_rep.warnings,
        )
        self.assertTrue(
            any(".agents/hooks.json" in w and "harness-gate" in w for w in doc_rep.warnings),
            doc_rep.warnings,
        )

    def test_e05_expanded_bash_guard_destructive_patterns(self) -> None:
        ws = self._init_git_ws("ws_bash")
        outside_dir = Path("/opt/agy_w5_outside_important_data")
        force_ask_cmds = [
            f"rm -rf {outside_dir}",
            f"mv {ws / 'app.py'} {outside_dir / 'app.py'}",
            "git branch -D feature/old",
            "git branch --delete --force feature/old",
            "git stash drop",
            "git stash clear",
            "find . -name '*.bak' -delete",
            "find /var/tmp -type f -exec rm -f {} +",
            "dropdb production_db",
            'psql -c "DROP TABLE users;"',
            'psql -c "TRUNCATE TABLE audit_logs;"',
            'sqlite3 app.db "DELETE FROM accounts;"',
            "docker system prune -af",
            "docker volume prune --all",
            "chmod -R 777 build",
        ]
        for cmd in force_ask_cmds:
            res = agy_hooks.handle_pre_tool_use(
                {
                    "workspacePaths": [str(ws)],
                    "toolCall": {"name": "run_command", "args": {"CommandLine": cmd, "Cwd": str(ws)}},
                }
            )
            self.assertEqual(res.get("decision"), "force_ask", f"Expected force_ask for: {cmd!r}, got {res}")

        # Safe workspace-local and /tmp commands must remain allowed
        safe_cmds = [
            "rm -rf build/cache",
            "rm -rf /tmp/agy_safe_scratch_dir",
            "mv app.py app_renamed.py",
            "git branch -d merged_branch",
            'sqlite3 app.db "DELETE FROM sessions WHERE expired = 1;"',
            "find . -name '*.py' -print",
            "chmod 755 app.py",
        ]
        for cmd in safe_cmds:
            res_ok = agy_hooks.handle_pre_tool_use(
                {
                    "workspacePaths": [str(ws)],
                    "toolCall": {"name": "run_command", "args": {"CommandLine": cmd, "Cwd": str(ws)}},
                }
            )
            self.assertEqual(res_ok, {"decision": "allow"}, f"Expected allow for safe cmd: {cmd!r}")

    def test_e06_design_md_scoped_to_harness_and_future_flagship_force_ask(self) -> None:
        ws_ext = self._init_git_ws("ws_external_app")
        # Non-harness workspace: editing DESIGN.md on Flash is allowed
        res_ext = agy_hooks.handle_pre_tool_use(
            {
                "modelName": "gemini-3-flash",
                "workspacePaths": [str(ws_ext)],
                "toolCall": {
                    "name": "write_file",
                    "args": {"Path": str(ws_ext / "DESIGN.md"), "Content": "# App Design\n"},
                },
            }
        )
        self.assertEqual(res_ext, {"decision": "allow"})

        # Harness repository scope: editing DESIGN.md on Flash is still denied
        res_har = agy_hooks.handle_pre_tool_use(
            {
                "modelName": "gemini-3-flash",
                "workspacePaths": [str(REPO_ROOT)],
                "toolCall": {
                    "name": "write_file",
                    "args": {"Path": str(REPO_ROOT / "DESIGN.md"), "Content": "# Harness Design\n"},
                },
            }
        )
        self.assertEqual(res_har.get("decision"), "deny")

        # Unrecognized future flagship model at verified high effort -> force_ask
        for future_payload in (
            {"modelName": "Gemini 5 Titan (High)", "effort": "high"},
            {"modelName": "Claude Opus 6 (High)", "effort": "1.00"},
            {"modelName": "gemini-5-ultra-xhigh"},
        ):
            res_fut = agy_hooks.handle_pre_tool_use(
                {
                    **future_payload,
                    "toolCall": {"name": "edit_file", "args": {"Path": "GEMINI.md"}},
                }
            )
            self.assertEqual(res_fut.get("decision"), "force_ask", future_payload)
            self.assertIn("not yet listed in `upstream_state.seed.json`", res_fut.get("reason", ""))

        # Known non-flagships or low effort on future model -> deny
        for deny_payload in (
            {"modelName": "Gemini 5 Flash (High)", "effort": "high"},
            {"modelName": "Gemini 5 Titan", "effort": "medium"},
            {"modelName": "Claude Sonnet 6 (High)", "effort": "high"},
        ):
            res_den = agy_hooks.handle_pre_tool_use(
                {
                    **deny_payload,
                    "toolCall": {"name": "edit_file", "args": {"Path": "GEMINI.md"}},
                }
            )
            self.assertEqual(res_den.get("decision"), "deny", deny_payload)

    def test_e07_skill_frontmatter_compaction_and_operator_summary_rules(self) -> None:
        total_desc_chars = 0
        for p in sorted((REPO_ROOT / "skills").glob("*/SKILL.md")):
            txt = p.read_text(encoding="utf-8")
            m = re.match(r"^---\n(.*?)\n---", txt, re.S)
            self.assertIsNotNone(m, f"Missing YAML frontmatter in {p}")
            m_desc = re.search(r"^description:(.*?)(?=^\w[\w-]*:|\Z)", m.group(1), re.S | re.M)
            self.assertIsNotNone(m_desc, f"Missing description in {p}")
            total_desc_chars += len(m_desc.group(1))
        # Pre-W5 baseline was 20,433 description chars across skills/*/SKILL.md
        self.assertLess(total_desc_chars, 16000, f"Expected compacted descriptions < 16,000 chars, got {total_desc_chars}")

        harness_md = (REPO_ROOT / "skills" / "harness" / "SKILL.md").read_text(encoding="utf-8")
        audit_md = (REPO_ROOT / "skills" / "audit" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Operatör Özeti", harness_md)
        self.assertIn("Claude Opus 5.5 (High)", harness_md)
        self.assertIn("Operatör Özeti", audit_md)
        self.assertIn("Claude Opus 5.5 (High)", audit_md)

    def test_e08_shell_mutation_flight_recorder_and_assertion_relaxation_detection(self) -> None:
        ws = self._init_git_ws("ws_shell_flight")
        res_cmd = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-shell-mut",
                "workspacePaths": [str(ws)],
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "sed -i 's/5/6/' app.py", "Cwd": str(ws)},
                },
            }
        )
        self.assertEqual(res_cmd, {"decision": "allow"})
        flight_data = json.loads((agy_hooks.state_dir() / "flight_recorder.json").read_text(encoding="utf-8"))
        ws_entry = flight_data.get(str(ws.resolve()), {})
        self.assertEqual(ws_entry.get("status"), "in_flight")
        self.assertEqual(ws_entry.get("last_tool"), "run_command")

        # Diff-level assertion relaxation detection (Python pytest, unittest, and JS expect)
        relaxed_diffs = [
            (
                "diff --git a/tests/test_calc.py b/tests/test_calc.py\n"
                "--- a/tests/test_calc.py\n"
                "+++ b/tests/test_calc.py\n"
                "@@ -2,1 +2,1 @@\n"
                "-    assert calc() == 5\n"
                "+    assert calc() >= 5\n"
            ),
            (
                "diff --git a/tests/test_calc.py b/tests/test_calc.py\n"
                "--- a/tests/test_calc.py\n"
                "+++ b/tests/test_calc.py\n"
                "@@ -2,1 +2,1 @@\n"
                "-    assert calc() == 5\n"
                "+    assert calc() is not None\n"
            ),
            (
                "diff --git a/tests/test_calc.py b/tests/test_calc.py\n"
                "--- a/tests/test_calc.py\n"
                "+++ b/tests/test_calc.py\n"
                "@@ -2,1 +2,1 @@\n"
                "-        self.assertEqual(resp.status_code, 200)\n"
                "+        self.assertGreaterEqual(resp.status_code, 200)\n"
            ),
            (
                "diff --git a/tests/calc.test.ts b/tests/calc.test.ts\n"
                "--- a/tests/calc.test.ts\n"
                "+++ b/tests/calc.test.ts\n"
                "@@ -2,1 +2,1 @@\n"
                "-  expect(calc()).toBe(5);\n"
                "+  expect(calc()).toBeTruthy();\n"
            ),
        ]
        for diff_str in relaxed_diffs:
            findings = agy_hooks.inspect_git_diff(diff_str)
            self.assertTrue(
                any("Unapproved test assertion relaxation" in f for f in findings),
                f"Expected assertion relaxation finding for diff:\n{diff_str}\nGot: {findings}",
            )

        # AST-level TestBoundaryGuard.python_weakening detection
        old_py = "def test_math():\n    assert calc() == 5\n"
        for new_py in (
            "def test_math():\n    assert calc() >= 5\n",
            "def test_math():\n    assert calc() != 0\n",
            "def test_math():\n    assert calc() is not None\n",
            "def test_math():\n    assert calc()\n",
        ):
            notes = TestBoundaryGuard.python_weakening(old_py, new_py)
            self.assertTrue(
                any("relaxes strict equality assertion" in n for n in notes),
                f"Expected AST relaxation note for:\n{new_py}\nGot: {notes}",
            )

    def test_e09_command_mutates_governance_no_false_positive_on_repo_path(self) -> None:
        benign_cmd = (
            'python3 -c "'
            "from pathlib import Path; "
            "p = Path('/home/tugay/Projeler/antigravity-harness/README.md'); "
            "print(p.read_text().replace('a', 'b')[:10])"
            '"'
        )
        self.assertFalse(agy_hooks._command_mutates_governance(benign_cmd))

        real_gov_cmd = (
            'python3 -c "'
            "from pathlib import Path; "
            "p = Path.home() / '.local' / 'state' / 'antigravity-harness' / 'leases.json'; "
            "p.write_text('{}')"
            '"'
        )
        self.assertTrue(agy_hooks._command_mutates_governance(real_gov_cmd))


if __name__ == "__main__":
    unittest.main()
