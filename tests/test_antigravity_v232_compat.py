"""
tests/test_antigravity_v232_compat.py — Regression seam tests for Antigravity v2.32.0
compatibility, hook schema modernization, `/swarm` governance, and Knowledge Work hygiene.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
for _p in (str(TESTS_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hermetic  # noqa: E402,F401  (isolates HOME/state before anything else is imported)

from guard import agy_hooks  # noqa: E402


class TestAntigravityV232ModelAndBuiltinSeed(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_v232_m_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_v232_flagships_and_orchestrator_highest_effort_pass(self) -> None:
        from unittest import mock

        # Live restricted seed allows strictly Gemini 4 Neon (XHigh) and Gemini 4 Carbon (High)
        live_passing_cases = [
            {"modelName": "Gemini 4 Neon (XHigh)", "effort": "xhigh"},
            {"modelName": "Gemini 4 Neon", "effort": "xhigh"},
            {"modelName": "Gemini 4 Neon", "effort": "extra"},
            {"modelName": "Gemini 4 Carbon (High)", "effort": "high"},
            {"modelName": "Gemini 4 Carbon (High)", "effort": "xhigh"},
            {"modelName": "Gemini 4 Carbon", "effort": "high"},
        ]
        for payload in live_passing_cases:
            with self.subTest(live_allow=payload):
                self.assertIsNone(agy_hooks._evaluate_customization_model_and_effort(payload))
                res = agy_hooks.handle_pre_tool_use(
                    {
                        **payload,
                        "toolCall": {"name": "edit_file", "args": {"Path": "GEMINI.md"}},
                    }
                )
                self.assertEqual(res.get("decision"), "allow", (payload, res))

        # Removed/unlisted flagships fail closed with force_ask; non-allowlisted orchestrators deny
        for payload in (
            {"modelName": "Gemini 4 Hydrogen (XHigh)", "effort": "xhigh"},
            {"modelName": "Gemini 4 Argon (High)", "effort": "high"},
            {"modelName": "Claude Opus 5.5 (High)", "effort": "high"},
        ):
            with self.subTest(live_unlisted=payload):
                verdict = agy_hooks._evaluate_customization_model_and_effort(payload)
                self.assertIsNotNone(verdict)
                self.assertEqual(verdict[0], "force_ask", (payload, verdict))

        # Preserve full Orchestrator/peer-flagship parser coverage using an isolated temporary seed
        fake_repo = self.tmp / "orchestrator_seed_repo"
        seed_dir = fake_repo / "skills" / "upstream-auditor"
        seed_dir.mkdir(parents=True, exist_ok=True)
        (seed_dir / "upstream_state.seed.json").write_text(
            json.dumps(
                {
                    "last_audited_model": "Gemini 4 Neon (XHigh)",
                    "last_model_slug": "gemini-4-neon-xhigh",
                    "approved_customization_models": [
                        "gemini-4-neon-xhigh",
                        "gemini-4-carbon-high",
                        "gemini-4-carbon-xhigh",
                        "gemini-4-hydrogen-xhigh",
                        "gemini-4-argon-high",
                        "claude-opus-5.5-high",
                        "orchestrator-carbon-high",
                        "orchestrator-carbon-xhigh",
                        "orchestrator-argon-high",
                        "orchestrator-argon-xhigh",
                    ],
                }
            ),
            encoding="utf-8",
        )
        isolated_passing_cases = [
            {"modelName": "Gemini 4 Carbon (XHigh)", "effort": "xhigh"},
            {"modelName": "Gemini 4 Hydrogen (XHigh)", "effort": "xhigh"},
            {"modelName": "Gemini 4 Hydrogen", "effort": "extra"},
            {"modelName": "Gemini 4 Argon (High)", "effort": "high"},
            {"modelName": "Claude Opus 5.5 (High)", "effort": "high"},
            {"modelName": "Orchestrator (Carbon)", "effort": "high"},
            {"modelName": "Orchestrator (Carbon)", "effort": "xhigh"},
            {"modelName": "Orchestrator (Argon)", "effort": "high"},
            {"modelName": "Orchestrator (Argon)", "effort": "xhigh"},
            {"modelName": "Orchestrator (Carbon) (High)"},
            {"modelName": "Orchestrator (Carbon, High)"},
            {"modelName": "Orchestrator (Argon, XHigh)"},
        ]
        with mock.patch.object(agy_hooks, "REPO_ROOT", fake_repo):
            for payload in isolated_passing_cases:
                with self.subTest(isolated_allow=payload):
                    self.assertIsNone(agy_hooks._evaluate_customization_model_and_effort(payload))
                    res = agy_hooks.handle_pre_tool_use(
                        {
                            **payload,
                            "toolCall": {"name": "edit_file", "args": {"Path": "GEMINI.md"}},
                        }
                    )
                    self.assertEqual(res.get("decision"), "allow", (payload, res))

    def test_v232_downgrades_and_unverified_orchestrator_deny(self) -> None:
        deny_cases = [
            {"modelName": "Gemini 4 Carbon", "effort": "low"},
            {"modelName": "Gemini 4 Carbon", "effort": "medium"},
            {"modelName": "Gemini 4 Carbon (Low)", "effort": "low"},
            {"modelName": "Gemini 4 Neon (Low)", "effort": "low"},
            {"modelName": "Gemini 4 Hydrogen (Low)", "effort": "low"},
            {"modelName": "Orchestrator (Carbon)"},
            {"modelName": "Orchestrator (Carbon)", "effort": "low"},
            {"modelName": "Orchestrator (Carbon)", "effort": "medium"},
            {"modelName": "Orchestrator (Argon)"},
            {"modelName": "Orchestrator (Argon)", "effort": "low"},
            {"modelName": "Orchestrator (Carbon, Low)"},
            {"modelName": "Orchestrator", "effort": "high"},
            {"modelName": "Orchestrator (Flash)", "effort": "high"},
        ]
        for payload in deny_cases:
            with self.subTest(payload=payload):
                verdict = agy_hooks._evaluate_customization_model_and_effort(payload)
                self.assertIsNotNone(verdict)
                self.assertEqual(verdict[0], "deny", (payload, verdict))
                res = agy_hooks.handle_pre_tool_use(
                    {
                        **payload,
                        "toolCall": {"name": "edit_file", "args": {"Path": "GEMINI.md"}},
                    }
                )
                self.assertEqual(res.get("decision"), "deny", (payload, res))

    def test_orchestrator_carbon_transcript_embedded_and_separate_effort(self) -> None:
        from unittest import mock

        tx_comma = self.tmp / "tx_comma.jsonl"
        tx_comma.write_text(
            json.dumps(
                {
                    "type": "USER_INPUT",
                    "source": "USER_EXPLICIT",
                    "content": (
                        "<USER_REQUEST>update rule</USER_REQUEST>\n"
                        "<USER_SETTINGS_CHANGE>\n"
                        "The user changed setting `Model Selection` from None to Orchestrator (Carbon, High).\n"
                        "</USER_SETTINGS_CHANGE>"
                    ),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual(
            agy_hooks._extract_transcript_model_and_effort({"transcriptPath": str(tx_comma)}),
            ("Orchestrator (Carbon, High)", "high"),
        )
        # Restricted live seed denies Orchestrator (Carbon, High)
        live_verdict = agy_hooks._evaluate_customization_model_and_effort({"transcriptPath": str(tx_comma)})
        self.assertIsNotNone(live_verdict)
        self.assertEqual(live_verdict[0], "deny", live_verdict)
        # Isolated seed approving orchestrator-carbon-high still allows the comma-embedded syntax
        fake_repo = self.tmp / "orch_tx_repo"
        seed_dir = fake_repo / "skills" / "upstream-auditor"
        seed_dir.mkdir(parents=True, exist_ok=True)
        (seed_dir / "upstream_state.seed.json").write_text(
            json.dumps(
                {
                    "last_audited_model": "Gemini 4 Neon (XHigh)",
                    "last_model_slug": "gemini-4-neon-xhigh",
                    "approved_customization_models": ["gemini-4-neon-xhigh", "orchestrator-carbon-high"],
                }
            ),
            encoding="utf-8",
        )
        with mock.patch.object(agy_hooks, "REPO_ROOT", fake_repo):
            self.assertIsNone(agy_hooks._evaluate_customization_model_and_effort({"transcriptPath": str(tx_comma)}))

        tx_low = self.tmp / "tx_low.jsonl"
        tx_low.write_text(
            json.dumps(
                {
                    "type": "USER_INPUT",
                    "source": "USER_EXPLICIT",
                    "content": (
                        "<USER_REQUEST>update rule</USER_REQUEST>\n"
                        "<USER_SETTINGS_CHANGE>\n"
                        "The user changed setting `Model Selection` from None to Orchestrator (Carbon, Low).\n"
                        "</USER_SETTINGS_CHANGE>"
                    ),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual(
            agy_hooks._extract_transcript_model_and_effort({"transcriptPath": str(tx_low)}),
            ("Orchestrator (Carbon, Low)", "low"),
        )
        verdict = agy_hooks._evaluate_customization_model_and_effort({"transcriptPath": str(tx_low)})
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict[0], "deny")

    def test_seed_approved_models_have_highest_effort_suffix_and_14_builtin_skills(self) -> None:
        seed_path = REPO_ROOT / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        seed = json.loads(seed_path.read_text(encoding="utf-8"))

        approved = seed.get("approved_customization_models", [])
        self.assertIsInstance(approved, list)
        self.assertTrue(approved)
        for slug in approved:
            self.assertIsInstance(slug, str)
            self.assertTrue(
                slug.endswith(agy_hooks._HIGHEST_EFFORT_SLUG_SUFFIXES),
                f"Unsuffixed or non-highest-effort peer slug forbidden by Rule 17: {slug}",
            )
        self.assertEqual(approved, ["gemini-4-neon-xhigh", "gemini-4-carbon-high"])

        expected_builtins = sorted(
            [
                "agy-customizations",
                "antigravity_guide",
                "automation",
                "generative_ui",
                "mcp-app-development",
                "migrate-agent-settings",
                "migrate-workflows",
                "native_swarm",
                "permissioned-github",
                "plugin",
                "run-workflow",
                "swarm_monitor",
                "swarm_narrator",
                "swarm_pane",
                "ui-plugin-navigation",
            ]
        )
        self.assertEqual(seed.get("recorded_builtin_skills"), expected_builtins)
        self.assertEqual(len(seed.get("recorded_builtin_skills", [])), 15)
        self.assertRegex(str(seed.get("builtin_skills_hash", "")), r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            seed.get("builtin_skills_hash"),
            "de9b7f32b1ca0f839bf78c59c6f479362ed7d3edce0da0a02579cc003df4798f",
        )

        # Guard fallback and upstream_watcher constants must stay aligned with the 15-skill seed
        from guard import upstream as guard_upstream
        import importlib.util

        self.assertEqual(list(guard_upstream.KNOWN_BUILTIN_SKILLS), expected_builtins)
        watcher_path = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
        wspec = importlib.util.spec_from_file_location("_v232_watcher_seed", watcher_path)
        assert wspec and wspec.loader
        wmod = importlib.util.module_from_spec(wspec)
        wspec.loader.exec_module(wmod)
        self.assertEqual(list(wmod.KNOWN_BUILTIN_SKILLS), expected_builtins)

    def test_w2_swarm_ecosystem_alignment_session_start_and_progressive_disclosure(self) -> None:
        # 1. hooks.json registers upstream-watchdog under SessionStart, never PreInvocation
        hooks_data = json.loads((REPO_ROOT / "hooks.json").read_text(encoding="utf-8"))
        uw = hooks_data.get("upstream-watchdog", {})
        self.assertIn("SessionStart", uw)
        self.assertTrue(isinstance(uw["SessionStart"], list) and uw["SessionStart"])
        self.assertNotIn("PreInvocation", uw)

        # 2. model-calibration-matrix.md reflects A1 (Pro-class Orchestrator force_ask, Flash deny)
        matrix_txt = (
            REPO_ROOT / "skills" / "upstream-auditor" / "references" / "model-calibration-matrix.md"
        ).read_text(encoding="utf-8")
        self.assertIn("force_ask", matrix_txt)
        self.assertIn("gemini-4-neon-xhigh", matrix_txt)
        self.assertIn("gemini-4-carbon-high", matrix_txt)
        self.assertIn("swarm_pane", matrix_txt)

        # 3. harness/SKILL.md progressive disclosure (<= 28 KB) & AC-3 Swarm alignment across docs
        harness_skill = REPO_ROOT / "skills" / "harness" / "SKILL.md"
        harness_bytes = harness_skill.stat().st_size
        self.assertLessEqual(harness_bytes, 28672, f"skills/harness/SKILL.md is {harness_bytes} bytes (> 28 KB)")
        harness_txt = harness_skill.read_text(encoding="utf-8")
        self.assertIn("references/context-and-artifacts.md", harness_txt)
        self.assertIn("references/multi-agent-orchestration.md", harness_txt)
        self.assertTrue((REPO_ROOT / "skills" / "harness" / "references" / "context-and-artifacts.md").is_file())
        self.assertTrue((REPO_ROOT / "skills" / "harness" / "references" / "multi-agent-orchestration.md").is_file())

        self.assertIn("references/multi-agent-orchestration.md", harness_txt)
        self.assertIn("§5", harness_txt)
        self.assertNotIn("swarm_pane", harness_txt)
        for rel_doc in (
            "skills/harness/references/multi-agent-orchestration.md",
            "skills/harness/references/marathon.md",
            "skills/harness/references/unlazy/references/dispatch.md",
        ):
            doc_txt = (REPO_ROOT / rel_doc).read_text(encoding="utf-8")
            with self.subTest(doc=rel_doc):
                self.assertIn("swarm_pane", doc_txt)
                self.assertIn(".system_generated/swarm/plan.json", doc_txt)
                self.assertIn("*/3 * * * *", doc_txt)
                self.assertIn("IsDaemon: true", doc_txt)


class TestAntigravityV232HookModernization(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_v232_hook_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pre_invocation_emits_nested_system_message_never_ephemeral(self) -> None:
        res = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "v232-sysmsg-1",
                "workspace": str(self.tmp),
                "prompt": "Please run /audit --strict on the schema.",
            }
        )
        steps = res.get("injectSteps", [])
        self.assertEqual(len(steps), 1, res)
        step = steps[0]
        self.assertNotIn("ephemeralMessage", step)
        self.assertIn("systemMessage", step)
        sm = step["systemMessage"]
        self.assertIsInstance(sm, dict)
        self.assertIn("`audit`", str(sm.get("systemMessage") or ""))

    def test_upstream_watcher_uses_operator_only_user_markdown_with_empty_model_system_message(self) -> None:
        import importlib.util
        import contextlib
        import io
        from unittest import mock

        watcher_path = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
        spec = importlib.util.spec_from_file_location("_v232_watcher", watcher_path)
        assert spec and spec.loader
        watcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(watcher)

        cfg = self.tmp / "cfg"
        skill_dir = cfg / "skills" / "upstream-auditor"
        skill_dir.mkdir(parents=True)
        seed_path = self.tmp / "seed.json"
        seed_path.write_text(
            json.dumps(
                {
                    "last_audited_model": "Gemini 4 Hydrogen (XHigh)",
                    "last_model_slug": "gemini-4-hydrogen-xhigh",
                    "builtin_skills_hash": "0" * 64,
                    "recorded_builtin_skills": ["agy-customizations"],
                    "tracked_repositories": {},
                }
            ),
            encoding="utf-8",
        )
        builtins_dir = self.tmp / "builtins"
        (builtins_dir / "agy-customizations").mkdir(parents=True)
        ((builtins_dir / "agy-customizations") / "SKILL.md").write_text("# agy\n", encoding="utf-8")
        (builtins_dir / "new-v232-skill").mkdir(parents=True)
        ((builtins_dir / "new-v232-skill") / "SKILL.md").write_text("# new\n", encoding="utf-8")

        with mock.patch.object(watcher, "BUILTIN_DIR", str(builtins_dir)), mock.patch.object(
            watcher, "CUSTOM_SKILLS_DIR", str(cfg / "skills")
        ), mock.patch.object(
            watcher, "LEGACY_STATE_FILE", str(self.tmp / "none_legacy.json")
        ), mock.patch.object(
            watcher, "SEED_STATE_FILE", str(seed_path)
        ), mock.patch.object(
            watcher, "BUNDLED_SEED_FILE", str(seed_path)
        ), mock.patch.object(watcher, "STATE_FILE", str(self.tmp / "state" / "upstream_state.json")), mock.patch.object(
            watcher, "CONFIG_DIR", str(cfg)
        ), mock.patch.dict("os.environ", {"PLUMB_GUARD_NOTIFY": "off"}):
            out = watcher.run_hook({"invocationNum": 1, "modelName": "Gemini 4 Hydrogen (XHigh)", "conversationId": "w-1"})

        steps = out.get("injectSteps", [])
        self.assertEqual(len(steps), 1, out)
        step = steps[0]
        self.assertNotIn("ephemeralMessage", step)
        sm = step.get("systemMessage")
        self.assertIsInstance(sm, dict)
        self.assertEqual(sm.get("systemMessage"), "")
        md = ((sm.get("metadata") or {}).get("user_markdown") if isinstance(sm, dict) else "") or ""
        self.assertIn("[UPSTREAM WATCHDOG", md)

    def test_meta_audit_extract_pre_invocation_text_supports_nested_system_message(self) -> None:
        from scripts.meta_audit import MetaAuditEngine

        nested = {"injectSteps": [{"systemMessage": {"systemMessage": "[Harness Skill Hint] audit"}}]}
        text = MetaAuditEngine._extract_pre_invocation_text(nested)
        self.assertIn("[Harness Skill Hint] audit", text)

        user_only = {
            "injectSteps": [
                {"systemMessage": {"systemMessage": "", "metadata": {"user_markdown": "[Upstream Watchdog] notice"}}}
            ]
        }
        self.assertEqual(MetaAuditEngine._extract_pre_invocation_text(user_only), "")

    def test_stop_handles_continuation_active_and_fully_idle_without_suppressing_violations(self) -> None:
        clean_diff = "+++ b/src/ok.py\n+def ok() -> int:\n+    return 1\n"
        dirty_diff = "+++ b/tests/test_sample.py\n+    assert x == x\n"

        # Clean diff returns {} even if continuationActive=True or fullyIdle=False
        self.assertEqual(
            agy_hooks.handle_stop(
                {
                    "conversationId": "stop-clean-cont",
                    "terminationReason": "NO_TOOL_CALL",
                    "continuationActive": True,
                    "fullyIdle": False,
                    "diffText": clean_diff,
                }
            ),
            {},
        )

        # Violations must NEVER be suppressed when continuationActive=True or fullyIdle=False
        res_cont = agy_hooks.handle_stop(
            {
                "conversationId": "stop-dirty-cont",
                "terminationReason": "NO_TOOL_CALL",
                "continuationActive": True,
                "executionNum": 1,
                "fullyIdle": False,
                "diffText": dirty_diff,
            }
        )
        self.assertEqual(res_cont.get("decision"), "continue", res_cont)
        self.assertIn("fullyIdle=false", str(res_cont.get("reason") or ""))


class TestAntigravityV232SwarmAndRouting(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_v232_swarm_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_swarm_in_matcher_and_hooks_json(self) -> None:
        self.assertIn("swarm", agy_hooks.PRE_TOOL_USE_MATCHER_TOOLS)
        repo_hooks = json.loads((REPO_ROOT / "hooks.json").read_text(encoding="utf-8"))
        matcher = repo_hooks["harness-gate"]["PreToolUse"][0]["matcher"]
        self.assertIn("swarm", matcher.split("|"))

    def test_swarm_blocks_downgrades_and_two_step_cust_bypass_while_allowing_top_and_readonly(self) -> None:
        deny_cases = [
            (
                "add_flash_customization",
                {
                    "conversationId": "sw-deny-1",
                    "modelName": "Gemini 4 Neon (XHigh)",
                    "effort": "xhigh",
                    "workspacePath": str(REPO_ROOT),
                    "toolCall": {
                        "name": "swarm",
                        "args": {
                            "action": "add",
                            "name": "rules-editor",
                            "model": "flash",
                            "brief": "Update GEMINI.md and guard/agy_hooks.py",
                        },
                    },
                },
            ),
            (
                "add_flash_lite_via_tasks",
                {
                    "conversationId": "sw-deny-2",
                    "modelName": "Gemini 4 Carbon (High)",
                    "effort": "high",
                    "workspacePath": str(REPO_ROOT),
                    "toolCall": {
                        "name": "swarm",
                        "args": {
                            "action": "add",
                            "name": "skill-editor",
                            "model": "flash_lite",
                            "brief": "Process list items cleanly",
                            "tasks": ["skills/audit/SKILL.md"],
                        },
                    },
                },
            ),
            (
                "parent_low_model_inherit_swarm",
                {
                    "conversationId": "sw-deny-3",
                    "modelName": "gemini-3-flash",
                    "workspacePath": str(REPO_ROOT),
                    "toolCall": {
                        "name": "swarm",
                        "args": {
                            "action": "add",
                            "name": "guard-editor",
                            "brief": "Refactor porter.py manifest engine",
                        },
                    },
                },
            ),
            (
                "action_model_flash_in_harness_repo",
                {
                    "conversationId": "sw-deny-4",
                    "modelName": "Gemini 4 Neon (XHigh)",
                    "effort": "xhigh",
                    "workspacePath": str(REPO_ROOT),
                    "toolCall": {
                        "name": "swarm",
                        "args": {"action": "model", "name": "rules-editor", "model": "flash"},
                    },
                },
            ),
        ]
        for label, payload in deny_cases:
            with self.subTest(case=label):
                res = agy_hooks.handle_pre_tool_use(payload)
                self.assertEqual(res.get("decision"), "deny", (label, res))

        # Two-step bypass inside a harness checkout: add cust worker without model, then switch its model to flash
        two_step_ws = self.tmp / "two_step_harness"
        (two_step_ws / ".harness").mkdir(parents=True, exist_ok=True)
        (two_step_ws / ".harness" / "manifest.json").write_text("{}", encoding="utf-8")
        conv = "sw-two-step"
        add_ok = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": conv,
                "modelName": "Gemini 4 Neon (XHigh)",
                "effort": "xhigh",
                "workspacePath": str(two_step_ws),
                "toolCall": {
                    "name": "swarm",
                    "args": {
                        "action": "add",
                        "name": "cfg-worker",
                        "brief": "Edit .agents/skills/custom/SKILL.md",
                    },
                },
            }
        )
        self.assertEqual(add_ok, {"decision": "allow"})
        switch_deny = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": conv,
                "modelName": "Gemini 4 Neon (XHigh)",
                "effort": "xhigh",
                "workspacePath": str(two_step_ws),
                "toolCall": {
                    "name": "swarm",
                    "args": {"action": "model", "name": "cfg-worker", "model": "flash_lite"},
                },
            }
        )
        self.assertEqual(switch_deny.get("decision"), "deny", switch_deny)

        # Allowed controls: status, models, kill, title, standard worker, top-model cust worker
        allow_cases = [
            {"action": "status"},
            {"action": "models"},
            {"action": "title", "title": "v2.32 audit"},
            {"action": "kill", "name": "worker-1"},
            {"action": "add", "name": "parser", "brief": "Fix src/parser.rs"},
            {"action": "add", "name": "rules", "brief": "Update GEMINI.md"},
        ]
        for args in allow_cases:
            with self.subTest(allow_args=args):
                res = agy_hooks.handle_pre_tool_use(
                    {
                        "conversationId": "sw-allow",
                        "modelName": "Gemini 4 Carbon (High)",
                        "effort": "high",
                        "workspacePath": str(REPO_ROOT),
                        "toolCall": {"name": "swarm", "args": args},
                    }
                )
                self.assertEqual(res, {"decision": "allow"}, (args, res))

    def test_v232_ecosystem_routing_and_gemini_rule15_budget(self) -> None:
        r_swarm = agy_hooks.handle_pre_invocation(
            {"conversationId": "eco-swarm-1", "prompt": "Run /swarm with parallel workers for these modules."}
        )
        msg_swarm = r_swarm.get("injectSteps", [{}])[0].get("systemMessage", {}).get("systemMessage", "")
        self.assertIn("native_swarm", msg_swarm)

        r_mig = agy_hooks.handle_pre_invocation(
            {"conversationId": "eco-mig-1", "prompt": "Use migrate-agent-settings to import Cursor rules and MCP servers."}
        )
        msg_mig = r_mig.get("injectSteps", [{}])[0].get("systemMessage", {}).get("systemMessage", "")
        self.assertIn("migrate-agent-settings", msg_mig)

        r_mcp_app = agy_hooks.handle_pre_invocation(
            {"conversationId": "eco-mcpapp-1", "prompt": "Build an interactive mcp-app-development UI resource."}
        )
        msg_mcp_app = r_mcp_app.get("injectSteps", [{}])[0].get("systemMessage", {}).get("systemMessage", "")
        self.assertIn("mcp-app-development", msg_mcp_app)

        gemini_bytes = (REPO_ROOT / "GEMINI.md").read_bytes()
        self.assertLess(len(gemini_bytes), 20000)
        maintainer_text = (REPO_ROOT / ".agents" / "rules" / "harness-maintainer.md").read_text(encoding="utf-8")
        for token in ("native_swarm", "migrate-agent-settings", "mcp-app-development", "/grill-me", "/learn"):
            self.assertIn(token, maintainer_text)


class TestAntigravityV232KnowledgeWorkHygiene(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_v232_kw_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_recovery_hint_adapts_to_non_git_vs_git_workspaces(self) -> None:
        non_git_ws = self.tmp / "docs_folder"
        non_git_ws.mkdir()
        (non_git_ws / "tasks.md").write_text(
            "**Campaign ID:** `2026-11-22-kw-nongit`\n- [ ] Draft quarterly summary\n",
            encoding="utf-8",
        )

        res_nongit = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "kw-rec-nongit",
                "workspacePath": str(non_git_ws),
                "prompt": "Continue preparing the summary document.",
            }
        )
        msg_nongit = res_nongit.get("injectSteps", [{}])[0].get("systemMessage", {}).get("systemMessage", "")
        self.assertIn("Harness Recovery & Continuity Gate", msg_nongit)
        self.assertIn("tasks.md", msg_nongit)
        self.assertNotIn("git status", msg_nongit)
        self.assertNotIn("git diff", msg_nongit)

        git_ws = self.tmp / "code_repo"
        git_ws.mkdir()
        (git_ws / ".git").mkdir()
        (git_ws / "tasks.md").write_text(
            "**Campaign ID:** `2026-11-22-kw-git`\n- [ ] Fix parser edge case\n",
            encoding="utf-8",
        )

        res_git = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "kw-rec-git",
                "workspacePath": str(git_ws),
                "prompt": "Continue working on the parser task.",
            }
        )
        msg_git = res_git.get("injectSteps", [{}])[0].get("systemMessage", {}).get("systemMessage", "")
        self.assertIn("Harness Recovery & Continuity Gate", msg_git)
        self.assertIn("git status", msg_git)
        self.assertIn("git diff", msg_git)

    def test_targets_customization_structure_non_harness_skills_agents_isolation(self) -> None:
        non_harness_ws = self.tmp / "knowledge_ws"
        non_harness_ws.mkdir()

        for rel in ("skills/notes.md", "agents/roster.md", "docs/skills/onboarding.md"):
            with self.subTest(non_cust=rel):
                self.assertFalse(
                    agy_hooks._targets_customization_structure(rel, workspace=non_harness_ws),
                    rel,
                )
                res = agy_hooks.handle_pre_tool_use(
                    {
                        "modelName": "gemini-3-flash",
                        "workspacePath": str(non_harness_ws),
                        "toolCall": {"name": "edit_file", "args": {"Path": rel}},
                    }
                )
                self.assertEqual(res.get("decision"), "allow", (rel, res))

        # Rule 17 model gate is scoped strictly to harness checkouts & ~/.gemini/config (2.3):
        # external non-harness repos can edit their own GEMINI.md / AGENTS.md / SKILL.md / .cursor/ on any model.
        for rel in (
            "skills/custom/SKILL.md",
            ".agents/skills/demo/foo.md",
            "GEMINI.md",
            "AGENTS.md",
            "hooks.json",
            ".cursor/rules/style.mdc",
        ):
            with self.subTest(external_allowed=rel):
                self.assertFalse(
                    agy_hooks._targets_customization_structure(rel, workspace=non_harness_ws),
                    rel,
                )
                res = agy_hooks.handle_pre_tool_use(
                    {
                        "modelName": "gemini-3-flash",
                        "workspacePath": str(non_harness_ws),
                        "toolCall": {"name": "edit_file", "args": {"Path": rel}},
                    }
                )
                self.assertEqual(res.get("decision"), "allow", (rel, res))

        harness_ws = self.tmp / "harness_ws"
        (harness_ws / ".harness").mkdir(parents=True)
        (harness_ws / ".harness" / "manifest.json").write_text("{}", encoding="utf-8")
        for rel in (
            "skills/notes.md",
            "agents/roster.md",
            "skills/custom/SKILL.md",
            ".agents/skills/demo/foo.md",
            "GEMINI.md",
            "hooks.json",
            ".cursor/rules/style.mdc",
        ):
            with self.subTest(harness_cust=rel):
                self.assertTrue(
                    agy_hooks._targets_customization_structure(rel, workspace=harness_ws),
                    rel,
                )
                res = agy_hooks.handle_pre_tool_use(
                    {
                        "modelName": "gemini-3-flash",
                        "workspacePath": str(harness_ws),
                        "toolCall": {"name": "edit_file", "args": {"Path": rel}},
                    }
                )
                self.assertEqual(res.get("decision"), "deny", (rel, res))

    def test_sweetspot_and_deep_grill_precision_avoids_knowledge_work_false_positives(self) -> None:
        negative_prompts = (
            "Toplantı takvimimi hızlandır.",
            "Sunumumu optimize et.",
            "Onay sürecini hızlandır lütfen.",
            "Yazı tipi boyutunu küçült.",
            "Run /grill-me on my startup pitch.",
            "Grill me on my startup pitch.",
            "İş görüşmesi için mülakat yapalım.",
        )
        for idx, prompt in enumerate(negative_prompts):
            with self.subTest(negative=prompt):
                res = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"kw-neg-{idx}", "prompt": prompt}
                )
                msg = res.get("injectSteps", [{}])[0].get("systemMessage", {}).get("systemMessage", "")
                self.assertNotIn("`sweetspot`", msg, (prompt, msg))
                self.assertNotIn("`deep-grill`", msg, (prompt, msg))

        positive_cases = (
            ("Bu oyunu optimize et.", "`sweetspot`"),
            ("Bu veritabanı sorgusunu optimize et.", "`sweetspot`"),
            ("Bu fonksiyonu hızlandır.", "`sweetspot`"),
            ("Üretilen çıktının boyutunu küçült.", "`sweetspot`"),
            ("Servisin indirme/yükleme hızlandır optimizasyonunu yap.", "`sweetspot`"),
            ("Run /deep-grill on this schema design.", "`deep-grill`"),
            ("Yeni mimari için beni sorgula ve edge-case interview başlat.", "`deep-grill`"),
            ("Grill me about this protocol architecture before coding.", "`deep-grill`"),
        )
        for idx, (prompt, expected_slug) in enumerate(positive_cases):
            with self.subTest(positive=prompt):
                res = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"kw-pos-{idx}", "prompt": prompt}
                )
                msg = res.get("injectSteps", [{}])[0].get("systemMessage", {}).get("systemMessage", "")
                self.assertIn(expected_slug, msg, (prompt, msg))


class TestSlice6SecurityAndRegressionHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_v232_s6_"))
        self._state_tmp = self.tmp / "state"
        self._state_tmp.mkdir(parents=True, exist_ok=True)
        self._old_state_env = None

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _with_isolated_state(self):
        import os
        from unittest import mock

        return mock.patch.dict(os.environ, {"PLUMB_GUARD_STATE_DIR": str(self._state_tmp)}, clear=False)

    def test_model_and_effort_hydrogen_paired_and_extra_low_transcript(self) -> None:
        # Neon requires XHigh/extra-high; `high` must fail closed even alone or overriding `(XHigh)`.
        for payload in (
            {"modelName": "Gemini 4 Neon", "effort": "high"},
            {"modelName": "Gemini 4 Neon (XHigh)", "effort": "high"},
        ):
            with self.subTest(payload=payload):
                verdict = agy_hooks._evaluate_customization_model_and_effort(payload)
                self.assertIsNotNone(verdict)
                self.assertEqual(verdict[0], "deny", (payload, verdict))

        tx_low = self.tmp / "tx_extra_low.jsonl"
        tx_low.write_text(
            json.dumps(
                {
                    "step_index": 0,
                    "type": "USER_INPUT",
                    "source": "USER_EXPLICIT",
                    "content": '<USER_SETTINGS_CHANGE>\n"Model Selection": "Gemini 4 Carbon",\n"Effort Level": "Extra Low"\n</USER_SETTINGS_CHANGE>',
                }
            )
            + "\n",
            encoding="utf-8",
        )
        v_low = agy_hooks._evaluate_customization_model_and_effort({"transcriptPath": str(tx_low)})
        self.assertIsNotNone(v_low)
        self.assertEqual(v_low[0], "deny", v_low)

        tx_high = self.tmp / "tx_extra_high.jsonl"
        tx_high.write_text(
            json.dumps(
                {
                    "step_index": 0,
                    "type": "USER_INPUT",
                    "source": "USER_EXPLICIT",
                    "content": '<USER_SETTINGS_CHANGE>\n"Model Selection": "Gemini 4 Neon",\n"Effort Level": "Extra High"\n</USER_SETTINGS_CHANGE>',
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertIsNone(agy_hooks._evaluate_customization_model_and_effort({"transcriptPath": str(tx_high)}))

    def test_stop_continuation_lock_timeout_rotating_cap_main_error_and_non_git_boundary(self) -> None:
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from unittest import mock
        from guard.test_boundary import TestBoundaryGuard

        dirty_diff = "+++ b/tests/test_x.py\n+    assert x == x\n"

        with self._with_isolated_state():
            # 1. Lock TimeoutError with continuationActive=true & executionNum=2 must fail CLOSED (`continue`).
            with mock.patch.object(agy_hooks, "file_lock", side_effect=TimeoutError("busy")):
                with redirect_stderr(io.StringIO()):
                    res_exec2 = agy_hooks.handle_stop(
                        {
                            "conversationId": "conv-lock-2",
                            "terminationReason": "NO_TOOL_CALL",
                            "continuationActive": True,
                            "fullyIdle": False,
                            "executionNum": 2,
                            "diffText": dirty_diff,
                        }
                    )
                    res_exec5 = agy_hooks.handle_stop(
                        {
                            "conversationId": "conv-lock-5",
                            "terminationReason": "NO_TOOL_CALL",
                            "continuationActive": True,
                            "executionNum": 5,
                            "diffText": dirty_diff,
                        }
                    )
            self.assertEqual(res_exec2.get("decision"), "continue", res_exec2)
            self.assertIn("continuationActive=true", res_exec2.get("reason", ""))
            self.assertIn("fullyIdle=false", res_exec2.get("reason", ""))
            self.assertEqual(res_exec5, {}, res_exec5)

            # 2. Rotating finding fingerprints still trip total_strikes circuit breaker at MAX_STRIKES + 2 (5th turn).
            for turn in range(1, 5):
                rot_diff = f"+++ b/tests/test_r{turn}.py\n+    assert rot_{turn} == rot_{turn}\n"
                r = agy_hooks.handle_stop(
                    {
                        "conversationId": "conv-rotate",
                        "terminationReason": "NO_TOOL_CALL",
                        "diffText": rot_diff,
                    }
                )
                self.assertEqual(r.get("decision"), "continue", (turn, r))
            r5 = agy_hooks.handle_stop(
                {
                    "conversationId": "conv-rotate",
                    "terminationReason": "NO_TOOL_CALL",
                    "diffText": "+++ b/tests/test_r5.py\n+    assert rot_5 == rot_5\n",
                }
            )
            self.assertEqual(r5, {}, r5)

            # 3. Malformed Stop stdin fails closed (`continue`), while unhandled dispatch_hook exceptions log loudly and degrade to `{}`.
            with mock.patch.object(sys, "stdin", io.StringIO("{bad-json")):
                buf_bad = io.StringIO()
                err_bad = io.StringIO()
                with redirect_stdout(buf_bad), redirect_stderr(err_bad):
                    agy_hooks.main(["stop"])
                self.assertEqual(json.loads(buf_bad.getvalue()).get("decision"), "continue")
                self.assertIn("Stop Gate", err_bad.getvalue())

            with mock.patch.object(agy_hooks, "dispatch_hook", side_effect=RuntimeError("boom")):
                with mock.patch.object(sys, "stdin", io.StringIO(json.dumps({"hookEventName": "Stop", "executionNum": 1}))):
                    buf = io.StringIO()
                    err = io.StringIO()
                    with redirect_stdout(buf), redirect_stderr(err):
                        agy_hooks.main(["stop"])
                    self.assertEqual(json.loads(buf.getvalue()), {})
                    self.assertIn("RuntimeError", err.getvalue())

            # 4. Non-git workspace returns clean diff status, clears interrupted_notified on clean Stop, and still enforces TestBoundaryGuard.
            non_git = self.tmp / "non_git_ws"
            (non_git / "tests").mkdir(parents=True)
            test_f = non_git / "tests" / "test_demo.py"
            test_f.write_text("assert 1 == 1\n", encoding="utf-8")
            doc_f = non_git / "notes.md"
            doc_f.write_text("# Clean\n", encoding="utf-8")
            agy_hooks._record_flight_pre_write(
                {"conversationId": "conv-old-nongit"}, non_git, "write_to_file", str(doc_f)
            )
            flight_path = self._state_tmp / "flight_recorder.json"
            fl_before = json.loads(flight_path.read_text(encoding="utf-8"))
            ws_key = str(non_git.resolve())
            fl_before[ws_key]["status"] = "interrupted_notified"
            flight_path.write_text(json.dumps(fl_before), encoding="utf-8")

            res_clean_ng = agy_hooks.handle_stop(
                {
                    "conversationId": "conv-nongit-clean",
                    "terminationReason": "NO_TOOL_CALL",
                    "workspacePath": str(non_git),
                }
            )
            self.assertEqual(res_clean_ng, {}, res_clean_ng)
            fl_after = json.loads(flight_path.read_text(encoding="utf-8"))
            self.assertEqual(fl_after[ws_key].get("status"), "turn_complete")

            tbg = TestBoundaryGuard(workspace_dir=non_git)
            tbg.snapshot()
            test_f.write_text("assert 1 == 2\n", encoding="utf-8")

            joined, ws_clean, ws_git_err = agy_hooks._collect_workspace_diff_status_ex(non_git)
            self.assertEqual(joined, "")
            self.assertTrue(ws_clean)
            self.assertFalse(ws_git_err)

            res_tb = agy_hooks.handle_stop(
                {
                    "conversationId": "conv-nongit-tb",
                    "terminationReason": "NO_TOOL_CALL",
                    "workspacePath": str(non_git),
                }
            )
            self.assertEqual(res_tb.get("decision"), "continue", res_tb)
            self.assertIn("Test boundary violation", res_tb.get("reason", ""))

    def test_swarm_persistence_fork_workflow_symlinks_and_kw_cwd(self) -> None:
        import os

        with self._with_isolated_state():
            # 1. Missing model metadata yields `force_ask`, yet persists tracked worker; later flash model switch is DENIED.
            r_add = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-sw-force",
                    "toolCall": {
                        "name": "swarm",
                        "args": {"action": "add", "name": "planner", "brief": "Update GEMINI.md"},
                    },
                }
            )
            self.assertEqual(r_add.get("decision"), "force_ask", r_add)

            r_mod = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-sw-force",
                    "modelName": "Gemini 4 Carbon (High)",
                    "toolCall": {
                        "name": "swarm",
                        "args": {"action": "model", "name": "planner", "model": "gemini-3-flash"},
                    },
                }
            )
            self.assertEqual(r_mod.get("decision"), "deny", r_mod)

            # 2. Downgraded worker spawn + forking customization worker from downgraded worker must deny.
            r_down = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-sw-fork",
                    "modelName": "Gemini 4 Carbon (High)",
                    "toolCall": {
                        "name": "swarm",
                        "args": {"action": "add", "name": "helper", "model": "flash", "brief": "Summarize README"},
                    },
                }
            )
            self.assertEqual(r_down.get("decision"), "force_ask", r_down)

            r_fork = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-sw-fork",
                    "modelName": "Gemini 4 Carbon (High)",
                    "toolCall": {
                        "name": "swarm",
                        "args": {"action": "add", "name": "helper2", "fork": "helper", "brief": "Update hooks.json"},
                    },
                }
            )
            self.assertEqual(r_fork.get("decision"), "deny", r_fork)

            # 3. Sharded worker spawn + kill clears worker; standalone run_workflow multi-step swarm enforces Rule 17.
            r_shard = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-sw-shard",
                    "modelName": "Gemini 4 Carbon (High)",
                    "toolCall": {
                        "name": "swarm",
                        "args": {"action": "add", "name": "ed", "tasks": ["Edit GEMINI.md"]},
                    },
                }
            )
            self.assertEqual(r_shard.get("decision"), "allow", r_shard)
            r_kill = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-sw-shard",
                    "toolCall": {"name": "swarm", "args": {"action": "kill", "name": "ed"}},
                }
            )
            self.assertEqual(r_kill.get("decision"), "allow", r_kill)

            wf_script = (
                "call_tool('swarm', {'action': 'add', 'name': 'wf_cust', 'brief': 'Edit GEMINI.md'})\n"
                "call_tool('swarm', {'action': 'model', 'name': 'wf_cust', 'model': 'flash'})\n"
            )
            r_wf = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-sw-wf",
                    "modelName": "Gemini 4 Carbon (High)",
                    "toolCall": {"name": "run_workflow", "args": {"Script": wf_script}},
                }
            )
            self.assertEqual(r_wf.get("decision"), "deny", r_wf)

            # 4. Knowledge Work Cwd outside harness checkout allows skills/notes.md, but still catches harness paths & symlinks.
            harness_ws = self.tmp / "harness_repo"
            (harness_ws / ".harness").mkdir(parents=True)
            (harness_ws / ".harness" / "manifest.json").write_text("{}", encoding="utf-8")
            (harness_ws / "skills").mkdir(parents=True)
            (harness_ws / "skills" / "real.md").write_text("# skill\n", encoding="utf-8")

            kw_dir = self.tmp / "kw_docs"
            (kw_dir / "skills").mkdir(parents=True)
            ext_target = self.tmp / "ext_dir"
            ext_target.mkdir(parents=True)
            ext_file = ext_target / "outside.md"
            ext_file.write_text("# ext\n", encoding="utf-8")

            r_kw = agy_hooks.handle_pre_tool_use(
                {
                    "modelName": "gemini-3-flash",
                    "workspacePath": str(harness_ws),
                    "cwd": str(kw_dir),
                    "toolCall": {"name": "write_to_file", "args": {"TargetFile": "skills/notes.md"}},
                }
            )
            self.assertEqual(r_kw.get("decision"), "allow", r_kw)

            r_kw_cmd = agy_hooks.handle_pre_tool_use(
                {
                    "modelName": "gemini-3-flash",
                    "workspacePath": str(harness_ws),
                    "toolCall": {"name": "run_command", "args": {"CommandLine": f"cd {kw_dir} && touch skills/notes.md"}},
                }
            )
            self.assertEqual(r_kw_cmd.get("decision"), "allow", r_kw_cmd)

            r_escape_cmd = agy_hooks.handle_pre_tool_use(
                {
                    "modelName": "gemini-3-flash",
                    "workspacePath": str(harness_ws),
                    "cwd": str(kw_dir),
                    "toolCall": {
                        "name": "run_command",
                        "args": {"CommandLine": f"touch {harness_ws / 'skills' / 'real.md'}"},
                    },
                }
            )
            self.assertEqual(r_escape_cmd.get("decision"), "deny", r_escape_cmd)

            if hasattr(os, "symlink"):
                link_out = harness_ws / "skills" / "out_link.md"
                link_in = kw_dir / "skills" / "in_link.md"
                try:
                    os.symlink(ext_file, link_out)
                    os.symlink(harness_ws / "skills" / "real.md", link_in)
                except OSError:
                    link_out = None
                    link_in = None
                if link_out is not None and link_in is not None:
                    r_sym1 = agy_hooks.handle_pre_tool_use(
                        {
                            "modelName": "gemini-3-flash",
                            "workspacePath": str(harness_ws),
                            "toolCall": {"name": "edit_file", "args": {"Path": str(link_out)}},
                        }
                    )
                    r_sym2 = agy_hooks.handle_pre_tool_use(
                        {
                            "modelName": "gemini-3-flash",
                            "workspacePath": str(kw_dir),
                            "toolCall": {"name": "edit_file", "args": {"Path": str(link_in)}},
                        }
                    )
                    self.assertEqual(r_sym1.get("decision"), "deny", r_sym1)
                    self.assertEqual(r_sym2.get("decision"), "deny", r_sym2)

    def test_upstream_reconciliation_corrupt_error_and_markdown_sanitization(self) -> None:
        import importlib.util
        import os
        from unittest import mock
        from guard.upstream import UpstreamAuditorBridge, reconcile_state_with_seed

        state = {
            "_reconciled_seed_digest": "old-digest",
            "last_pbtxt_model": "MODEL_PLACEHOLDER_M26",
            "tracked_repositories": {
                "rea": {
                    "repo": "morluto/rea",
                    "branch": "main",
                    "track": "release",
                    "path": "old/path",
                    "last_synced_commit": "rea-agents-6.7.0",
                }
            },
        }
        seed = {
            "last_audited_model": "Gemini 4 Hydrogen (XHigh)",
            "last_model_slug": "gemini-4-hydrogen-xhigh",
            "last_pbtxt_model": "Gemini 4 Carbon",
            "tracked_repositories": {
                "rea": {
                    "repo": "morluto/rea",
                    "branch": "main",
                    "last_synced_commit": "abc1234",
                }
            },
        }
        merged, changed = reconcile_state_with_seed(state, seed)
        self.assertTrue(changed)
        self.assertEqual(merged.get("last_pbtxt_model"), "Gemini 4 Carbon")
        self.assertNotIn("track", merged["tracked_repositories"]["rea"])
        self.assertNotIn("path", merged["tracked_repositories"]["rea"])

        # UpstreamAuditorBridge error surfacing when state or seed is corrupt
        cfg = self.tmp / "cfg"
        (cfg / "skills" / "upstream-auditor").mkdir(parents=True)
        seed_f = cfg / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        seed_f.write_text("{corrupt-seed", encoding="utf-8")
        st_f = self._state_tmp / "upstream_state.json"
        st_f.write_text("{corrupt-state", encoding="utf-8")

        with mock.patch.dict(
            os.environ,
            {
                "ANTIGRAVITY_CONFIG_DIR": str(cfg),
                "PLUMB_GUARD_STATE_DIR": str(self._state_tmp),
                "UPSTREAM_STATE_FILE": str(st_f),
            },
            clear=False,
        ):
            bridge = UpstreamAuditorBridge(target_dir=cfg)
            repo_rows = bridge.check_repositories()
            self.assertEqual(len(repo_rows), 1)
            self.assertTrue(str(repo_rows[0]["status"]).startswith("Invalid "), repo_rows)
            drift = bridge.get_model_drift_status()
            self.assertIn("state_error", drift)
            summary = bridge.get_summary()
            self.assertEqual(summary["status"], "FAIL")
            self.assertTrue(any("seed" in w.lower() for w in summary["warnings"]), summary["warnings"])

        # Markdown / ANSI escaping in upstream_watcher.collect_reasons
        watcher_path = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
        spec = importlib.util.spec_from_file_location("uw_s6_sanitize", watcher_path)
        assert spec and spec.loader
        uw = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(uw)
        malicious_state = {
            "last_audited_model": "Gemini 4 Carbon (High)",
            "tracked_repositories": {"bad[link](http://evil.invalid)": {"last_synced_commit": "1111111"}},
            "pending_repo_updates": {"bad[link](http://evil.invalid)": {"recorded": "1111111", "remote": "2222222"}},
        }
        reasons = uw.collect_reasons(malicious_state, payload_model="Gemini <script>alert(1)</script>\n# Heading")
        joined = "\n".join(reasons)
        self.assertIn("\\[link\\]", joined)
        self.assertIn("\\<script\\>", joined)
        self.assertNotIn("\n# Heading", joined)

    def test_meta_audit_enforces_gemini_byte_budget(self) -> None:
        from scripts.meta_audit import MetaAuditEngine

        synth = self.tmp / "synth_repo"
        (synth / "skills" / "demo").mkdir(parents=True)
        (synth / "agents").mkdir(parents=True)
        (synth / "templates").mkdir(parents=True)
        (synth / "skills" / "demo" / "SKILL.md").write_text(
            "---\nname: demo\ndescription: demo skill\n---\n# Demo\n", encoding="utf-8"
        )
        (synth / "GEMINI.md").write_text("a" * 20001, encoding="utf-8")
        eng_warn = MetaAuditEngine(synth)
        eng_warn.pass2_cross_references()
        warn_msgs = [f.message for f in eng_warn.findings if f.severity == "WARNING" and f.target == "GEMINI.md"]
        self.assertTrue(any("20001" in m for m in warn_msgs), eng_warn.findings)

        (synth / "GEMINI.md").write_text("b" * 24001, encoding="utf-8")
        eng_crit = MetaAuditEngine(synth)
        eng_crit.pass2_cross_references()
        crit_msgs = [f.message for f in eng_crit.findings if f.severity == "CRITICAL" and f.target == "GEMINI.md"]
        self.assertTrue(any("24001" in m for m in crit_msgs), eng_crit.findings)


if __name__ == "__main__":
    unittest.main()
