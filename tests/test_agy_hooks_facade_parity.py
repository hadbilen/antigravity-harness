"""
tests/test_agy_hooks_facade_parity.py — Seam characterization & facade compatibility suite
for `guard/agy_hooks.py` -> `guard/hooks/` modularization (`ADR-0008`).

Pins:
1. All 51 externally accessed/imported attributes (+ `data_dir` = 52) and `dir(agy_hooks)` visibility.
2. `scripts/meta_audit.py` Pass 2 AST (`PRE_TOOL_USE_MATCHER_TOOLS`), `ECOSYSTEM_ROUTING_HINTS`
   repo subagent existence, and Pass 7 `importlib.util.spec_from_file_location` (`hooks_mod.REPO_ROOT`
   isolation when `guard.agy_hooks` is already in `sys.modules`).
3. All 17 facade-pinned collaborator & router seams (`13` submodule collaborator proxies + `4` router seams)
   across `PreInvocation`, `PreToolUse`, `Stop`, `dispatch_hook`, and `main`, including clean
   post-`with` restoration.
4. End-to-end CLI event contracts (`pre-invocation`, `pre-tool-use`, `stop`) and malformed-stdin
   fail-closed behavior.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
for _p in (str(TESTS_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hermetic  # noqa: E402, F401
import guard.agy_hooks as agy_hooks  # noqa: E402
from scripts.meta_audit import _extract_pre_tool_use_matcher_tools  # noqa: E402

PINNED_EXTERNAL_ATTRIBUTES = (
    "COMMAND_TOOL_NAMES",
    "ECOSYSTEM_ROUTING_HINTS",
    "MAX_HINTS",
    "PRE_TOOL_USE_MATCHER",
    "PRE_TOOL_USE_MATCHER_TOOLS",
    "REPO_ROOT",
    "SKILL_HINTS",
    "WRITE_TOOL_NAMES",
    "_FENCE_RE",
    "_HIGHEST_EFFORT_SLUG_SUFFIXES",
    "_LazyRegex",
    "_NEW_FILE_CAPABILITY_SKIP_RE",
    "_ROUTE_SLASH_ALIASES",
    "_SCANNER_EXEMPT_SUFFIXES",
    "_SKILL_SLASH_ALIASES",
    "__file__",
    "_batch_update_swarm_workers_ledger",
    "_capture_git_baseline",
    "_catalog_top_model_spec",
    "_collect_workspace_diff_status_ex",
    "_command_mutates_customization_structure",
    "_command_mutates_governance",
    "_detect_workspace_recovery_hint",
    "_evaluate_customization_model_and_effort",
    "_extract_latest_user_prompt",
    "_extract_transcript_model_and_effort",
    "_flight_recorder_file",
    "_has_authorized_test_modifications",
    "_read_bounded_bytes_nofollow",
    "_record_flight_pre_write",
    "_session_flight_base_head",
    "_swarm_workers_file",
    "_targets_customization_structure",
    "_unquote_git_diff_path",
    "_update_swarm_workers_ledger",
    "_workspaces_from_payload",
    "atomic_write_json",
    "config_dir",
    "configured_config_dir",
    "data_dir",
    "dispatch_hook",
    "file_lock",
    "handle_pre_invocation",
    "handle_pre_tool_use",
    "handle_stop",
    "inspect_git_diff",
    "json",
    "main",
    "state_dir",
    "subprocess",
    "tomllib",
    "validate_structured_content",
)

EXPECTED_MATCHER_TOOLS = (
    "run_command",
    "bash",
    "execute_command",
    "shell",
    "send_command_input",
    "manage_task",
    "run_workflow",
    "invoke_subagent",
    "swarm",
    "post_message",
    "send_message",
    "define_subagent",
    "schedule",
    "call_mcp_tool",
    "mcp_.*",
    "write_to_file",
    "write_file",
    "replace_file_content",
    "multi_replace_file_content",
    "edit_file",
    "create_file",
    "write",
    "edit",
    "multiedit",
    "notebookedit",
)


def _extract_injected_text(resp: dict) -> str:
    parts: list[str] = []
    if isinstance(resp.get("additionalContext"), str):
        parts.append(resp["additionalContext"])
    steps = resp.get("injectSteps")
    if isinstance(steps, list):
        for step in steps:
            if isinstance(step, dict):
                sm = step.get("systemMessage")
                if isinstance(sm, dict):
                    for key in ("systemMessage", "message"):
                        val = sm.get(key)
                        if isinstance(val, str):
                            parts.append(val)
                elif isinstance(sm, str):
                    parts.append(sm)
    return "\n".join(parts)


class TestAgyHooksFacadeParity(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-facade-parity-")
        self.tmp = Path(self._tmp.name)
        self.cfg_dir = self.tmp / "config"
        self.state_dir = self.tmp / "state"
        self.data_dir = self.tmp / "data"
        self.ws_dir = self.tmp / "workspace"
        for d in (self.cfg_dir, self.state_dir, self.data_dir, self.ws_dir):
            d.mkdir(parents=True, exist_ok=True)
        (self.cfg_dir / "GEMINI.md").write_text("# Hermetic Constitution\n", encoding="utf-8")
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.tmp),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
                "AGY_GUARD_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_STATE_DIR": str(self.state_dir),
                "AGY_GUARD_DATA_DIR": str(self.data_dir),
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        self._tmp.cleanup()

    def test_all_external_attributes_resolve_and_appear_in_dir(self) -> None:
        self.assertEqual(len(PINNED_EXTERNAL_ATTRIBUTES), 52)
        dir_entries = set(dir(agy_hooks))
        for attr in PINNED_EXTERNAL_ATTRIBUTES:
            with self.subTest(attr=attr):
                self.assertTrue(hasattr(agy_hooks, attr), f"Missing attribute on guard.agy_hooks: {attr}")
                val = getattr(agy_hooks, attr)
                if attr != "tomllib":
                    self.assertIsNotNone(val)
                if not attr.startswith("__"):
                    self.assertIn(attr, dir_entries, f"{attr} missing from dir(guard.agy_hooks)")

    def test_meta_audit_ast_matcher_routing_tables_and_spec_from_file_location(self) -> None:
        hooks_py = REPO_ROOT / "guard" / "agy_hooks.py"
        extracted = _extract_pre_tool_use_matcher_tools(hooks_py.read_text(encoding="utf-8"))
        self.assertEqual(extracted, EXPECTED_MATCHER_TOOLS)
        self.assertEqual(agy_hooks.PRE_TOOL_USE_MATCHER_TOOLS, EXPECTED_MATCHER_TOOLS)
        self.assertEqual(agy_hooks.PRE_TOOL_USE_MATCHER, "|".join(EXPECTED_MATCHER_TOOLS))

        skill_hints = agy_hooks.SKILL_HINTS
        eco_hints = agy_hooks.ECOSYSTEM_ROUTING_HINTS
        self.assertGreaterEqual(len(skill_hints), 34)
        self.assertGreaterEqual(len(eco_hints), 6)
        for s_name, s_rel, s_rx, s_summary in skill_hints:
            self.assertIsInstance(s_name, str)
            self.assertIsInstance(s_rel, str)
            self.assertIsInstance(s_rx, re.Pattern)
            self.assertTrue(s_summary)

        available_agents = {p.stem for p in (REPO_ROOT / "agents").glob("*.md")}
        referenced_repo_agents: set[str] = set()
        for r_key, r_rx, r_directive in eco_hints:
            self.assertIsInstance(r_key, str)
            self.assertIsInstance(r_rx, re.Pattern)
            for m in re.finditer(r"(?<!Built-in\s)Subagents?\s+((?:`[a-z0-9-]+`(?:\s*(?:&|,|and)\s*)?)+)", r_directive):
                for agent in re.findall(r"`([a-z0-9-]+)`", m.group(1)):
                    if agent != "self":
                        referenced_repo_agents.add(agent)
                        self.assertIn(agent, available_agents, f"Missing agents/{agent}.md for {r_key}")
        self.assertGreaterEqual(len(referenced_repo_agents), 5)

        # Simulate scripts/meta_audit.py Pass 7 spec_from_file_location while guard.agy_hooks is in sys.modules
        spec = importlib.util.spec_from_file_location("_meta_audit_agy_hooks", hooks_py)
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        hooks_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hooks_mod)

        orig_global_repo = agy_hooks.REPO_ROOT
        empty_repo = self.tmp / "empty_repo"
        empty_repo.mkdir()
        hooks_mod.REPO_ROOT = empty_repo  # type: ignore[attr-defined]
        res_absent = hooks_mod.handle_pre_invocation(
            {"prompt": "/rea inspect binary header", "cwd": str(self.ws_dir), "conversationId": "spec-no-rea"}
        )
        self.assertNotIn("reverse-engineer-anything", _extract_injected_text(res_absent))

        rea_repo = self.tmp / "rea_repo"
        rea_skill = rea_repo / "plugins" / "rea" / "skills" / "reverse-engineer-anything" / "SKILL.md"
        rea_skill.parent.mkdir(parents=True)
        rea_skill.write_text("# REA\n", encoding="utf-8")
        hooks_mod.REPO_ROOT = rea_repo  # type: ignore[attr-defined]
        res_present = hooks_mod.handle_pre_invocation(
            {"prompt": "/rea inspect binary header", "cwd": str(self.ws_dir), "conversationId": "spec-with-rea"}
        )
        self.assertIn("reverse-engineer-anything", _extract_injected_text(res_present))
        self.assertEqual(agy_hooks.REPO_ROOT, orig_global_repo)

    def test_monkeypatch_seams_for_pre_invocation_collaborators(self) -> None:
        custom_state = self.tmp / "custom_pi_state"
        custom_state.mkdir()
        write_calls: list[Path] = []
        lock_calls: list[Path] = []
        orig_write = agy_hooks.atomic_write_json
        orig_lock = agy_hooks.file_lock

        def spy_write(path: Path, data: object) -> None:
            write_calls.append(Path(path))
            orig_write(path, data)

        def spy_lock(path: Path, *args: object, **kwargs: object):
            lock_calls.append(Path(path))
            return orig_lock(path, *args, **kwargs)

        with (
            mock.patch(
                "guard.agy_hooks._detect_workspace_recovery_hint",
                return_value=(True, ("recovery_custom", "[Custom Recovery Marker]", None)),
            ),
            mock.patch.object(agy_hooks, "state_dir", return_value=custom_state),
            mock.patch.object(agy_hooks, "atomic_write_json", side_effect=spy_write),
            mock.patch.object(agy_hooks, "file_lock", side_effect=spy_lock),
        ):
            out = agy_hooks.handle_pre_invocation(
                {
                    "prompt": "lütfen bu modülü refactor et ve sadeleştir",
                    "workspace": str(self.ws_dir),
                    "conversationId": "conv-mp-pi",
                }
            )
        injected = _extract_injected_text(out)
        self.assertIn("[Custom Recovery Marker]", injected)
        self.assertIn("skills/refactoring/SKILL.md", injected)
        self.assertTrue(any(p.parent == custom_state for p in write_calls), write_calls)
        self.assertTrue(any(p.parent == custom_state for p in lock_calls), lock_calls)

        # Verify clean unpatch restoration
        self.assertTrue(callable(agy_hooks._detect_workspace_recovery_hint))
        out_after = agy_hooks.handle_pre_invocation(
            {
                "prompt": "lütfen bu modülü refactor et ve sadeleştir",
                "workspace": str(self.ws_dir),
                "conversationId": "conv-mp-pi-after",
            }
        )
        self.assertNotIn("[Custom Recovery Marker]", _extract_injected_text(out_after))

        # Patch REPO_ROOT, config_dir, configured_config_dir for optional plugin availability
        fake_cfg = self.tmp / "empty_cfg"
        fake_cfg.mkdir()
        (fake_cfg / "GEMINI.md").write_text("# cfg\n", encoding="utf-8")
        fake_repo = self.tmp / "plugin_repo"
        (fake_repo / "plugins" / "rea" / "skills" / "reverse-engineer-anything").mkdir(parents=True)
        (fake_repo / "plugins" / "rea" / "skills" / "reverse-engineer-anything" / "SKILL.md").write_text(
            "# REA\n", encoding="utf-8"
        )
        with (
            mock.patch.object(agy_hooks, "REPO_ROOT", self.tmp / "absent_repo"),
            mock.patch.object(agy_hooks, "configured_config_dir", return_value=fake_cfg),
            mock.patch.object(agy_hooks, "config_dir", return_value=fake_cfg),
        ):
            self.assertFalse(
                agy_hooks._optional_plugin_skill_available(
                    "plugins/rea/skills/reverse-engineer-anything/SKILL.md", [self.ws_dir]
                )
            )
        with (
            mock.patch.object(agy_hooks, "REPO_ROOT", fake_repo),
            mock.patch.object(agy_hooks, "configured_config_dir", return_value=fake_cfg),
            mock.patch.object(agy_hooks, "config_dir", return_value=fake_cfg),
        ):
            self.assertTrue(
                agy_hooks._optional_plugin_skill_available(
                    "plugins/rea/skills/reverse-engineer-anything/SKILL.md", [self.ws_dir]
                )
            )

    def test_monkeypatch_seams_for_pre_tool_use_collaborators(self) -> None:
        # 1. __file__ is mutable and cleanly restored on guard.agy_hooks
        orig_file = agy_hooks.__file__
        fake_file = str(self.tmp / "isolated" / "guard" / "agy_hooks.py")
        with mock.patch.object(agy_hooks, "__file__", fake_file):
            self.assertEqual(agy_hooks.__file__, fake_file)
        self.assertEqual(agy_hooks.__file__, orig_file)

        # 2. REPO_ROOT + config_dir + configured_config_dir govern _catalog_top_model_spec
        custom_cfg = self.tmp / "seed_cfg"
        seed_path = custom_cfg / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        seed_path.parent.mkdir(parents=True)
        seed_path.write_text(
            json.dumps(
                {
                    "last_audited_model": "Synthetic Flagship 9 (XHigh)",
                    "last_model_slug": "synthetic-flagship-9-xhigh",
                    "approved_customization_models": ["synthetic-flagship-9-xhigh"],
                }
            ),
            encoding="utf-8",
        )
        with (
            mock.patch.object(agy_hooks, "REPO_ROOT", self.tmp / "no_seed_repo"),
            mock.patch.object(agy_hooks, "configured_config_dir", return_value=custom_cfg),
            mock.patch.object(agy_hooks, "config_dir", return_value=custom_cfg),
        ):
            top_name, allowed = agy_hooks._catalog_top_model_spec()
        self.assertEqual(top_name, "Synthetic Flagship 9 (XHigh)")
        self.assertIn("synthetic-flagship-9-xhigh", allowed)

        # 3. _batch_update_swarm_workers_ledger monkeypatch fails safe (force_ask) on swarm customization add
        (self.ws_dir / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")
        real_top_name, _ = agy_hooks._catalog_top_model_spec()
        with mock.patch.object(agy_hooks, "_batch_update_swarm_workers_ledger", return_value=False):
            res_swarm = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-mp-swarm",
                    "workspace": str(self.ws_dir),
                    "modelName": real_top_name,
                    "effort": "xhigh",
                    "toolName": "swarm",
                    "toolInput": {
                        "action": "add",
                        "name": "author-a",
                        "brief": "Update GEMINI.md rule wording.",
                    },
                }
            )
        self.assertEqual(res_swarm.get("decision"), "force_ask", res_swarm)
        self.assertIn("Failed to persist customization worker ledger", res_swarm.get("reason", ""))

        # 4. subprocess.run + state_dir + atomic_write_json + file_lock on flight recorder write
        git_ws = self.tmp / "git_ws"
        git_ws.mkdir()
        subprocess.run(["git", "-C", str(git_ws), "init"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(git_ws), "config", "user.email", "t@example.com"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(git_ws), "config", "user.name", "Tester"], check=True, capture_output=True)
        (git_ws / "a.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(git_ws), "add", "a.py"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(git_ws), "commit", "-m", "init"], check=True, capture_output=True)
        (git_ws / "a.py").write_text("x = 2\n", encoding="utf-8")

        real_run = subprocess.run
        seen_git_cmds: list[list[str]] = []

        def intercept_run(cmd: list[str], *args: object, **kwargs: object):
            if isinstance(cmd, list) and cmd and cmd[0] == "git":
                seen_git_cmds.append(list(cmd))
            return real_run(cmd, *args, **kwargs)  # type: ignore[arg-type]

        with mock.patch("guard.agy_hooks.subprocess.run", side_effect=intercept_run):
            res_write = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-mp-flight",
                    "workspace": str(git_ws),
                    "toolCall": {"name": "write_file", "args": {"Path": str(git_ws / "b.py")}},
                }
            )
        self.assertEqual(res_write.get("decision"), "allow")
        self.assertGreaterEqual(len(seen_git_cmds), 1)

        # 5. Recursive handle_pre_tool_use inside run_workflow call_tool simulation
        intercepted_nested: list[str] = []
        orig_ptu = agy_hooks.handle_pre_tool_use

        def wrapped_ptu(payload: dict) -> dict:
            tc = payload.get("toolCall") or {}
            if tc.get("name") == "run_command":
                intercepted_nested.append(str((tc.get("args") or {}).get("CommandLine", "")))
                return {"decision": "deny", "reason": "[Custom Nested Intercept]"}
            return orig_ptu(payload)

        with mock.patch.object(agy_hooks, "handle_pre_tool_use", side_effect=wrapped_ptu):
            wf_res = orig_ptu(
                {
                    "conversationId": "conv-mp-wf",
                    "workspace": str(self.ws_dir),
                    "toolCall": {
                        "name": "run_workflow",
                        "args": {
                            "Script": 'call_tool("run_command", CommandLine="echo nested-check")\n',
                        },
                    },
                }
            )
        self.assertEqual(wf_res.get("decision"), "deny", wf_res)
        self.assertIn("echo nested-check", intercepted_nested)

    def test_monkeypatch_seams_for_stop_and_dispatcher_collaborators(self) -> None:
        # 1. json.loads patch inside validate_structured_content
        with mock.patch("guard.agy_hooks.json.loads", side_effect=RecursionError("deep json")):
            findings = agy_hooks.validate_structured_content("nested.json", "{}")
        self.assertTrue(any("Malformed JSON syntax in `nested.json`" in f for f in findings), findings)
        self.assertEqual(agy_hooks.validate_structured_content("ok.json", '{"a": 1}'), [])

        # 2. dispatch_hook routes dynamically to patched handle_pre_invocation / handle_pre_tool_use / handle_stop
        with mock.patch.object(agy_hooks, "handle_pre_invocation", return_value={"custom": "pi"}):
            self.assertEqual(agy_hooks.dispatch_hook("pre-invocation", {}), {"custom": "pi"})
        with mock.patch.object(agy_hooks, "handle_pre_tool_use", return_value={"decision": "force_ask", "reason": "r"}):
            self.assertEqual(
                agy_hooks.dispatch_hook("pre-tool-use", {}),
                {"decision": "force_ask", "reason": "r"},
            )
        with mock.patch.object(agy_hooks, "handle_stop", return_value={"decision": "continue", "reason": "s"}):
            self.assertEqual(
                agy_hooks.dispatch_hook("stop", {}),
                {"decision": "continue", "reason": "s"},
            )

        # 3. main() honors patched handle_pre_tool_use, handle_stop, and dispatch_hook (failing closed)
        with (
            mock.patch.object(agy_hooks, "handle_pre_tool_use", side_effect=RuntimeError("ptu boom")),
            mock.patch.object(sys, "stdin", io.StringIO('{"toolName": "read_file"}')),
            mock.patch.object(sys, "stdout", new_callable=io.StringIO) as out_ptu,
        ):
            rc = agy_hooks.main(["pre-tool-use"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out_ptu.getvalue())["decision"], "deny")

        with (
            mock.patch.object(agy_hooks, "handle_stop", side_effect=RuntimeError("stop boom")),
            mock.patch.object(sys, "stdin", io.StringIO('{"terminationReason": "NO_TOOL_CALL"}')),
            mock.patch.object(sys, "stdout", new_callable=io.StringIO) as out_stop,
            mock.patch.object(sys, "stderr", new_callable=io.StringIO) as err_stop,
        ):
            rc_stop = agy_hooks.main(["stop"])
        self.assertEqual(rc_stop, 0)
        self.assertEqual(json.loads(out_stop.getvalue()), {})
        self.assertIn("stop boom", err_stop.getvalue())

        with (
            mock.patch.object(agy_hooks, "dispatch_hook", side_effect=RuntimeError("dispatch boom")),
            mock.patch.object(sys, "stdin", io.StringIO('{"toolName": "read_file"}')),
            mock.patch.object(sys, "stdout", new_callable=io.StringIO) as out_disp,
        ):
            rc_disp = agy_hooks.main(["pre-tool-use"])
        self.assertEqual(rc_disp, 0)
        self.assertEqual(json.loads(out_disp.getvalue())["decision"], "deny")

    def test_cli_event_contracts_and_malformed_stdin_fail_closed(self) -> None:
        hook_script = str(REPO_ROOT / "guard" / "agy_hooks.py")
        env = dict(os.environ)

        def run_hook(args: list[str], stdin_raw: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, hook_script, *args],
                input=stdin_raw,
                text=True,
                capture_output=True,
                env=env,
                check=True,
            )

        # pre-invocation explicit trigger vs intra-turn fast-path
        cp_pi = run_hook(
            ["pre-invocation"],
            json.dumps(
                {
                    "conversationId": "cli-pi-1",
                    "workspace": str(self.ws_dir),
                    "prompt": "Use /refactoring to extract this helper cleanly",
                }
            ),
        )
        pi_data = json.loads(cp_pi.stdout)
        self.assertIn("skills/refactoring/SKILL.md", _extract_injected_text(pi_data))

        cp_pi_intra = run_hook(
            ["pre-invocation"],
            json.dumps(
                {
                    "conversationId": "cli-pi-1",
                    "invocationNum": 2,
                    "workspace": str(self.ws_dir),
                    "prompt": "Use /refactoring to extract this helper cleanly",
                }
            ),
        )
        self.assertEqual(json.loads(cp_pi_intra.stdout), {})

        # pre-tool-use allow, deny, force_ask, malformed stdin
        cp_allow = run_hook(
            ["pre-tool-use"],
            json.dumps(
                {
                    "conversationId": "cli-ptu-1",
                    "workspace": str(self.ws_dir),
                    "toolCall": {"name": "read_file", "args": {"Path": str(self.ws_dir / "note.txt")}},
                }
            ),
        )
        self.assertEqual(json.loads(cp_allow.stdout), {"decision": "allow"})

        cp_deny = run_hook(
            ["pre-tool-use"],
            json.dumps(
                {
                    "conversationId": "cli-ptu-2",
                    "workspace": str(self.ws_dir),
                    "toolCall": {"name": "run_command", "args": {"CommandLine": "agy-guard unlock"}},
                }
            ),
        )
        self.assertEqual(json.loads(cp_deny.stdout)["decision"], "deny")

        cp_ask = run_hook(
            ["pre-tool-use"],
            json.dumps(
                {
                    "conversationId": "cli-ptu-3",
                    "workspace": str(self.ws_dir),
                    "toolCall": {"name": "run_command", "args": {"CommandLine": "git reset --hard HEAD~1"}},
                }
            ),
        )
        self.assertEqual(json.loads(cp_ask.stdout)["decision"], "force_ask")

        cp_bad_ptu = run_hook(["pre-tool-use"], "{not-json")
        self.assertEqual(json.loads(cp_bad_ptu.stdout)["decision"], "deny")

        # stop abnormal skip, tautology block, malformed stdin
        cp_stop_cancel = run_hook(
            ["stop"],
            json.dumps(
                {"conversationId": "cli-stop-1", "terminationReason": "user_canceled", "workspace": str(self.ws_dir)}
            ),
        )
        self.assertEqual(json.loads(cp_stop_cancel.stdout), {})

        cp_stop_taut = run_hook(
            ["stop"],
            json.dumps(
                {
                    "conversationId": "cli-stop-2",
                    "terminationReason": "NO_TOOL_CALL",
                    "workspace": str(self.ws_dir),
                    "diffText": "+++ b/tests/test_sample.py\n+" + "    assert value == value\n",
                }
            ),
        )
        stop_taut_data = json.loads(cp_stop_taut.stdout)
        self.assertEqual(stop_taut_data.get("decision"), "continue")
        self.assertIn("Tautological", stop_taut_data.get("reason", ""))

        cp_bad_stop = run_hook(["stop"], "")
        self.assertEqual(json.loads(cp_bad_stop.stdout)["decision"], "continue")

    def test_event_scoped_lazy_import_isolation_in_subprocesses(self) -> None:
        env = dict(os.environ)

        def query_loaded(snippet: str, stdin_raw: str = "") -> dict:
            cp = subprocess.run(
                [sys.executable, "-c", snippet],
                input=stdin_raw,
                text=True,
                capture_output=True,
                cwd=str(REPO_ROOT),
                env=env,
                check=True,
            )
            return json.loads(cp.stdout.strip().splitlines()[-1])

        # 1. Importing PRE_TOOL_USE_MATCHER loads zero guard.hooks submodules
        matcher_mods = query_loaded(
            "import json, sys; from guard.agy_hooks import PRE_TOOL_USE_MATCHER; "
            "print(json.dumps(sorted(m for m in sys.modules if m == 'guard.hooks' or m.startswith('guard.hooks.'))))"
        )
        self.assertEqual(matcher_mods, [])

        # 2. Dispatching pre-tool-use loads common + pre_tool_use ONLY
        ptu_mods = query_loaded(
            "import json, sys, guard.agy_hooks as h; "
            "res = h.dispatch_hook('pre-tool-use', {'toolCall': {'name': 'read_file', 'args': {'Path': 'README.md'}}}); "
            "print(json.dumps({'res': res, 'mods': sorted(m for m in sys.modules if m.startswith('guard.hooks.'))}))"
        )
        self.assertEqual(ptu_mods["res"], {"decision": "allow"})
        self.assertEqual(ptu_mods["mods"], ["guard.hooks.common", "guard.hooks.pre_tool_use"])

        # 3. Dispatching pre-invocation loads common + pre_invocation ONLY
        pi_mods = query_loaded(
            "import json, sys, guard.agy_hooks as h; "
            "res = h.dispatch_hook('pre-invocation', {'prompt': 'Use /refactoring here', 'conversationId': 'lazy-pi'}); "
            "print(json.dumps({'ok': bool(res), 'mods': sorted(m for m in sys.modules if m.startswith('guard.hooks.'))}))"
        )
        self.assertTrue(pi_mods["ok"])
        self.assertEqual(pi_mods["mods"], ["guard.hooks.common", "guard.hooks.pre_invocation"])

        # 4. Dispatching stop loads common + stop_gate ONLY
        stop_mods = query_loaded(
            "import json, sys, guard.agy_hooks as h; "
            "res = h.dispatch_hook('stop', {'terminationReason': 'user_canceled'}); "
            "print(json.dumps({'res': res, 'mods': sorted(m for m in sys.modules if m.startswith('guard.hooks.'))}))"
        )
        self.assertEqual(stop_mods["res"], {})
        self.assertEqual(stop_mods["mods"], ["guard.hooks.common", "guard.hooks.stop_gate"])

        # 5. CLI __main__ execution sets sys.modules['guard.agy_hooks'] alias without double-importing or loading siblings
        cli_mods = query_loaded(
            "import io, json, runpy, sys; "
            "sys.argv = ['guard/agy_hooks.py', 'pre-tool-use']; "
            "sys.stdin = io.StringIO(json.dumps({'toolCall': {'name': 'read_file', 'args': {'Path': 'README.md'}}})); "
            "buf = io.StringIO(); orig_out = sys.stdout; sys.stdout = buf; "
            "exec_code = None\n"
            "try:\n"
            "    runpy.run_path('guard/agy_hooks.py', run_name='__main__')\n"
            "except SystemExit as exc:\n"
            "    exec_code = exc.code\n"
            "finally:\n"
            "    sys.stdout = orig_out\n"
            "print(json.dumps({"
            "'code': exec_code, "
            "'out': json.loads(buf.getvalue()), "
            "'aliased': 'guard.agy_hooks' in sys.modules, "
            "'mods': sorted(m for m in sys.modules if m.startswith('guard.hooks.'))"
            "}))"
        )
        self.assertEqual(cli_mods["code"], 0)
        self.assertEqual(cli_mods["out"], {"decision": "allow"})
        self.assertTrue(cli_mods["aliased"])
        self.assertEqual(cli_mods["mods"], ["guard.hooks.common", "guard.hooks.pre_tool_use"])

    def test_all_submodule_top_level_definitions_registered_in_facade(self) -> None:
        hooks_py = REPO_ROOT / "guard" / "agy_hooks.py"
        line_count = len(hooks_py.read_text(encoding="utf-8").splitlines())
        self.assertLessEqual(line_count, 350, f"guard/agy_hooks.py exceeds 350-line facade cap ({line_count})")

        internal_shims = {
            "_DEFAULT_REPO_ROOT",
            "_FacadeModuleProxy",
            "_facade",
            "_repo_root",
        }
        facade_native = {
            "atomic_write_json",
            "config_dir",
            "configured_config_dir",
            "data_dir",
            "file_lock",
            "json",
            "state_dir",
            "subprocess",
        }
        dir_entries = set(dir(agy_hooks))
        for submod in ("common", "pre_invocation", "pre_tool_use", "stop_gate"):
            mod_path = REPO_ROOT / "guard" / "hooks" / f"{submod}.py"
            tree = ast.parse(mod_path.read_text(encoding="utf-8"), filename=str(mod_path))
            for node in tree.body:
                names: list[str] = []
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    names = [node.name]
                elif isinstance(node, ast.Assign):
                    names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    names = [node.target.id]
                for nm in names:
                    if nm in internal_shims or nm in facade_native:
                        continue
                    with self.subTest(submod=submod, symbol=nm):
                        self.assertEqual(agy_hooks._SYMBOL_TO_SUBMODULE.get(nm), submod)
                        self.assertIn(nm, dir_entries)
                        self.assertTrue(hasattr(agy_hooks, nm))

    def test_split_layout_synthetic_package_bootstrap_when_guard_points_elsewhere(self) -> None:
        fake_guard_dir = self.tmp / "fake_installed_guard"
        fake_guard_dir.mkdir()
        hooks_py = REPO_ROOT / "guard" / "agy_hooks.py"
        guard_mod = sys.modules["guard"]
        with mock.patch.object(guard_mod, "__path__", [str(fake_guard_dir)]):
            spec = importlib.util.spec_from_file_location("_split_layout_agy_hooks", hooks_py)
            self.assertIsNotNone(spec)
            assert spec is not None and spec.loader is not None
            split_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(split_mod)

            split_mod.REPO_ROOT = self.tmp / "no_rea_checkout"  # type: ignore[attr-defined]
            pi_res = split_mod.handle_pre_invocation(
                {"prompt": "/rea inspect firmware", "cwd": str(self.ws_dir), "conversationId": "split-1"}
            )
            self.assertNotIn("reverse-engineer-anything", _extract_injected_text(pi_res))
            disp_res = split_mod.dispatch_hook(
                "pre-invocation",
                {"prompt": "/rea inspect firmware", "cwd": str(self.ws_dir), "conversationId": "split-disp-1"},
            )
            self.assertNotIn("reverse-engineer-anything", _extract_injected_text(disp_res))
            ptu_res = split_mod.handle_pre_tool_use(
                {"toolCall": {"name": "read_file", "args": {"Path": str(self.ws_dir / "x.txt")}}}
            )
            self.assertEqual(ptu_res, {"decision": "allow"})
            stop_res = split_mod.handle_stop({"terminationReason": "user_canceled"})
            self.assertEqual(stop_res, {})

    def test_meta_audit_pass2_scans_guard_hooks_submodules_for_missing_subagents(self) -> None:
        from scripts.meta_audit import MetaAuditEngine

        synth_root = self.tmp / "synth_meta_hooks"
        (synth_root / "agents").mkdir(parents=True)
        (synth_root / "agents" / "meta-auditor.md").write_text(
            "---\nname: meta-auditor\ndescription: Meta.\naccess: read-only\n---\n# Meta\n",
            encoding="utf-8",
        )
        (synth_root / "guard" / "hooks").mkdir(parents=True)
        (synth_root / "guard" / "agy_hooks.py").write_text(
            'PRE_TOOL_USE_MATCHER_TOOLS = ("run_command",)\n',
            encoding="utf-8",
        )
        (synth_root / "guard" / "hooks" / "pre_invocation.py").write_text(
            "ECOSYSTEM_ROUTING_HINTS = (\n"
            '    ("r_ok", None, "Subagent `meta-auditor` (`invoke_subagent`)"),\n'
            '    ("r_builtin", None, "Built-in Subagent `browser` (`invoke_subagent`)"),\n'
            '    ("r_self", None, "Subagent `self` (`invoke_subagent`)"),\n'
            '    ("r_missing", None, "Subagents `meta-auditor` & `missing-hook-auditor` (`invoke_subagent`)"),\n'
            ")\n",
            encoding="utf-8",
        )
        eng = MetaAuditEngine(repo_root=synth_root)
        eng.pass2_cross_references()
        hook_findings = [f for f in eng.findings if f.target == "guard/hooks/pre_invocation.py"]
        self.assertEqual(len(hook_findings), 1, eng.findings)
        self.assertEqual(hook_findings[0].severity, "WARNING")
        self.assertIn("missing-hook-auditor", hook_findings[0].message)

    def test_stop_gate_corrupt_flight_recorder_fails_closed_even_when_read_only(self) -> None:
        git_ws = self.tmp / "f01_git_ws"
        git_ws.mkdir()
        subprocess.run(["git", "-C", str(git_ws), "init"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(git_ws), "config", "user.email", "t@example.com"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(git_ws), "config", "user.name", "Tester"], check=True, capture_output=True)
        (git_ws / "main.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(git_ws), "add", "main.py"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(git_ws), "commit", "-m", "init"], check=True, capture_output=True)

        flight_file = agy_hooks._flight_recorder_file()
        flight_file.parent.mkdir(parents=True, exist_ok=True)
        flight_file.write_text("{corrupt-flight-ledger", encoding="utf-8")

        res = agy_hooks.handle_stop(
            {
                "conversationId": "conv-f01-readonly",
                "readOnly": True,
                "terminationReason": "NO_TOOL_CALL",
                "workspace": str(git_ws),
            }
        )
        self.assertTrue(flight_file.is_file(), "Corrupt flight_recorder.json must not be silently moved aside")
        self.assertEqual(res.get("decision"), "continue", res)
        self.assertIn("Git diff inspection failed", res.get("reason", ""))

    def test_pre_invocation_intra_turn_transcript_fast_path_clean_and_heavy_trace(self) -> None:
        tx_path = self.tmp / "transcript.jsonl"
        tx_path.write_text(
            json.dumps({"type": "USER_INPUT", "content": "Build the project and run checks"}) + "\n"
            + json.dumps({"type": "TOOL_RESULT", "tool_name": "run_command", "status": "DONE", "content": "Command exited with code 0\n"}) + "\n",
            encoding="utf-8",
        )
        prompt_text = "Lütfen projeyi derle ve tüm kontrolleri çalıştır"
        r1 = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-f02-tx",
                "invocationNum": 1,
                "prompt": prompt_text,
                "transcriptPath": str(tx_path),
            }
        )
        self.assertIsInstance(r1, dict)

        # Clean intra-turn invocation with transcriptPath must return {} without TypeError
        r2 = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-f02-tx",
                "invocationNum": 2,
                "prompt": prompt_text,
                "transcriptPath": str(tx_path),
            }
        )
        self.assertEqual(r2, {})

        # >500-line error trace in transcript must emit build-error-resolver routing without ValueError
        heavy_err = "\n".join(f"src/app.ts({i},1): error TS2322: Type mismatch" for i in range(1, 520))
        with tx_path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "type": "TOOL_RESULT",
                        "tool_name": "run_command",
                        "status": "ERROR",
                        "content": heavy_err,
                    }
                )
                + "\n"
            )
        r3 = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-f02-tx",
                "invocationNum": 3,
                "prompt": prompt_text,
                "transcriptPath": str(tx_path),
            }
        )
        injected = _extract_injected_text(r3)
        self.assertIn("[Harness Ecosystem Routing]", injected)
        self.assertIn("build-error-resolver", injected)

        # Identical digest on subsequent intra-turn step deduplicates cleanly
        r4 = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-f02-tx",
                "invocationNum": 4,
                "prompt": prompt_text,
                "transcriptPath": str(tx_path),
            }
        )
        self.assertEqual(r4, {})

    def test_scanner_exempt_paths_reject_suffix_spoofing_and_non_harness_workspaces(self) -> None:
        from scripts import verify_invariants

        env_var = "PYTEST_" + "CURRENT_TEST"
        sniff_line = f"+x = os.environ.get('{env_var}')\n"
        # 1. Nested suffix spoofing is flagged even when workspace=None
        spoof_findings = agy_hooks.inspect_git_diff(
            "+++ b/evil/guard/hooks/stop_gate.py\n" + sniff_line, workspace=None
        )
        self.assertTrue(any("Test-runner detection" in f for f in spoof_findings), spoof_findings)

        # 2. Exact path inside a non-harness user workspace is flagged
        user_ws_findings = agy_hooks.inspect_git_diff(
            "+++ b/guard/hooks/stop_gate.py\n" + sniff_line, workspace=self.ws_dir
        )
        self.assertTrue(any("Test-runner detection" in f for f in user_ws_findings), user_ws_findings)

        # 3. Exact path inside actual harness checkout remains exempt
        harness_findings = agy_hooks.inspect_git_diff(
            "+++ b/guard/hooks/stop_gate.py\n" + sniff_line, workspace=REPO_ROOT
        )
        self.assertEqual(harness_findings, [])

        # 4. verify_invariants.scan_directory flags local guard/hooks/stop_gate.py in non-harness project
        non_harness_proj = self.tmp / "non_harness_proj"
        target_py = non_harness_proj / "guard" / "hooks" / "stop_gate.py"
        target_py.parent.mkdir(parents=True)
        target_py.write_text(f"import os\nx = os.environ.get('{env_var}')\n", encoding="utf-8")
        scan_violations = verify_invariants.scan_directory(non_harness_proj)
        self.assertTrue(any("C9" in desc for _loc, _ln, desc in scan_violations), scan_violations)

    def test_stop_bootstrap_import_error_fails_closed_while_runtime_error_yields(self) -> None:
        hooks_py = REPO_ROOT / "guard" / "agy_hooks.py"
        spec = importlib.util.spec_from_file_location("_bootstrap_err_hooks", hooks_py)
        assert spec is not None and spec.loader is not None
        isolated_hooks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(isolated_hooks)

        with (
            mock.patch.object(isolated_hooks, "_load_submodule", side_effect=ImportError("corrupt stop_gate")),
            mock.patch.object(sys, "stdin", io.StringIO('{"terminationReason": "NO_TOOL_CALL", "executionNum": 0}')),
            mock.patch.object(sys, "stdout", new_callable=io.StringIO) as out_boot,
            mock.patch.object(sys, "stderr", new_callable=io.StringIO),
        ):
            rc = isolated_hooks.main(["stop"])
        self.assertEqual(rc, 0)
        boot_resp = json.loads(out_boot.getvalue())
        self.assertEqual(boot_resp.get("decision"), "continue", boot_resp)
        self.assertIn("Failed to load Stop gate submodule", boot_resp.get("reason", ""))

        # Circuit breaker at executionNum >= 2 prevents infinite IDE trap on broken disk install
        with (
            mock.patch.object(isolated_hooks, "_load_submodule", side_effect=ImportError("corrupt stop_gate")),
            mock.patch.object(sys, "stdin", io.StringIO('{"terminationReason": "NO_TOOL_CALL", "executionNum": 2}')),
            mock.patch.object(sys, "stdout", new_callable=io.StringIO) as out_cb,
            mock.patch.object(sys, "stderr", new_callable=io.StringIO),
        ):
            isolated_hooks.main(["stop"])
        self.assertEqual(json.loads(out_cb.getvalue()), {})

    def test_dunder_file_data_dir_tomllib_and_router_edge_seams(self) -> None:
        # 1. Patching __file__ alone (without REPO_ROOT) dynamically redirects _repo_root()
        fake_root = self.tmp / "dunder_file_repo"
        fake_seed = fake_root / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        fake_seed.parent.mkdir(parents=True)
        fake_seed.write_text(
            json.dumps(
                {
                    "last_audited_model": "Dunder File Model 5 (High)",
                    "last_model_slug": "dunder-file-model-5-high",
                    "approved_customization_models": ["dunder-file-model-5-high"],
                }
            ),
            encoding="utf-8",
        )
        empty_cfg = self.tmp / "dunder_empty_cfg"
        empty_cfg.mkdir()
        with (
            mock.patch.object(agy_hooks, "__file__", str(fake_root / "guard" / "agy_hooks.py")),
            mock.patch.object(agy_hooks, "config_dir", return_value=empty_cfg),
            mock.patch.object(agy_hooks, "configured_config_dir", return_value=empty_cfg),
        ):
            top_label, top_slugs = agy_hooks._catalog_top_model_spec()
        self.assertEqual(top_label, "Dunder File Model 5 (High)")
        self.assertIn("dunder-file-model-5-high", top_slugs)

        # 2. Patching data_dir redirects protected runtime path detection
        custom_data = self.tmp / "custom_guard_data"
        custom_data.mkdir()
        with mock.patch.object(agy_hooks, "data_dir", return_value=custom_data):
            self.assertTrue(agy_hooks._command_mutates_governance(f"rm -rf {custom_data}/runtime"))

        # 3. Patching tomllib governs TOML validation in validate_structured_content
        fake_toml = mock.MagicMock()
        fake_toml.loads.side_effect = ValueError("synthetic toml failure")
        with mock.patch.object(agy_hooks, "tomllib", fake_toml):
            toml_issues = agy_hooks.validate_structured_content("pyproject.toml", "[project]\nname = 'x'\n")
        self.assertTrue(any("Malformed TOML syntax" in x for x in toml_issues), toml_issues)

        # 4. state_dir + atomic_write_json + file_lock monkeypatches in Stop strike recording
        stop_state = self.tmp / "custom_stop_state"
        stop_state.mkdir()
        stop_writes: list[Path] = []
        stop_locks: list[Path] = []
        real_write = agy_hooks.atomic_write_json
        real_lock = agy_hooks.file_lock
        with (
            mock.patch.object(agy_hooks, "state_dir", return_value=stop_state),
            mock.patch.object(
                agy_hooks,
                "atomic_write_json",
                side_effect=lambda p, d: (stop_writes.append(Path(p)), real_write(p, d))[1],
            ),
            mock.patch.object(
                agy_hooks,
                "file_lock",
                side_effect=lambda p, *a, **kw: (stop_locks.append(Path(p)), real_lock(p, *a, **kw))[1],
            ),
        ):
            stop_res = agy_hooks.handle_stop(
                {
                    "conversationId": "conv-stop-seams",
                    "terminationReason": "NO_TOOL_CALL",
                    "diffText": "+++ b/tests/test_x.py\n+" + "    assert val == val\n",
                }
            )
        self.assertEqual(stop_res.get("decision"), "continue")
        self.assertTrue(any(p == stop_state / "hook_strikes.json" for p in stop_writes), stop_writes)
        self.assertTrue(any(p == stop_state / "hook_strikes.json" for p in stop_locks), stop_locks)

        # 5. AGY_RECORD_HOST_FIXTURES, unknown event, malformed stdin stop event inference, pre-invocation fallback
        recorded: list[tuple[str, dict]] = []
        with (
            mock.patch.dict(os.environ, {"AGY_RECORD_HOST_FIXTURES": "1"}, clear=False),
            mock.patch.object(agy_hooks, "_maybe_record_host_fixture", side_effect=lambda e, p: recorded.append((e, p))),
        ):
            self.assertEqual(agy_hooks.dispatch_hook("unknown-event", {"x": 1}), {})
        self.assertEqual(recorded, [("unknown-event", {"x": 1})])

        with (
            mock.patch.object(sys, "stdin", io.StringIO('{"hookEventName": "stop", broken')),
            mock.patch.object(sys, "stdout", new_callable=io.StringIO) as out_raw_stop,
            mock.patch.object(sys, "stderr", new_callable=io.StringIO),
        ):
            agy_hooks.main([])
        self.assertEqual(json.loads(out_raw_stop.getvalue()).get("decision"), "continue")

        with (
            mock.patch.object(agy_hooks, "handle_pre_invocation", side_effect=RuntimeError("pi boom")),
            mock.patch.object(sys, "stdin", io.StringIO('{"prompt": "hello world testing"}')),
            mock.patch.object(sys, "stdout", new_callable=io.StringIO) as out_pi_err,
        ):
            agy_hooks.main(["pre-invocation"])
        self.assertEqual(json.loads(out_pi_err.getvalue()), {})

    def test_synthetic_package_rollback_multi_load_generator_binding_and_star_import(self) -> None:
        import runpy
        import shutil

        # 1. Failed exec_module on synthetic hooks/__init__.py rolls back sys.modules cleanly
        broken_guard = self.tmp / "broken_pkg" / "guard"
        (broken_guard / "hooks").mkdir(parents=True)
        shutil.copy2(REPO_ROOT / "guard" / "agy_hooks.py", broken_guard / "agy_hooks.py")
        (broken_guard / "hooks" / "__init__.py").write_text("raise RuntimeError('init failed')\n", encoding="utf-8")
        spec_b = importlib.util.spec_from_file_location("_broken_facade", broken_guard / "agy_hooks.py")
        assert spec_b is not None and spec_b.loader is not None
        mod_b = importlib.util.module_from_spec(spec_b)
        spec_b.loader.exec_module(mod_b)
        with self.assertRaises(RuntimeError):
            _ = mod_b.MAX_HINTS
        self.assertNotIn(mod_b._SYNTHETIC_PKG_NAME, sys.modules)

        # 2. Repeated spec_from_file_location calls on same path pick up fresh on-disk submodule changes
        copy_guard = self.tmp / "editable_pkg" / "guard"
        shutil.copytree(REPO_ROOT / "guard" / "hooks", copy_guard / "hooks")
        shutil.copy2(REPO_ROOT / "guard" / "agy_hooks.py", copy_guard / "agy_hooks.py")

        def _load_copy() -> object:
            sp = importlib.util.spec_from_file_location("_editable_facade", copy_guard / "agy_hooks.py")
            assert sp is not None and sp.loader is not None
            m = importlib.util.module_from_spec(sp)
            sp.loader.exec_module(m)
            return m

        m1 = _load_copy()
        self.assertEqual(m1.MAX_HINTS, 2)  # type: ignore[attr-defined]
        common_copy = copy_guard / "hooks" / "common.py"
        common_copy.write_text(
            common_copy.read_text(encoding="utf-8").replace("MAX_HINTS = 2", "MAX_HINTS = 7", 1),
            encoding="utf-8",
        )
        m2 = _load_copy()
        self.assertEqual(m2.MAX_HINTS, 7)  # type: ignore[attr-defined]

        # 3. Generator _iter_jsonl_tail_entries keeps _ACTIVE_FACADE bound across yield steps
        jsonl_file = self.tmp / "tail.jsonl"
        jsonl_file.write_text('{"a": 1}\n{"a": 2}\n', encoding="utf-8")
        seen_loads: list[str] = []
        fake_json = mock.MagicMock()
        fake_json.loads.side_effect = lambda s: (seen_loads.append(s), json.loads(s))[1]
        m2.json = fake_json  # type: ignore[attr-defined]
        entries = list(m2._iter_jsonl_tail_entries(jsonl_file))  # type: ignore[attr-defined]
        self.assertEqual([e["a"] for e in entries], [2, 1])
        self.assertEqual(len(seen_loads), 2)

        # 4. In-process runpy.run_path does not overwrite canonical sys.modules['guard.agy_hooks']
        canonical_before = sys.modules["guard.agy_hooks"]
        with (
            mock.patch.object(sys, "argv", ["pytest"]),
            mock.patch.object(sys, "stdin", io.StringIO('{"terminationReason": "user_canceled"}')),
            mock.patch.object(sys, "stdout", new_callable=io.StringIO),
        ):
            with self.assertRaises(SystemExit) as cm:
                runpy.run_path(str(REPO_ROOT / "guard" / "agy_hooks.py"), run_name="__main__")
        self.assertEqual(cm.exception.code, 0)
        self.assertIs(sys.modules["guard.agy_hooks"], canonical_before)

        # 5. __all__ exposes public facade + lazy submodule symbols for star-import consumers
        star_ns: dict[str, object] = {}
        exec("from guard.agy_hooks import *", star_ns)
        for pub_sym in (
            "PRE_TOOL_USE_MATCHER",
            "SKILL_HINTS",
            "ECOSYSTEM_ROUTING_HINTS",
            "dispatch_hook",
            "handle_pre_invocation",
            "handle_pre_tool_use",
            "handle_stop",
            "inspect_git_diff",
        ):
            self.assertIn(pub_sym, star_ns)

    def test_pre_tool_use_corrupt_environments_and_cmd_input_buffers_fail_closed(self) -> None:
        # 1. Corrupt environments.json fails closed on mutating/command tools without quarantining registry
        env_file = self.state_dir / "environments.json"
        env_file.write_text("{corrupt-env-registry", encoding="utf-8")

        deny_write = agy_hooks.handle_pre_tool_use(
            {
                "workspace": str(self.ws_dir),
                "toolCall": {"name": "write_file", "args": {"Path": str(self.ws_dir / "app.py")}},
            }
        )
        self.assertEqual(deny_write.get("decision"), "deny", deny_write)
        self.assertIn("environments.json", deny_write.get("reason", ""))
        self.assertTrue(env_file.is_file(), "environments.json must remain intact for operator recovery")

        deny_cmd = agy_hooks.handle_pre_tool_use(
            {
                "workspace": str(self.ws_dir),
                "toolCall": {"name": "run_command", "args": {"CommandLine": "echo hi"}},
            }
        )
        self.assertEqual(deny_cmd.get("decision"), "deny", deny_cmd)

        allow_read = agy_hooks.handle_pre_tool_use(
            {
                "workspace": str(self.ws_dir),
                "toolCall": {"name": "read_file", "args": {"Path": str(self.ws_dir / "app.py")}},
            }
        )
        self.assertEqual(allow_read.get("decision"), "allow")

        allow_list_tasks = agy_hooks.handle_pre_tool_use(
            {
                "workspace": str(self.ws_dir),
                "toolCall": {"name": "manage_task", "args": {"Action": "list"}},
            }
        )
        self.assertEqual(allow_list_tasks.get("decision"), "allow")
        env_file.unlink()

        # 2. Corrupt cmd_input_buffers.json quarantines and requires force_ask (while explicit deny still denies)
        buf_file = self.state_dir / "cmd_input_buffers.json"
        buf_file.write_text("{corrupt-cmd-buffer", encoding="utf-8")
        ask_chunk = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-buf-1",
                "workspace": str(self.ws_dir),
                "toolCall": {"name": "send_command_input", "args": {"TaskId": "t1", "Input": "lock\n"}},
            }
        )
        self.assertEqual(ask_chunk.get("decision"), "force_ask", ask_chunk)
        self.assertFalse(buf_file.exists())

        buf_file.write_text("{corrupt-cmd-buffer-2", encoding="utf-8")
        deny_chunk = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-buf-2",
                "workspace": str(self.ws_dir),
                "toolCall": {"name": "send_command_input", "args": {"TaskId": "t2", "Input": "agy-guard unlock\n"}},
            }
        )
        self.assertEqual(deny_chunk.get("decision"), "deny", deny_chunk)

    def test_meta_audit_split_layout_pass2_and_pass7_broken_lazy_export_detection(self) -> None:
        from scripts.meta_audit import MetaAuditEngine

        # 1. Split-layout Pass 2 scans AGY_GUARD_DATA_DIR/runtime/guard/hooks/*.py and checks missing submodules
        split_cfg = self.tmp / "split_cfg"
        split_data = self.tmp / "split_data"
        (split_cfg / "agents").mkdir(parents=True)
        (split_cfg / "agents" / "meta-auditor.md").write_text(
            "---\nname: meta-auditor\ndescription: Meta.\naccess: read-only\n---\n# Meta\n",
            encoding="utf-8",
        )
        (split_cfg / ".harness").mkdir(parents=True)
        (split_cfg / ".harness" / "manifest.json").write_text(
            json.dumps({"agents": [{"name": "meta-auditor"}]}),
            encoding="utf-8",
        )
        rt_hooks = split_data / "runtime" / "guard" / "hooks"
        rt_hooks.mkdir(parents=True)
        (split_data / "runtime" / "guard" / "agy_hooks.py").write_text(
            'PRE_TOOL_USE_MATCHER_TOOLS = ("run_command",)\n_SUBMODULE_EXPORTS = {"common": ()}\n',
            encoding="utf-8",
        )
        (rt_hooks / "__init__.py").write_text("", encoding="utf-8")
        (rt_hooks / "common.py").write_text("", encoding="utf-8")
        (rt_hooks / "pre_invocation.py").write_text(
            'ECOSYSTEM_ROUTING_HINTS = (("r1", None, "Subagent `ghost-split-agent` (`invoke_subagent`)"),)\n',
            encoding="utf-8",
        )
        (rt_hooks / "pre_tool_use.py").write_text("", encoding="utf-8")
        # Deliberately omit stop_gate.py to verify CRITICAL missing submodule detection + WARNING ghost-split-agent
        with mock.patch.dict(os.environ, {"AGY_GUARD_DATA_DIR": str(split_data)}, clear=False):
            eng_split = MetaAuditEngine(repo_root=split_cfg)
            eng_split.pass2_cross_references()
        self.assertTrue(
            any(f.severity == "WARNING" and "ghost-split-agent" in f.message for f in eng_split.findings),
            eng_split.findings,
        )
        self.assertTrue(
            any(f.severity == "CRITICAL" and "guard/hooks/stop_gate.py" in f.target for f in eng_split.findings),
            eng_split.findings,
        )

        # 2. Pass 7 flags broken lazy export AttributeError as CRITICAL instead of swallowing via 3-arg getattr
        broken_p7 = self.tmp / "broken_p7"
        (broken_p7 / "skills").mkdir(parents=True)
        (broken_p7 / "guard" / "hooks").mkdir(parents=True)
        (broken_p7 / "guard" / "hooks" / "pre_invocation.py").write_text("# stub\n", encoding="utf-8")
        (broken_p7 / "guard" / "agy_hooks.py").write_text(
            '_SYMBOL_TO_SUBMODULE = {"SKILL_HINTS": "pre_invocation"}\n'
            "def __getattr__(name):\n"
            "    raise AttributeError(f'broken lazy export: {name}')\n",
            encoding="utf-8",
        )
        eng_p7 = MetaAuditEngine(repo_root=broken_p7)
        eng_p7.pass7_trigger_specificity()
        self.assertTrue(
            any(f.severity == "CRITICAL" and "broken lazy export" in f.message for f in eng_p7.findings),
            eng_p7.findings,
        )


if __name__ == "__main__":
    unittest.main()
