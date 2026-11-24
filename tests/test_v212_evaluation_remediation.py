#!/usr/bin/env python3
"""
tests/test_v212_evaluation_remediation.py — Seam & adversarial regression suite for ADR-0010 (Windows 2..3):
  - AC-1: PEP 562 lazy `guard/__init__.py`, `_LazyRegex` & `lru_cache` root-pattern caching, lazy `guard/hooks/_workflow_ast.py`
  - AC-2: Unified `ast.parse` pure read-only Python inline/heredoc governance shield & flight-recorder precision
  - AC-3: Reactive wakeup `tx_mid_turn` continuity (`invocationNum == 1`) & true-consecutive `build-error-resolver` filter
  - AC-4: Standalone subprocess hermetic isolation across `tests/test_*.py` + static `scripts/meta_audit.py` gate
  - AC-5: Backward-compatible `known_placeholder_models` (`M417`/`M427`/`M528`) & `skills/harness/SKILL.md` §1 routing deduplication
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
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
import guard  # noqa: E402
import guard.agy_hooks as agy_hooks  # noqa: E402


def _injected_text(resp: dict) -> str:
    chunks: list[str] = []
    if isinstance(resp.get("additionalContext"), str):
        chunks.append(resp["additionalContext"])
    steps = resp.get("injectSteps")
    if isinstance(steps, list):
        for st in steps:
            if isinstance(st, dict):
                sm = st.get("systemMessage")
                if isinstance(sm, dict):
                    for k in ("systemMessage", "message"):
                        v = sm.get(k)
                        if isinstance(v, str):
                            chunks.append(v)
                elif isinstance(sm, str):
                    chunks.append(sm)
    return "\n".join(chunks)


class HermeticHookCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-v212-")
        self.tmp = Path(self._tmp.name)
        self.cfg_dir = self.tmp / ".gemini" / "config"
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
                "USERPROFILE": str(self.tmp),
                "XDG_STATE_HOME": str(self.tmp / "xdg_state"),
                "XDG_DATA_HOME": str(self.tmp / "xdg_data"),
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
        hermetic.force_rmtree(self.tmp)
        self._tmp.cleanup()

    def _init_git_ws(self, ws: Path) -> None:
        ws.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(ws)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(ws), "config", "user.email", "t@example.com"], check=True)
        subprocess.run(["git", "-C", str(ws), "config", "user.name", "Tester"], check=True)
        (ws / "app.py").write_text("X = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(ws), "add", "app.py"], check=True)
        subprocess.run(["git", "-C", str(ws), "commit", "-m", "init"], check=True, capture_output=True)


class TestAC1LazyGuardInitAndHookColdStart(HermeticHookCase):
    def test_guard_package_lazy_pep562_loads_zero_non_hook_submodules(self) -> None:
        """Catches eager imports in `guard/__init__.py` pulling in `porter`/`snapshot`/`lease` on hook startup."""
        probe = (
            "import json, sys\n"
            "import guard.paths\n"
            "import guard.agy_hooks\n"
            "loaded = sorted(m for m in sys.modules if m.startswith('guard.') or m.startswith('porter'))\n"
            "print(json.dumps(loaded))\n"
        )
        cp = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=str(REPO_ROOT),
            env=dict(os.environ),
            text=True,
            capture_output=True,
            check=True,
        )
        loaded = json.loads(cp.stdout.strip())
        self.assertEqual(loaded, ["guard.agy_hooks", "guard.paths"], loaded)

        expected_all = [
            "__version__",
            "OSProtectionAdapter",
            "FileIntegrityMonitor",
            "SnapshotEngine",
            "PorterBridge",
            "UpstreamAuditorBridge",
            "StartupManager",
            "TestBoundaryGuard",
            "RunProvenanceTracker",
            "AgentEnvironment",
            "EnvironmentRegistry",
            "GuardNotifier",
            "NotificationSeverity",
            "LeaseManager",
            "UnlockLease",
            "create_tray_adapter",
        ]
        self.assertEqual(guard.__all__, expected_all)
        dir_names = set(dir(guard))
        for sym in expected_all:
            self.assertIn(sym, dir_names)
            self.assertIsNotNone(getattr(guard, sym))
        with self.assertRaises(AttributeError):
            _ = guard.NON_EXISTENT_GUARD_EXPORT  # type: ignore[attr-defined]

    def test_workflow_ast_extracted_lazily_reexported_and_root_patterns_cached(self) -> None:
        """Catches eager `_workflow_ast` import on non-workflow PreToolUse calls or broken re-exports/caches."""
        probe = (
            "import json, sys\n"
            "import guard.agy_hooks as h\n"
            "res = h.dispatch_hook('pre-tool-use', {'toolCall': {'name': 'run_command', 'args': {'CommandLine': 'git status'}}})\n"
            "from guard.hooks import common, pre_tool_use\n"
            "uncompiled_fence = common._FENCE_RE._compiled is None\n"
            "uncompiled_settings = pre_tool_use._SETTINGS_MODEL_RE._compiled is None\n"
            "mods = sorted(m for m in sys.modules if m.startswith('guard.hooks.'))\n"
            "print(json.dumps({'res': res, 'mods': mods, 'uf': uncompiled_fence, 'us': uncompiled_settings}))\n"
        )
        cp = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=str(REPO_ROOT),
            env=dict(os.environ),
            text=True,
            capture_output=True,
            check=True,
        )
        data = json.loads(cp.stdout.strip())
        self.assertEqual(data["res"], {"decision": "allow"})
        self.assertEqual(
            data["mods"],
            ["guard.hooks._shell_guard", "guard.hooks.common", "guard.hooks.pre_tool_use"],
        )
        for deferred_mod in (
            "guard.hooks._workflow_ast",
            "guard.hooks._swarm_guard",
            "guard.hooks._mcp_guard",
            "guard.hooks._write_guard",
        ):
            self.assertNotIn(deferred_mod, data["mods"])
        self.assertTrue(data["uf"])
        self.assertTrue(data["us"])

        from guard.hooks import _workflow_ast, pre_tool_use

        self.assertTrue(callable(pre_tool_use._inspect_workflow_script))
        self.assertTrue(callable(_workflow_ast._inspect_workflow_script))
        deny_res, _fw = pre_tool_use._inspect_workflow_script(
            "import subprocess\nsubprocess.run(['ls'])\n",
            [],
            {},
            self.ws_dir,
        )
        self.assertEqual(deny_res.get("decision"), "deny")
        allow_res, fw = pre_tool_use._inspect_workflow_script(
            f'call_tool("read_file", Path="{self.ws_dir.as_posix()}/a.txt")\n',
            [],
            {},
            self.ws_dir,
        )
        self.assertEqual(allow_res.get("decision"), "allow")
        self.assertEqual(fw, [])

        pre_tool_use._compiled_governance_root_patterns.cache_clear()
        cfg_str = str(self.cfg_dir)
        self.assertTrue(agy_hooks._command_mutates_governance(f"rm -f {cfg_str}/GEMINI.md"))
        self.assertTrue(agy_hooks._command_mutates_governance(f"rm -f {cfg_str}/GEMINI.md"))
        self.assertGreaterEqual(pre_tool_use._compiled_governance_root_patterns.cache_info().hits, 1)


class TestAC2UnifiedReadOnlyPythonAstInlineShield(HermeticHookCase):
    def test_readonly_python_inline_and_heredoc_allow_without_in_flight_writes(self) -> None:
        """Catches false-positive denials on read-only `python3 -c`/`<<'EOF'` diagnostics or false `in_flight` writes."""
        git_ws = self.tmp / "ro_git_ws"
        self._init_git_ws(git_ws)
        cfg_file = self.cfg_dir / "GEMINI.md"
        flight_file = agy_hooks._flight_recorder_file()

        readonly_cmds = [
            f'python3 -c "# inspect {cfg_file.as_posix()}\nimport json, pathlib\np = pathlib.Path(\'{cfg_file.as_posix()}\')\nprint(p.exists(), p.is_file(), p.is_dir(), p.is_symlink(), p.stat().st_size, len(p.read_text()))"',
            "python3 -c \"from pathlib import Path; root = Path.home() / '.gemini' / 'config'; print([p.name for p in root.iterdir()], list(root.glob('*.md')), list(root.rglob('*.md')))\"",
            f'python3 -c "with open(\'{cfg_file.as_posix()}\', \'r\', encoding=\'utf-8\') as f:\n    print(len(f.read().replace(\'a\', \'b\')))"',
            f"cd {self.cfg_dir} && python3 -c 'import os; print(len(os.listdir(\".\")))'",
            (
                "python3 <<'EOF'\n"
                "# Read-only heredoc referencing ~/.gemini/config with `>` comparison operator\n"
                "import json\n"
                "from pathlib import Path\n"
                "p = Path.home() / '.gemini' / 'config' / 'GEMINI.md'\n"
                "raw = p.read_bytes()\n"
                "if len(raw) > 2:\n"
                "    print(json.dumps({'bytes': len(raw), 'lstat': p.lstat().st_mode}))\n"
                "EOF"
            ),
        ]

        for idx, cmd in enumerate(readonly_cmds):
            with self.subTest(idx=idx, cmd=cmd[:80]):
                self.assertFalse(agy_hooks._command_mutates_governance(cmd), cmd)
                self.assertFalse(agy_hooks._shell_has_unquoted_mutation(cmd), cmd)
                res = agy_hooks.handle_pre_tool_use(
                    {
                        "conversationId": f"conv-ro-{idx}",
                        "workspace": str(git_ws),
                        "toolCall": {"name": "run_command", "args": {"CommandLine": cmd}},
                    }
                )
                self.assertEqual(res, {"decision": "allow"}, cmd)
        self.assertFalse(flight_file.exists(), "Read-only Python probes must not create flight_recorder.json")

        # Verify actual mutating Python command in workspace DOES still record "in_flight"
        mut_ws_cmd = f"python3 -c 'from pathlib import Path; Path({str(git_ws / 'out.txt')!r}).write_text(\"1\")'"
        res_mut_ws = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-mut-ws",
                "workspace": str(git_ws),
                "toolCall": {"name": "run_command", "args": {"CommandLine": mut_ws_cmd}},
            }
        )
        self.assertEqual(res_mut_ws, {"decision": "allow"})
        ledger = json.loads(flight_file.read_text(encoding="utf-8"))
        self.assertEqual(ledger[str(git_ws.resolve())]["status"], "in_flight")

    def test_mutating_obfuscated_and_non_python_interpreters_fail_closed_on_governance(self) -> None:
        """Catches regex-evading Python mutations (`touch`, `truncate`, `FileIO`, `sqlite3`, `tarfile`, `getattr`, etc.) and non-Python `-e`/`<<`."""
        cfg_target = str(self.cfg_dir / "GEMINI.md")
        state_target = str(self.state_dir / "leases.json")

        blocked_cmds = [
            f"python3 -c 'from pathlib import Path; Path({cfg_target!r}).touch()'",
            "python3 -c \"from pathlib import Path; (Path.home() / '.gemini' / 'config' / 'pwn').touch()\"",
            f"python3 -c 'import os; os.truncate({cfg_target!r}, 0)'",
            f"python3 -c 'import io; io.FileIO({cfg_target!r}, \"w\").close()'",
            f"python3 -c 'open({cfg_target!r}, \"w\").close()'",
            f"python3 -c 'open({cfg_target!r}, \"a\").close()'",
            f"python3 -c 'open({cfg_target!r}, \"x\").close()'",
            f"python3 -c 'open({cfg_target!r}, \"r+\").close()'",
            f"python3 -c 'import os; open({cfg_target!r}, \"r\", opener=os.open)'",
            f"python3 -c 'import sqlite3; sqlite3.connect({state_target!r})'",
            f"python3 -c 'import tarfile; tarfile.open({state_target!r}, \"w\")'",
            f"python3 -c 'import zipfile; zipfile.ZipFile({state_target!r}, \"w\")'",
            f"python3 -c 'import shutil; shutil.rmtree({str(self.cfg_dir)!r})'",
            f"python3 -c 'import subprocess; subprocess.run([\"rm\", {cfg_target!r}])'",
            f"python3 -c 'import ctypes; print({cfg_target!r})'",
            f"python3 -c 'import importlib; importlib.import_module(\"shutil\").unlink({cfg_target!r})'",
            "python3 -c \"from pathlib import Path; p = Path.home() / '.gemini' / 'config' / 'GEMINI.md'; getattr(p, 'un' + 'link')()\"",
            "python3 -c \"import operator; from pathlib import Path; operator.methodcaller('touch')(Path.home() / '.gemini' / 'config' / 'x')\"",
            f"python3 -c 'import functools; functools.partial(open, {cfg_target!r}, \"w\")()'",
            f"python3 -c 'list(map(open, [{cfg_target!r}], [\"w\"]))'",
            f"python3 -c 'f = open; f({cfg_target!r}, \"w\")'",
            f"python3 -c 'eval(\"open({cfg_target!r}, \\\"w\\\")\")'",
            f"python3 -c 'exec(\"import os; os.unlink({cfg_target!r})\")'",
            f"python3 -c 'compile(\"1\", {cfg_target!r}, \"exec\")'",
            f"python3 -c '__import__(\"os\").unlink({cfg_target!r})'",
            f"python3 -c 'import os; os.replace(\"/tmp/a\", {cfg_target!r})'",
            f"python3 -c 'from pathlib import Path; Path.replace(Path(\"/tmp/a\"), Path({cfg_target!r}))'",
            f"python3 -c 'from pathlib import Path; Path(\"/tmp/a\").replace({cfg_target!r})'",
            f"python3 -c 'import os; e = os.environ; e.update({{\"X\": {cfg_target!r}}})'",
            f"python3 -c 'def broken(:\n    {cfg_target!r}'",
            # Multi-statement split home-path heredoc
            (
                "python3 <<'EOF'\n"
                "from pathlib import Path\n"
                "d = Path.home() / '.gemini'\n"
                "(d / 'config' / 'GEMINI.md').touch()\n"
                "EOF"
            ),
            # Env-var indirection (`ANTIGRAVITY_CONFIG_DIR`)
            "python3 -c \"import os; from pathlib import Path; (Path(os.environ['ANTIGRAVITY_CONFIG_DIR']) / 'GEMINI.md').touch()\"",
            # Shell expansion inside double-quoted `-c` or unquoted heredoc
            f'python3 -c "x = \'$(touch {cfg_target})\'"',
            f"python3 <<EOF\nx = '$(touch {cfg_target})'\nEOF",
            # Command substitution & shell output redirection around read-only Python
            f"rm $(python3 -c 'print({cfg_target!r})')",
            f"python3 -c 'print(\"x\")' > {cfg_target}",
            f"echo 'print(1)' | python3 # {cfg_target}",
            f"python3 -m zipfile -e /tmp/a.zip {self.cfg_dir}",
            # Non-Python inline and heredoc interpreters fail closed on governance roots
            f"node -e 'console.log({cfg_target!r})'",
            "node -e \"const os=require('os'),fs=require('fs');fs.truncateSync(os.homedir()+'/.gemini/config/GEMINI.md',0)\"",
            f"perl -e 'unlink {cfg_target!r}'",
            f"ruby -e 'File.delete({cfg_target!r})'",
            f"node <<'EOF'\n// {cfg_target}\nEOF",
        ]

        for idx, cmd in enumerate(blocked_cmds):
            with self.subTest(idx=idx, cmd=cmd[:90]):
                res = agy_hooks.handle_pre_tool_use(
                    {
                        "conversationId": f"conv-blk-{idx}",
                        "workspace": str(self.ws_dir),
                        "toolCall": {"name": "run_command", "args": {"CommandLine": cmd}},
                    }
                )
                self.assertEqual(res.get("decision"), "deny", f"Expected deny for #{idx}: {cmd}\nGot: {res}")

        # Verify state_dir()/staging RFC carve-out remains permitted
        staging_cmd = f"python3 -c 'from pathlib import Path; Path({str(self.state_dir / 'staging' / 'rfc.json')!r}).write_text(\"{{}}\")'"
        self.assertFalse(agy_hooks._command_mutates_governance(staging_cmd))


class TestAC3ReactiveWakeupContinuityAndConsecutiveBuildFilter(HermeticHookCase):
    def test_reactive_wakeup_invocation_one_preserves_mid_turn_and_post_crash_user_input_recovers(self) -> None:
        """Catches `invocationNum == 1` clobbering `tx_mid_turn` on background-task/subagent wakeups."""
        ws = self.tmp / "wakeup_ws"
        self._init_git_ws(ws)
        tx = self.tmp / "wakeup_tx.jsonl"
        prompt = "Run async benchmark and update app.py cleanly."

        tx.write_text(
            json.dumps({"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": prompt}) + "\n",
            encoding="utf-8",
        )
        r_start = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-wakeup",
                "invocationNum": 1,
                "workspace": str(ws),
                "transcriptPath": str(tx),
                "prompt": prompt,
            }
        )
        self.assertNotIn("[Harness Recovery & Continuity Gate]", _injected_text(r_start))

        # Record in-flight edit
        self.assertEqual(
            agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-wakeup",
                    "workspace": str(ws),
                    "toolCall": {"name": "edit_file", "args": {"Path": str(ws / "app.py")}},
                }
            ),
            {"decision": "allow"},
        )
        (ws / "app.py").write_text("X = 2\n", encoding="utf-8")
        flight_file = agy_hooks._flight_recorder_file()
        ws_key = str(ws.resolve())
        self.assertEqual(json.loads(flight_file.read_text(encoding="utf-8"))[ws_key]["status"], "in_flight")

        # Background task completes; host wakes up agent at invocationNum=1 with trailing tool/system steps
        with tx.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"step_index": 2, "type": "PLANNER_RESPONSE", "content": ""}) + "\n")
            fh.write(
                json.dumps(
                    {
                        "step_index": 3,
                        "type": "SYSTEM_MESSAGE",
                        "source": "SYSTEM",
                        "content": 'Task id "task-132" finished with result: Command exited with code 0.',
                    }
                )
                + "\n"
            )

        for wakeup_payload in (
            {
                "conversationId": "conv-wakeup",
                "invocationNum": 1,
                "workspace": str(ws),
                "transcriptPath": str(tx),
                "prompt": prompt,
            },
            {
                "conversationId": "conv-wakeup",
                "invocationNum": 1,
                "workspace": str(ws),
                "transcriptPath": str(tx),
            },
        ):
            r_wake = agy_hooks.handle_pre_invocation(wakeup_payload)
            self.assertEqual(r_wake, {}, f"Expected silent mid-turn wakeup, got: {r_wake}")
            self.assertEqual(
                json.loads(flight_file.read_text(encoding="utf-8"))[ws_key]["status"],
                "in_flight",
            )

        # Clean Stop transitions "in_flight" -> "turn_complete"
        self.assertEqual(
            agy_hooks.handle_stop({"conversationId": "conv-wakeup", "workspace": str(ws), "stopReason": "end_turn"}),
            {},
        )
        self.assertEqual(json.loads(flight_file.read_text(encoding="utf-8"))[ws_key]["status"], "turn_complete")

        # Now simulate a real mid-flight crash followed by a genuine new USER_INPUT turn at invocationNum=1
        self.assertEqual(
            agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-wakeup",
                    "workspace": str(ws),
                    "toolCall": {"name": "edit_file", "args": {"Path": str(ws / "app.py")}},
                }
            ),
            {"decision": "allow"},
        )
        with tx.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"step_index": 4, "type": "PLANNER_RESPONSE", "content": ""}) + "\n")
            fh.write(
                json.dumps({"step_index": 5, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "devam et"})
                + "\n"
            )
        r_crash = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-wakeup",
                "invocationNum": 1,
                "workspace": str(ws),
                "transcriptPath": str(tx),
                "prompt": "devam et",
            }
        )
        self.assertIn("[Harness Recovery & Continuity Gate]", _injected_text(r_crash))

    def test_build_signal_filter_skips_126_127_short_cli_status_and_resets_on_clean_exit_zero(self) -> None:
        """Catches `rg` exit 127, `agy-guard doctor` exit 1, and non-consecutive fails triggering `build-error-resolver`."""
        # 1. `agy-guard doctor` exit 1 + 3x `rg` exit 127 (`command not found`) -> {}
        tx_127 = self.tmp / "tx_127.jsonl"
        tx_127.write_text(
            "\n".join(
                [
                    json.dumps({"type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Audit live status"}),
                    json.dumps(
                        {
                            "type": "PLANNER_RESPONSE",
                            "tool_calls": [{"name": "run_command", "args": {"CommandLine": "agy-guard doctor"}}],
                        }
                    ),
                    json.dumps(
                        {
                            "type": "TOOL_RESULT",
                            "tool_name": "run_command",
                            "status": "ERROR",
                            "content": "Command exited with code 1.\n[WARN] 2 stale symlinks in plugins/",
                        }
                    ),
                    json.dumps(
                        {
                            "type": "PLANNER_RESPONSE",
                            "tool_calls": [
                                {"name": "run_command", "args": {"CommandLine": "rg foo guard/"}},
                                {"name": "run_command", "args": {"CommandLine": "rg bar porter/"}},
                                {"name": "run_command", "args": {"CommandLine": "/tmp/not_exec.sh"}},
                            ],
                        }
                    ),
                    json.dumps(
                        {
                            "type": "TOOL_RESULT",
                            "tool_name": "run_command",
                            "status": "ERROR",
                            "content": "Command exited with code 127.\nbash: rg: command not found",
                        }
                    ),
                    json.dumps(
                        {
                            "type": "TOOL_RESULT",
                            "tool_name": "run_command",
                            "status": "ERROR",
                            "content": "Command exited with code 127.\nbash: rg: command not found",
                        }
                    ),
                    json.dumps(
                        {
                            "type": "TOOL_RESULT",
                            "tool_name": "run_command",
                            "status": "ERROR",
                            "content": "Command exited with code 126.\nbash: /tmp/not_exec.sh: Permission denied",
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual(
            agy_hooks.handle_pre_invocation(
                {"conversationId": "conv-127", "invocationNum": 2, "transcriptPath": str(tx_127)}
            ),
            {},
        )

        # 2. Non-consecutive compiler fails separated by a clean `exit 0` shell step reset `consec_build_fails`
        tx_interleaved = self.tmp / "tx_interleaved.jsonl"
        interleaved_entries = [
            json.dumps({"type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Fix typecheck"}),
            json.dumps(
                {
                    "type": "PLANNER_RESPONSE",
                    "tool_calls": [{"name": "run_command", "args": {"CommandLine": "mypy src/"}}],
                }
            ),
            json.dumps(
                {
                    "type": "TOOL_RESULT",
                    "tool_name": "run_command",
                    "status": "ERROR",
                    "content": "Command exited with code 1.\nsrc/a.py:4: error: Incompatible types",
                }
            ),
            json.dumps(
                {
                    "type": "PLANNER_RESPONSE",
                    "tool_calls": [{"name": "run_command", "args": {"CommandLine": "git status --short"}}],
                }
            ),
            json.dumps(
                {
                    "type": "TOOL_RESULT",
                    "tool_name": "run_command",
                    "status": "DONE",
                    "content": "Command exited with code 0.\n M src/a.py",
                }
            ),
            json.dumps(
                {
                    "type": "PLANNER_RESPONSE",
                    "tool_calls": [{"name": "run_command", "args": {"CommandLine": "mypy src/"}}],
                }
            ),
            json.dumps(
                {
                    "type": "TOOL_RESULT",
                    "tool_name": "run_command",
                    "status": "ERROR",
                    "content": "Command exited with code 1.\nsrc/a.py:9: error: Name 'y' is not defined",
                }
            ),
        ]
        tx_interleaved.write_text("\n".join(interleaved_entries) + "\n", encoding="utf-8")
        self.assertEqual(
            agy_hooks.handle_pre_invocation(
                {"conversationId": "conv-interleaved", "invocationNum": 2, "transcriptPath": str(tx_interleaved)}
            ),
            {},
        )

        # Adding a 2nd consecutive mypy failure right after triggers build-error-resolver
        interleaved_entries.extend(
            [
                json.dumps(
                    {
                        "type": "PLANNER_RESPONSE",
                        "tool_calls": [{"name": "run_command", "args": {"CommandLine": "mypy src/"}}],
                    }
                ),
                json.dumps(
                    {
                        "type": "TOOL_RESULT",
                        "tool_name": "run_command",
                        "status": "ERROR",
                        "content": "Command exited with code 1.\nsrc/a.py:9: error: Name 'y' is not defined",
                    }
                ),
            ]
        )
        tx_interleaved.write_text("\n".join(interleaved_entries) + "\n", encoding="utf-8")
        res_consec = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-interleaved", "invocationNum": 3, "transcriptPath": str(tx_interleaved)}
        )
        self.assertIn("build-error-resolver", _injected_text(res_consec))

        # 3. >500-line trace followed by plain `git status` (`exit 0`, no `_CLEAN_BUILD_PASS_RE`) retains heavy_fail
        tx_heavy_git = self.tmp / "tx_heavy_git.jsonl"
        heavy_body = "Command exited with code 1\n" + "\n".join(
            f"src/mod.ts({i},2): error TS2322: Type mismatch" for i in range(1, 515)
        )
        tx_heavy_git.write_text(
            "\n".join(
                [
                    json.dumps({"type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Build app"}),
                    json.dumps({"type": "TOOL_RESULT", "tool_name": "run_command", "status": "ERROR", "content": heavy_body}),
                    json.dumps(
                        {
                            "type": "TOOL_RESULT",
                            "tool_name": "run_command",
                            "status": "DONE",
                            "content": "Command exited with code 0.\n M src/mod.ts",
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        res_heavy = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-heavy-git", "invocationNum": 2, "transcriptPath": str(tx_heavy_git)}
        )
        self.assertIn("build-error-resolver", _injected_text(res_heavy))


class TestAC4StandaloneHermeticSubprocessIsolation(HermeticHookCase):
    def test_standalone_unittest_modules_create_zero_entries_in_caller_sentinel_home(self) -> None:
        """Catches standalone `python3 -m unittest <module>` leaking files/symlinks into caller's pre-import HOME/config/state."""
        sentinel = self.tmp / "caller_sentinel"
        sentinel_cfg = sentinel / ".gemini" / "config"
        sentinel_state = sentinel / "state"
        sentinel_data = sentinel / "data"
        for d in (sentinel_cfg, sentinel_state, sentinel_data):
            d.mkdir(parents=True, exist_ok=True)

        env = dict(os.environ)
        env.update(
            {
                "HOME": str(sentinel),
                "USERPROFILE": str(sentinel),
                "XDG_STATE_HOME": str(sentinel_state),
                "XDG_DATA_HOME": str(sentinel_data),
                "ANTIGRAVITY_CONFIG_DIR": str(sentinel_cfg),
                "AGY_GUARD_STATE_DIR": str(sentinel_state),
                "ANTIGRAVITY_STATE_DIR": str(sentinel_state),
                "AGY_GUARD_DATA_DIR": str(sentinel_data),
            }
        )

        targets = [
            "tests.test_agy_hooks.TestPorterSanitizerNewPatterns",
            "tests.test_code_map.TestCodeMapSeams.test_find_callers_ignores_comments_and_string_literals",
            "tests.test_rustify_and_codemap.TestCodeMapRustAndCppSeams.test_rust_lifetimes_do_not_erase_intermediate_definitions_or_calls",
        ]
        if shutil.which("ffmpeg") and shutil.which("ffprobe"):
            targets.append("tests.test_media_studio.MediaStudioQcTests.test_probe_and_check_clean_av_mp4_passes_all_rules")
        else:
            targets.append("tests.test_media_studio")

        for target in targets:
            with self.subTest(target=target):
                cp = subprocess.run(
                    [sys.executable, "-m", "unittest", target],
                    cwd=str(REPO_ROOT),
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(cp.returncode, 0, f"{target} failed:\n{cp.stdout}\n{cp.stderr}")

        leaked = sorted(
            str(p.relative_to(sentinel))
            for p in sentinel.rglob("*")
            if p not in (sentinel / ".gemini", sentinel_cfg, sentinel_state, sentinel_data)
        )
        self.assertEqual(leaked, [], f"Leaked entries in caller sentinel tree: {leaked}")

    def test_meta_audit_flags_test_modules_missing_or_late_hermetic_import(self) -> None:
        """Catches `tests/test_*.py` omitting top-level `hermetic` import or importing `guard`/`porter` before `hermetic`."""
        from scripts import meta_audit

        # Positive control on clean synthetic repo
        clean_root = self.tmp / "meta_hermetic_clean"
        (clean_root / "tests").mkdir(parents=True, exist_ok=True)
        (clean_root / "tests" / "test_ok_import.py").write_text(
            "import sys\nimport hermetic  # noqa: F401\nimport guard.paths\n",
            encoding="utf-8",
        )
        (clean_root / "tests" / "test_ok_from.py").write_text(
            "from hermetic import force_rmtree\nfrom guard import paths\n",
            encoding="utf-8",
        )
        (clean_root / "tests" / "support_util.py").write_text(
            "# Non-test helper module does not match test_*.py\nX = 1\n",
            encoding="utf-8",
        )
        eng_clean = meta_audit.MetaAuditEngine(repo_root=clean_root)
        eng_clean.pass1_schema_validation()
        self.assertEqual(eng_clean.findings, [], f"Expected 0 findings on clean test modules, got: {eng_clean.findings}")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(meta_audit.main(["--root", str(clean_root), "--pass", "1", "--strict"]), 0)

        # Negative cases: missing (comment/docstring fake), function-buried, late (after guard), and nested
        bad_root = self.tmp / "meta_hermetic_bad"
        (bad_root / "tests" / "nested").mkdir(parents=True, exist_ok=True)
        (bad_root / "tests" / "test_comment_only.py").write_text(
            '"""import hermetic"""\n# import hermetic\nimport unittest\nS = "import hermetic"\n',
            encoding="utf-8",
        )
        (bad_root / "tests" / "test_buried_in_fn.py").write_text(
            "import unittest\ndef test_lazy():\n    import hermetic\n",
            encoding="utf-8",
        )
        (bad_root / "tests" / "test_late_after_guard.py").write_text(
            "import guard.paths\nimport hermetic\n",
            encoding="utf-8",
        )
        (bad_root / "tests" / "nested" / "test_sub_missing.py").write_text(
            "import unittest\n",
            encoding="utf-8",
        )

        eng_bad = meta_audit.MetaAuditEngine(repo_root=bad_root)
        eng_bad.pass1_schema_validation()
        flagged_targets = {f.target for f in eng_bad.findings if "hermetic" in f.message.lower()}
        self.assertEqual(
            flagged_targets,
            {
                "tests/test_comment_only.py",
                "tests/test_buried_in_fn.py",
                "tests/test_late_after_guard.py",
                "tests/nested/test_sub_missing.py",
            },
            f"Unexpected flagged targets: {eng_bad.findings}",
        )
        with contextlib.redirect_stdout(io.StringIO()):
            rc_strict = meta_audit.main(["--root", str(bad_root), "--pass", "1", "--strict", "--json"])
        self.assertEqual(rc_strict, 1)


class TestAC5KnownPlaceholderModelsAndHarnessRouting(HermeticHookCase):
    EXPECTED_PLACEHOLDERS = {
        "MODEL_PLACEHOLDER_M427": "Gemini 4 Carbon (High)",
        "MODEL_PLACEHOLDER_M535": "Gemini 4 Neon (XHigh)",
    }

    def _load_watcher_isolated(self, env_overrides: dict[str, str]):
        watcher_path = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
        with mock.patch.dict(os.environ, env_overrides, clear=False):
            spec = importlib.util.spec_from_file_location(f"uw_v212_{os.urandom(4).hex()}", watcher_path)
            assert spec is not None and spec.loader is not None
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        return mod

    def test_seed_known_placeholder_models_watcher_bridge_and_pre_tool_use_wiring(self) -> None:
        """Catches false 'unmapped placeholder' alerts on M427/M535 or auto-allow leaks on unknown M999."""
        import guard.upstream as guard_upstream

        seed_path = REPO_ROOT / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        shipped_seed = json.loads(seed_path.read_text(encoding="utf-8"))
        self.assertEqual(shipped_seed.get("last_pbtxt_model"), "MODEL_PLACEHOLDER_M535")
        self.assertEqual(shipped_seed.get("known_placeholder_models"), self.EXPECTED_PLACEHOLDERS)

        # 1. Seed digest parity and sensitivity to known_placeholder_models updates
        uw_base = self._load_watcher_isolated({})
        d_guard = guard_upstream.compute_seed_digest(shipped_seed)
        d_watcher = uw_base._compute_seed_digest(shipped_seed)
        self.assertEqual(d_guard, d_watcher)
        mutated_seed = {
            **shipped_seed,
            "known_placeholder_models": {
                **self.EXPECTED_PLACEHOLDERS,
                "MODEL_PLACEHOLDER_M600": "Gemini 4 Nitrogen (XHigh)",
            },
        }
        self.assertNotEqual(d_guard, guard_upstream.compute_seed_digest(mutated_seed))
        self.assertEqual(
            guard_upstream.compute_seed_digest(mutated_seed),
            uw_base._compute_seed_digest(mutated_seed),
        )

        # 2. Seed reconciliation propagates known_placeholder_models and M535 into stale per-user ledgers
        stale_state = {
            "_reconciled_seed_digest": "pre-v212-digest",
            "last_audited_model": "Gemini 4 Hydrogen (XHigh)",
            "last_pbtxt_model": "MODEL_PLACEHOLDER_M417",
            "last_audit_timestamp": "2026-11-10T00:00:00+00:00",
            "tracked_repositories": {},
        }
        rec_guard, changed_guard = guard_upstream.reconcile_state_with_seed(dict(stale_state), shipped_seed)
        self.assertTrue(changed_guard)
        self.assertEqual(rec_guard.get("last_pbtxt_model"), "MODEL_PLACEHOLDER_M535")
        self.assertEqual(rec_guard.get("known_placeholder_models"), self.EXPECTED_PLACEHOLDERS)

        rec_uw = dict(stale_state)
        changed_uw = uw_base._reconcile_with_seed(rec_uw, shipped_seed)
        self.assertTrue(changed_uw)
        self.assertEqual(rec_uw.get("last_pbtxt_model"), "MODEL_PLACEHOLDER_M535")
        self.assertEqual(rec_uw.get("known_placeholder_models"), self.EXPECTED_PLACEHOLDERS)

        # 3. upstream_watcher switching across M417 / M427 / M528 emits 0 drift alerts; M999 warns
        cfg_u = self.tmp / "uw_cfg"
        builtin_u = self.tmp / "uw_builtin"
        (builtin_u / "agy-customizations").mkdir(parents=True)
        (builtin_u / "agy-customizations" / "SKILL.md").write_text("---\nname: agy-customizations\n---\n", encoding="utf-8")
        pbtxt_u = self.tmp / ".gemini" / "antigravity" / "antigravity_state.pbtxt"
        pbtxt_u.parent.mkdir(parents=True, exist_ok=True)
        state_u = self.state_dir / "upstream_state.json"
        uw_env = {
            "ANTIGRAVITY_CONFIG_DIR": str(cfg_u),
            "ANTIGRAVITY_BUILTIN_SKILLS_DIR": str(builtin_u),
            "ANTIGRAVITY_PBTXT_FILE": str(pbtxt_u),
            "UPSTREAM_STATE_FILE": str(state_u),
            "AGY_GUARD_NOTIFY": "off",
        }
        uw = self._load_watcher_isolated(uw_env)
        local_seed = {
            **shipped_seed,
            "builtin_skills_hash": uw.compute_builtin_hash(),
            "recorded_builtin_skills": uw.get_builtin_skills_list(),
            "last_skills_audit_timestamp": "2099-01-01T00:00:00+00:00",
            "tracked_repositories": {},
        }
        local_seed_file = cfg_u / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        local_seed_file.parent.mkdir(parents=True, exist_ok=True)
        local_seed_file.write_text(json.dumps(local_seed, indent=2), encoding="utf-8")

        with mock.patch.dict(os.environ, uw_env, clear=False), mock.patch.object(uw, "spawn_desktop_notification"):
            for idx, (ph_id, expected_label) in enumerate(self.EXPECTED_PLACEHOLDERS.items(), 1):
                pbtxt_u.write_text(f'last_selected_agent_model: "{ph_id}"\n', encoding="utf-8")
                hook_out = uw.run_hook({"invocationNum": 1, "modelName": ph_id, "conversationId": f"known-{idx}"})
                self.assertEqual(hook_out, {}, f"Unexpected drift notice for {ph_id}: {hook_out}")

                buf_status = io.StringIO()
                with contextlib.redirect_stdout(buf_status):
                    rc_st = uw.cmd_status(model=ph_id)
                status_txt = buf_status.getvalue()
                self.assertEqual(rc_st, 0)
                self.assertIn(expected_label, status_txt)
                self.assertNotIn("unmapped placeholder", status_txt.lower())
                self.assertIn("No upstream changes detected.", status_txt)

            # Unknown placeholder M999 MUST warn in both run_hook and cmd_status
            pbtxt_u.write_text('last_selected_agent_model: "MODEL_PLACEHOLDER_M999"\n', encoding="utf-8")
            hook_m999 = uw.run_hook(
                {"invocationNum": 1, "modelName": "MODEL_PLACEHOLDER_M999", "conversationId": "unknown-m999"}
            )
            notice_md = hook_m999["injectSteps"][0]["systemMessage"]["metadata"]["user_markdown"]
            self.assertIn("Unmapped placeholder model change", notice_md)
            self.assertIn("MODEL_PLACEHOLDER_M999", notice_md)

            buf_m999 = io.StringIO()
            with contextlib.redirect_stdout(buf_m999):
                uw.cmd_status(model="MODEL_PLACEHOLDER_M999")
            self.assertIn("unmapped placeholder", buf_m999.getvalue().lower())

            # 4. UpstreamAuditorBridge resolves M427 via known_placeholder_models and does not invent M999
            pbtxt_u.write_text('last_selected_agent_model: "MODEL_PLACEHOLDER_M427"\n', encoding="utf-8")
            bridge = guard_upstream.UpstreamAuditorBridge(target_dir=cfg_u)
            drift_m427 = bridge.get_model_drift_status()
            self.assertEqual(drift_m427["active_model"], "Gemini 4 Carbon (High)")
            self.assertIn("pbtxt", drift_m427["model_source"])

            ok_ack, _ = bridge.acknowledge_drift()
            self.assertTrue(ok_ack)
            acked_state = json.loads(state_u.read_text(encoding="utf-8"))
            self.assertEqual(acked_state["last_audited_model"], "Gemini 4 Carbon (High)")
            self.assertEqual(acked_state["last_pbtxt_model"], "MODEL_PLACEHOLDER_M427")

        # 5. PreToolUse `_seed_placeholder_diagnostic` & fail-closed `force_ask` on Rule 17 governance writes
        ws_gov = self.tmp / "ws_gov_ac5"
        ws_gov.mkdir(parents=True, exist_ok=True)
        (ws_gov / ".harness").mkdir(parents=True, exist_ok=True)
        (ws_gov / ".harness" / "manifest.json").write_text("{}", encoding="utf-8")
        (ws_gov / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")

        for ph_id, expected_label in self.EXPECTED_PLACEHOLDERS.items():
            diag = agy_hooks._seed_placeholder_diagnostic(ph_id, effort_verified=True)
            self.assertIn(expected_label, diag)
            self.assertNotIn("unmapped placeholder", diag.lower())

        diag_m999 = agy_hooks._seed_placeholder_diagnostic("MODEL_PLACEHOLDER_M999", effort_verified=True)
        self.assertIn("unmapped placeholder", diag_m999.lower())
        res_m999 = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-m999-failclosed",
                "modelName": "MODEL_PLACEHOLDER_M999",
                "effort": "xhigh",
                "workspace": str(ws_gov),
                "toolCall": {"name": "edit_file", "args": {"Path": str(ws_gov / "GEMINI.md")}},
            }
        )
        self.assertEqual(res_m999.get("decision"), "force_ask", res_m999)
        self.assertIn("unmapped placeholder", res_m999.get("reason", "").lower())

    def test_harness_skill_routing_deduplicated_and_antislop_forty_rules_intact(self) -> None:
        """Catches bloated prose regressions in `harness/SKILL.md` §1 or accidental rule pruning in `antislop/SKILL.md`."""
        harness_md = (REPO_ROOT / "skills" / "harness" / "SKILL.md").read_text(encoding="utf-8")
        m_routing = re.search(
            r"\* \*\*Specialized Skill Routing by Task Shape:\*\*\n((?:  \* .*\n)+)",
            harness_md,
        )
        self.assertIsNotNone(m_routing, "Missing 'Specialized Skill Routing by Task Shape' block in harness/SKILL.md")
        assert m_routing is not None
        routing_block = m_routing.group(1)
        self.assertLess(
            len(routing_block),
            1800,
            f"Expected compact pointer bullets (< 1800 chars), got {len(routing_block)} chars",
        )
        for expected_ptr in (
            "refactoring",
            "skills/sweetspot/SKILL.md",
            "skills/harness/references/marathon.md",
            "skills/harness/references/dependency-upgrade.md",
            "skills/renew/SKILL.md",
            "skills/rustify/SKILL.md",
            "skills/harness/references/mistake-proofing.md",
            "skills/harness/references/test-design.md",
            "game-engineering",
            "skills/media-studio/SKILL.md",
        ):
            self.assertIn(expected_ptr, routing_block)

        ui_refinery_md = (REPO_ROOT / "skills" / "ui-refinery" / "SKILL.md").read_text(encoding="utf-8")
        rule_ids = sorted(set(re.findall(r"\bR-(?:0[1-9]|[1-3][0-9]|40)\b", ui_refinery_md)))
        self.assertEqual(len(rule_ids), 40, f"Expected all 40 R-01..R-40 rules intact in ui-refinery/SKILL.md, got {len(rule_ids)}")


class TestAuditorMutualFalsificationRegressions(HermeticHookCase):
    def test_lazy_regex_methods_submodule_getattr_and_workflow_ast_failclosed_seams(self) -> None:
        """Pins `_LazyRegex` methods/flags/groups, `guard.<submod>` lazy access, and `_workflow_ast` rebinding/MemoryError/import guards."""
        from guard.hooks import common, pre_tool_use

        # 1. guard.<submod> lazy resolution
        self.assertTrue(hasattr(guard.upstream, "UpstreamAuditorBridge"))
        self.assertTrue(hasattr(guard.paths, "state_dir"))

        # 2. _LazyRegex fullmatch / subn / split / flags / groups / groupindex
        rx = common._LazyRegex(r"(?ms)^(?P<tag>[a-z]+):(\d+)$")
        self.assertIsNotNone(rx.fullmatch("abc:42"))
        self.assertIsNone(rx.fullmatch("abc:42!"))
        self.assertEqual(rx.subn(r"\1=#", "abc:42\nxyz:99"), ("abc=#\nxyz=#", 2))
        self.assertEqual(common._LazyRegex(r",").split("a,b,c", maxsplit=1), ["a", "b,c"])
        self.assertEqual(rx.groups, 2)
        self.assertEqual(dict(rx.groupindex), {"tag": 1})
        self.assertTrue(bool(common._FENCE_RE.flags & re.MULTILINE) and bool(common._FENCE_RE.flags & re.DOTALL))

        # 3. _workflow_ast rebinding `io` module alias & MemoryError (>200 nested parens) & ImportError fail-closed
        cfg_file = str(self.cfg_dir / "GEMINI.md")
        rebind_res, _ = pre_tool_use._inspect_workflow_script(
            f"import io\nfrom pathlib import Path\nio = Path({cfg_file!r})\nio.open('w')\n",
            [],
            {},
            self.ws_dir,
        )
        self.assertEqual(rebind_res.get("decision"), "deny", rebind_res)

        mem_res, _ = pre_tool_use._inspect_workflow_script("(" * 210 + "1" + ")" * 210, [], {}, self.ws_dir)
        self.assertEqual(mem_res.get("decision"), "deny", mem_res)

        import guard.hooks as hooks_pkg

        orig_wf_attr = getattr(hooks_pkg, "_workflow_ast", None)
        try:
            if hasattr(hooks_pkg, "_workflow_ast"):
                delattr(hooks_pkg, "_workflow_ast")
            with mock.patch.dict(sys.modules, {"guard.hooks._workflow_ast": None}):
                imp_res, _ = pre_tool_use._inspect_workflow_script("x = 1\n", [], {}, self.ws_dir)
                self.assertEqual(imp_res.get("decision"), "deny", imp_res)
        finally:
            if orig_wf_attr is not None:
                setattr(hooks_pkg, "_workflow_ast", orig_wf_attr)

    def test_ac2_auditor_adversarial_bypasses_and_compound_command_precision(self) -> None:
        """Pins all `CRITICAL`/`HIGH` AC-2 vectors surfaced by `security-boundary-verifier`, `specification-gap-auditor`, and `consistency-auditor`."""
        cfg_target = str(self.cfg_dir / "GEMINI.md")
        ws_gov = self.tmp / "ws_cust_hd"
        ws_gov.mkdir(parents=True, exist_ok=True)
        (ws_gov / ".harness").mkdir(parents=True, exist_ok=True)
        (ws_gov / ".harness" / "manifest.json").write_text("{}", encoding="utf-8")
        (ws_gov / "GEMINI.md").write_text("# WS Constitution\n", encoding="utf-8")

        deny_vectors = [
            f'python3 -c "import linecache; linecache.os.replace(\'/tmp/src\', {cfg_target!r})"',
            f'python3 -c "import platform; platform.os.replace(\'/tmp/src\', {cfg_target!r})"',
            f'python3 -c "from inspect import builtins; sorted([\'{cfg_target}\'], key=builtins.eval)"',
            f"python3 -m json.tool /tmp/in.json {cfg_target}",
            f'python3 -c "import io\nfrom pathlib import Path\ndef f(io): io.open(\'w\')\nf(Path({cfg_target!r}))"',
            f'python3 -c "m = \'r\'\nmatch \'w\':\n case m: open({cfg_target!r}, m)"',
            f"python3 <<'EOF' -c \"import os; os.utime({cfg_target!r})\"\n1\nEOF",
            f"python3 <<'EOF' | xargs rm -f\nprint({cfg_target!r})\nEOF",
            f"rm $(echo \")\" >/dev/null;\npython3 <<'EOF'\nprint({cfg_target!r})\nEOF\n)",
            f"PYTHONUSERBASE=/tmp/ub python3 -c 'print(1)' && touch {cfg_target}",
            f"/tmp/python3 -c 'print(1)' {cfg_target}",
            (
                "python3 <<'EOF'\n"
                "# -*- coding: ascii -*-\n"
                "import os\n"
                "open(os.path.expanduser('~/' + '.gem' + 'ini/con' + 'fig/GEMINI.md'), 'w')\n"
                "EOF"
            ),
            (
                "python3 <<'EOF'\n"
                "import os\n"
                "p = '~/' + '.gem'\n"
                "p += 'ini/con' + 'fig/GEMINI.md'\n"
                "open(os.path.expanduser(p), 'w')\n"
                "EOF"
            ),
            f"cd {self.cfg_dir.parent} && python3 -c \"open('config/GEMINI.md', 'w')\"",
        ]
        for idx, cmd in enumerate(deny_vectors):
            with self.subTest(idx=idx, cmd=cmd[:90]):
                res = agy_hooks.handle_pre_tool_use(
                    {
                        "conversationId": f"conv-mf-deny-{idx}",
                        "workspace": str(self.ws_dir),
                        "toolCall": {"name": "run_command", "args": {"CommandLine": cmd}},
                    }
                )
                self.assertEqual(res.get("decision"), "deny", f"Expected deny for #{idx}: {cmd}\nGot: {res}")

        # Benign compound commands across `&&` and read-only `-m ruff` allow cleanly
        for allow_cmd in (
            f"python3 scripts/meta_audit.py --strict && grep -i Hermetic {cfg_target}",
            f"python3 -m ruff check {self.cfg_dir}",
        ):
            res_ok = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-mf-allow",
                    "workspace": str(REPO_ROOT),
                    "toolCall": {"name": "run_command", "args": {"CommandLine": allow_cmd}},
                }
            )
            self.assertEqual(res_ok, {"decision": "allow"}, f"Unexpected block on {allow_cmd}: {res_ok}")

        # Mutating workspace heredoc targeting customization file under unknown M999 fails closed (`force_ask`)
        cust_hd = f"python3 <<'EOF'\nfrom pathlib import Path\nPath({str(ws_gov / 'GEMINI.md')!r}).write_text('x')\nEOF"
        res_m999_hd = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-mf-cust-hd",
                "workspace": str(ws_gov),
                "modelName": "MODEL_PLACEHOLDER_M999",
                "effort": "xhigh",
                "toolCall": {"name": "run_command", "args": {"CommandLine": cust_hd}},
            }
        )
        self.assertEqual(res_m999_hd.get("decision"), "force_ask", res_m999_hd)

    def test_ac3_preflush_crash_recovery_generic_read_file_and_subcmd_build_signals(self) -> None:
        """Pins pre-flush / empty-`_tx_text` post-crash recovery, `GENERIC` `read_file` silence, and subcmd build runners."""
        ws = self.tmp / "ac3_gap_ws"
        self._init_git_ws(ws)

        # 1a. Post-crash recovery before new USER_INPUT is flushed to transcript (`explicit_differs`)
        tx_pre = self.tmp / "tx_preflush.jsonl"
        tx_pre.write_text(
            "\n".join(
                [
                    json.dumps({"type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Initial task"}),
                    json.dumps({"type": "PLANNER_RESPONSE", "content": ""}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-preflush",
                "workspace": str(ws),
                "toolCall": {"name": "edit_file", "args": {"Path": str(ws / "app.py")}},
            }
        )
        r_preflush = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-preflush",
                "invocationNum": 1,
                "workspace": str(ws),
                "transcriptPath": str(tx_pre),
                "prompt": "Brand new follow-up instruction after crash",
            }
        )
        self.assertIn("[Harness Recovery & Continuity Gate]", _injected_text(r_preflush))

        # 1b. Post-crash recovery when transcript tail has only non-USER_INPUT steps (`not _tx_text`)
        tx_nouser = self.tmp / "tx_nouser.jsonl"
        tx_nouser.write_text(json.dumps({"type": "PLANNER_RESPONSE", "content": ""}) + "\n", encoding="utf-8")
        agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-nouser",
                "invocationNum": 1,
                "workspace": str(ws),
                "prompt": "First prompt recorded in conv_hint_state",
            }
        )
        agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-nouser",
                "workspace": str(ws),
                "toolCall": {"name": "edit_file", "args": {"Path": str(ws / "app.py")}},
            }
        )
        r_nouser = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-nouser",
                "invocationNum": 1,
                "workspace": str(ws),
                "transcriptPath": str(tx_nouser),
                "prompt": "Second distinct prompt after crash",
            }
        )
        self.assertIn("[Harness Recovery & Continuity Gate]", _injected_text(r_nouser))

        # 2. >500-line `GENERIC` `read_file` transcript entry containing `TypeError:` does NOT trigger build-error-resolver
        tx_generic_read = self.tmp / "tx_generic_read.jsonl"
        big_read_content = "Created At: 2026-11-16T10:00:00+03:00\n" + "\n".join(
            f"{i}: raise TypeError('example line {i}')  # Command exited with code 1" for i in range(1, 520)
        )
        tx_generic_read.write_text(
            "\n".join(
                [
                    json.dumps({"type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Read source slice"}),
                    json.dumps(
                        {
                            "type": "PLANNER_RESPONSE",
                            "tool_calls": [{"name": "read_file", "args": {"Path": "guard/hooks/pre_tool_use.py"}}],
                        }
                    ),
                    json.dumps({"type": "GENERIC", "status": "DONE", "content": big_read_content}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual(
            agy_hooks.handle_pre_invocation(
                {"conversationId": "conv-generic-read", "invocationNum": 2, "transcriptPath": str(tx_generic_read)}
            ),
            {},
        )

        # 3. Short (<25-line) consecutive failures from `npm run typecheck` and `python3 -m mypy` DO trigger build-error-resolver
        tx_subcmd = self.tmp / "tx_subcmd.jsonl"
        tx_subcmd.write_text(
            "\n".join(
                [
                    json.dumps({"type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Run typecheck"}),
                    json.dumps(
                        {
                            "type": "PLANNER_RESPONSE",
                            "tool_calls": [{"name": "run_command", "args": {"CommandLine": "npm run typecheck"}}],
                        }
                    ),
                    json.dumps(
                        {
                            "type": "TOOL_RESULT",
                            "tool_name": "run_command",
                            "status": "ERROR",
                            "content": "Command exited with code 2.\nCheck failed.",
                        }
                    ),
                    json.dumps(
                        {
                            "type": "PLANNER_RESPONSE",
                            "tool_calls": [{"name": "run_command", "args": {"CommandLine": "python3 -m mypy app/"}}],
                        }
                    ),
                    json.dumps(
                        {
                            "type": "TOOL_RESULT",
                            "tool_name": "run_command",
                            "status": "ERROR",
                            "content": "Command exited with code 1.\nFound 1 problem.",
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertIn(
            "build-error-resolver",
            _injected_text(
                agy_hooks.handle_pre_invocation(
                    {"conversationId": "conv-subcmd", "invocationNum": 2, "transcriptPath": str(tx_subcmd)}
                )
            ),
        )

    def test_ac4_meta_audit_try_importfrom_syntaxerror_export_dir_and_missing_workflow_ast(self) -> None:
        """Pins `try/except` early imports, `ImportFrom`, `tests/export/`, `SyntaxError`, and Pass 2 `_workflow_ast.py` presence."""
        from scripts.meta_audit import MetaAuditEngine

        repo = self.tmp / "meta_gap_repo"
        (repo / "tests" / "export").mkdir(parents=True)
        (repo / "tests" / "helper_local.py").write_text("import guard\n", encoding="utf-8")
        (repo / "tests" / "test_try_guard.py").write_text(
            "try:\n    import guard.paths\nexcept ImportError:\n    pass\nimport hermetic\n",
            encoding="utf-8",
        )
        (repo / "tests" / "test_from_guard.py").write_text(
            "from guard import agy_hooks\nimport hermetic\n",
            encoding="utf-8",
        )
        (repo / "tests" / "test_sibling_before_hermetic.py").write_text(
            "import helper_local\nimport hermetic\n",
            encoding="utf-8",
        )
        (repo / "tests" / "export" / "test_in_export.py").write_text("import unittest\n", encoding="utf-8")
        (repo / "tests" / "test_syntax_broken.py").write_text("def broken(:\n", encoding="utf-8")

        eng = MetaAuditEngine(repo_root=repo)
        eng.pass1_schema_validation()
        flagged = {f.target for f in eng.findings if f.severity == "CRITICAL"}
        self.assertEqual(
            flagged,
            {
                "tests/test_try_guard.py",
                "tests/test_from_guard.py",
                "tests/test_sibling_before_hermetic.py",
                "tests/export/test_in_export.py",
                "tests/test_syntax_broken.py",
            },
        )

        # Pass 2 detects missing `guard/hooks/_workflow_ast.py` when declared in `_SUBMODULE_EXPORTS`
        hooks_repo = self.tmp / "meta_wf_missing"
        hooks_dir = hooks_repo / "guard" / "hooks"
        hooks_dir.mkdir(parents=True)
        (hooks_repo / "guard" / "agy_hooks.py").write_text(
            'PRE_TOOL_USE_MATCHER_TOOLS = ("run_command",)\n_SUBMODULE_EXPORTS = {"common": (), "_workflow_ast": ("_eval_workflow_const_value",)}\n',
            encoding="utf-8",
        )
        for fn in ("__init__.py", "common.py", "pre_invocation.py", "pre_tool_use.py", "stop_gate.py"):
            (hooks_dir / fn).write_text("", encoding="utf-8")
        eng_p2 = MetaAuditEngine(repo_root=hooks_repo)
        eng_p2.pass2_cross_references()
        self.assertTrue(
            any(f.severity == "CRITICAL" and f.target == "guard/hooks/_workflow_ast.py" for f in eng_p2.findings),
            eng_p2.findings,
        )

    def test_ac5_state_only_fallback_corrupt_schema_unapproved_placeholder_and_ack_parity(self) -> None:
        """Pins state-only placeholder diagnostics, corrupt `known_placeholder_models` `WARN`, unapproved placeholder drift, and `cmd_ack` parity."""
        import guard.doctor as guard_doctor
        import guard.upstream as guard_upstream

        # 1. State-only `known_placeholder_models` fallback when seed lacks `known_placeholder_models`
        iso_cfg = self.tmp / "iso_cfg"
        iso_seed_file = iso_cfg / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        iso_seed_file.parent.mkdir(parents=True, exist_ok=True)
        iso_seed = {
            "last_audited_model": "Gemini 4 Hydrogen (XHigh)",
            "last_pbtxt_model": "MODEL_PLACEHOLDER_M528",
            "approved_customization_models": ["gemini-4-hydrogen-xhigh", "gemini-4-argon-high"],
            "tracked_repositories": {},
        }
        iso_seed_file.write_text(json.dumps(iso_seed), encoding="utf-8")
        iso_state_file = self.state_dir / "upstream_state.json"
        iso_state_file.write_text(
            json.dumps(
                {
                    **iso_seed,
                    "known_placeholder_models": {"MODEL_PLACEHOLDER_M611": "Gemini 4 Argon (High)"},
                }
            ),
            encoding="utf-8",
        )
        ws_iso = self.tmp / "ws_iso"
        ws_iso.mkdir()
        (ws_iso / ".harness").mkdir(parents=True, exist_ok=True)
        (ws_iso / ".harness" / "manifest.json").write_text("{}", encoding="utf-8")
        (ws_iso / "GEMINI.md").write_text("# C\n", encoding="utf-8")
        with (
            mock.patch.object(agy_hooks, "REPO_ROOT", self.tmp / "absent_repo"),
            mock.patch.object(agy_hooks, "configured_config_dir", return_value=iso_cfg),
            mock.patch.object(agy_hooks, "config_dir", return_value=iso_cfg),
        ):
            res_state_ph = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-state-ph",
                    "workspace": str(ws_iso),
                    "modelName": "MODEL_PLACEHOLDER_M611",
                    "effort": "high",
                    "toolCall": {"name": "edit_file", "args": {"Path": str(ws_iso / "GEMINI.md")}},
                }
            )
        self.assertEqual(res_state_ph.get("decision"), "force_ask", res_state_ph)
        self.assertIn("matches state `known_placeholder_models` -> `Gemini 4 Argon (High)`", res_state_ph.get("reason", ""))

        # 2. `upstream_watcher` state-only fallback, unapproved known placeholder alert, `cmd_ack` parity, & OSC sanitization
        uw_env = {
            "ANTIGRAVITY_CONFIG_DIR": str(iso_cfg),
            "UPSTREAM_STATE_FILE": str(iso_state_file),
            "ANTIGRAVITY_PBTXT_FILE": str(self.tmp / "iso.pbtxt"),
            "AGY_GUARD_NOTIFY": "off",
        }
        with mock.patch.dict(os.environ, uw_env, clear=False):
            spec = importlib.util.spec_from_file_location(
                "uw_gap_check", REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
            )
            assert spec and spec.loader
            uw = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(uw)

            buf_st = io.StringIO()
            with contextlib.redirect_stdout(buf_st):
                uw.cmd_status(model="MODEL_PLACEHOLDER_M611")
            self.assertIn("placeholder matches state known_placeholder_models (Gemini 4 Argon (High))", buf_st.getvalue())

            # Known placeholder mapped to unapproved model with corrupt/empty `approved_customization_models` emits Model change
            unapproved_reasons = uw.collect_reasons(
                {
                    "last_audited_model": "Gemini 4 Hydrogen (XHigh)",
                    "known_placeholder_models": {"MODEL_PLACEHOLDER_M699": "Gemini 3.8 Nano (Low)"},
                    "approved_customization_models": [123],
                },
                raw_payload_model="MODEL_PLACEHOLDER_M699",
                seed=None,
            )
            self.assertEqual(
                unapproved_reasons,
                ["Model change: 'Gemini 4 Hydrogen (XHigh)' -> 'Gemini 3.8 Nano (Low)'"],
            )

            # `cmd_ack` on known placeholder updates `last_audited_model` and `last_model_slug`
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(uw.cmd_ack(model="MODEL_PLACEHOLDER_M611"), 0)
            after_ack = json.loads(iso_state_file.read_text(encoding="utf-8"))
            self.assertEqual(after_ack["last_audited_model"], "Gemini 4 Argon (High)")
            self.assertEqual(after_ack["last_model_slug"], "gemini-4-argon-high")
            self.assertEqual(after_ack["last_pbtxt_model"], "MODEL_PLACEHOLDER_M611")

            # OSC + C1 + bidi sanitization
            sanitized = uw._sanitize_notice_fragment("MODEL_\x1b]8;;https://evil.invalid\x07lbl\x9b31m\u202e")
            self.assertNotIn("evil.invalid", sanitized)
            self.assertNotIn("\u202e", sanitized)
            self.assertNotIn("\x9b", sanitized)

        # 3. Unchanged-digest backfill + corrupt `known_placeholder_models` `WARN` in `UpstreamAuditorBridge` & `doctor`
        shipped_seed = json.loads((REPO_ROOT / "skills" / "upstream-auditor" / "upstream_state.seed.json").read_text(encoding="utf-8"))
        same_digest = guard_upstream.compute_seed_digest(shipped_seed)
        backfilled, bf_changed = guard_upstream.reconcile_state_with_seed(
            {"_reconciled_seed_digest": same_digest, "last_audited_model": "Gemini 4 Hydrogen (XHigh)", "tracked_repositories": {}},
            shipped_seed,
        )
        self.assertTrue(bf_changed)
        self.assertIn("MODEL_PLACEHOLDER_M427", backfilled["known_placeholder_models"])

        (self.cfg_dir / "skills" / "upstream-auditor").mkdir(parents=True, exist_ok=True)
        (self.cfg_dir / "skills" / "upstream-auditor" / "upstream_state.seed.json").write_text(
            json.dumps(shipped_seed), encoding="utf-8"
        )
        iso_state_file.write_text(json.dumps({"known_placeholder_models": ["corrupt"], "tracked_repositories": {}}), encoding="utf-8")
        with mock.patch.dict(os.environ, {"UPSTREAM_STATE_FILE": str(iso_state_file)}, clear=False):
            summary = guard_upstream.UpstreamAuditorBridge(target_dir=self.cfg_dir).get_summary()
        self.assertEqual(summary["status"], "WARN", summary)
        self.assertTrue(any("known_placeholder_models" in w for w in summary["warnings"]), summary)

        reg = guard.EnvironmentRegistry()
        ag_env = reg.get_environment("antigravity")
        assert ag_env is not None
        doc_report = guard_doctor.diagnose(ag_env, reg)
        self.assertTrue(
            any("known_placeholder_models" in w for w in doc_report.warnings),
            doc_report.warnings,
        )

    def test_windows_drive_double_backslash_and_dq_staging_parity(self) -> None:
        """Catches `C://` duplicate-slash normalization misses, POSIX-vs-CommandLineToArgvW `-c` `\\U` SyntaxErrors, and `\\\\staging` regex misses."""
        from pathlib import PureWindowsPath
        from guard.hooks import pre_tool_use

        self.assertEqual(
            pre_tool_use._normalize_shell_paths("C://Users//RUNNER~1//AppData//Local//Temp//state"),
            "C:/Users/RUNNER~1/AppData/Local/Temp/state",
        )
        self.assertEqual(
            pre_tool_use._normalize_shell_paths("https://example.com//a//b"),
            "https://example.com/a/b",
        )

        win_cfg_p = Path("C:/Users/RUNNER~1/AppData/Local/Temp/agy-win-parity/.gemini/config")
        win_state_p = Path("C:/Users/RUNNER~1/AppData/Local/Temp/agy-win-parity/state/antigravity-harness")
        win_cfg_bs = str(PureWindowsPath(win_cfg_p.as_posix()))
        win_state_bs = str(PureWindowsPath(win_state_p.as_posix()))

        with (
            mock.patch.object(pre_tool_use, "configured_config_dir", return_value=win_cfg_p),
            mock.patch.object(pre_tool_use, "config_dir", return_value=win_cfg_p),
            mock.patch.object(pre_tool_use, "_config_root_candidates", return_value=[win_cfg_p]),
            mock.patch.object(pre_tool_use, "state_dir", return_value=win_state_p),
            mock.patch.object(pre_tool_use, "_state_root_candidates", return_value=[win_state_p]),
            mock.patch.object(pre_tool_use, "_governance_roots", return_value=[win_cfg_p, win_state_p]),
        ):
            leases_bs = win_state_bs + "\\leases.json"
            for mut_cmd in (
                f"python3 -c 'import sqlite3; sqlite3.connect({leases_bs!r})'",
                f"python3 -c 'import tarfile; tarfile.open({leases_bs!r}, \"w\")'",
                f"python3 -c 'import zipfile; zipfile.ZipFile({leases_bs!r}, \"w\")'",
                f'cp payload.py "{win_cfg_bs}\\plugins\\pkg\\skills\\SKILL.md"',
            ):
                res_deny = agy_hooks.handle_pre_tool_use(
                    {
                        "conversationId": "conv-win-deny",
                        "workspace": str(self.ws_dir),
                        "toolCall": {"name": "run_command", "args": {"CommandLine": mut_cmd}},
                    }
                )
                self.assertEqual(res_deny.get("decision"), "deny", f"Expected deny for {mut_cmd}, got {res_deny}")

            staging_bs = win_state_bs + "\\staging\\out.json"
            staging_dq_cmd = f'python3 -c "from pathlib import Path; Path({staging_bs!r}).write_text(\'ok\')"'
            self.assertFalse(agy_hooks._command_mutates_governance(staging_dq_cmd))

            ro_dq_cmd = f'python3 -c "from pathlib import Path; print(Path({(win_cfg_bs + chr(92) + "GEMINI.md")!r}).read_text())"'
            res_ro = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-win-ro",
                    "workspace": str(self.ws_dir),
                    "toolCall": {"name": "run_command", "args": {"CommandLine": ro_dq_cmd}},
                }
            )
            self.assertEqual(res_ro, {"decision": "allow"}, res_ro)


if __name__ == "__main__":
    unittest.main()
