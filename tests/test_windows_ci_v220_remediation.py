"""
tests/test_windows_ci_v220_remediation.py: Hermetic regression suite for Windows CI failures
on v2.2.0 (`CRLF` 400 KiB `HANDOFF.md` truncation in `_read_bounded_markdown_checked` and
`file://` URI unwrapping in `_resolve_target_and_ws`, `_record_flight_pre_write`,
`_workspace_for_target`, and `_targets_customization_structure`).
"""

from __future__ import annotations

import json
import os
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

import hermetic  # noqa: E402  # must precede repository imports per ADR-0010

from guard import agy_hooks  # noqa: E402
from guard.test_boundary import TestBoundaryGuard  # noqa: E402


def _injected_text(resp: dict) -> str:
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


class TestWindowsCIV220Remediation(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-win-v220-")
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
                "PLUMB_GUARD_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_STATE_DIR": str(self.state_dir),
                "PLUMB_GUARD_DATA_DIR": str(self.data_dir),
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        hermetic.force_rmtree(self.tmp)
        self._tmp.cleanup()

    def _init_git_repo(self, ws: Path) -> str:
        ws.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(ws)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(ws), "config", "user.email", "tester@example.com"], check=True)
        subprocess.run(["git", "-C", str(ws), "config", "user.name", "Tester"], check=True)
        tests_dir = ws / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        (tests_dir / "test_alpha.py").write_text(
            "import unittest\n\nclass TestAlpha(unittest.TestCase):\n    def test_one(self):\n        self.assertEqual(1, 1)\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(ws), "add", "."], check=True)
        subprocess.run(["git", "-C", str(ws), "commit", "-m", "initial commit"], check=True, capture_output=True)
        return subprocess.run(
            ["git", "-C", str(ws), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def test_crlf_400kib_handoff_within_512kib_bound_preserves_in_progress_precedence(self) -> None:
        self._init_git_repo(self.ws_dir)
        (self.ws_dir / "tasks.md").write_text(
            "**Campaign ID:** `2026-11-18-tier2-slice`\r\n\r\n"
            "| Window | Scope | Status |\r\n"
            "| :--- | :--- | :--- |\r\n"
            "| `W1` | Implement slice | `[ ] NEXT` |\r\n",
            encoding="utf-8",
        )
        # On Windows, Path.write_text("\n" * (200 * 1024)) writes 409,600 bytes of CRLF (~400 KiB),
        # exceeding 256 KiB while remaining well below the 512 KiB HANDOFF.md bound.
        (self.ws_dir / "HANDOFF.md").write_bytes(
            (
                "\ufeff"
                + ("\r\n" * (200 * 1024))
                + "- **Campaign ID**: `2026-11-18-handoff-wins`\r\n"
                + "- **Status**: [IN-PROGRESS]\r\n"
            ).encode("utf-8")
        )
        res = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-crlf-handoff",
                "workspace": str(self.ws_dir),
                "prompt": "Resume handoff.",
            }
        )
        msg = _injected_text(res)
        self.assertIn("`HANDOFF.md` has `Status: [IN-PROGRESS]` (Campaign ID: `2026-11-18-handoff-wins`)", msg)

    def test_file_uri_write_unwraps_for_flight_recorder_and_python312_winerror123_parity(self) -> None:
        self._init_git_repo(self.ws_dir)
        tasks_file = self.ws_dir / "tasks.md"
        handoff_file = self.ws_dir / "HANDOFF.md"
        alpha_file = self.ws_dir / "tests" / "test_alpha.py"
        handoff_file.write_text("# Done\n\n**Status:** [COMPLETE]\n", encoding="utf-8")
        stale_tasks = (
            "# Old\n\n## Authorized Test Modifications\n"
            "- `tests/test_alpha.py`: Authorized in old campaign.\n"
        )
        fresh_tasks = "# Fresh\n\n**Campaign ID:** `2026-11-18-fresh`\n- [ ] `AC-1`: Slice\n"
        tasks_file.write_text(stale_tasks, encoding="utf-8")

        # Step 1: Initial conversation `conv-ac2` records `base_head` prior to contract commit
        self.assertEqual(
            agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-ac2",
                    "workspace": str(self.ws_dir),
                    "cwd": str(self.ws_dir),
                    "toolCall": {"name": "write_file", "args": {"Path": str(tasks_file), "Content": fresh_tasks}},
                }
            ),
            {"decision": "allow"},
        )

        # Step 2: Simulate Windows Python 3.12 `Path.resolve()` raising OSError (`WinError 123`)
        # whenever an un-unwrapped `file:` segment remains inside a Path object.
        orig_resolve = Path.resolve

        def _strict_win312_resolve(path_self: Path, *args: object, **kwargs: object) -> Path:
            if "file:" in str(path_self).lower():
                raise OSError(22, "WinError 123: The filename, directory name, or volume label syntax is incorrect")
            return orig_resolve(path_self, *args, **kwargs)

        encoded_uri = f"file://{self.ws_dir.as_posix()}/tasks%2Emd"
        with mock.patch.object(Path, "resolve", _strict_win312_resolve):
            res_uri = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-uri-clean",
                    "workspace": str(self.ws_dir),
                    "cwd": str(self.ws_dir),
                    "toolCall": {"name": "write_file", "args": {"Path": encoded_uri, "Content": fresh_tasks}},
                }
            )
        self.assertEqual(res_uri, {"decision": "allow"})

        flight_data = json.loads((self.state_dir / "flight_recorder.json").read_text(encoding="utf-8"))
        ws_entry = flight_data[str(self.ws_dir.resolve())]
        self.assertEqual(ws_entry["conversation_id"], "conv-uri-clean")
        self.assertEqual(ws_entry["last_target"], "tasks.md")

        # Step 3: Commit authorized contract update + refresh TestBoundaryGuard snapshot -> reset must allow
        tbg = TestBoundaryGuard(workspace_dir=self.ws_dir)
        tasks_file.write_text("# Baseline\n", encoding="utf-8")
        tbg.snapshot()
        tasks_file.write_text(stale_tasks, encoding="utf-8")
        alpha_file.write_text(
            "import unittest\n\nclass TestAlpha(unittest.TestCase):\n    def test_one(self):\n        self.assertEqual(2, 2)\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(self.ws_dir), "add", "tests/test_alpha.py"], check=True)
        subprocess.run(["git", "-C", str(self.ws_dir), "commit", "-m", "contract update"], check=True, capture_output=True)
        tbg.snapshot()
        self.assertEqual(
            agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-ac2",
                    "workspace": str(self.ws_dir),
                    "cwd": str(self.ws_dir),
                    "toolCall": {"name": "write_file", "args": {"Path": str(tasks_file), "Content": fresh_tasks}},
                }
            ),
            {"decision": "allow"},
        )

    def test_percent_encoded_file_uri_gates_workspace_hooks_json_and_customization_targets(self) -> None:
        self._init_git_repo(self.ws_dir)
        hooks_uri = f"file://{self.ws_dir.as_posix()}/.agents/hooks%2Ejson"
        res_hooks = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-uri-hooks",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "model": "Gemini 4 Hydrogen (XHigh)",
                "toolCall": {"name": "write_file", "args": {"Path": hooks_uri, "Content": "{}"}},
            }
        )
        self.assertEqual(res_hooks.get("decision"), "force_ask")

        (self.ws_dir / ".harness").mkdir(parents=True, exist_ok=True)
        (self.ws_dir / ".harness" / "manifest.json").write_text("{}", encoding="utf-8")
        gemini_uri = f"file://{self.ws_dir.as_posix()}/GEMINI%2Emd"
        res_cust = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-uri-cust",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "model": "Gemini 3.1 Flash (Low)",
                "toolCall": {"name": "write_file", "args": {"Path": gemini_uri, "Content": "# Downgraded\n"}},
            }
        )
        self.assertIn(res_cust.get("decision"), ("deny", "force_ask"))

    def test_rfc8089_single_slash_whatwg_drive_bar_loopback_wsl_and_null_byte_file_uris(self) -> None:
        from guard.hooks import pre_tool_use as ptu

        self._init_git_repo(self.ws_dir)
        # RFC 8089 single-slash `file:/...`, fragment `#/../` traversal, and `%00` null bytes
        for gov_uri in (
            f"file:{self.cfg_dir.as_posix()}/GEMINI.md",
            f"file://{self.ws_dir.as_posix()}/d#/../../config/GEMINI.md",
            f"file://wsl.localhost/Ubuntu{self.cfg_dir.as_posix()}/GEMINI.md",
            f"file:{self.ws_dir.as_posix()}/a%00.py",
        ):
            res_gov = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-rfc8089-gov",
                    "workspace": str(self.ws_dir),
                    "cwd": str(self.ws_dir),
                    "toolCall": {"name": "write_file", "args": {"Path": gov_uri, "Content": "x"}},
                }
            )
            self.assertEqual(res_gov.get("decision"), "deny", f"Expected deny for {gov_uri!r}, got {res_gov!r}")

        # Remote non-local host remains non-governance (`False`)
        self.assertFalse(ptu._targets_governance_dir("file://evil.example.com/skills/antislop/SKILL.md"))

        # Windows WHATWG `C|`, device `\\.\C:`, and loopback `127.0.0.1/C$` URIs map to `C:/...`
        fake_win_gov = Path("C:/Users/runner/.gemini/config")
        with mock.patch.object(ptu, "_governance_roots", return_value=[fake_win_gov]):
            for win_uri in (
                "file:///C|/Users/runner/.gemini/config/GEMINI.md",
                "file://C|/Users/runner/.gemini/config/GEMINI.md",
                "file://./C:/Users/runner/.gemini/config/GEMINI.md",
                "file://127.0.0.1/C$/Users/runner/.gemini/config/GEMINI.md",
                "file://localhost/C$/Users/runner/.gemini/config/GEMINI.md",
                "file:/C:/Users/runner/.gemini/config/GEMINI.md",
            ):
                self.assertTrue(ptu._targets_governance_dir(win_uri), f"Missed Windows URI {win_uri!r}")

        # RFC 8089 `file:/...` and `file:guard/...` under harness checkout trigger Rule 17 even with `cwd` set
        for cust_uri in (
            f"file:{REPO_ROOT.as_posix()}/guard/hooks/common.py",
            "file:guard/hooks/common.py",
            f"file://wsl.localhost/Ubuntu{REPO_ROOT.as_posix()}/guard/hooks/common.py",
        ):
            res_r17 = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-rfc8089-r17",
                    "workspace": str(REPO_ROOT),
                    "cwd": str(REPO_ROOT),
                    "model": "Gemini 3.1 Flash (Low)",
                    "toolCall": {"name": "write_file", "args": {"Path": cust_uri, "Content": "x"}},
                }
            )
            self.assertIn(res_r17.get("decision"), ("deny", "force_ask"), f"Missed Rule 17 on {cust_uri!r}")

    def test_normalized_hooks_json_tasks_trailing_dot_mcp_and_workflow_parity(self) -> None:
        self._init_git_repo(self.ws_dir)
        for hooks_variant in (
            f"file://{self.ws_dir.as_posix()}/.agents//hooks.json",
            f"file://{self.ws_dir.as_posix()}/.agents/./hooks.json",
            f"file://{self.ws_dir.as_posix()}/.agents/sub/../hooks.json",
            f"file://{self.ws_dir.as_posix()}/.agents/hooks.json.",
        ):
            res_h = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-norm-hooks",
                    "workspace": str(self.ws_dir),
                    "cwd": str(self.ws_dir),
                    "model": "Gemini 4 Hydrogen (XHigh)",
                    "toolCall": {"name": "write_file", "args": {"Path": hooks_variant, "Content": "{}"}},
                }
            )
            self.assertEqual(res_h.get("decision"), "force_ask", f"Expected force_ask for {hooks_variant!r}")

        # Trailing-dot `tasks.md.` mutating `## Authorized Test Modifications` -> force_ask
        res_tasks_dot = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-tasks-dot",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "toolCall": {
                    "name": "write_file",
                    "args": {
                        "Path": f"file://{self.ws_dir.as_posix()}/tasks.md.",
                        "Content": "## Authorized Test Modifications\n- `tests/test_alpha.py`: dot\n",
                    },
                },
            }
        )
        self.assertEqual(res_tasks_dot.get("decision"), "force_ask")

        # MCP write to `.agents/hooks.json` -> force_ask
        res_mcp_hooks = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-mcp-hooks",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "model": "Gemini 4 Hydrogen (XHigh)",
                "toolCall": {
                    "name": "call_mcp_tool",
                    "args": {
                        "ServerName": "fs",
                        "ToolName": "write_file",
                        "Arguments": {"path": f"file://{self.ws_dir.as_posix()}/.agents/hooks.json", "content": "{}"},
                    },
                },
            }
        )
        self.assertEqual(res_mcp_hooks.get("decision"), "force_ask")

        # `run_workflow` `call_tool("write_file", Path="file:///...")` enforces Rule 17 and `.agents/hooks.json`
        wf_cust = f'call_tool("write_file", Path="file://{REPO_ROOT.as_posix()}/guard/hooks/common.py", Content="x")\n'
        res_wf_cust = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-wf-cust",
                "workspace": str(REPO_ROOT),
                "cwd": str(REPO_ROOT),
                "model": "Gemini 3.1 Flash (Low)",
                "toolCall": {"name": "run_workflow", "args": {"Script": wf_cust, "Cwd": str(REPO_ROOT)}},
            }
        )
        self.assertIn(res_wf_cust.get("decision"), ("deny", "force_ask"))

        wf_hooks = f'call_tool("write_file", Path="file://{self.ws_dir.as_posix()}/.agents/hooks.json", Content="{{}}")\n'
        res_wf_hooks = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-wf-hooks",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "model": "Gemini 4 Hydrogen (XHigh)",
                "toolCall": {"name": "run_workflow", "args": {"Script": wf_hooks, "Cwd": str(self.ws_dir)}},
            }
        )
        self.assertEqual(res_wf_hooks.get("decision"), "force_ask")

    def test_multi_workspace_relative_target_and_nested_workspace_longest_match(self) -> None:
        from guard.hooks import pre_tool_use as ptu

        ws_app = self.tmp / "ws_app"
        ws_nested = ws_app / "nested_pkg"
        ws_nested.mkdir(parents=True, exist_ok=True)

        # Nested workspace selects deepest matching root
        nested_file = ws_nested / "mod.py"
        self.assertEqual(
            ptu._workspace_for_target(str(nested_file), [ws_app, ws_nested], fallback=ws_app),
            ws_nested,
        )

        # Multi-root `[ws_app, REPO_ROOT]` without payload `cwd` routes `"guard/cli.py"` to `REPO_ROOT`
        res_multi = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-multi-ws",
                "workspacePaths": [str(ws_app), str(REPO_ROOT)],
                "model": "Gemini 3.1 Flash (Low)",
                "toolCall": {"name": "write_file", "args": {"Path": "guard/cli.py", "Content": "x"}},
            }
        )
        self.assertIn(res_multi.get("decision"), ("deny", "force_ask"))

    def test_read_bounded_markdown_checked_fifo_eloop_and_null_byte_safety(self) -> None:
        import errno
        from guard.hooks import common as hcommon

        # Null byte returns `(False, "")` without raising ValueError
        self.assertEqual(hcommon._read_bounded_markdown_checked(Path("bad\x00name.md")), (False, ""))

        # `ELOOP` on `HANDOFF.md` returns `(False, "")` and does NOT mark `__workspace_checked__`
        self._init_git_repo(self.ws_dir)
        orig_lstat = os.lstat

        def _eloop_handoff(p: object, *args: object, **kwargs: object) -> os.stat_result:
            if str(p).endswith("HANDOFF.md"):
                raise OSError(errno.ELOOP, "Too many levels of symbolic links")
            return orig_lstat(p, *args, **kwargs)  # type: ignore[arg-type]

        with mock.patch("os.lstat", _eloop_handoff):
            self.assertEqual(hcommon._read_bounded_markdown_checked(self.ws_dir / "HANDOFF.md"), (False, ""))
            agy_hooks.handle_pre_invocation(
                {
                    "conversationId": "conv-eloop",
                    "workspace": str(self.ws_dir),
                    "prompt": "Check status.",
                }
            )
        hints_file = self.state_dir / "hook_hints.json"
        if hints_file.is_file():
            hints_data = json.loads(hints_file.read_text(encoding="utf-8"))
            conv_state = hints_data.get("conv-eloop", {})
            seen_map = conv_state.get("seen", conv_state) if isinstance(conv_state, dict) else {}
            self.assertNotIn("__workspace_checked__", seen_map)

        # POSIX FIFO does not block and returns `(True, "")`
        if hasattr(os, "mkfifo"):
            fifo_path = self.ws_dir / "fifo.md"
            os.mkfifo(fifo_path)
            self.assertEqual(hcommon._read_bounded_markdown_checked(fifo_path), (True, ""))


if __name__ == "__main__":
    unittest.main()
