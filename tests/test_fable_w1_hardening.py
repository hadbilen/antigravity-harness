#!/usr/bin/env python3
"""
tests/test_fable_w1_hardening.py — Hermetic seam regression tests for Campaign
`2026-11-22-fable-audit-hardening-and-simplification` Window 1 (`AC-1`, `AC-2`):
  - 5.3: Stop-gate default TestBoundaryGuard (mode="tdd", base_ref="HEAD") & honest verify_invariants.py --diff
  - 5.4: Throttled desktop alert & one-line operator warning on Stop circuit-breaker trip
  - 5.5: Non-git workspace Stop-gate fallback over flight_recorder touched_files
  - 11.1: Python 3.10 stdlib TOML fallback when tomllib is absent
  - 11.2: porter/archive.py bounded memory without private ZipExtFile._left internals
  - 3.5: media_qc.py ffmpeg < 5.1 -vsync fallback & README.md >= 5.1 documentation
  - 1.1 & 1.2: Transcript-anchored turn detection (inv=0 & inv=1) & AGY_RECORD_HOST_FIXTURES docs
  - 5.7: Campaign ID / HANDOFF.md gating on tasks.md recovery & question-only reset suppression
  - 8.1: code_map.py INCOMPLETE fail-loud exit on unsupported extensions & TS/JS/Python callback refs
"""

from __future__ import annotations

import ast
import contextlib
import gc
import io
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
import zipfile
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
for _p in (str(TESTS_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hermetic  # noqa: E402, F401
import guard.agy_hooks as agy_hooks  # noqa: E402
from porter.archive import inspect_zip  # noqa: E402
from scripts import code_map  # noqa: E402


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="Tester",
        GIT_AUTHOR_EMAIL="tester@example.com",
        GIT_COMMITTER_NAME="Tester",
        GIT_COMMITTER_EMAIL="tester@example.com",
    )
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        env=env,
        check=True,
        timeout=15,
    )


def _init_git_repo(ws: Path) -> None:
    ws.mkdir(parents=True, exist_ok=True)
    _git(ws, "init", "-q")
    _git(ws, "config", "user.email", "tester@example.com")
    _git(ws, "config", "user.name", "Tester")


def _extract_step_texts(resp: dict) -> tuple[list[str], list[str]]:
    sys_msgs: list[str] = []
    user_mds: list[str] = []
    for step in resp.get("injectSteps") or []:
        if not isinstance(step, dict):
            continue
        sm = step.get("systemMessage")
        if isinstance(sm, dict) and isinstance(sm.get("systemMessage"), str):
            sys_msgs.append(sm["systemMessage"])
        meta = step.get("metadata")
        if isinstance(meta, dict) and isinstance(meta.get("user_markdown"), str):
            user_mds.append(meta["user_markdown"])
    return sys_msgs, user_mds


def _write_jsonl(path: Path, entries: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")


def _planner_step(step_index: int, active_tokens: int, model: str = "gemini-4-neon-xhigh") -> dict:
    return {
        "step_index": step_index,
        "type": "PLANNER_RESPONSE",
        "source": "MODEL",
        "status": "DONE",
        "model": model,
        "input_tokens": min(10_000, active_tokens),
        "cache_read_tokens": max(0, active_tokens - 10_000),
        "output_tokens": 500,
        "content": "Working on task.",
    }


class TestW1Rule9ExpectedValueCircuitBreakerAndNonGitStopGate(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="agy_w1_ac1_"))
        self.cfg_dir = self.root / "config"
        self.state_dir = self.root / "state"
        self.data_dir = self.root / "data"
        for d in (self.cfg_dir, self.state_dir, self.data_dir):
            d.mkdir(parents=True, exist_ok=True)
        (self.cfg_dir / "GEMINI.md").write_text("# Hermetic Constitution\n", encoding="utf-8")
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.root / "home"),
                "USERPROFILE": str(self.root / "home"),
                "XDG_STATE_HOME": str(self.state_dir),
                "PLUMB_GUARD_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_STATE_DIR": str(self.state_dir),
                "PLUMB_GUARD_DATA_DIR": str(self.data_dir),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
                "PLUMB_GUARD_NOTIFY": "off",
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        hermetic.force_rmtree(self.root)

    def test_5_3_stop_gate_blocks_expected_value_mutation_without_snapshot_py_and_ts(self) -> None:
        ws = self.root / "repo_rule9"
        _init_git_repo(ws)
        (ws / "src").mkdir()
        (ws / "tests").mkdir()
        (ws / "src" / "calc.py").write_text("def calc(x):\n    return x * 1.1\n", encoding="utf-8")
        py_test = ws / "tests" / "test_calc.py"
        py_test.write_text("from src.calc import calc\n\ndef test_total():\n    assert calc(100) == 110\n", encoding="utf-8")
        ts_test = ws / "src" / "calc.test.ts"
        ts_test.write_text("test('total', () => {\n  expect(calc(100)).toBe(110);\n});\n", encoding="utf-8")
        _git(ws, "add", ".")
        _git(ws, "commit", "-q", "-m", "initial")

        # 1. Unauthorized Python expected-value mutation (110 -> 99.0) with NO manual snapshot MUST block
        py_test.write_text("from src.calc import calc\n\ndef test_total():\n    assert calc(100) == 99.0\n", encoding="utf-8")
        res_py = agy_hooks.handle_stop(
            {"conversationId": "conv-r9-py", "workspacePaths": [str(ws)], "terminationReason": "NO_TOOL_CALL"}
        )
        self.assertEqual(res_py.get("decision"), "continue", res_py)
        self.assertIn("Test boundary violation", res_py.get("reason", ""))
        self.assertIn("tests/test_calc.py", res_py.get("reason", ""))

        # Restore Python test; mutate TS expected value (110 -> 99) without snapshot -> MUST block
        py_test.write_text("from src.calc import calc\n\ndef test_total():\n    assert calc(100) == 110\n", encoding="utf-8")
        ts_test.write_text("test('total', () => {\n  expect(calc(100)).toBe(99);\n});\n", encoding="utf-8")
        res_ts = agy_hooks.handle_stop(
            {"conversationId": "conv-r9-ts", "workspacePaths": [str(ws)], "terminationReason": "NO_TOOL_CALL"}
        )
        self.assertEqual(res_ts.get("decision"), "continue", res_ts)
        self.assertIn("Test boundary violation", res_ts.get("reason", ""))
        self.assertIn("src/calc.test.ts", res_ts.get("reason", ""))

        # 2. Pure TDD additive extension + brand-new test file MUST stay allowed
        ts_test.write_text("test('total', () => {\n  expect(calc(100)).toBe(110);\n});\n", encoding="utf-8")
        py_test.write_text(
            "from src.calc import calc\n\n"
            "def test_total():\n    assert calc(100) == 110\n\n"
            "def test_zero():\n    assert calc(0) == 0\n",
            encoding="utf-8",
        )
        (ws / "tests" / "test_new_suite.py").write_text("def test_brand_new():\n    assert 2 + 2 == 4\n", encoding="utf-8")
        res_tdd = agy_hooks.handle_stop(
            {"conversationId": "conv-r9-tdd", "workspacePaths": [str(ws)], "terminationReason": "NO_TOOL_CALL"}
        )
        self.assertEqual(res_tdd, {}, res_tdd)

        # 3. Authorized expected-value update logged in tasks.md passes cleanly
        (ws / "tasks.md").write_text(
            "# Tasks\n\n## Authorized Test Modifications\n- `tests/test_calc.py`: tax rate changed to 0.99\n",
            encoding="utf-8",
        )
        py_test.write_text("from src.calc import calc\n\ndef test_total():\n    assert calc(100) == 99.0\n", encoding="utf-8")
        res_auth = agy_hooks.handle_stop(
            {"conversationId": "conv-r9-auth", "workspacePaths": [str(ws)], "terminationReason": "NO_TOOL_CALL"}
        )
        self.assertEqual(res_auth, {}, res_auth)

        # 4. Unborn HEAD repo (0 commits) does not falsely fail
        unborn = self.root / "repo_unborn"
        _init_git_repo(unborn)
        (unborn / "app.py").write_text("X = 1\n", encoding="utf-8")
        res_unborn = agy_hooks.handle_stop(
            {"conversationId": "conv-r9-unborn", "workspacePaths": [str(unborn)], "terminationReason": "NO_TOOL_CALL"}
        )
        self.assertEqual(res_unborn, {}, res_unborn)

    def test_5_3_verify_invariants_diff_catches_expected_value_mutations_and_is_honest(self) -> None:
        ws = self.root / "repo_vi"
        _init_git_repo(ws)
        (ws / "tests").mkdir()
        (ws / "src").mkdir()
        py_test = ws / "tests" / "test_calc.py"
        ts_test = ws / "src" / "calc.test.ts"
        py_test.write_text("def test_total():\n    assert calc(100) == 110\n", encoding="utf-8")
        ts_test.write_text("test('total', () => {\n  expect(calc(100)).toBe(110);\n});\n", encoding="utf-8")
        _git(ws, "add", ".")
        _git(ws, "commit", "-q", "-m", "initial")

        vi_script = str(REPO_ROOT / "scripts" / "verify_invariants.py")

        # Mutate Python expected value -> exit 1 (no false PASS / Zero test weakening)
        py_test.write_text("def test_total():\n    assert calc(100) == 99.0\n", encoding="utf-8")
        p_py = subprocess.run(
            [sys.executable, vi_script, "--diff", "--path", str(ws)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(p_py.returncode, 1, p_py.stdout + p_py.stderr)
        self.assertNotIn("Zero test weakening", p_py.stdout)
        self.assertIn("tests/test_calc.py", p_py.stdout)

        # Mutate TS expected value -> exit 1
        py_test.write_text("def test_total():\n    assert calc(100) == 110\n", encoding="utf-8")
        ts_test.write_text("test('total', () => {\n  expect(calc(100)).toBe(99);\n});\n", encoding="utf-8")
        p_ts = subprocess.run(
            [sys.executable, vi_script, "--diff", "--path", str(ws)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(p_ts.returncode, 1, p_ts.stdout + p_ts.stderr)
        self.assertIn("src/calc.test.ts", p_ts.stdout)

        # Pure additive TDD test extension -> exit 0 + TestBoundaryGuard verified
        ts_test.write_text("test('total', () => {\n  expect(calc(100)).toBe(110);\n});\n", encoding="utf-8")
        py_test.write_text(
            "def test_total():\n    assert calc(100) == 110\n\ndef test_extra():\n    assert calc(10) == 11\n",
            encoding="utf-8",
        )
        p_ok = subprocess.run(
            [sys.executable, vi_script, "--diff", "--path", str(ws)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(p_ok.returncode, 0, p_ok.stdout + p_ok.stderr)
        self.assertIn("TestBoundaryGuard verified", p_ok.stdout)

        # Static --all scan does NOT falsely claim baseline test-weakening verification
        p_all = subprocess.run(
            [sys.executable, vi_script, "--all", "--path", str(ws)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(p_all.returncode, 0, p_all.stdout + p_all.stderr)
        self.assertNotIn("Zero test weakening / skip mutations detected", p_all.stdout)
        self.assertIn("Static scan clean", p_all.stdout)

    def test_5_4_circuit_breaker_fires_throttled_desktop_alert_and_operator_warning(self) -> None:
        from guard.notifier import GuardNotifier

        bad_diff = "+++ b/src/app.py\n+if 'PYTEST_" "CURRENT_TEST' in os.environ: pass\n"
        payload = {
            "conversationId": "conv-cb-alert",
            "terminationReason": "NO_TOOL_CALL",
            "diffText": bad_diff,
        }
        dispatched_calls: list[tuple[str, str, str]] = []

        def fake_native(self_n, title: str, message: str, severity) -> tuple[bool, str]:
            dispatched_calls.append((title, message, severity.value))
            return True, "fake-desktop"

        with (
            mock.patch.dict(os.environ, {"PLUMB_GUARD_NOTIFY": ""}, clear=False),
            mock.patch.object(GuardNotifier, "_dispatch_native", fake_native),
        ):
            err12 = io.StringIO()
            with contextlib.redirect_stderr(err12):
                r1 = agy_hooks.handle_stop(payload)
                r2 = agy_hooks.handle_stop(payload)
            self.assertEqual(r1.get("decision"), "continue")
            self.assertEqual(r2.get("decision"), "continue")
            self.assertEqual(dispatched_calls, [])
            self.assertNotIn("CIRCUIT BREAKER TRIPPED", err12.getvalue())

            # Strike 3: trips circuit breaker -> returns {}, emits operator stderr line, fires 1 desktop alert
            err3 = io.StringIO()
            with contextlib.redirect_stderr(err3):
                r3 = agy_hooks.handle_stop(payload)
            self.assertEqual(r3, {})
            self.assertIn("[Harness Stop Gate — CIRCUIT BREAKER TRIPPED]", err3.getvalue())
            self.assertIn("conv=conv-cb-alert", err3.getvalue())
            self.assertEqual(len(dispatched_calls), 1, dispatched_calls)
            self.assertIn("Circuit Breaker Tripped", dispatched_calls[0][0])
            self.assertEqual(dispatched_calls[0][2], "warning")

            # Retries 4 & 5 on same fingerprint: frozen, zero alert flood, zero extra stderr spam
            err45 = io.StringIO()
            with contextlib.redirect_stderr(err45):
                self.assertEqual(agy_hooks.handle_stop(payload), {})
                self.assertEqual(agy_hooks.handle_stop(payload), {})
            self.assertEqual(len(dispatched_calls), 1)
            self.assertEqual(err45.getvalue(), "")

            # Even if hook_strikes.json is cleared, notifier cooldown cache still throttles same (conv, fp)
            (self.state_dir / "hook_strikes.json").unlink()
            with contextlib.redirect_stderr(io.StringIO()):
                agy_hooks.handle_stop(payload)
                agy_hooks.handle_stop(payload)
                agy_hooks.handle_stop(payload)
            self.assertEqual(len(dispatched_calls), 1, "GuardNotifier cooldown must prevent repeat flood for same fingerprint")

            # Distinct conversation triggers a new alert cleanly
            other_payload = {**payload, "conversationId": "conv-cb-other"}
            with contextlib.redirect_stderr(io.StringIO()):
                agy_hooks.handle_stop(other_payload)
                agy_hooks.handle_stop(other_payload)
                agy_hooks.handle_stop(other_payload)
            self.assertEqual(len(dispatched_calls), 2)

    def test_5_5_non_git_workspace_stop_gate_scans_touched_files_for_syntax_slop_skip_and_c9(self) -> None:
        # Ensure temp dir has no .git in any ancestor
        ng_root = Path(tempfile.mkdtemp(prefix="agy_nongit_5_5_"))
        self.addCleanup(hermetic.force_rmtree, ng_root)
        self.assertFalse(agy_hooks._is_git_repo_workspace(ng_root))

        def _touch_and_stop(conv: str, rel: str, content: str) -> dict:
            ws = ng_root / conv
            target = ws / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            pre = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": conv,
                    "workspacePaths": [str(ws)],
                    "toolCall": {"name": "write_file", "args": {"Path": str(target), "Content": content}},
                }
            )
            self.assertEqual(pre.get("decision"), "allow", pre)
            return agy_hooks.handle_stop(
                {"conversationId": conv, "workspacePaths": [str(ws)], "terminationReason": "NO_TOOL_CALL"}
            )

        # 1. Python syntax corruption
        r_py = _touch_and_stop("ng_syntax_py", "app.py", "def broken(:\n    pass\n")
        self.assertEqual(r_py.get("decision"), "continue", r_py)
        self.assertIn("Malformed Python syntax", r_py.get("reason", ""))

        # 2. Malformed JSON syntax
        r_json = _touch_and_stop("ng_syntax_json", "config.json", '{"a": }\n')
        self.assertEqual(r_json.get("decision"), "continue", r_json)
        self.assertIn("Malformed JSON syntax", r_json.get("reason", ""))

        # 3. UI slop in HTML
        slop_html = (
            "<!doctype html><html><head><style>"
            "body { font-family: 'Inter', sans-serif; background: linear-gradient(135deg, #6366f1, #a855f7); }"
            "</style></head><body><h1>Hero</h1></body></html>\n"
        )
        r_ui = _touch_and_stop("ng_ui_slop", "index.html", slop_html)
        self.assertEqual(r_ui.get("decision"), "continue", r_ui)
        self.assertIn("UI slop violation", r_ui.get("reason", ""))

        # 4. Unapproved test-skip marker
        skip_line = "@pytest.mark." + "sk" + "ip(reason='later')\ndef test_x():\n    assert 1 == 2\n"
        r_skip = _touch_and_stop("ng_skip", "tests/test_sample.py", skip_line)
        self.assertEqual(r_skip.get("decision"), "continue", r_skip)
        self.assertIn("Unapproved test skip", r_skip.get("reason", ""))

        # 5. C9 test-runner sniffing in production file
        c9_src = "import os\ndef run():\n    return 0 if 'PYTEST_" "CURRENT_TEST' in os.environ else 1\n"
        r_c9 = _touch_and_stop("ng_c9", "src/service.py", c9_src)
        self.assertEqual(r_c9.get("decision"), "continue", r_c9)
        self.assertIn("Test-runner detection", r_c9.get("reason", ""))

        # 6. Clean files in non-git workspace pass cleanly
        r_ok = _touch_and_stop("ng_clean", "src/clean.py", "def add(a: int, b: int) -> int:\n    return a + b\n")
        self.assertEqual(r_ok, {}, r_ok)


class TestW1Py310ArchiveMediaTurnTasksAndCodeMap(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="agy_w1_ac2_"))
        self.cfg_dir = self.root / "config"
        self.state_dir = self.root / "state"
        self.ws_dir = self.root / "ws"
        for d in (self.cfg_dir, self.state_dir, self.ws_dir):
            d.mkdir(parents=True, exist_ok=True)
        (self.cfg_dir / "GEMINI.md").write_text("# Hermetic Constitution\n", encoding="utf-8")
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.root / "home"),
                "USERPROFILE": str(self.root / "home"),
                "XDG_STATE_HOME": str(self.state_dir),
                "PLUMB_GUARD_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
                "PLUMB_GUARD_NOTIFY": "off",
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        hermetic.force_rmtree(self.root)

    def test_11_1_python310_toml_fallback_matches_stdlib_and_rejects_invalid_toml(self) -> None:
        import test_adr0014_predictive_handoff_rust_decisions_procoder as adr14_tests

        gf_text = (REPO_ROOT / "skills" / "rust-harden" / "references" / "greenfield-architecture.md").read_text(
            encoding="utf-8"
        )
        toml_blocks = re.findall(r"```toml\n(.*?)```", gf_text, re.DOTALL)
        self.assertGreaterEqual(len(toml_blocks), 3)

        # Mask tomllib as unavailable (simulating Python 3.10)
        with mock.patch.dict(sys.modules, {"tomllib": None}):
            fallback_docs = [adr14_tests._load_toml_text(blk) for blk in toml_blocks]
        try:
            import tomllib  # type: ignore[import-not-found]
        except ImportError:
            tomllib = None
        if tomllib is not None:
            native_docs = [tomllib.loads(blk) for blk in toml_blocks]
            self.assertEqual(fallback_docs, native_docs)
        else:
            ws_doc = next(d for d in fallback_docs if "workspace" in d)
            self.assertEqual(ws_doc["workspace"]["package"]["edition"], "2024")

        with self.assertRaises(ValueError):
            adr14_tests._parse_toml_stdlib_fallback("[workspace\nmissing_bracket = true\n")

    def test_11_2_porter_archive_bounded_memory_without_private_left_internals(self) -> None:
        archive_src = (REPO_ROOT / "porter" / "archive.py").read_text(encoding="utf-8")
        tree = ast.parse(archive_src)
        forbidden_attrs = [
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr in ("_left", "_compress_left")
        ]
        forbidden_strings = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in ("_left", "_compress_left")
        ]
        self.assertEqual(forbidden_attrs, [], "porter/archive.py must not access private ZipExtFile._left attrs")
        self.assertEqual(forbidden_strings, [], "porter/archive.py must not look up private _left attrs dynamically")

        # 1. Spoofed 30 MiB bombs across BZIP2, DEFLATED, and LZMA stay strictly memory-bounded
        uncompressed_len = 30 * 1024 * 1024
        orig_sz = struct.pack("<I", uncompressed_len)
        fake_sz = struct.pack("<I", 64)
        for label, comp, max_peak in (
            ("bzip2", zipfile.ZIP_BZIP2, 6 * 1024 * 1024),
            ("deflate", zipfile.ZIP_DEFLATED, 6 * 1024 * 1024),
            # LZMA1 default preset allocates a fixed 8 MiB dictionary regardless of 30 MiB payload size.
            ("lzma", zipfile.ZIP_LZMA, 12 * 1024 * 1024),
        ):
            with self.subTest(compression=label):
                zpath = self.root / f"spoof_{label}.zip"
                with zipfile.ZipFile(zpath, "w", compression=comp) as zf_w:
                    zf_w.writestr("rule.md", b"\x00" * uncompressed_len)
                raw = zpath.read_bytes()
                zpath.write_bytes(raw.replace(orig_sz, fake_sz))
                del raw

                gc.collect()
                tracemalloc.start()
                tracemalloc.reset_peak()
                try:
                    rep = inspect_zip(zpath, harness_root=self.root)
                    _, peak_bytes = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()

                self.assertFalse(rep.is_safe, f"{label} spoofed bomb must be flagged unsafe")
                self.assertLess(
                    peak_bytes,
                    max_peak,
                    f"{label} peak memory {peak_bytes} exceeded {max_peak // (1024 * 1024)} MiB",
                )

        # 1b. Adversarial LZMA1 header requesting a 256 MiB dictionary is rejected before allocation
        huge_dict_zip = self.root / "huge_lzma_dict.zip"
        with zipfile.ZipFile(huge_dict_zip, "w", compression=zipfile.ZIP_LZMA) as zf_w:
            zf_w.writestr("rule.md", b"safe small body\n")
        raw_lz = huge_dict_zip.read_bytes()
        default_dict_le = struct.pack("<I", 8 * 1024 * 1024)
        huge_dict_le = struct.pack("<I", 256 * 1024 * 1024)
        self.assertIn(default_dict_le, raw_lz)
        huge_dict_zip.write_bytes(raw_lz.replace(default_dict_le, huge_dict_le, 1))
        rep_huge = inspect_zip(huge_dict_zip, harness_root=self.root)
        self.assertFalse(rep_huge.is_safe)
        self.assertTrue(
            any(h.kind == "OVERSIZE" and "LZMA dictionary" in h.message for h in rep_huge.hazards),
            rep_huge.hazards,
        )

        # 2. Valid archives across STORED, DEFLATED, BZIP2, LZMA inspect cleanly as safe
        for label, comp in (
            ("stored", zipfile.ZIP_STORED),
            ("deflate", zipfile.ZIP_DEFLATED),
            ("bzip2", zipfile.ZIP_BZIP2),
            ("lzma", zipfile.ZIP_LZMA),
        ):
            with self.subTest(valid_compression=label):
                ok_zip = self.root / f"valid_{label}.zip"
                with zipfile.ZipFile(ok_zip, "w", compression=comp) as zf_w:
                    zf_w.writestr("guide.md", "# Guide\nAlways verify outputs deterministically.\n")
                rep_ok = inspect_zip(ok_zip, harness_root=self.root)
                self.assertTrue(rep_ok.is_safe, (label, rep_ok.hazards, rep_ok.members))

        # 3. Corrupted CRC-32 payload is rejected as UNREADABLE_MEMBER
        bad_crc_zip = self.root / "bad_crc.zip"
        with zipfile.ZipFile(bad_crc_zip, "w", compression=zipfile.ZIP_STORED) as zf_w:
            zf_w.writestr("rule.md", b"hello deterministic world\n")
        raw_ok = bytearray(bad_crc_zip.read_bytes())
        payload_idx = raw_ok.index(b"hello deterministic world")
        raw_ok[payload_idx] ^= 0x01
        bad_crc_zip.write_bytes(bytes(raw_ok))
        rep_crc = inspect_zip(bad_crc_zip, harness_root=self.root)
        self.assertFalse(rep_crc.is_safe)
        self.assertTrue(any(h.kind == "UNREADABLE_MEMBER" for h in rep_crc.hazards), rep_crc.hazards)

    def test_3_5_media_qc_ffmpeg_5_1_doc_and_pre_5_1_vsync_fallback(self) -> None:
        import importlib.util

        readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertRegex(readme_text, r"ffmpeg.*>=\s*5\.1")

        mq_path = REPO_ROOT / "skills" / "media-studio" / "scripts" / "media_qc.py"
        spec = importlib.util.spec_from_file_location("media_qc_w1_test", mq_path)
        assert spec is not None and spec.loader is not None
        media_qc = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = media_qc
        spec.loader.exec_module(media_qc)

        self.assertEqual(media_qc._parse_ffmpeg_version("ffmpeg version 4.4.2-0ubuntu0.22.04.1 Copyright"), (4, 4))
        self.assertEqual(media_qc._parse_ffmpeg_version("ffmpeg version 7:4.4.2-0ubuntu0.22.04.1 Copyright"), (4, 4))
        self.assertEqual(media_qc._parse_ffmpeg_version("ffmpeg version n5.1.4 Copyright"), (5, 1))
        self.assertEqual(media_qc._parse_ffmpeg_version("ffmpeg version 8.1.2-2ubuntu2 Copyright"), (8, 1))
        self.assertIsNone(media_qc._parse_ffmpeg_version("ffmpeg version N-114321-gabcdef Copyright"))

        dummy_png = self.root / "sprite.png"
        dummy_png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
        expected_rgba = b"\xff\x00\x00\xff" * 16  # 4x4 RGBA

        # Case A: ffmpeg 4.4 detected -> directly uses `-vsync passthrough` (no `-fps_mode`)
        seen_cmds: list[list[str]] = []

        def fake_bounded(cmd, max_bytes, timeout=None):
            seen_cmds.append(list(cmd))
            return 0, expected_rgba, b""

        media_qc._FFMPEG_VERSION_CACHE.clear()
        fake_v44 = subprocess.CompletedProcess(["ffmpeg", "-version"], 0, "ffmpeg version 4.4.2 Copyright\n", "")
        with (
            mock.patch.object(media_qc, "_require_tool", return_value="/fake/ffmpeg44"),
            mock.patch.object(media_qc, "_run_media_subprocess", return_value=fake_v44),
            mock.patch.object(media_qc, "_run_media_subprocess_bounded_bytes", side_effect=fake_bounded),
        ):
            raw = media_qc._decode_image_rgba_frames(dummy_png, 4, 4, max_frames=1)
        self.assertEqual(raw, expected_rgba)
        self.assertEqual(len(seen_cmds), 1)
        self.assertIn("-vsync", seen_cmds[0])
        self.assertNotIn("-fps_mode", seen_cmds[0])

        # Case B: Unparsed version tries `-fps_mode`, gets "Unrecognized option 'fps_mode'", retries with `-vsync`
        retry_cmds: list[list[str]] = []

        def fake_retry(cmd, max_bytes, timeout=None):
            retry_cmds.append(list(cmd))
            if "-fps_mode" in cmd:
                return 1, b"", b"Unrecognized option 'fps_mode'.\nError splitting the argument list: Option not found\n"
            return 0, expected_rgba, b""

        media_qc._FFMPEG_VERSION_CACHE.clear()
        fake_git_ver = subprocess.CompletedProcess(["ffmpeg", "-version"], 0, "ffmpeg version N-99999-g1234\n", "")
        with (
            mock.patch.object(media_qc, "_require_tool", return_value="/fake/ffmpeg_custom"),
            mock.patch.object(media_qc, "_run_media_subprocess", return_value=fake_git_ver),
            mock.patch.object(media_qc, "_run_media_subprocess_bounded_bytes", side_effect=fake_retry),
        ):
            raw_retry = media_qc._decode_image_rgba_frames(dummy_png, 4, 4, max_frames=1)
        self.assertEqual(raw_retry, expected_rgba)
        self.assertEqual(len(retry_cmds), 2)
        self.assertIn("-fps_mode", retry_cmds[0])
        self.assertIn("-vsync", retry_cmds[1])

    def test_1_1_1_2_transcript_anchored_turn_detection_inv0_inv1_and_host_fixture_docs(self) -> None:
        # 1.2: Host fixture README documents AGY_RECORD_HOST_FIXTURES=1 workflow
        host_readme = REPO_ROOT / "tests" / "fixtures" / "host" / "README.md"
        self.assertTrue(host_readme.is_file(), "tests/fixtures/host/README.md must exist")
        readme_body = host_readme.read_text(encoding="utf-8")
        self.assertIn("AGY_RECORD_HOST_FIXTURES=1", readme_body)
        self.assertIn("synthetic", readme_body.lower())
        self.assertIn("redacted", readme_body.lower())

        # 1.1: Predictive context-window handoff fires identically on invocationNum=0 and invocationNum=1
        heavy_prompt = (
            "Implement the multi-file storage layer redesign across 6 modules and verify all edge cases end-to-end"
        )
        for inv_val in (0, 1):
            with self.subTest(invocationNum=inv_val):
                tx = self.root / f"tx_inv_{inv_val}.jsonl"
                _write_jsonl(
                    tx,
                    [
                        {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Prior step"},
                        _planner_step(2, 390_000),
                        _planner_step(3, 405_000),
                        _planner_step(4, 420_000),
                        {"step_index": 5, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": heavy_prompt},
                    ],
                )
                res = agy_hooks.handle_pre_invocation(
                    {
                        "conversationId": f"conv-inv-{inv_val}",
                        "invocationNum": inv_val,
                        "cwd": str(self.ws_dir),
                        "transcriptPath": str(tx),
                        "prompt": heavy_prompt,
                    }
                )
                sys_m, _md = _extract_step_texts(res)
                self.assertTrue(
                    any("[Harness Context Handoff]" in m for m in sys_m),
                    f"Expected predictive handoff at invocationNum={inv_val}, got: {res}",
                )

        # 0-indexed host: Call 1 at inv=0 fires; Call 2 of SAME turn at inv=1 (with PLANNER_RESPONSE appended) stays silent
        tx_0idx = self.root / "tx_0idx_mid.jsonl"
        _write_jsonl(
            tx_0idx,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Prior step"},
                _planner_step(2, 390_000),
                _planner_step(3, 405_000),
                _planner_step(4, 420_000),
                {"step_index": 5, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": heavy_prompt},
            ],
        )
        r_call1 = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-0idx-turn",
                "invocationNum": 0,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx_0idx),
                "prompt": heavy_prompt,
            }
        )
        self.assertTrue(any("[Harness Context Handoff]" in m for m in _extract_step_texts(r_call1)[0]), r_call1)
        with tx_0idx.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(_planner_step(6, 430_000)) + "\n")
        r_call2 = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-0idx-turn",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx_0idx),
                "prompt": heavy_prompt,
            }
        )
        self.assertEqual(r_call2, {}, f"Mid-turn inv=1 after inv=0 must stay silent: {r_call2}")

        # Conversation-global invocationNum > 1 with fresh trailing USER_INPUT must NOT fast-noop
        tx_global = self.root / "tx_global_inv5.jsonl"
        _write_jsonl(
            tx_global,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Step 1"},
                _planner_step(2, 420_000),
                {"step_index": 3, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": heavy_prompt},
            ],
        )
        payload_inv5 = {
            "conversationId": "conv-global-inv5",
            "invocationNum": 5,
            "cwd": str(self.ws_dir),
            "transcriptPath": str(tx_global),
            "prompt": heavy_prompt,
        }
        self.assertFalse(agy_hooks._is_fast_pre_invocation_noop(payload_inv5))
        r_inv5 = agy_hooks.handle_pre_invocation(payload_inv5)
        self.assertTrue(any("[Harness Context Handoff]" in m for m in _extract_step_texts(r_inv5)[0]), r_inv5)

    def test_5_7_tasks_md_campaign_gating_and_question_only_reset_suppression(self) -> None:
        # 1. Plain tasks.md without Campaign ID and without HANDOFF.md NEVER triggers recovery gate
        plain_ws = self.root / "plain_tasks_ws"
        plain_ws.mkdir()
        (plain_ws / "tasks.md").write_text("# My Todo List\n- [ ] Buy coffee\n- [ ] Reply to email\n", encoding="utf-8")
        res_plain = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-plain-tasks",
                "workspace": str(plain_ws),
                "prompt": "Implement the new invoice formatter cleanly.",
            }
        )
        sys_plain, _ = _extract_step_texts(res_plain)
        self.assertFalse(any("[Harness Recovery & Continuity Gate]" in m for m in sys_plain), res_plain)

        # 2. Campaign-backed tasks.md emits reset guidance on edit/new-task prompts, yet silences reset on pure questions
        camp_ws = self.root / "camp_tasks_ws"
        camp_ws.mkdir()
        (camp_ws / "tasks.md").write_text(
            "**Campaign ID:** `2026-11-22-billing-slice`\n- [ ] Implement tax calculator\n",
            encoding="utf-8",
        )
        for idx, q_prompt in enumerate(
            (
                "How does TestBoundaryGuard validate pure line additions?",
                "Bu projede hooks.json dosyası nerede tanımlı?",
                "Explain how porter/archive.py bounds bzip2 memory.",
                "MISTAKES.md ne işe yarıyor?",
            )
        ):
            with self.subTest(question=q_prompt):
                r_q = agy_hooks.handle_pre_invocation(
                    {
                        "conversationId": f"conv-qonly-{idx}",
                        "workspace": str(camp_ws),
                        "prompt": q_prompt,
                    }
                )
                joined_q = "\n".join(_extract_step_texts(r_q)[0])
                self.assertIn("[Harness Recovery & Continuity Gate]", joined_q)
                self.assertNotIn("reset `tasks.md`", joined_q, f"Reset directive must be silenced on question: {q_prompt}")

        # 3. Actionable/edit prompts (including polite question-form edit requests) KEEP reset guidance
        for idx, act_prompt in enumerate(
            (
                "Start a brand new authentication refactor.",
                "Can you fix the bug in auth.py?",
                "Bu dosyadaki hatayı düzeltir misin?",
            )
        ):
            with self.subTest(action_prompt=act_prompt):
                r_act = agy_hooks.handle_pre_invocation(
                    {
                        "conversationId": f"conv-act-{idx}",
                        "workspace": str(camp_ws),
                        "prompt": act_prompt,
                    }
                )
                joined_act = "\n".join(_extract_step_texts(r_act)[0])
                self.assertIn("[Harness Recovery & Continuity Gate]", joined_act)
                self.assertIn("reset `tasks.md`", joined_act, f"Action prompt must retain reset guidance: {act_prompt}")

    def test_8_1_code_map_incomplete_exit_on_unsupported_extensions_and_callbacks(self) -> None:
        # 1. Unsupported extensions (.kt, .java, .qml) -> INCOMPLETE + non-zero exit (never 0 callers -> Tier 1)
        kt_dir = self.root / "kt_qml_proj"
        kt_dir.mkdir()
        (kt_dir / "Pricing.kt").write_text("fun priceWithTax(x: Double): Double = x * 1.1\n", encoding="utf-8")
        (kt_dir / "CartView.qml").write_text("Item { property var total: priceWithTax(100) }\n", encoding="utf-8")
        (kt_dir / "Legacy.java").write_text("class Legacy { double f() { return 1.0; } }\n", encoding="utf-8")

        kt_callers = code_map.find_callers("priceWithTax", [kt_dir], base_dir=kt_dir)
        self.assertFalse(kt_callers.complete)
        self.assertEqual(sorted(kt_callers.unsupported_files), ["CartView.qml", "Legacy.java", "Pricing.kt"])

        kt_blast = code_map.compute_blast_radius("priceWithTax", [kt_dir], base_dir=kt_dir)
        self.assertFalse(kt_blast["complete"])
        self.assertIn("INCOMPLETE", kt_blast["tier_recommendation"])
        self.assertNotEqual(kt_blast["tier_recommendation"], "Tier 1")

        for subcmd in ("callers", "blast-radius"):
            out_b, err_b = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out_b), contextlib.redirect_stderr(err_b):
                rc = code_map.main([subcmd, "priceWithTax", str(kt_dir), "--json"])
            self.assertNotEqual(rc, 0, f"{subcmd} must exit non-zero on unsupported .kt/.qml/.java files")
            self.assertIn("INCOMPLETE", err_b.getvalue())
            parsed = json.loads(out_b.getvalue())
            self.assertIs(parsed.get("complete"), False)
            unsupported = parsed.get("unsupported_files", [])
            self.assertTrue(
                any(p.endswith("Pricing.kt") for p in unsupported),
                f"Expected Pricing.kt in unsupported_files, got {unsupported!r}",
            )

        # 2. TS/JS callback reference: xs.map(priceWithTax) -> INCOMPLETE + non-zero exit
        ts_dir = self.root / "ts_cb_proj"
        ts_dir.mkdir()
        (ts_dir / "pricing.ts").write_text(
            "export function priceWithTax(x: number): number { return x * 1.1; }\n",
            encoding="utf-8",
        )
        (ts_dir / "cart.ts").write_text(
            "import { priceWithTax } from './pricing';\n"
            "export const totals = (xs: number[]) => xs.map(priceWithTax);\n",
            encoding="utf-8",
        )
        ts_callers = code_map.find_callers("priceWithTax", [ts_dir], base_dir=ts_dir)
        self.assertFalse(ts_callers.complete)
        self.assertEqual(len(ts_callers.non_call_references), 1)
        self.assertEqual(ts_callers.non_call_references[0]["file"], "cart.ts")
        self.assertEqual(ts_callers.non_call_references[0]["line"], 2)

        ts_blast = code_map.compute_blast_radius("priceWithTax", [ts_dir], base_dir=ts_dir)
        self.assertFalse(ts_blast["complete"])
        self.assertIn("INCOMPLETE", ts_blast["tier_recommendation"])
        self.assertIn("cart.ts", ts_blast["affected_files"])

        out_ts, err_ts = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out_ts), contextlib.redirect_stderr(err_ts):
            rc_ts = code_map.main(["callers", "priceWithTax", str(ts_dir), "--json"])
        self.assertNotEqual(rc_ts, 0)
        self.assertIn("INCOMPLETE", err_ts.getvalue())
        self.assertIs(json.loads(out_ts.getvalue()).get("complete"), False)

        # 3. Python callback reference: list(map(price_with_tax, xs)) -> INCOMPLETE + non-zero exit
        py_dir = self.root / "py_cb_proj"
        py_dir.mkdir()
        (py_dir / "pricing.py").write_text("def price_with_tax(x: float) -> float:\n    return x * 1.1\n", encoding="utf-8")
        (py_dir / "cart.py").write_text(
            "from pricing import price_with_tax\ndef totals(xs):\n    return list(map(price_with_tax, xs))\n",
            encoding="utf-8",
        )
        py_callers = code_map.find_callers("price_with_tax", [py_dir], base_dir=py_dir)
        self.assertFalse(py_callers.complete)
        self.assertEqual(len(py_callers.non_call_references), 1)
        self.assertEqual(py_callers.non_call_references[0]["file"], "cart.py")
        out_py, err_py = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out_py), contextlib.redirect_stderr(err_py):
            rc_py = code_map.main(["blast-radius", "price_with_tax", str(py_dir), "--json"])
        self.assertNotEqual(rc_py, 0)
        self.assertIn("INCOMPLETE", err_py.getvalue())

        # 4. Negative control: direct calls only in TS and Python -> complete=True, exit 0
        clean_dir = self.root / "clean_direct_proj"
        clean_dir.mkdir()
        (clean_dir / "pricing.ts").write_text(
            "export function priceWithTax(x: number): number { return x * 1.1; }\n",
            encoding="utf-8",
        )
        (clean_dir / "checkout.ts").write_text(
            "import { priceWithTax } from './pricing';\nexport function run(x: number) { return priceWithTax(x); }\n",
            encoding="utf-8",
        )
        out_ok, err_ok = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out_ok), contextlib.redirect_stderr(err_ok):
            rc_ok = code_map.main(["callers", "priceWithTax", str(clean_dir), "--json"])
        self.assertEqual(rc_ok, 0, err_ok.getvalue())
        self.assertEqual(len(json.loads(out_ok.getvalue())), 1)


class TestFableW4AuditRegressionsW1(unittest.TestCase):
    """W4 independent-auditor confirmed defect regressions for W1 runtime/sensor seams."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="agy_w4_w1_"))
        self.home = self.root / "home"
        self.cfg_dir = self.home / ".gemini" / "config"
        self.state_dir = self.root / "state"
        self.ws_dir = self.root / "ws"
        for d in (self.cfg_dir, self.state_dir, self.ws_dir):
            d.mkdir(parents=True, exist_ok=True)
        (self.cfg_dir / "GEMINI.md").write_text("# Hermetic Constitution\n", encoding="utf-8")
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "XDG_STATE_HOME": str(self.state_dir),
                "PLUMB_GUARD_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
                "PLUMB_GUARD_NOTIFY": "off",
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        hermetic.force_rmtree(self.root)

    def _init_git_repo(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        for cmd in (
            ["git", "init"],
            ["git", "config", "user.email", "test@example.com"],
            ["git", "config", "user.name", "Test"],
        ):
            subprocess.run(cmd, cwd=str(path), check=True, capture_output=True)

    def test_w4_sbv4_default_conv_committed_test_mutation_and_verify_invariants_clean_tree(self) -> None:
        repo = self.root / "git_default_conv"
        self._init_git_repo(repo)
        tdir = repo / "tests"
        tdir.mkdir()
        tfile = tdir / "test_calc.py"
        tfile.write_text("def test_price():\n    assert 100 == 100\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo), check=True, capture_output=True)

        # Trigger PreToolUse with omitted conversationId (routes to "default") to capture base_head
        agy_hooks.handle_pre_tool_use(
            {
                "workspacePath": str(repo),
                "toolCall": {"name": "edit_file", "args": {"Path": "tests/test_calc.py"}},
            }
        )
        # Mutate expected value AND commit it so HEAD advances & working tree is clean
        tfile.write_text("def test_price():\n    assert 100 == 99\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "weaken"], cwd=str(repo), check=True, capture_output=True)

        # 1. Stop gate MUST still catch the committed weakening via session base_head even on "default" conv
        res = agy_hooks.handle_stop(
            {
                "workspacePath": str(repo),
                "terminationReason": "completed",
                "lastAssistantMessage": "Done.",
            }
        )
        self.assertEqual(res.get("decision"), "continue", res)
        self.assertIn("test_calc.py", res.get("reason", ""))
        self.assertIn("Rule 9", res.get("reason", ""))

        # 2. verify_invariants.py --diff MUST fail non-zero on clean-tree committed test weakening
        vi_proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "verify_invariants.py"), "--diff", "--root", str(repo)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(vi_proc.returncode, 0, vi_proc.stdout + vi_proc.stderr)
        self.assertIn("test_calc.py", vi_proc.stdout + vi_proc.stderr)

    def test_w4_sbv3_sfh1_non_git_stop2_shell_write_oversize_and_ansi_sanitization(self) -> None:
        from guard.hooks import stop_gate

        # 1. Non-git Stop #2 (after in_progress_blocked) and empty diffText must NOT silently pass
        ng = self.root / "non_git_repeat"
        ng.mkdir()
        bad_py = ng / "broken.py"
        bad_py.write_text("def oops(:\n    pass\n", encoding="utf-8")
        agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "ng-stop2",
                "workspacePath": str(ng),
                "toolCall": {"name": "write_file", "args": {"Path": "broken.py", "Content": "def oops(:\n"}},
            }
        )
        r1 = agy_hooks.handle_stop(
            {"conversationId": "ng-stop2", "workspacePath": str(ng), "diffText": "", "terminationReason": "completed"}
        )
        self.assertEqual(r1.get("decision"), "continue", r1)
        r2 = agy_hooks.handle_stop(
            {"conversationId": "ng-stop2", "workspacePath": str(ng), "diffText": "", "terminationReason": "completed"}
        )
        self.assertEqual(r2.get("decision"), "continue", r2)
        self.assertIn("Malformed Python syntax", r2.get("reason", ""))

        # 2. Non-git shell write (no edit_file) triggers bounded workspace walk
        ng_sh = self.root / "non_git_shell"
        ng_sh.mkdir()
        (ng_sh / "bad.json").write_text('{"k": }\n', encoding="utf-8")
        agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "ng-shell",
                "workspacePath": str(ng_sh),
                "toolCall": {"name": "run_command", "args": {"CommandLine": "printf '{\"k\": }\n' > bad.json"}},
            }
        )
        r_sh = agy_hooks.handle_stop({"conversationId": "ng-shell", "workspacePath": str(ng_sh), "terminationReason": "completed"})
        self.assertEqual(r_sh.get("decision"), "continue", r_sh)
        self.assertIn("Malformed JSON syntax", r_sh.get("reason", ""))

        # 3. Oversized (>256 KiB) touched file in non-git fails closed instead of silently skipping
        ng_big = self.root / "non_git_big"
        ng_big.mkdir()
        (ng_big / "huge.py").write_text("# " + ("x" * (270 * 1024)) + "\n", encoding="utf-8")
        agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "ng-big",
                "workspacePath": str(ng_big),
                "toolCall": {"name": "write_file", "args": {"Path": "huge.py", "Content": "# big\n"}},
            }
        )
        r_big = agy_hooks.handle_stop({"conversationId": "ng-big", "workspacePath": str(ng_big), "terminationReason": "completed"})
        self.assertEqual(r_big.get("decision"), "continue", r_big)
        self.assertIn("huge.py", r_big.get("reason", ""))
        self.assertIn("exceeds", r_big.get("reason", "").lower())

        # 4. ANSI / OSC / bidi control sequences are stripped from operator strike-3 output
        cleaned = stop_gate._sanitize_operator_text("err \x1b[31mRED\x1b[0m \x1b]0;title\x07 \u202ebidi\nnext")
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\u202e", cleaned)
        self.assertIn("RED", cleaned)

    def test_w4_sfh4_sfh5_sfh12_code_map_flow_rust_go_c_callbacks_and_sol_gd_wgsl(self) -> None:
        # 1. .sol / .gd / .wgsl are flagged unsupported across callers and flow
        extra_dir = self.root / "extra_langs"
        extra_dir.mkdir()
        (extra_dir / "Vault.sol").write_text("contract Vault { function settle() public {} }\n", encoding="utf-8")
        (extra_dir / "player.gd").write_text("func settle(): pass\n", encoding="utf-8")
        (extra_dir / "shader.wgsl").write_text("fn settle() {}\n", encoding="utf-8")
        out_f, err_f = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out_f), contextlib.redirect_stderr(err_f):
            rc_f = code_map.main(["flow", "settle", str(extra_dir), "--json"])
        self.assertNotEqual(rc_f, 0)
        self.assertIn("INCOMPLETE", err_f.getvalue())
        self.assertIs(json.loads(out_f.getvalue()).get("complete"), False)

        # 2. Rust / Go / C non-call function pointer/callback references -> INCOMPLETE
        for label, fname, src in (
            ("rust", "lib.rs", "fn compute(x: i32) -> i32 { x }\nfn run(v: Vec<i32>) { let _ = v.into_iter().map(compute); }\n"),
            ("go", "main.go", "package main\nfunc compute(x int) int { return x }\nfunc run() { register(compute) }\n"),
            ("c", "main.c", "int compute(int x) { return x; }\nvoid run(void) { register_cb(compute); }\n"),
        ):
            with self.subTest(lang=label):
                d = self.root / f"cb_{label}"
                d.mkdir()
                (d / fname).write_text(src, encoding="utf-8")
                res = code_map.find_callers("compute", [d], base_dir=d)
                self.assertFalse(res.complete, (label, res))
                self.assertTrue(res.non_call_references, (label, res))

        # 3. Python direct-call negative control remains complete=True & rc=0
        py_ok = self.root / "py_direct_ok"
        py_ok.mkdir()
        (py_ok / "mod.py").write_text("def compute(x):\n    return x + 1\ndef run():\n    return compute(2)\n", encoding="utf-8")
        out_p, err_p = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out_p), contextlib.redirect_stderr(err_p):
            rc_p = code_map.main(["callers", "compute", str(py_ok), "--json"])
        self.assertEqual(rc_p, 0, err_p.getvalue())

    def test_w4_sfh8_sfh9_sga11_large_transcript_widening_inv_gt1_prompt_and_fast_midturn(self) -> None:
        from guard.hooks import common as h_common

        # 1. Single >128 KiB USER_INPUT line is found via 2 MiB tail widening
        big_tx = self.root / "big_user_input.jsonl"
        big_tx.write_text(
            json.dumps({"step_index": 7, "type": "USER_INPUT", "content": "x" * 160_000}) + "\n",
            encoding="utf-8",
        )
        latest_txt, resolved_step, is_mid, has_tx, ends_user = h_common._inspect_transcript_turn_state_ex(
            {"transcriptPath": str(big_tx)}
        )
        self.assertTrue(has_tx)
        self.assertTrue(ends_user)
        self.assertFalse(is_mid)
        self.assertEqual(resolved_step, 7)
        self.assertTrue(latest_txt.startswith("xxxx"))

        # 2. inv_num > 1 with USER_INPUT-tail transcript or missing transcript must NOT silently fast-noop
        self.assertFalse(
            agy_hooks._is_fast_pre_invocation_noop(
                {"invocationNum": 3, "prompt": "Bu projeyi hızlandır", "transcriptPath": str(big_tx)}
            )
        )
        self.assertFalse(
            agy_hooks._is_fast_pre_invocation_noop(
                {"invocationNum": 3, "prompt": "Bu projeyi hızlandır"}
            )
        )

        # 3. >1.5 MiB mid-turn transcript (with non-user tail entries) stays on fast noop path
        mid_tx = self.root / "mid_1500k.jsonl"
        with mid_tx.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps({"step_index": 1, "type": "USER_INPUT", "content": "start"}) + "\n")
            filler = json.dumps({"step_index": 2, "type": "TOOL_RESULT", "content": "y" * 1500}) + "\n"
            for _ in range(1100):
                fh.write(filler)
        self.assertGreater(mid_tx.stat().st_size, 1_500_000)
        self.assertTrue(
            agy_hooks._is_fast_pre_invocation_noop(
                {"invocationNum": 4, "transcriptPath": str(mid_tx)}
            )
        )

    def test_w4_sfh14_taa12_media_qc_hardening_and_toml_fallback_edge_cases(self) -> None:
        import importlib.util
        import test_adr0014_predictive_handoff_rust_decisions_procoder as adr14_tests

        mq_path = REPO_ROOT / "skills" / "media-studio" / "scripts" / "media_qc.py"
        spec = importlib.util.spec_from_file_location("media_qc_w4_test", mq_path)
        assert spec is not None and spec.loader is not None
        media_qc = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = media_qc
        spec.loader.exec_module(media_qc)

        # 1. Non-positive timeout raises ValueError
        with self.assertRaises(ValueError):
            media_qc._run_media_subprocess(["ffmpeg", "-version"], timeout=0)

        # 2. Transient non-zero ffmpeg -version must NOT poison cache (next call sees 4.4.2 -> False)
        media_qc._FFMPEG_VERSION_CACHE.clear()
        calls = [
            subprocess.CompletedProcess(["ffmpeg", "-version"], 1, "", "busy"),
            subprocess.CompletedProcess(["ffmpeg", "-version"], 0, "ffmpeg version 4.4.2 Copyright\n", ""),
        ]
        with mock.patch.object(media_qc, "_run_media_subprocess", side_effect=calls):
            self.assertTrue(media_qc._ffmpeg_supports_fps_mode("/usr/bin/fake-ffmpeg"))
            self.assertFalse(media_qc._ffmpeg_supports_fps_mode("/usr/bin/fake-ffmpeg"))

        # 3. TOML fallback rejects duplicate keys and malformed quotes/arrays
        for bad_toml in (
            '[pkg]\nname = "a"\nname = "b"\n',
            '[pkg]\nname = "unterminated\n',
            '[pkg]\nitems = [1, 2\n',
        ):
            with self.subTest(bad_toml=bad_toml):
                with self.assertRaises(ValueError):
                    adr14_tests._parse_toml_stdlib_fallback(bad_toml)


if __name__ == "__main__":
    unittest.main()
