"""
tests/test_w2_remediation.py — Window 2/2 seam regression suite covering Pass 2A & Pass 2B.
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)
from hermetic import force_rmtree

import argparse
import contextlib
import io
import json
import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestArchiveHardeningW2(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-w2-arch-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_inspect_zip_analyzes_dotfiles_and_yaml_and_flags_scripts_and_unknown_members(self) -> None:
        from porter.archive import inspect_zip

        class RecordingAnalyzer:
            def __init__(self) -> None:
                self.seen: list[str] = []

            def analyze(self, content: str, source_identifier: str = ""):
                from porter.models import SuitabilityReport

                self.seen.append(source_identifier)
                return SuitabilityReport(
                    source=source_identifier,
                    is_safe_to_import=True,
                    constitutional_score=100,
                    recommended_type="rule",
                    issues=[],
                    sanitized_content=content,
                )

        zpath = self.tmp / "mixed.zip"
        with zipfile.ZipFile(zpath, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(".cursorrules", "# Clean rule\nRun checks before committing.\n")
            zf.writestr(".windsurfrules", "# Windsurf rule\nVerify types.\n")
            zf.writestr(".clinerules", "# Cline rule\nVerify lint.\n")
            zf.writestr(".aider.conf.yml", "auto-commits: false\n")
            zf.writestr("config.toml", 'mode = "strict"\n')
            zf.writestr("assets/logo.png", b"\x89PNG\r\n\x1a\n")
            zf.writestr("hooks/install.sh", "#!/bin/sh\necho pwned\n")
            zf.writestr("mystery.dat", b"\x00\x01\x02\x03")

        rec = RecordingAnalyzer()
        report = inspect_zip(zpath, harness_root=REPO_ROOT, analyzer=rec)
        self.assertFalse(report.is_safe)
        analyzed_names = {s.split("!", 1)[1] for s in rec.seen}
        self.assertEqual(
            analyzed_names,
            {".cursorrules", ".windsurfrules", ".clinerules", ".aider.conf.yml", "config.toml"},
        )
        hazard_by_member = {(h.member, h.kind) for h in report.hazards}
        self.assertIn(("hooks/install.sh", "EXECUTABLE_MEMBER"), hazard_by_member)
        self.assertIn(("mystery.dat", "UNANALYZED_MEMBER"), hazard_by_member)
        self.assertFalse(any(h.member == "assets/logo.png" for h in report.hazards))

    def test_inspect_zip_detects_spoofed_header_decompressed_size_bomb(self) -> None:
        from porter.archive import inspect_zip

        zpath = self.tmp / "spoofed.zip"
        payload = b"A" * (128 * 1024)  # compresses tiny; we spoof declared size to 16 bytes
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("logo.png", payload)
        raw = bytearray(buf.getvalue())

        # Patch uncompressed size (4 bytes at offset +22 in local header PK\x03\x04 and +24 in central dir PK\x01\x02)
        lh = raw.find(b"PK\x03\x04")
        cd = raw.find(b"PK\x01\x02")
        self.assertGreaterEqual(lh, 0)
        self.assertGreaterEqual(cd, 0)
        raw[lh + 22 : lh + 26] = struct.pack("<I", 16)
        raw[cd + 24 : cd + 28] = struct.pack("<I", 16)
        zpath.write_bytes(bytes(raw))

        report = inspect_zip(zpath, harness_root=REPO_ROOT)
        self.assertFalse(report.is_safe)
        kinds = {h.kind for h in report.hazards}
        self.assertTrue(
            kinds & {"COMPRESSION_RATIO", "DECOMPRESSED_MISMATCH", "UNREADABLE_MEMBER"},
            f"Expected spoofed stream hazard, got: {report.hazards}",
        )


class TestPackagingParityW2(unittest.TestCase):
    def test_pkgbuild_and_binary_linux_packager_include_porter_hooks_manifest_and_completions(self) -> None:
        from installers.packaging.package_linux import LinuxPackager

        pkgbuild = (REPO_ROOT / "installers" / "packaging" / "PKGBUILD").read_text(encoding="utf-8")
        for token in (
            "porter.py",
            "agy-porter",
            "hooks.json",
            ".harness/manifest.json",
            "bash-completion/completions/agy-guard",
        ):
            self.assertIn(token, pkgbuild, f"PKGBUILD missing {token}")

        with tempfile.TemporaryDirectory(prefix="agy-w2-pkg-") as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "agy-guard-bin"
            fake_bin.write_bytes(b"\x7fELFfakebinary")
            fake_bin.chmod(0o755)
            stage = tmp_path / "stage"

            packager = LinuxPackager(
                repo_root=REPO_ROOT,
                version="2.0.0",
                arch="x86_64",
                out_dir=tmp_path / "dist",
                binary_path=fake_bin,
            )
            packager.prepare_payload(stage)

            self.assertTrue((stage / "usr" / "bin" / "agy-guard").is_file())
            self.assertTrue((stage / "usr" / "bin" / "agy-porter").is_file())
            self.assertTrue(os.access(stage / "usr" / "bin" / "agy-porter", os.X_OK))
            self.assertTrue((stage / "usr" / "lib" / "antigravity-guard" / "porter.py").is_file())
            self.assertTrue((stage / "usr" / "lib" / "antigravity-guard" / "porter").is_dir())
            self.assertTrue((stage / "usr" / "share" / "antigravity-harness" / "hooks.json").is_file())
            self.assertTrue((stage / "usr" / "share" / "antigravity-harness" / ".harness" / "manifest.json").is_file())
            self.assertTrue((stage / "usr" / "share" / "bash-completion" / "completions" / "agy-guard").is_file())


class TestCodeMapResilienceW2(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-w2-cm-")
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_code_map_surfaces_parse_and_encoding_errors_and_never_exits_zero_tier1(self) -> None:
        from scripts.code_map import compute_blast_radius, main, profile_symbol, trace_data_flow

        (self.root / "core.py").write_text("def target_fn(x: int) -> int:\n    return x + 1\n", encoding="utf-8")
        # Broken caller with SyntaxError
        (self.root / "broken_caller.py").write_text("def caller(:\n    return target_fn(1)\n", encoding="utf-8")
        # Non-UTF8 Python file (UnicodeDecodeError) and null-byte Python file (ValueError)
        (self.root / "latin1_bad.py").write_bytes(b"def bad():\n    return '\xff\xfe'\n")
        (self.root / "nul_bad.py").write_bytes(b"x = 1\x00\n")

        blast = compute_blast_radius("target_fn", [self.root], base_dir=self.root)
        self.assertGreaterEqual(len(blast.get("parse_errors", [])), 3)
        self.assertNotEqual(blast["tier_recommendation"], "Tier 1")

        prof = profile_symbol("target_fn", [self.root], base_dir=self.root)
        self.assertGreaterEqual(len(prof.get("parse_errors", [])), 3)

        flow = trace_data_flow("target_fn", [self.root], base_dir=self.root)
        self.assertGreaterEqual(len(flow.get("parse_errors", [])), 3)

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            rc = main(["blast-radius", "target_fn", str(self.root), "--json"])
        self.assertNotEqual(rc, 0, "blast-radius CLI must not exit 0 when callers failed to parse")
        self.assertIn("broken_caller.py", err_buf.getvalue())
        parsed_blast = json.loads(out_buf.getvalue())
        self.assertIs(parsed_blast.get("complete"), False)
        self.assertGreaterEqual(len(parsed_blast.get("parse_errors", [])), 3)


class TestDiagnosticsAndWatchdogHardeningW2(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-w2-diag-")
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_doctor_and_upstream_monitor_surface_corrupt_json_files(self) -> None:
        from guard.doctor import diagnose
        from guard.environment import EnvironmentRegistry
        from guard.paths import state_dir
        from guard.upstream import UpstreamMonitor

        cfg_root = self.root / "cfg"
        (cfg_root / "skills").mkdir(parents=True)
        (cfg_root / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")
        (cfg_root / "config.json").write_text("{corrupt-config", encoding="utf-8")

        st_dir = self.root / "state"
        st_dir.mkdir(parents=True)
        (st_dir / "hook_strikes.json").write_text("{bad-strikes", encoding="utf-8")
        (st_dir / "install_receipt.json").write_text("{bad-receipt", encoding="utf-8")
        (st_dir / "upstream_state.json").write_text("{bad-upstream", encoding="utf-8")

        with mock.patch.dict(
            os.environ,
            {
                "AGY_GUARD_STATE_DIR": str(st_dir),
                "ANTIGRAVITY_CONFIG_DIR": str(cfg_root),
                "UPSTREAM_STATE_FILE": str(st_dir / "upstream_state.json"),
            },
        ):
            self.assertEqual(state_dir(), st_dir)
            reg = EnvironmentRegistry(config_path=st_dir / "environments.json")
            env = next(e for e in reg.list_environments() if e.is_global)
            report = diagnose(env, reg, sentinel_active=True)
            joined = "\n".join(report.warnings)
            self.assertIn("hook_strikes.json", joined)
            self.assertIn("install_receipt.json", joined)
            self.assertIn("upstream_state.json", joined)
            self.assertIn("config.json", joined)

            mon = UpstreamMonitor(target_dir=cfg_root)
            summary = mon.get_summary()
            self.assertIn(summary["status"], ("WARN", "FAIL"))
            self.assertTrue(summary["state_corrupt"])

    def test_upstream_watcher_does_not_advance_last_checked_iso_or_exit_zero_on_http_403_429(self) -> None:
        import importlib.util

        cfg_root = self.root / "cfg"
        (cfg_root / "skills" / "upstream-auditor").mkdir(parents=True)
        seed_path = cfg_root / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        seed_data = {
            "last_audited_model": "Gemini 4 Argon (High)",
            "last_checked_iso": "2026-10-01T00:00:00+00:00",
            "last_skills_audit_timestamp": "2020-01-01T00:00:00+00:00",
            "skills_audit_interval_hours": 72,
            "tracked_repositories": {
                "repo-a": {"repo": "owner/repo-a", "branch": "main", "last_synced_commit": "aaaaaaa"},
            },
        }
        seed_path.write_text(json.dumps(seed_data), encoding="utf-8")
        st_file = self.root / "state" / "upstream_state.json"
        st_file.parent.mkdir(parents=True)
        st_file.write_text(json.dumps(seed_data), encoding="utf-8")

        env = {
            "ANTIGRAVITY_CONFIG_DIR": str(cfg_root),
            "AGY_GUARD_STATE_DIR": str(self.root / "state"),
            "UPSTREAM_STATE_FILE": str(st_file),
            "ANTIGRAVITY_BUILTIN_SKILLS_DIR": str(self.root / "builtin"),
            "AGY_GUARD_NOTIFY": "0",
        }
        with mock.patch.dict(os.environ, env):
            spec = importlib.util.spec_from_file_location(
                "w2_upstream_watcher",
                REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py",
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            def rate_limited(req, timeout=None):
                raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", hdrs=None, fp=None)

            state, _ = mod.load_state(write=True)
            with mock.patch("urllib.request.urlopen", side_effect=rate_limited):
                mod.check_tracked_skills(state)

            saved = json.loads(st_file.read_text(encoding="utf-8"))
            self.assertTrue(saved["last_audit_failed"])
            self.assertEqual(saved.get("last_checked_iso"), "2026-10-01T00:00:00+00:00")

            status_buf = io.StringIO()
            with redirect_stdout(status_buf):
                rc = mod.cmd_status()
            self.assertNotEqual(rc, 0)
            self.assertNotIn("No upstream changes detected", status_buf.getvalue())

    @unittest.skipIf(os.name == "nt", "POSIX bash check_skills.sh test")
    def test_check_skills_sh_exits_nonzero_on_invalid_or_unreachable_repo(self) -> None:
        bad_state = self.root / "bad_upstream.json"
        bad_state.write_text(
            json.dumps(
                {
                    "tracked_repositories": {
                        "broken-repo": {"repo": "not a valid repo", "branch": "main", "last_synced_commit": "1234567"}
                    }
                }
            ),
            encoding="utf-8",
        )
        env = dict(os.environ)
        env["UPSTREAM_STATE_FILE"] = str(bad_state)
        res = subprocess.run(
            ["bash", str(REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "check_skills.sh")],
            env=env,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=15,
        )
        self.assertNotEqual(res.returncode, 0, f"check_skills.sh must fail on errors:\n{res.stdout}\n{res.stderr}")
        self.assertNotIn("[OK] All external skill repositories are synchronized", res.stdout)


class TestTlsHandshakeDeadlineW2(unittest.TestCase):
    def test_pinned_https_connection_applies_remaining_deadline_before_wrap_socket(self) -> None:
        from porter.net import FetchDeadlineExceeded, _PinnedHTTPSConnection

        seen_timeouts: list[float | None] = []

        class FakeRawSocket:
            def __init__(self) -> None:
                self._agy_per_op = 10.0
                self._agy_deadline = None
                self.closed = False
                self.timeout: float | None = 10.0

            def settimeout(self, val: float | None) -> None:
                self.timeout = val

            def close(self) -> None:
                self.closed = True

        class StallingContext:
            def wrap_socket(self, sock: FakeRawSocket, server_hostname: str = ""):
                seen_timeouts.append(sock.timeout)
                raise socket.timeout("TLS handshake timed out")

        fake_raw = FakeRawSocket()
        deadline = time.monotonic() + 0.25
        conn = _PinnedHTTPSConnection("example.com", 443, timeout=10.0, agy_deadline=deadline, context=StallingContext())
        with mock.patch("porter.net._pinned_socket", return_value=fake_raw):
            with self.assertRaises(FetchDeadlineExceeded):
                conn.connect()
        self.assertEqual(len(seen_timeouts), 1)
        self.assertIsNotNone(seen_timeouts[0])
        self.assertLessEqual(seen_timeouts[0], 0.3)
        self.assertTrue(fake_raw.closed, "raw socket must be closed when wrap_socket fails/times out")


class TestMetaAuditExpansionW2(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-w2-meta-")
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_meta_audit_flags_v1_tools_read_exec_stale_xdg_paths_and_packaging_drift(self) -> None:
        import re as _re
        from scripts.meta_audit import MetaAuditEngine

        (self.root / "agents").mkdir(parents=True)
        (self.root / "agents" / "bad-agent.md").write_text(
            "---\nname: bad-agent\ndescription: Bad agent.\naccess: read-exec\n---\n"
            "Inspect files with `view_file` and `grep_search`.\n",
            encoding="utf-8",
        )
        (self.root / "skills" / "demo").mkdir(parents=True)
        (self.root / "skills" / "demo" / "SKILL.md").write_text(
            "---\nname: demo\ndescription: Demo skill. Invoke with /demo. Not for other tasks.\n---\n"
            "Run `python3 ~/.local/share/antigravity-guard/runtime/scripts/code_map.py`.\n",
            encoding="utf-8",
        )
        (self.root / "installers" / "packaging").mkdir(parents=True)
        (self.root / "installers" / "packaging" / "PKGBUILD").write_text(
            "pkgname=antigravity-guard\npackage() { cp guard.py \"$pkgdir/\"; }\n",
            encoding="utf-8",
        )
        (self.root / "README.md").write_text("# Demo\n", encoding="utf-8")
        (self.root / "guard").mkdir(parents=True)
        (self.root / "guard" / "cli.py").write_text(
            "import argparse\ndef build_parser():\n"
            "    p = argparse.ArgumentParser()\n"
            "    p.add_subparsers(dest='cmd')\n"
            "    return p\n",
            encoding="utf-8",
        )
        (self.root / "guard" / "environment.py").write_text("VALID_POLICIES = ('enforced',)\n", encoding="utf-8")
        (self.root / "guard" / "agy_hooks.py").write_text(
            "import re\nSKILL_HINTS = (\n"
            "    ('demo', 'skills/demo/SKILL.md', re.compile(r'/other-cmd\\b'), 'demo'),\n"
            ")\n",
            encoding="utf-8",
        )
        _ = _re  # keep import explicit

        eng = MetaAuditEngine(repo_root=self.root)
        eng.pass1_schema_validation()
        eng.pass2_cross_references()
        eng.pass5_cli_doc_sync()
        eng.pass7_trigger_specificity()

        msgs = "\n".join(f.message for f in eng.findings)
        self.assertIn("read-exec", msgs)
        self.assertIn("view_file", msgs)
        self.assertIn("antigravity-guard", msgs)
        self.assertIn("PKGBUILD is missing required packaging artifact", msgs)
        self.assertIn("Positive frontmatter slash trigger `/demo`", msgs)


class TestContractAuditorRemediationsW2(unittest.TestCase):
    """Regression tests for contract-change-auditor findings in Pass 2C."""

    def test_install_preserves_custom_entries_on_first_install_and_target_mismatch(self):
        import install as install_mod

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            st_dir = root / "state"
            st_dir.mkdir(parents=True)

            # Case 1: First-time install (no install_receipt.json) must keep user custom entries.
            cfg1 = root / "cfg1"
            (cfg1 / "skills" / "custom-user-skill").mkdir(parents=True)
            (cfg1 / "skills" / "custom-user-skill" / "SKILL.md").write_text("# Custom\n", encoding="utf-8")
            (cfg1 / "agents").mkdir(parents=True)
            (cfg1 / "agents" / "custom-agent.md").write_text("# Agent\n", encoding="utf-8")
            (cfg1 / "templates").mkdir(parents=True)
            (cfg1 / "templates" / "CUSTOM.template.md").write_text("# Template\n", encoding="utf-8")

            with mock.patch.object(install_mod, "state_dir", return_value=st_dir):
                inst1 = install_mod.Installer(target_dir=cfg1, mode="copy")
                inst1.log = lambda *_a, **_kw: None
                inst1.install_governance()

            self.assertTrue((cfg1 / "skills" / "custom-user-skill" / "SKILL.md").is_file())
            self.assertTrue((cfg1 / "agents" / "custom-agent.md").is_file())
            self.assertTrue((cfg1 / "templates" / "CUSTOM.template.md").is_file())

            # Case 2: Receipt targeting cfg1 must NOT prune entries when installing to cfg2.
            (st_dir / "install_receipt.json").write_text(
                json.dumps({"target": str(cfg1), "installed": ["skills/retired-skill"]}),
                encoding="utf-8",
            )
            cfg2 = root / "cfg2"
            (cfg2 / "skills" / "retired-skill").mkdir(parents=True)
            (cfg2 / "skills" / "retired-skill" / "SKILL.md").write_text("# Keep in cfg2\n", encoding="utf-8")

            with mock.patch.object(install_mod, "state_dir", return_value=st_dir):
                inst2 = install_mod.Installer(target_dir=cfg2, mode="copy")
                inst2.log = lambda *_a, **_kw: None
                inst2.install_governance()

            self.assertTrue((cfg2 / "skills" / "retired-skill" / "SKILL.md").is_file())

    def test_acknowledge_drift_prefers_last_seen_model_over_pbtxt_placeholder_and_expands_tilde(self):
        import importlib.util
        from guard.upstream import UpstreamAuditorBridge

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            cfg = home / ".gemini" / "config"
            (cfg / "skills").mkdir(parents=True)
            pbtxt_dir = home / ".gemini" / "antigravity"
            pbtxt_dir.mkdir(parents=True)
            pbtxt = pbtxt_dir / "antigravity_state.pbtxt"
            pbtxt.write_text('last_selected_agent_model: "MODEL_PLACEHOLDER_M37"\n', encoding="utf-8")
            builtin = home / "custom_builtin"
            (builtin / "demo-builtin").mkdir(parents=True)
            (builtin / "demo-builtin" / "SKILL.md").write_text("# Demo\n", encoding="utf-8")

            st_dir = home / "state"
            st_dir.mkdir(parents=True)
            state_file = st_dir / "upstream_state.json"
            state_file.write_text(
                json.dumps(
                    {
                        "last_seen_model": "Gemini 3.1 Pro (High)",
                        "last_audited_model": "Gemini 2.5 Pro",
                        "last_pbtxt_model": "OLD_MODEL",
                        "tracked_repositories": {},
                        "pending_repo_updates": {},
                    }
                ),
                encoding="utf-8",
            )

            env = {
                "HOME": str(home),
                "UPSTREAM_STATE_FILE": str(state_file),
                "ANTIGRAVITY_PBTXT_FILE": str(pbtxt),
                "ANTIGRAVITY_BUILTIN_SKILLS_DIR": "~/custom_builtin",
                "ANTIGRAVITY_MODEL": "",
            }
            with mock.patch.dict(os.environ, env, clear=False):
                bridge = UpstreamAuditorBridge(target_dir=cfg)
                ok, _msg = bridge.acknowledge_drift()
                self.assertTrue(ok)

                saved = json.loads(state_file.read_text(encoding="utf-8"))
                self.assertEqual(saved["last_audited_model"], "Gemini 3.1 Pro (High)")
                self.assertEqual(saved["recorded_builtin_skills"], ["demo-builtin"])

                watcher_path = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
                spec = importlib.util.spec_from_file_location("uw_ack_check", watcher_path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                reasons = mod.collect_reasons(saved, "Gemini 3.1 Pro (High)")
                self.assertEqual(mod.unacknowledged(saved, reasons), [])

    def test_linux_binary_package_includes_guard_lib_rewrites_hooks_and_falls_back_to_usr_share(self):
        from installers.packaging.package_linux import LinuxPackager

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_bin = root / "agy-guard-bin"
            fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_bin.chmod(0o755)
            stage = root / "stage"
            packager = LinuxPackager(
                repo_root=REPO_ROOT,
                version="2.0.0",
                arch="amd64",
                out_dir=root / "out",
                binary_path=fake_bin,
            )
            packager._prepare_payload(stage)

            self.assertTrue((stage / "usr" / "lib" / "antigravity-guard" / "guard" / "__init__.py").is_file())
            hooks_data = json.loads(
                (stage / "usr" / "share" / "antigravity-harness" / "hooks.json").read_text(encoding="utf-8")
            )
            hooks_blob = json.dumps(hooks_data)
            self.assertIn("/usr/share/antigravity-harness/skills/upstream-auditor/scripts/upstream_watcher.py", hooks_blob)
            self.assertIn("/usr/lib/antigravity-guard/guard/agy_hooks.py", hooks_blob)

            empty_cfg = root / "empty_cfg"
            empty_cfg.mkdir(parents=True)
            export_dir = root / "export_out"
            env = dict(os.environ)
            env["ANTIGRAVITY_CONFIG_DIR"] = str(empty_cfg)
            res = subprocess.run(
                [
                    sys.executable,
                    str(stage / "usr" / "lib" / "antigravity-guard" / "porter.py"),
                    "export",
                    "--target",
                    "claude",
                    "--out",
                    str(export_dir),
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            self.assertGreaterEqual(len(list((export_dir / ".claude" / "skills").iterdir())), 30)


class TestSliceAPorterArchiveSymlinkAndNetW2(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-w2-slicea-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _spoof_zip_sizes(
        self,
        raw: bytes,
        *,
        declared_uncompressed: int | None = None,
        declared_compressed: int | None = None,
        central_only: bool = False,
    ) -> bytes:
        buf = bytearray(raw)
        lh = buf.find(b"PK\x03\x04")
        cd = buf.find(b"PK\x01\x02")
        self.assertGreaterEqual(lh, 0)
        self.assertGreaterEqual(cd, 0)
        if declared_compressed is not None:
            if not central_only:
                buf[lh + 18 : lh + 22] = struct.pack("<I", declared_compressed)
            buf[cd + 20 : cd + 24] = struct.pack("<I", declared_compressed)
        if declared_uncompressed is not None:
            if not central_only:
                buf[lh + 22 : lh + 26] = struct.pack("<I", declared_uncompressed)
            buf[cd + 24 : cd + 28] = struct.pack("<I", declared_uncompressed)
        return bytes(buf)

    def test_archive_stream_shebang_mismatch_budgets_magic_configs_utf8_and_zlib(self) -> None:
        import porter.archive as arch
        from porter.archive import inspect_zip

        # 1. Stream shebang (#! and UTF-8 BOM + #!) on non-executable suffix + executable configs + magic bytes + case dupes
        z1 = self.tmp / "shebang_and_magic.zip"
        with zipfile.ZipFile(z1, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("rules/hook.txt", "#!/bin/sh\necho hi\n")
            zf.writestr("rules/bom_hook.txt", b"\xef\xbb\xbf#!/bin/sh\necho hi\n")
            zf.writestr("assets/fake_elf.png", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
            zf.writestr("assets/fake_zip.png", b"PK\x03\x04" + b"\x00" * 32)
            zf.writestr("hooks.json", '{"hooks": {}}\n')
            zf.writestr(".github/workflows/ci.yml", "name: ci\n")
            zf.writestr("SKILL.md", "# Clean rule\nRun tests.\n")
            zf.writestr("skill.md", "# Clean rule\nRun tests.\n")
        r1 = inspect_zip(z1, harness_root=REPO_ROOT)
        self.assertFalse(r1.is_safe)
        pairs = {(h.member, h.kind) for h in r1.hazards}
        self.assertIn(("rules/hook.txt", "EXECUTABLE_MEMBER"), pairs)
        self.assertIn(("rules/bom_hook.txt", "EXECUTABLE_MEMBER"), pairs)
        self.assertIn(("assets/fake_elf.png", "EXECUTABLE_MEMBER"), pairs)
        self.assertIn(("assets/fake_zip.png", "NESTED_ARCHIVE"), pairs)
        self.assertIn(("hooks.json", "EXECUTABLE_CONFIG"), pairs)
        self.assertIn((".github/workflows/ci.yml", "EXECUTABLE_CONFIG"), pairs)
        self.assertIn(("skill.md", "DUPLICATE_NAME"), pairs)

        # 2. < 64 KB stream with spoofed upward file_size (4096 vs 1088 real bytes) -> exact DECOMPRESSED_MISMATCH
        b_mis = io.BytesIO()
        with zipfile.ZipFile(b_mis, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("notes.txt", b"Plain rule text.\n" * 64)
        z_mis = self.tmp / "mismatch.zip"
        z_mis.write_bytes(self._spoof_zip_sizes(b_mis.getvalue(), declared_uncompressed=4096))
        r_mis = inspect_zip(z_mis, harness_root=REPO_ROOT)
        self.assertFalse(r_mis.is_safe)
        self.assertIn(("notes.txt", "DECOMPRESSED_MISMATCH"), {(h.member, h.kind) for h in r_mis.hazards})

        # 3. Central-directory spoofed >64 KB stream (CD says 16 B, local header streams 128 KB) hitting MEMBER_TOO_LARGE & OVERSIZE
        b_big = io.BytesIO()
        with zipfile.ZipFile(b_big, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("huge.md", "".join(f"Rule line {i:05d}\n" for i in range(8000)).encode("utf-8"))
        z_big = self.tmp / "member_too_large.zip"
        z_big.write_bytes(self._spoof_zip_sizes(b_big.getvalue(), declared_uncompressed=16, central_only=True))
        with mock.patch.object(arch, "MAX_ANALYZED_MEMBER_BYTES", 16384):
            r_big = inspect_zip(z_big, harness_root=REPO_ROOT)
        self.assertIn(("huge.md", "MEMBER_TOO_LARGE"), {(h.member, h.kind) for h in r_big.hazards})

        with mock.patch.object(arch, "MAX_TOTAL_UNCOMPRESSED", 16384):
            r_over = inspect_zip(z_big, harness_root=REPO_ROOT)
        self.assertIn(("huge.md", "OVERSIZE"), {(h.member, h.kind) for h in r_over.hazards})

        # 4. Spoofed compress_size = 1_000_000 on 500 KB compressible member (~1 KB archive)
        b_comp = io.BytesIO()
        with zipfile.ZipFile(b_comp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("SKILL.md", b"A" * 500_000)
        z_comp = self.tmp / "spoofed_comp.zip"
        z_comp.write_bytes(
            self._spoof_zip_sizes(b_comp.getvalue(), declared_uncompressed=500_000, declared_compressed=1_000_000)
        )
        r_comp = inspect_zip(z_comp, harness_root=REPO_ROOT)
        self.assertFalse(r_comp.is_safe)

        # 5. Invalid UTF-8 & embedded NUL in .md + truncated deflate stream (zlib.error)
        z_bad_utf = self.tmp / "bad_utf8.zip"
        with zipfile.ZipFile(z_bad_utf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("corrupt.md", b"\xff\xfe\x00\x81")
        r_utf = inspect_zip(z_bad_utf, harness_root=REPO_ROOT)
        self.assertFalse(r_utf.is_safe)
        self.assertIn(("corrupt.md", "BINARY_OR_INVALID_UTF8"), {(h.member, h.kind) for h in r_utf.hazards})

        b_zlib = io.BytesIO()
        with zipfile.ZipFile(b_zlib, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("broken.md", ("# Clean rule\n" * 200).encode("utf-8"))
        raw_zlib = bytearray(b_zlib.getvalue())
        lh_z = raw_zlib.find(b"PK\x03\x04")
        fname_len = struct.unpack_from("<H", raw_zlib, lh_z + 26)[0]
        extra_len = struct.unpack_from("<H", raw_zlib, lh_z + 28)[0]
        data_start = lh_z + 30 + fname_len + extra_len
        raw_zlib[data_start : data_start + 8] = b"\xff\xff\xff\xff\xff\xff\xff\xff"
        z_zlib = self.tmp / "bad_deflate.zip"
        z_zlib.write_bytes(bytes(raw_zlib))
        r_zlib = inspect_zip(z_zlib, harness_root=REPO_ROOT)
        self.assertFalse(r_zlib.is_safe)
        self.assertIn(("broken.md", "UNREADABLE_MEMBER"), {(h.member, h.kind) for h in r_zlib.hazards})

    @unittest.skipIf(os.name == "nt", "POSIX symlink test")
    def test_porter_import_and_bridge_reject_intra_tree_symlinks(self) -> None:
        import argparse
        import importlib.util
        from guard.porter_bridge import PorterBridge

        spec = importlib.util.spec_from_file_location("_porter_cli_mod", REPO_ROOT / "porter.py")
        assert spec and spec.loader
        porter_cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(porter_cli)

        root = self.tmp / "harness"
        victim = root / "skills" / "victim"
        victim.mkdir(parents=True)
        (root / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")
        (victim / "SKILL.md").write_text("ORIGINAL_VICTIM\n", encoding="utf-8")
        (root / "skills" / "alias").symlink_to(victim)

        src = self.tmp / "safe.md"
        src.write_text("# Safe Imported Skill\nAlways run unit tests and type checks before delivery.\n", encoding="utf-8")

        with mock.patch.object(porter_cli, "_harness_root", return_value=root):
            rc = porter_cli.cmd_import(
                argparse.Namespace(
                    target=str(src),
                    as_skill="alias",
                    as_agent=None,
                    force=False,
                    overwrite=True,
                    dry_run=False,
                )
            )
        self.assertEqual(rc, 1)
        self.assertEqual((victim / "SKILL.md").read_text(encoding="utf-8"), "ORIGINAL_VICTIM\n")

        # PorterBridge: symlinked `skills` parent directory must also be refused before resolve()
        cfg = self.tmp / "live_cfg"
        cfg.mkdir(parents=True)
        (cfg / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")
        real_skills = self.tmp / "elsewhere_skills"
        real_skills.mkdir(parents=True)
        (cfg / "skills").symlink_to(real_skills)
        bridge = PorterBridge(target_dir=cfg)
        ok, msg = bridge.stage_and_ingest(str(src), target_name="new-skill")
        self.assertFalse(ok)
        self.assertIn("symlink", msg.lower())

    def test_safe_fetch_url_closes_sockets_on_blocked_redirect_and_http_error(self) -> None:
        import gc
        import http.server
        import threading
        import warnings
        from porter import net

        class _ErrAndRedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redir":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:9/internal")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    body = b"boom"
                    self.send_response(500)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ErrAndRedirectHandler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]

        orig_allowed = net._address_allowed

        def allow_initial_only(ip_obj):
            # Allow connecting to our test server when validate_safe_url checks port-agnostic IP only on first hop:
            return orig_allowed(ip_obj)

        unraisables: list[object] = []
        old_hook = sys.unraisablehook
        sys.unraisablehook = lambda args: unraisables.append(args)
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", ResourceWarning)
                # 1. Blocked redirect: allow first validate_safe_url + _pinned_socket, deny second validate_safe_url
                calls = {"n": 0}

                def validate_first_then_block(u: str) -> None:
                    calls["n"] += 1
                    if calls["n"] >= 2:
                        raise ValueError("blocked redirect target")

                with (
                    mock.patch.object(net, "_address_allowed", return_value=True),
                    mock.patch.object(net, "validate_safe_url", side_effect=validate_first_then_block),
                ):
                    with self.assertRaises(ValueError):
                        net.safe_fetch_url(f"http://127.0.0.1:{port}/redir", timeout=2.0)

                # 2. HTTP 500 error
                with mock.patch.object(net, "_address_allowed", return_value=True):
                    with self.assertRaises(urllib.error.HTTPError) as ctx:
                        net.safe_fetch_url(f"http://127.0.0.1:{port}/err500", timeout=2.0)
                    self.assertEqual(ctx.exception.code, 500)
                del ctx
                gc.collect()
                gc.collect()
            res_warns = [w for w in caught if issubclass(w.category, ResourceWarning)]
            self.assertEqual(res_warns, [], f"Leaked socket ResourceWarning: {res_warns}")
            self.assertEqual(unraisables, [], f"Unraisable socket warning: {unraisables}")
        finally:
            sys.unraisablehook = old_hook


class TestSliceBHooksWorkflowAndProtectionW2(unittest.TestCase):
    """W2 Pass 2C Slice B: PreToolUse, Workflow Sandbox, SKILL_HINTS, Stop Scanners & Protection."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy-w2-sliceb-"))

    def tearDown(self) -> None:
        force_rmtree(self.tmp)

    def test_pre_tool_use_empty_quotes_backticks_comments_admin_flags_and_snapshot_approval(self) -> None:
        from guard import cli as guard_cli
        from guard.agy_hooks import handle_pre_tool_use

        denied_cmds = [
            'agy-""guard unlock',
            "agy-''guard unlock",
            'python3 in""stall.py',
            'rm -rf ~/.gemini/""config/GEMINI.md',
            'git commit --no-""verify',
            "`agy-guard unlock`",
            "agy-guard test-boundary --output /tmp/forged.json snapshot",
            "env -i agy-guard unlock",
            "agy-guard provenance generate --authorize tests/test_x.py",
            "python3 install.py # --dry-run",
        ]
        for cmd in denied_cmds:
            res = handle_pre_tool_use({"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}})
            self.assertEqual(res.get("decision"), "deny", f"Expected deny for {cmd!r}, got {res}")

        res_reset = handle_pre_tool_use(
            {"toolCall": {"name": "run_command", "args": {"CommandLine": 'git reset --""hard'}}}
        )
        self.assertEqual(res_reset.get("decision"), "force_ask")

        ws = self.tmp / "ws"
        ws.mkdir()
        out_snap = self.tmp / "new_boundary_snap.json"
        ns = argparse.Namespace(dir=str(ws), action="snapshot", output=str(out_snap))
        with (
            mock.patch.object(guard_cli, "request_approval", return_value=False) as m_app,
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            rc = guard_cli.cmd_test_boundary(ns)
        m_app.assert_called_once()
        self.assertNotEqual(rc, 0)
        self.assertFalse(out_snap.exists())

    def test_authorized_test_section_parser_parity_workflow_and_shell_tasks_md(self) -> None:
        from guard.agy_hooks import _has_authorized_test_modifications, handle_pre_tool_use

        ws = self.tmp / "ws_auth"
        ws.mkdir()
        tasks_p = ws / "tasks.md"
        tasks_p.write_text("# Tasks\n\n- [ ] Item 1\n", encoding="utf-8")

        for body in (
            "## Authorized  Test Modifications\n- tests/test_a.py: contract update\n",
            "  ### Authorized Test Modifications\n- tests/test_a.py: contract update\n",
            "## Authorized Test Modifications\nNone\n\n## Authorized Test Modifications\n- tests/test_a.py: second\n",
        ):
            res = handle_pre_tool_use(
                {
                    "cwd": str(ws),
                    "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(tasks_p), "CodeContent": body}},
                }
            )
            self.assertEqual(res.get("decision"), "force_ask", f"Expected force_ask on heading variant: {body!r}")

        wf_res = handle_pre_tool_use(
            {
                "cwd": str(ws),
                "model": "gemini-3.1-pro-high",
                "effort": "high",
                "toolCall": {
                    "name": "run_workflow",
                    "args": {
                        "Script": (
                            'call_tool("write_file", Path="tasks.md", '
                            'Content="## Authorized Test Modifications\\n- tests/test_a.py: reason\\n")'
                        )
                    },
                },
            }
        )
        self.assertEqual(wf_res.get("decision"), "force_ask")

        sh_res = handle_pre_tool_use(
            {
                "cwd": str(ws),
                "toolCall": {"name": "run_command", "args": {"CommandLine": "cat payload.txt >> tasks.md"}},
            }
        )
        self.assertEqual(sh_res.get("decision"), "force_ask")

        ro_res = handle_pre_tool_use(
            {
                "cwd": str(ws),
                "toolCall": {"name": "run_command", "args": {"CommandLine": "grep -n DONE tasks.md"}},
            }
        )
        self.assertEqual(ro_res.get("decision"), "allow")
        self.assertFalse(_has_authorized_test_modifications(ws, "tests/test_a.py"))

    def test_porter_launcher_marker_and_command_governance_shield(self) -> None:
        from guard.agy_hooks import handle_pre_tool_use

        fake_home = self.tmp / "fake_home"
        bin_dir = fake_home / ".local" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        porter_bin = bin_dir / "porter"
        porter_bin.write_text('#!/bin/sh\n# antigravity-harness launcher\nexec python3 porter.py "$@"\n', encoding="utf-8")

        with mock.patch.dict(os.environ, {"HOME": str(fake_home), "USERPROFILE": str(fake_home)}):
            r_write = handle_pre_tool_use(
                {"toolCall": {"name": "write_to_file", "args": {"TargetFile": str(porter_bin), "CodeContent": "#!/bin/sh\n"}}}
            )
            r_cmd = handle_pre_tool_use(
                {
                    "toolCall": {
                        "name": "run_command",
                        "args": {"CommandLine": f"rm -f {porter_bin} && cp /bin/echo {porter_bin}"},
                    }
                }
            )
        self.assertEqual(r_write.get("decision"), "deny")
        self.assertEqual(r_cmd.get("decision"), "deny")

        # Pre-planting ~/.local/bin/porter when absent AND mutating /usr/bin/agy-guard are denied,
        # whereas an existing third-party CNCF porter binary without harness marker stays allowed.
        porter_bin.unlink()
        with mock.patch.dict(os.environ, {"HOME": str(fake_home), "USERPROFILE": str(fake_home)}):
            r_preplant = handle_pre_tool_use(
                {"toolCall": {"name": "write_to_file", "args": {"TargetFile": str(porter_bin), "CodeContent": "#!/bin/sh\n"}}}
            )
            r_usr_bin = handle_pre_tool_use(
                {"toolCall": {"name": "write_to_file", "args": {"TargetFile": "/usr/bin/agy-guard", "CodeContent": "#!/bin/sh\n"}}}
            )
        self.assertEqual(r_preplant.get("decision"), "deny")
        if os.name != "nt":
            self.assertEqual(r_usr_bin.get("decision"), "deny")
        porter_bin.write_text("#!/bin/sh\n# CNCF Porter v1.0\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"HOME": str(fake_home), "USERPROFILE": str(fake_home)}):
            r_cncf = handle_pre_tool_use(
                {"toolCall": {"name": "write_to_file", "args": {"TargetFile": str(porter_bin), "CodeContent": "#!/bin/sh\n"}}}
            )
        self.assertEqual(r_cncf.get("decision"), "allow")

    def test_workflow_invoke_subagent_namespaced_tools_and_startfile(self) -> None:
        from guard.agy_hooks import handle_pre_tool_use

        r_sub = handle_pre_tool_use(
            {
                "model": "gemini-2.5-flash",
                "toolCall": {
                    "name": "run_workflow",
                    "args": {
                        "Script": (
                            'call_tool("invoke_subagent", TypeName="self", Model="flash", '
                            'Prompt="Edit GEMINI.md and guard/agy_hooks.py")'
                        )
                    },
                },
            }
        )
        self.assertEqual(r_sub.get("decision"), "deny")

        r_ns_wf = handle_pre_tool_use(
            {
                "toolCall": {
                    "name": "run_workflow",
                    "args": {"Script": 'call_tool("default_api:run_command", CommandLine="agy-guard unlock")'},
                }
            }
        )
        self.assertEqual(r_ns_wf.get("decision"), "deny")

        r_ns_direct = handle_pre_tool_use(
            {"toolCall": {"name": "default_api:run_command", "args": {"CommandLine": "agy-guard unlock"}}}
        )
        self.assertEqual(r_ns_direct.get("decision"), "deny")

        for code in ('import os\nos.startfile("calc.exe")\n', 'from os import startfile\nstartfile("calc.exe")\n'):
            r_sf = handle_pre_tool_use({"toolCall": {"name": "run_workflow", "args": {"Script": code}}})
            self.assertEqual(r_sf.get("decision"), "deny", f"Expected startfile deny for {code!r}")

    def test_skill_hints_slash_boundaries_and_sweetspot_turkish_triggers(self) -> None:
        from guard.agy_hooks import handle_pre_invocation

        res_paths = handle_pre_invocation(
            {
                "conversationId": "w2-paths-conv",
                "prompt": (
                    "Read src/optimize/worker.py, apps/marathon/main.go, "
                    "pkg/test-design/runner.py, and skills/visualizer/SKILL.md."
                ),
            }
        )
        injected_paths = str(res_paths)
        for slug in ("`sweetspot`", "`marathon`", "`test-design`", "`visualizer`"):
            self.assertNotIn(slug, injected_paths)

        for idx, prompt in enumerate(("Bu veritabanı sorgusunu optimize et.", "Bu fonksiyonu hızlandır.")):
            res_tr = handle_pre_invocation({"conversationId": f"w2-tr-{idx}", "prompt": prompt})
            self.assertIn("`sweetspot`", res_tr["injectSteps"][0]["ephemeralMessage"])

    def test_stop_gate_modified_test_stale_negative_multi_occurrence_and_per_func_timebomb(self) -> None:
        from guard.agy_hooks import inspect_git_diff

        ws = self.tmp / "ws_diff"
        (ws / "src").mkdir(parents=True)
        (ws / "tests").mkdir(parents=True)
        (ws / "src" / "app.py").write_text("def greet():\n    return 'NEW_BANNER_99'\n", encoding="utf-8")
        (ws / "tests" / "test_app.py").write_text(
            "import unittest\n"
            "from datetime import datetime, timedelta\n"
            "class T(unittest.TestCase):\n"
            "    def test_old(self):\n"
            "        # Ensure 'LEGACY_SENTINEL_XYZ' stays absent\n"
            "        self.assertNotIn('LEGACY_SENTINEL_XYZ', 'NEW_BANNER_99')\n"
            "    def test_good_clock(self):\n"
            "        _ = timedelta(days=1)\n"
            "    def test_timebomb(self):\n"
            "        self.assertTrue(datetime.now().isoformat() < '2029-01-01T00:00')\n",
            encoding="utf-8",
        )
        diff = (
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -2 +2 @@\n"
            "-    return 'LEGACY_SENTINEL_XYZ'\n"
            "+    return 'NEW_BANNER_99'\n"
            "--- a/tests/test_app.py\n"
            "+++ b/tests/test_app.py\n"
            "@@ -6,0 +7,4 @@\n"
            "+    def test_good_clock(self):\n"
            "+        _ = timedelta(days=1)\n"
            "+    def test_timebomb(self):\n"
            "+        self.assertTrue(datetime.now().isoformat() < '2029-01-01T00:00')\n"
        )
        findings = inspect_git_diff(diff, workspace=ws)
        joined = "\n".join(findings)
        self.assertIn("Stale negative assertion", joined)
        self.assertIn("Calendar time-bomb", joined)

    def test_snapshot_restore_slash_dunder_collision_and_os_adapter_symlink_safety(self) -> None:
        from guard.os_adapter import OSProtectionAdapter
        from guard.snapshot import SnapshotEngine

        target = self.tmp / "gov_target"
        (target / "a").mkdir(parents=True)
        (target / "a" / "b").write_text("NESTED_ORIG", encoding="utf-8")
        (target / "a__b").write_text("FLAT_ORIG", encoding="utf-8")

        snap_root = self.tmp / "snaps"
        engine = SnapshotEngine(
            target_dir=target,
            snapshots_dir=snap_root,
            scope_paths=["a/b", "a__b", "extra/dir", "extra__dir"],
        )
        snap_id, _ = engine.create_snapshot(label="collision-test")

        (target / "a" / "b").write_text("MUTATED_1", encoding="utf-8")
        (target / "a__b").write_text("MUTATED_2", encoding="utf-8")
        (target / "extra__dir").write_text("EXTRA_FLAT", encoding="utf-8")
        (target / "extra").mkdir()
        (target / "extra" / "dir").write_text("EXTRA_NESTED", encoding="utf-8")

        ok, msg = engine.restore_snapshot(snap_id)
        self.assertTrue(ok, msg)
        self.assertEqual((target / "a" / "b").read_text(encoding="utf-8"), "NESTED_ORIG")
        self.assertEqual((target / "a__b").read_text(encoding="utf-8"), "FLAT_ORIG")
        self.assertFalse((target / "extra__dir").exists())
        self.assertFalse((target / "extra" / "dir").exists())

        win_dir = self.tmp / "win_gov"
        win_dir.mkdir()
        (win_dir / "GEMINI.md").write_text("# Rule\n", encoding="utf-8")
        adapter = OSProtectionAdapter(target_dir=win_dir)
        adapter.system = "windows"
        calls: list[list[str]] = []

        def fake_run(cmd: list[str]) -> tuple[bool, str]:
            calls.append(list(cmd))
            return True, ""

        with (
            mock.patch.object(adapter, "_run", side_effect=fake_run),
            mock.patch.object(adapter, "protection_issues", return_value=[]),
        ):
            adapter.lock(win_dir, recursive=True)
            adapter.unlock(win_dir, recursive=True)
        icacls_cmds = [c for c in calls if c and c[0] == "icacls"]
        self.assertTrue(len(icacls_cmds) >= 2)
        for ic in icacls_cmds:
            self.assertIn("/L", ic, f"Expected /L symlink-safe flag in icacls call: {ic}")


class TestSliceCDiagnosticsPackagingCodeMapAndWatchdogW2(unittest.TestCase):
    """W2 Pass 2C Slice C: CLI Self-Audit Root, Upstream, Doctor, Lease, Installer, Packaging, CodeMap & Watchdog."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-w2-slice-c-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        from hermetic import force_rmtree

        force_rmtree(self.tmp)
        self._tmp.cleanup()

    def test_self_audit_default_root_fallback_split_runtime_and_system_share(self) -> None:
        import guard.cli as cli_mod

        fake_runtime_cli = self.tmp / "opt" / "lib" / "antigravity-guard" / "guard" / "cli.py"
        fake_runtime_cli.parent.mkdir(parents=True, exist_ok=True)
        fake_runtime_cli.write_text("# stub\n", encoding="utf-8")

        cfg_dir = self.tmp / "cfg"
        (cfg_dir / "skills" / "demo").mkdir(parents=True)
        (cfg_dir / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")
        # Plant deliberate drift (missing frontmatter / manifest) so self-audit MUST fail if it finds cfg_dir
        (cfg_dir / "skills" / "demo" / "SKILL.md").write_text("# Broken skill without frontmatter\n", encoding="utf-8")

        with (
            mock.patch.object(cli_mod, "__file__", str(fake_runtime_cli)),
            mock.patch("guard.cli.config_dir", return_value=cfg_dir),
        ):
            self.assertEqual(cli_mod._default_audit_root(), cfg_dir)
            out_buf = io.StringIO()
            with redirect_stdout(out_buf):
                rc = cli_mod.main(["self-audit", "--strict", "--json"])
            self.assertEqual(rc, 1)
            payload = json.loads(out_buf.getvalue())
            self.assertEqual(Path(payload["root"]).resolve(), cfg_dir.resolve())
            self.assertFalse(payload["is_valid"])

        empty_cfg = self.tmp / "empty_cfg"
        share_dir = self.tmp / "opt" / "share" / "antigravity-harness"
        (share_dir / "skills" / "demo").mkdir(parents=True)
        (share_dir / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")
        (share_dir / "skills" / "demo" / "SKILL.md").write_text("# Broken system share skill\n", encoding="utf-8")

        with (
            mock.patch.object(cli_mod, "__file__", str(fake_runtime_cli)),
            mock.patch("guard.cli.config_dir", return_value=empty_cfg),
        ):
            self.assertEqual(cli_mod._default_audit_root(), share_dir.resolve())
            out_buf2 = io.StringIO()
            with redirect_stdout(out_buf2):
                rc2 = cli_mod.main(["self-audit", "--strict", "--json"])
            self.assertEqual(rc2, 1)
            payload2 = json.loads(out_buf2.getvalue())
            self.assertEqual(Path(payload2["root"]).resolve(), share_dir.resolve())

    def test_upstream_ack_signature_parity_corrupt_guard_and_worker_errors(self) -> None:
        import importlib.util
        import guard.cli as cli_mod
        from guard.upstream import UpstreamAuditorBridge

        cfg = self.tmp / "config"
        state_root = self.tmp / "state"
        builtin_dir = self.tmp / "builtin"
        (cfg / "skills" / "upstream-auditor").mkdir(parents=True)
        (cfg / "skills" / "plugin").mkdir(parents=True)
        (builtin_dir / "plugin").mkdir(parents=True)
        (builtin_dir / "plugin" / "SKILL.md").write_text("# builtin\n", encoding="utf-8")
        state_root.mkdir(parents=True)

        seed_data = {
            "last_seen_model": "Gemini 3.1 Pro (High)",
            "last_audited_model": "Gemini 3.1 Pro (High)",
            "tracked_repositories": {
                "skill-alpha": {
                    "repo": "owner/skill-alpha",
                    "branch": "main",
                    "track": "commits",
                    "last_synced_commit": "1111111",
                }
            },
            "pending_repo_updates": {
                "skill-alpha": {"recorded": "1111111", "remote": "2222222"}
            },
        }
        seed_path = cfg / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        seed_path.write_text(json.dumps(seed_data), encoding="utf-8")
        seed_path.chmod(0o444)

        env_vars = {
            "ANTIGRAVITY_CONFIG_DIR": str(cfg),
            "AGY_GUARD_STATE_DIR": str(state_root),
            "ANTIGRAVITY_BUILTIN_SKILLS_DIR": str(builtin_dir),
            "ANTIGRAVITY_PBTXT_FILE": str(self.tmp / "no_pbtxt"),
        }
        try:
            with mock.patch.dict(os.environ, env_vars, clear=False):
                os.environ.pop("UPSTREAM_STATE_FILE", None)
                bridge = UpstreamAuditorBridge(target_dir=cfg)
                ok, msg = bridge.acknowledge_drift()
                self.assertTrue(ok, msg)
                dest_state = state_root / "upstream_state.json"
                self.assertTrue(dest_state.is_file())
                saved = json.loads(dest_state.read_text(encoding="utf-8"))

                watcher_path = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
                spec = importlib.util.spec_from_file_location("uw_slice_c", watcher_path)
                assert spec and spec.loader
                uw = importlib.util.module_from_spec(spec)
                os.environ["UPSTREAM_STATE_FILE"] = str(dest_state)
                spec.loader.exec_module(uw)
                reasons = uw.collect_reasons(saved, "Gemini 3.1 Pro (High)")
                self.assertGreaterEqual(len(reasons), 2, f"Expected collision + pending update reasons, got {reasons}")
                self.assertEqual(uw.unacknowledged(saved, reasons), [])

                # Corrupt state file must NOT be silently overwritten by acknowledge_drift / cmd_upstream ack
                dest_state.write_text("{bad json", encoding="utf-8")
                bad_bridge = UpstreamAuditorBridge(target_dir=cfg)
                ok_bad, _ = bad_bridge.acknowledge_drift()
                self.assertFalse(ok_bad)
                self.assertEqual(dest_state.read_text(encoding="utf-8"), "{bad json")
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    rc_ack = cli_mod.cmd_upstream(argparse.Namespace(action="ack", model=None, offline=False))
                self.assertEqual(rc_ack, 1)
                self.assertEqual(dest_state.read_text(encoding="utf-8"), "{bad json")

                # Malformed non-dict tracked repository entry & empty tracked_repositories must fail non-zero
                dest_state.write_text(json.dumps({"tracked_repositories": {"bad_entry": "not-a-dict"}}), encoding="utf-8")
                mal_bridge = UpstreamAuditorBridge(target_dir=cfg)
                rows = mal_bridge.check_repositories()
                self.assertEqual(len(rows), 1)
                self.assertTrue(str(rows[0]["status"]).startswith("Invalid "), rows)
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    rc_mal = cli_mod.cmd_upstream(argparse.Namespace(action="check", model=None, offline=False))
                self.assertEqual(rc_mal, 1)

                dest_state.write_text(json.dumps({"tracked_repositories": {}}), encoding="utf-8")
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    rc_empty_off = cli_mod.cmd_upstream(argparse.Namespace(action="check", model=None, offline=True))
                    rc_empty_on = cli_mod.cmd_upstream(argparse.Namespace(action="check", model=None, offline=False))
                self.assertEqual(rc_empty_off, 1)
                self.assertEqual(rc_empty_on, 1)
        finally:
            seed_path.chmod(0o644)

    def test_doctor_all_hook_runtime_branches_and_fix_unhealed_warnings(self) -> None:
        import guard.cli as cli_mod
        from guard.doctor import diagnose
        from guard.environment import EnvironmentRegistry

        home = self.tmp / "doc_home"
        cfg = home / ".gemini" / "config"
        st = home / ".local" / "state" / "antigravity-harness"
        (cfg / "skills").mkdir(parents=True)
        st.mkdir(parents=True)
        (cfg / "GEMINI.md").write_text("# Rule\n", encoding="utf-8")

        env_vars = {
            "HOME": str(home),
            "ANTIGRAVITY_CONFIG_DIR": str(cfg),
            "AGY_GUARD_STATE_DIR": str(st),
        }
        with mock.patch.dict(os.environ, env_vars, clear=False):
            reg = EnvironmentRegistry()
            env = reg.get_environment("antigravity")
            assert env is not None

            # 1. Missing hooks.json in global environment
            r1 = diagnose(env, reg, sentinel_active=True)
            self.assertTrue(any("hooks.json" in w for w in r1.warnings), r1.warnings)

            # 2. Corrupt hooks.json
            (cfg / "hooks.json").write_text("{corrupt", encoding="utf-8")
            r2 = diagnose(env, reg, sentinel_active=True)
            self.assertTrue(any("not a valid JSON object" in w for w in r2.warnings), r2.warnings)

            # 3. Missing upstream-watchdog & harness-gate + 4. Missing .py script
            (cfg / "hooks.json").write_text(
                json.dumps({"other": {"command": "python3 guard/nonexistent_hook.py"}}),
                encoding="utf-8",
            )
            # 5. Strikes >= 3 AND malformed non-int count (must not raise ValueError)
            (st / "hook_strikes.json").write_text(
                json.dumps({"s1": {"count": 3}, "s2": {"count": "not-a-number"}}),
                encoding="utf-8",
            )
            # 6. Install receipt version mismatch
            (st / "install_receipt.json").write_text(
                json.dumps({"version": "0.0.1-old"}),
                encoding="utf-8",
            )
            # 7. Upstream audit failed
            (st / "upstream_state.json").write_text(
                json.dumps({"last_audit_failed": True}),
                encoding="utf-8",
            )
            r3 = diagnose(env, reg, sentinel_active=True)
            joined = "\n".join(r3.warnings)
            self.assertIn("missing 'upstream-watchdog'", joined)
            self.assertIn("missing 'harness-gate'", joined)
            self.assertIn("does not exist: guard/nonexistent_hook.py", joined)
            self.assertIn("reached max strikes (>= 3)", joined)
            self.assertIn("does not match active Guard version", joined)
            self.assertIn("Last upstream repository audit failed", joined)

            # cmd_doctor --fix when lock fails and rebaseline is refused must NOT strip unhealed warnings
            (cfg / "hooks.json").write_text(
                json.dumps({"upstream-watchdog": {}, "harness-gate": {}}),
                encoding="utf-8",
            )
            (st / "hook_strikes.json").unlink()
            (st / "install_receipt.json").unlink()
            (st / "upstream_state.json").unlink()
            with (
                mock.patch("guard.cli._registry", return_value=reg),
                mock.patch.object(reg, "lock", return_value=(False, "chattr denied")),
                mock.patch.object(reg, "protection_issues", return_value=["GEMINI.md is writable"]),
                mock.patch("guard.cli.request_approval", return_value=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                rc_doc = cli_mod.cmd_doctor(argparse.Namespace(env="antigravity", fix=True, root=None))
            self.assertEqual(rc_doc, 1)

    def test_code_map_missing_paths_non_python_invalid_bytes_and_cli_exit_codes(self) -> None:
        from scripts.code_map import compute_blast_radius, find_callers, main

        proj = self.tmp / "cm_proj"
        proj.mkdir()
        (proj / "ok.ts").write_text("function targetFn() { return 1; }\nfunction runIt() { return targetFn(); }\n", encoding="utf-8")
        (proj / "bad_utf8.ts").write_bytes(b"function broken() { return targetFn(); }\xff\xfe\n")
        (proj / "bad_nul.js").write_bytes(b"function nulFn() { return targetFn(); }\x00\n")

        callers = find_callers("targetFn", [proj], base_dir=proj)
        self.assertEqual(len(callers), 1)
        self.assertGreaterEqual(len(getattr(callers, "parse_errors", [])), 2)

        for subcmd in ("profile", "callers", "flow", "blast-radius"):
            out_b, err_b = io.StringIO(), io.StringIO()
            with redirect_stdout(out_b), redirect_stderr(err_b):
                rc = main([subcmd, "targetFn", str(proj), "--json"])
            self.assertEqual(rc, 2, f"Expected exit 2 for {subcmd} with non-Python parse errors, got {rc}")
            parsed = json.loads(out_b.getvalue())
            self.assertIn("parse_errors", parsed, f"Expected parse_errors in {subcmd} --json output")

        missing_path = self.tmp / "does_not_exist_at_all"
        blast_missing = compute_blast_radius("targetFn", [missing_path])
        self.assertIs(blast_missing.get("complete"), False)
        self.assertNotEqual(blast_missing["tier_recommendation"], "Tier 1")

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc_blast_missing = main(["blast-radius", "targetFn", str(missing_path), "--json"])
            rc_fts_missing = main(["fts-search", "token", str(missing_path), "--json"])
        self.assertEqual(rc_blast_missing, 2)
        self.assertEqual(rc_fts_missing, 2)

    def test_upstream_watcher_partial_failure_quarantine_guard_and_check_skills_sh(self) -> None:
        import http.server
        import importlib.util
        import subprocess
        import threading

        state_file = self.tmp / "uw_state.json"
        initial_checked = "2026-10-01T00:00:00+00:00"
        state_data = {
            "last_checked_iso": initial_checked,
            "last_skills_audit_timestamp": "2020-01-01T00:00:00+00:00",
            "last_audit_failed": False,
            "tracked_repositories": {
                "repo_ok": {"repo": "org/repo-ok", "branch": "main", "track": "commits", "last_synced_commit": "1111111"},
                "repo_429": {"repo": "org/repo-429", "branch": "main", "track": "commits", "last_synced_commit": "2222222"},
            },
        }
        state_file.write_text(json.dumps(state_data), encoding="utf-8")

        watcher_path = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
        spec = importlib.util.spec_from_file_location("uw_partial_w2", watcher_path)
        assert spec and spec.loader
        uw = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, {"UPSTREAM_STATE_FILE": str(state_file)}, clear=False):
            spec.loader.exec_module(uw)
            with mock.patch.object(uw, "_fetch_all", return_value={"repo_ok": "9999999abcdef", "repo_429": None}):
                uw.check_tracked_skills(state_data)
            saved = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertTrue(saved["last_audit_failed"])
            self.assertEqual(saved["last_checked_iso"], initial_checked)
            self.assertIn("repo_ok", saved["pending_repo_updates"])

            # Quarantine failure must NOT overwrite corrupt STATE_FILE
            state_file.write_text("{corrupt_unmovable", encoding="utf-8")
            with mock.patch.object(uw, "quarantine_corrupt_state", return_value=""):
                st_obj, reason = uw.load_state(write=True)
            self.assertIsNone(st_obj)
            self.assertIn("quarantine", reason.lower())
            self.assertEqual(state_file.read_text(encoding="utf-8"), "{corrupt_unmovable")

            # Successful quarantine during cmd_ack emits [WARN]
            out_ack, err_ack = io.StringIO(), io.StringIO()
            with redirect_stdout(out_ack), redirect_stderr(err_ack):
                rc_ack = uw.cmd_ack(model="Gemini 3.1 Pro (High)")
            self.assertEqual(rc_ack, 0)
            self.assertIn("[WARN]", out_ack.getvalue() + err_ack.getvalue())

        # check_skills.sh tests: (1) missing explicit UPSTREAM_STATE_FILE, (2) empty {}, (3) empty release tag_name
        script_sh = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "check_skills.sh"
        res_missing = subprocess.run(
            ["bash", str(script_sh)],
            env={**os.environ, "UPSTREAM_STATE_FILE": str(self.tmp / "missing_explicit.json")},
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res_missing.returncode, 1, res_missing.stdout + res_missing.stderr)

        empty_state = self.tmp / "empty_tracked.json"
        empty_state.write_text(json.dumps({"tracked_repositories": {}}), encoding="utf-8")
        res_empty = subprocess.run(
            ["bash", str(script_sh)],
            env={**os.environ, "UPSTREAM_STATE_FILE": str(empty_state)},
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res_empty.returncode, 1, res_empty.stdout + res_empty.stderr)

        rel_state = self.tmp / "rel_empty.json"
        rel_state.write_text(
            json.dumps(
                {
                    "tracked_repositories": {
                        "rel_pkg": {"repo": "org/rel-pkg", "track": "release", "last_synced_commit": "v1.0.0"}
                    }
                }
            ),
            encoding="utf-8",
        )
        res_bad_base = subprocess.run(
            ["bash", str(script_sh)],
            env={
                **os.environ,
                "UPSTREAM_STATE_FILE": str(rel_state),
                "GITHUB_API_BASE": "http://127.0.0.1:9999",
            },
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res_bad_base.returncode, 1, res_bad_base.stdout + res_bad_base.stderr)
        self.assertIn("Invalid GITHUB_API_BASE", res_bad_base.stdout + res_bad_base.stderr)

        shim_dir = self.tmp / "py_shim"
        shim_dir.mkdir(exist_ok=True)
        (shim_dir / "sitecustomize.py").write_text(
            f"import sys\nsys.path.insert(0, {str(REPO_ROOT)!r})\nimport porter.net\nporter.net.safe_fetch_url = lambda *a, **kw: '{{}}'\n",
            encoding="utf-8",
        )
        existing_pypath = os.environ.get("PYTHONPATH", "")
        shim_pypath = f"{shim_dir}{os.pathsep}{existing_pypath}" if existing_pypath else str(shim_dir)
        res_rel = subprocess.run(
            ["bash", str(script_sh)],
            env={
                **os.environ,
                "UPSTREAM_STATE_FILE": str(rel_state),
                "PYTHONPATH": shim_pypath,
            },
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res_rel.returncode, 1, res_rel.stdout + res_rel.stderr)
        self.assertIn("EMPTY REPLY", res_rel.stdout + res_rel.stderr)

    def test_linux_packaging_fail_closed_and_hooks_validation(self) -> None:
        import installers.packaging.package_linux as pkg_mod

        out_dir = self.tmp / "pkg_out"
        bad_bin_packager = pkg_mod.LinuxPackager(
            version="2.0.0",
            out_dir=out_dir,
            binary_path=self.tmp / "nonexistent_agy_guard_bin",
        )
        with self.assertRaises(FileNotFoundError):
            bad_bin_packager._prepare_payload(self.tmp / "stage_bad_bin")

        with (
            mock.patch.object(sys, "argv", ["package_linux.py", "--check-only", "--binary", str(self.tmp / "no_bin")]),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(pkg_mod.main(), 1)

        # Missing mandatory repo entry fails _prepare_payload and --check-only
        broken_repo = self.tmp / "broken_repo"
        broken_repo.mkdir()
        (broken_repo / "GEMINI.md").write_text("# Rule\n", encoding="utf-8")
        broken_packager = pkg_mod.LinuxPackager(version="2.0.0", out_dir=out_dir)
        broken_packager.repo_root = broken_repo
        with self.assertRaises(FileNotFoundError):
            broken_packager._prepare_payload(self.tmp / "stage_broken_repo")

        # Non-zero rpmbuild / dpkg-deb / tar must raise RuntimeError instead of falling back silently
        valid_packager = pkg_mod.LinuxPackager(version="2.0.0", out_dir=out_dir)
        failed_proc = mock.Mock(returncode=1, stdout="", stderr="packager tool failed")
        with (
            mock.patch("installers.packaging.package_linux.shutil.which", return_value="/usr/bin/rpmbuild"),
            mock.patch("installers.packaging.package_linux.subprocess.run", return_value=failed_proc),
        ):
            with self.assertRaises(RuntimeError):
                valid_packager.build_rpm()

        with (
            mock.patch("installers.packaging.package_linux.shutil.which", return_value="/usr/bin/dpkg-deb"),
            mock.patch("installers.packaging.package_linux.subprocess.run", return_value=failed_proc),
        ):
            with self.assertRaises(RuntimeError):
                valid_packager.build_deb()

        with (
            mock.patch("installers.packaging.package_linux.shutil.which", return_value="/usr/bin/tar"),
            mock.patch("installers.packaging.package_linux.subprocess.run", return_value=failed_proc),
        ):
            with self.assertRaises(RuntimeError):
                valid_packager.build_arch()

        # Explicit --format rpm when rpmbuild is absent returns .spec from build_rpm(), and main() must exit 1
        with (
            mock.patch("installers.packaging.package_linux.shutil.which", return_value=None),
            mock.patch.object(sys, "argv", ["package_linux.py", "--format", "rpm", "--out-dir", str(out_dir)]),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(pkg_mod.main(), 1)

        pkgbuild_txt = (REPO_ROOT / "installers" / "packaging" / "PKGBUILD").read_text(encoding="utf-8")
        self.assertIn("sys.argv[1]", pkgbuild_txt)
        self.assertNotIn("Path(\"'\"" + "$pkgdir", pkgbuild_txt)

    def test_installer_startup_failure_mcp_corrupt_and_binary_nofollow(self) -> None:
        import install as install_mod

        home = self.tmp / "inst_home"
        cfg = home / ".gemini" / "config"
        st = home / ".local" / "state" / "antigravity-harness"
        cfg.mkdir(parents=True)
        st.mkdir(parents=True)

        inst = install_mod.Installer(cfg, "copy", dry_run=False)
        (cfg / "mcp_config.json").write_text("{corrupt", encoding="utf-8")
        buf1 = io.StringIO()
        with redirect_stdout(buf1), redirect_stderr(buf1):
            inst.migrate_mcp_config()
        self.assertIn("[WARN]", buf1.getvalue())

        (cfg / "mcp_config.json").write_text("[]", encoding="utf-8")
        buf2 = io.StringIO()
        with redirect_stdout(buf2), redirect_stderr(buf2):
            inst.migrate_mcp_config()
        self.assertIn("[WARN]", buf2.getvalue())

        # install_binary must refuse symlink at .tmp destination
        victim = self.tmp / "victim_bin"
        victim.write_bytes(b"ORIGINAL_VICTIM")
        bin_dir = home / ".local" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "agy-guard.tmp").symlink_to(victim)
        fake_payload = b"#!/bin/sh\necho hi\n"
        fake_sha = f"{__import__('hashlib').sha256(fake_payload).hexdigest()}  agy-guard-linux-x86_64\n"

        with (
            mock.patch.dict(os.environ, {"HOME": str(home)}, clear=False),
            mock.patch.object(install_mod, "SYSTEM", "Linux"),
            mock.patch("install.platform.machine", return_value="x86_64"),
            mock.patch("pathlib.Path.is_file", autospec=True) as mock_isfile,
        ):
            orig_isfile = Path.is_file

            def _side_isfile(p: Path) -> bool:
                if p.name in ("agy-guard-linux-x86_64", "agy-guard-linux-x86_64.sha256") and p.parent.name == "dist":
                    return True
                return orig_isfile(p)

            mock_isfile.side_effect = _side_isfile
            with (
                mock.patch("pathlib.Path.read_bytes", return_value=fake_payload),
                mock.patch("pathlib.Path.read_text", return_value=fake_sha),
                redirect_stdout(io.StringIO()),
            ):
                ok_bin = inst.install_binary()
        self.assertFalse(ok_bin)
        self.assertEqual(victim.read_bytes(), b"ORIGINAL_VICTIM")

        # --enable-startup failure in install.main must exit 1 without printing [SUCCESS]
        out_m, err_m = io.StringIO(), io.StringIO()
        with (
            mock.patch.dict(
                os.environ,
                {"HOME": str(home), "ANTIGRAVITY_CONFIG_DIR": str(cfg), "AGY_GUARD_STATE_DIR": str(st)},
                clear=False,
            ),
            mock.patch("guard.startup.StartupManager.enable", return_value=(False, "systemd unavailable")),
            redirect_stdout(out_m),
            redirect_stderr(err_m),
        ):
            rc_main = install_mod.main(["--no-lock", "--enable-startup"])
        self.assertEqual(rc_main, 1)
        self.assertNotIn("[SUCCESS] Antigravity Harness installed.", out_m.getvalue())

    def test_lease_corrupt_list_update_record_and_expire_baseline_resilience(self) -> None:
        from guard.environment import AgentEnvironment, EnvironmentRegistry
        from guard.lease import LeaseManager

        st = self.tmp / "lease_state"
        env_dir = self.tmp / "lease_env"
        st.mkdir()
        env_dir.mkdir()
        (env_dir / "GEMINI.md").write_text("# Rule\n", encoding="utf-8")

        with mock.patch.dict(os.environ, {"AGY_GUARD_STATE_DIR": str(st)}, clear=False):
            adapter = mock.MagicMock()
            adapter.lock.return_value = (True, "locked")
            adapter.unlock.return_value = (True, "unlocked")
            adapter.protection_issues.return_value = []
            adapter.is_protected.return_value = True

            reg = EnvironmentRegistry(config_path=st / "envs.json", os_adapter=adapter)
            reg.register_environment(
                AgentEnvironment(
                    id="env_a",
                    name="Env A",
                    platform_type="custom",
                    root_path=str(env_dir),
                    governance_paths=["GEMINI.md"],
                    enabled=True,
                    policy="enforced",
                )
            )
            notifier = mock.MagicMock()
            mgr = LeaseManager(
                registry=reg,
                lease_file=st / "leases.json",
                notifier=notifier,
                scheduler=lambda lease, m: (True, "mocked"),
            )

            # 1. list_leases() on corrupt store triggers _fail_closed (quarantine + lock)
            (st / "leases.json").write_text("{corrupt_lease_json", encoding="utf-8")
            self.assertEqual(mgr.list_leases(), [])
            adapter.lock.assert_called()
            self.assertFalse((st / "leases.json").exists())
            self.assertTrue(list(st.glob("leases.json.corrupt-*")))

            # 2. request_unlock guards _update_record against OSError and checks relock result
            with mock.patch.object(mgr, "_update_record", side_effect=OSError("disk full")):
                ok_u, msg_u, lease_u = mgr.request_unlock("env_a", "maint", 60, approver=lambda _: True)
            self.assertFalse(ok_u)
            self.assertIsNone(lease_u)
            self.assertEqual(mgr.list_leases(), [])

            # 3. expire_lease still removes lease record even if save_pending_baseline raises OSError
            ok_g, _, granted = mgr.request_unlock("env_a", "maint2", 60, approver=lambda _: True)
            self.assertTrue(ok_g)
            assert granted is not None
            (env_dir / "GEMINI.md").write_text("# Modified during window\n", encoding="utf-8")
            with mock.patch("guard.integrity.FileIntegrityMonitor.save_pending_baseline", side_effect=OSError("ro fs")):
                ok_exp, msg_exp = mgr.expire_lease(granted)
            self.assertTrue(ok_exp, msg_exp)
            self.assertEqual(mgr.list_leases(), [])


class TestSliceDMetaAuditSplitLayoutAndGovernanceW2(unittest.TestCase):
    """W2 Pass 2C Slice D: MetaAudit package_linux/runtime/config probes, slash path-boundary, split layout & media-studio."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-w2-slice-d-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        from hermetic import force_rmtree

        force_rmtree(self.tmp)
        self._tmp.cleanup()

    def test_meta_audit_package_linux_broken_runtime_config_paths_and_slash_boundary_probe(self) -> None:
        from scripts.meta_audit import MetaAuditEngine

        root = self.tmp / "repo"
        (root / "skills" / "demo").mkdir(parents=True)
        (root / "skills" / "demo" / "SKILL.md").write_text(
            "---\nname: demo\ndescription: Demo skill. Invoke with /demo. Not for other tasks.\n---\n"
            "Inspect ~/.local/share/antigravity-harness/runtime/guard/nonexistent_xyz.py and "
            "see ~/.gemini/config/skills/nonexistent-xyz/SKILL.md in prose.\n",
            encoding="utf-8",
        )
        (root / "install.py").write_text(
            'GOVERNANCE_FILES = ("GEMINI.md",)\nGOVERNANCE_DIRS = ("skills", "agents", "templates")\n',
            encoding="utf-8",
        )
        (root / "GEMINI.md").write_text("# Rule\n", encoding="utf-8")
        (root / "agents").mkdir()
        (root / "templates").mkdir()
        (root / "installers" / "packaging").mkdir(parents=True)
        (root / "installers" / "packaging" / "package_linux.py").write_text(
            "# Drifted package_linux missing agy-porter and manifest.json\n",
            encoding="utf-8",
        )
        (root / "README.md").write_text("# Demo\n", encoding="utf-8")
        (root / "guard").mkdir()
        (root / "guard" / "cli.py").write_text(
            "import argparse\ndef build_parser():\n"
            "    p = argparse.ArgumentParser()\n"
            "    p.add_subparsers(dest='cmd')\n"
            "    return p\n",
            encoding="utf-8",
        )
        (root / "guard" / "environment.py").write_text("VALID_POLICIES = ('enforced',)\n", encoding="utf-8")
        # Unguarded /demo\b matches file path src/demo/worker.py!
        (root / "guard" / "agy_hooks.py").write_text(
            "import re\nSKILL_HINTS = (\n"
            "    ('demo', 'skills/demo/SKILL.md', re.compile(r'/demo\\b'), 'demo'),\n"
            ")\n",
            encoding="utf-8",
        )

        eng = MetaAuditEngine(repo_root=root)
        eng.pass2_cross_references()
        eng.pass5_cli_doc_sync()
        eng.pass7_trigger_specificity()

        msgs = "\n".join(f.message for f in eng.findings)
        self.assertIn("package_linux.py is missing required packaging artifact", msgs)
        self.assertIn("~/.local/share/antigravity-harness/runtime/guard/nonexistent_xyz.py", msgs)
        self.assertIn("~/.gemini/config/skills/nonexistent-xyz/SKILL.md", msgs)
        self.assertIn("src/demo/", msgs)

    def test_meta_audit_split_layout_hooks_fallback_and_custom_skill_manifest_scope(self) -> None:
        from porter.manifest import ManifestEngine
        from scripts.meta_audit import MetaAuditEngine

        home = self.tmp / "split_home"
        cfg = home / ".gemini" / "config"
        data_root = home / ".local" / "share" / "antigravity-harness"
        state_root = home / ".local" / "state" / "antigravity-harness"
        (cfg / "skills" / "managed-skill").mkdir(parents=True)
        (cfg / "agents").mkdir(parents=True)
        (cfg / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")
        (cfg / "skills" / "managed-skill" / "SKILL.md").write_text(
            "---\nname: managed-skill\ndescription: Managed skill. Invoke with /managed-skill. Not for other tasks.\n---\n"
            "# Managed\n",
            encoding="utf-8",
        )
        # Seal manifest BEFORE user adds custom skill
        m_eng = ManifestEngine(harness_root=cfg)
        m_eng.save_manifest(cfg / ".harness" / "manifest.json", deterministic=True)

        # User adds custom skill in ~/.gemini/config/skills/user-custom
        (cfg / "skills" / "user-custom").mkdir(parents=True)
        (cfg / "skills" / "user-custom" / "SKILL.md").write_text(
            "---\nname: user-custom\ndescription: Custom user skill. Invoke with /user-custom. Not for other tasks.\n---\n"
            "# User Custom\n",
            encoding="utf-8",
        )

        state_root.mkdir(parents=True)
        (state_root / "install_receipt.json").write_text(
            json.dumps(
                {
                    "version": "2.0.0",
                    "target": str(cfg),
                    "installed": ["GEMINI.md", "skills/managed-skill", ".harness"],
                }
            ),
            encoding="utf-8",
        )
        (data_root / "runtime" / "guard").mkdir(parents=True)
        (data_root / "runtime" / "guard" / "agy_hooks.py").write_text(
            "import re\nSKILL_HINTS = (\n"
            "    ('managed-skill', 'skills/managed-skill/SKILL.md', re.compile(r'/wrong-trigger\\b'), 'managed'),\n"
            ")\n",
            encoding="utf-8",
        )

        env_vars = {
            "HOME": str(home),
            "ANTIGRAVITY_CONFIG_DIR": str(cfg),
            "AGY_GUARD_DATA_DIR": str(data_root),
            "AGY_GUARD_STATE_DIR": str(state_root),
        }
        with mock.patch.dict(os.environ, env_vars, clear=False):
            eng = MetaAuditEngine(repo_root=cfg)
            eng.pass4_porter_parity()
            eng.pass7_trigger_specificity()
            p4_msgs = [f.message for f in eng.findings if "Pass 4" in f.pass_name]
            p7_msgs = [f.message for f in eng.findings if "Pass 7" in f.pass_name]
            self.assertEqual(p4_msgs, [], f"User custom skill should not cause stale manifest error: {p4_msgs}")
            self.assertTrue(
                any("/managed-skill" in m for m in p7_msgs),
                f"Split-layout fallback hooks_py must still catch managed-skill trigger drift: {p7_msgs}",
            )
            self.assertFalse(
                any("user-custom" in m for m in p7_msgs),
                f"User custom skill must not be required in harness SKILL_HINTS: {p7_msgs}",
            )

            # Tampering with harness-managed skill MUST still fail Pass 4 with CRITICAL
            (cfg / "skills" / "managed-skill" / "SKILL.md").write_text(
                "---\nname: managed-skill\ndescription: Tampered. Invoke with /managed-skill. Not for x.\n---\n# Tampered\n",
                encoding="utf-8",
            )
            eng_tampered = MetaAuditEngine(repo_root=cfg)
            eng_tampered.pass4_porter_parity()
            self.assertTrue(
                any(f.severity == "CRITICAL" and "stale" in f.message.lower() for f in eng_tampered.findings),
                eng_tampered.findings,
            )

        media_txt = (REPO_ROOT / "skills" / "media-studio" / "SKILL.md").read_text(encoding="utf-8")
        self.assertNotIn("python3 skills/media-studio/scripts/media_qc.py", media_txt)
        self.assertIn("/usr/share/antigravity-harness/skills/media-studio/scripts/media_qc.py", media_txt)


if __name__ == "__main__":
    unittest.main()
