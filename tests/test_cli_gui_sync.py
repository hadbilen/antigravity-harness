#!/usr/bin/env python3
"""
tests/test_cli_gui_sync.py — Seam tests for Slice 7 (Post-v1.4.0 CLI, GUI, PorterBridge,
TestBoundary, Upstream, Doctor, and Packaging synchronization).
"""

from __future__ import annotations

import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import hermetic  # noqa: F401, E402  (isolates HOME/state before guard is imported)

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guard.environment import ANTIGRAVITY_GOVERNANCE_SEAMS, EnvironmentRegistry  # noqa: E402
from guard.porter_bridge import PorterBridge  # noqa: E402
from scripts.meta_audit import MetaAuditEngine  # noqa: E402


class TestPorterBridgeZipAndFrontmatter(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_sync_porter_"))
        self.cfg = self.tmp / "cfg"
        self.cfg.mkdir(parents=True)
        self.bridge = PorterBridge(target_dir=self.cfg)

    def tearDown(self) -> None:
        hermetic.force_rmtree(self.tmp)

    def test_zip_archive_is_inspected_read_only_and_never_staged(self) -> None:
        safe_zip = self.tmp / "bundle.zip"
        with zipfile.ZipFile(safe_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("clean_rule.md", "# Clean Rule\nVerify contracts at public seams.\n")

        report = self.bridge.inspect_source(str(safe_zip))
        self.assertEqual(report["target_type"], "archive")
        self.assertTrue(report["is_admissible"])
        self.assertTrue(report.get("is_archive"))
        self.assertIn("Porter Archive Inspection Report", report["sanitized_content"])

        # Staging a ZIP archive must be refused per GEMINI.md Rule 16
        ok, msg = self.bridge.stage_and_ingest(str(safe_zip))
        self.assertFalse(ok)
        self.assertIn("Rule 16", msg)

        # Unsafe ZIP archive with path traversal hazard must report is_admissible == False
        bad_zip = self.tmp / "traversal.zip"
        with zipfile.ZipFile(bad_zip, "w") as zf:
            zf.writestr("../escape.md", "# Bad\n")
        bad_report = self.bridge.inspect_source(str(bad_zip))
        self.assertFalse(bad_report["is_admissible"])
        self.assertTrue(any("PATH_TRAVERSAL" in v for v in bad_report["violations"]))

        # Remote HTTP(S) ZIP URLs (including query strings) must be rejected without fetching
        with self.assertRaises(ValueError):
            self.bridge.inspect_source("https://example.com/rules.zip?download=1")
        ok_url, msg_url = self.bridge.stage_and_ingest("https://example.com/rules.zip?download=1")
        self.assertFalse(ok_url)
        self.assertIn("Rule 16", msg_url)

    def test_stage_and_ingest_synthesizes_valid_frontmatter_and_tracks_rules_seam(self) -> None:
        self.assertIn("rules", ANTIGRAVITY_GOVERNANCE_SEAMS)

        # Plain markdown file without YAML frontmatter
        raw_rule = self.tmp / "plain_skill.md"
        raw_rule.write_text(
            "# API Contract Guide\n"
            "When designing endpoints, verify request and response schemas with unit tests.\n",
            encoding="utf-8",
        )
        ok, msg = self.bridge.stage_and_ingest(str(raw_rule), target_name="api-contract-guide")
        self.assertTrue(ok, msg)

        # Self-audit Pass 1 (Schema Validation) on the target directory must pass with 0 findings
        auditor = MetaAuditEngine(repo_root=self.cfg)
        findings = auditor.run_pass(1)
        self.assertEqual(findings, [], f"Expected 0 schema findings after ingestion, got: {findings}")


class TestBoundaryAuthorizedModifications(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_sync_tb_"))
        (self.tmp / "tests").mkdir()
        self.test_file = self.tmp / "tests" / "test_contract.py"
        self.test_file.write_text("def test_v1():\n    assert 1 == 1\n", encoding="utf-8")

    def tearDown(self) -> None:
        hermetic.force_rmtree(self.tmp)

    def test_tasks_md_authorized_test_modifications_and_cli_authorize_flag(self) -> None:
        from guard.cli import main as cli_main
        from guard.provenance import RunProvenanceTracker
        from guard.test_boundary import TestBoundaryGuard

        guard = TestBoundaryGuard(workspace_dir=self.tmp)
        guard.snapshot()

        # Mutate existing test file (line replacement)
        self.test_file.write_text("def test_v2():\n    assert 2 == 2\n", encoding="utf-8")

        # Without authorization, both bugfix and tdd modes reject the modification
        self.assertFalse(guard.verify(mode="bugfix").is_intact)
        self.assertFalse(guard.verify(mode="tdd").is_intact)

        # CLI --authorize flag permits the specific file
        rc = cli_main([
            "test-boundary", "verify",
            "--dir", str(self.tmp),
            "--mode", "bugfix",
            "--authorize", "tests/test_contract.py",
        ])
        self.assertEqual(rc, 0)

        # RunProvenanceTracker forwards authorized_modifications cleanly
        att = RunProvenanceTracker(workspace_dir=self.tmp).generate_manifest(
            mode="bugfix",
            authorized_modifications={"tests/test_contract.py"},
        )
        self.assertTrue(att.test_boundary_verified)

        # Recording the file under ## Authorized Test Modifications and sealing via human snapshot permits it
        self.test_file.write_text("def test_v1():\n    assert 1 == 1\n", encoding="utf-8")
        (self.tmp / "tasks.md").write_text(
            "# Tasks\n\n"
            "## Authorized Test Modifications\n"
            "- `tests/test_contract.py`: Contract updated from v1 to v2 with user approval.\n",
            encoding="utf-8",
        )
        parsed = TestBoundaryGuard.load_authorized_from_tasks_md(self.tmp)
        self.assertIn("tests/test_contract.py", parsed)
        guard.snapshot()
        self.test_file.write_text("def test_v2():\n    assert 2 == 2\n", encoding="utf-8")
        report = guard.verify(mode="bugfix")
        self.assertTrue(report.is_intact, report.violations)

        # Inline heading syntax from skills/harness/SKILL.md: ## Authorized Test Modifications: [file: reason]
        (self.tmp / "tasks.md").write_text(
            "# Tasks\n\n"
            "## Authorized Test Modifications: [tests/test_contract.py: inline reason]\n",
            encoding="utf-8",
        )
        self.assertIn("tests/test_contract.py", TestBoundaryGuard.load_authorized_from_tasks_md(self.tmp))

        # Weakening markers (@pytest.mark.skip) are still blocked even on an authorized file
        self.test_file.write_text("@pytest.mark.skip\ndef test_v2():\n    assert 2 == 2\n", encoding="utf-8")
        weak_report = guard.verify(mode="bugfix")
        self.assertFalse(weak_report.is_intact)


class TestUpstreamSyncAndAck(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_sync_upstream_"))
        self.gemini_dir = self.tmp / ".gemini"
        self.cfg_dir = self.gemini_dir / "config"
        self.ag_dir = self.gemini_dir / "antigravity"
        self.cfg_dir.mkdir(parents=True)
        self.ag_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        hermetic.force_rmtree(self.tmp)

    def test_pbtxt_model_detection_and_ack_and_offline_status(self) -> None:
        from guard.cli import main as cli_main
        from guard.upstream import UpstreamAuditorBridge

        pbtxt = self.ag_dir / "antigravity_state.pbtxt"
        pbtxt.write_text('last_selected_agent_model: "Gemini 3.1 Pro (High)"\n', encoding="utf-8")

        state_file = self.tmp / "upstream_state.json"
        state_file.write_text(
            json.dumps({
                "tracked_repositories": {
                    "antislop": {"url": "https://example.com/antislop.git", "last_synced_commit": "d8529a6"}
                },
                "pending_repo_updates": {
                    "antislop": {"recorded": "d8529a6", "remote": "aaaaaaa"}
                },
            }),
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {
            "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
            "UPSTREAM_STATE_FILE": str(state_file),
        }):
            bridge = UpstreamAuditorBridge(target_dir=self.cfg_dir)
            info = bridge.get_model_drift_status()
            self.assertEqual(info["active_model"], "Gemini 3.1 Pro (High)")
            self.assertIn("pbtxt", info["model_source"])

            # CLI upstream ack --model records the audited model, preserves pending_repo_updates, and records acknowledged_reasons
            rc = cli_main(["upstream", "ack", "--model", "Gemini 3.1 Pro (High)"])
            self.assertEqual(rc, 0)
            saved = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["last_audited_model"], "Gemini 3.1 Pro (High)")
            self.assertIn("last_ack_timestamp", saved)
            self.assertIn("antislop", saved["pending_repo_updates"])
            self.assertTrue(saved.get("acknowledged_reasons"))

            # CLI upstream status --offline does not make network calls
            with mock.patch.object(UpstreamAuditorBridge, "check_repositories") as check_mock:
                rc_offline = cli_main(["upstream", "status", "--offline"])
            self.assertEqual(rc_offline, 0)
            check_mock.assert_not_called()

    def test_upstream_bridge_release_and_path_tracking(self) -> None:
        import contextlib
        import hashlib
        import io
        from guard.cli import main as cli_main
        from guard.upstream import UpstreamAuditorBridge

        state_file = self.tmp / "upstream_state.json"
        state_file.write_text(
            json.dumps({
                "tracked_repositories": {
                    "rea": {
                        "repo": "morluto/rea",
                        "branch": "main",
                        "track": "release",
                        "last_synced_commit": "rea-agents-6.5.0",
                    },
                    "rea-synced": {
                        "repo": "morluto/rea-synced",
                        "branch": "main",
                        "track": "release",
                        "last_synced_commit": "rea-agents-6.7.0",
                    },
                    "scoped": {
                        "repo": "owner/scoped",
                        "branch": "main",
                        "path": "skills/sub",
                        "last_synced_commit": "aaaaaaa",
                    },
                    "bad-path": {
                        "repo": "owner/bad",
                        "branch": "main",
                        "path": "/etc/passwd",
                        "last_synced_commit": "1111111",
                    },
                    "bad-track": {
                        "repo": "owner/bad-track",
                        "branch": "main",
                        "track": "tags",
                        "last_synced_commit": "1111111",
                    },
                },
                "pending_repo_updates": {
                    "rea": {"recorded": "rea-agents-6.5.0", "remote": "rea-agents-6.7.0"},
                    "rea-synced": {"recorded": "rea-agents-6.5.0", "remote": "rea-agents-6.7.0"},
                },
            }),
            encoding="utf-8",
        )

        def fake_safe_fetch(url, user_agent="", timeout=10.0, max_bytes=10_000_000, deadline=None, headers=None):
            if "morluto/rea/releases/latest" in url or "morluto/rea-synced/releases/latest" in url:
                return json.dumps({"tag_name": "rea-agents-6.7.0", "name": "rea-agents 6.7.0"})
            if "owner/scoped/commits" in url and "path=skills%2Fsub" in url:
                return json.dumps([{"sha": "bbbbbbb123456", "commit": {"message": "feat: update sub"}}])
            raise AssertionError(f"Unexpected URL: {url}")

        with mock.patch.dict(os.environ, {
            "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
            "UPSTREAM_STATE_FILE": str(state_file),
        }):
            bridge = UpstreamAuditorBridge(target_dir=self.cfg_dir)
            with mock.patch("porter.net.safe_fetch_url", side_effect=fake_safe_fetch):
                rows = {r["name"]: r for r in bridge.check_repositories()}

            self.assertEqual(rows["rea"]["local_sha"], "rea-agents-6.5.0")
            self.assertEqual(rows["rea"]["remote_sha"], "rea-agents-6.7.0")
            self.assertEqual(rows["rea"]["status"], "Updates Available")
            self.assertEqual(rows["rea-synced"]["status"], "Up-to-date")
            self.assertEqual(rows["scoped"]["local_sha"], "aaaaaaa")
            self.assertEqual(rows["scoped"]["remote_sha"], "bbbbbbb")
            self.assertEqual(rows["scoped"]["status"], "Updates Available")
            self.assertEqual(rows["bad-path"]["status"], "Invalid repository path")
            self.assertEqual(rows["bad-track"]["status"], "Invalid track mode")

            # Offline status preserves full release tag for active pending and ignores stale pending ('rea-synced')
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["upstream", "status", "--offline"])
            self.assertEqual(rc, 0)
            offline_out = buf.getvalue()
            self.assertIn("rea-agents-6.5.0", offline_out)
            self.assertIn("rea-agents-6.7.0", offline_out)
            for line in offline_out.splitlines():
                if line.startswith("rea-synced "):
                    self.assertIn("Recorded", line)

            # acknowledge_drift records the exact non-truncated reason fingerprint matching upstream_watcher.py
            ok, _ = bridge.acknowledge_drift("Gemini 4 Argon (High)")
            self.assertTrue(ok)
            saved = json.loads(state_file.read_text(encoding="utf-8"))
            expected_fp = hashlib.sha256(
                b"New commits in tracked repositories (rea (rea-agents-6.5.0->rea-agents-6.7.0))"
            ).hexdigest()[:16]
            self.assertEqual(saved["acknowledged_reasons"], [expected_fp])



class TestDoctorHooksAndReceipt(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_sync_doctor_"))
        self.cfg = self.tmp / "cfg"
        self.cfg.mkdir(parents=True)
        (self.cfg / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")

    def tearDown(self) -> None:
        from guard.paths import state_dir
        for name in ("hook_strikes.json", "install_receipt.json"):
            (state_dir() / name).unlink(missing_ok=True)
        hermetic.force_rmtree(self.tmp)

    def test_doctor_detects_missing_harness_gate_dangling_script_strikes_and_receipt_mismatch(self) -> None:
        from guard.doctor import diagnose
        from guard.environment import EnvironmentRegistry
        from guard.os_adapter import OSProtectionAdapter
        from guard.paths import state_dir

        adapter = mock.MagicMock(spec=OSProtectionAdapter)
        adapter.protection_issues.return_value = []
        adapter.is_locked.return_value = True

        with mock.patch.dict(os.environ, {"ANTIGRAVITY_CONFIG_DIR": str(self.cfg)}):
            reg = EnvironmentRegistry(config_path=self.tmp / "reg.json", os_adapter=adapter)
            env = reg.get_environment("antigravity")
            state_dir().mkdir(parents=True, exist_ok=True)

            # 1. hooks.json missing harness-gate and pointing to a non-existent script
            (self.cfg / "hooks.json").write_text(
                json.dumps({
                    "upstream-watchdog": {
                        "PreInvocation": [{"type": "command", "command": f"python3 {self.tmp / 'missing_watcher.py'}"}]
                    }
                }),
                encoding="utf-8",
            )
            # 2. hook_strikes.json with tripped circuit breaker (>= 3)
            (state_dir() / "hook_strikes.json").write_text(
                json.dumps({"conv-123": {"count": 3, "updated_at": 1700000000}}),
                encoding="utf-8",
            )
            # 3. install_receipt.json with stale version
            (state_dir() / "install_receipt.json").write_text(
                json.dumps({"version": "1.2.0"}),
                encoding="utf-8",
            )

            report = diagnose(env, reg, sentinel_active=True)
            joined_warnings = "\n".join(report.warnings)
            self.assertIn("harness-gate", joined_warnings)
            self.assertIn("missing_watcher.py", joined_warnings)
            self.assertIn("circuit breaker", joined_warnings)
            self.assertIn("1.2.0", joined_warnings)

            # 4. Clean hooks.json with existing scripts reports info
            valid_script = self.tmp / "valid_hook.py"
            valid_script.write_text("# valid\n", encoding="utf-8")
            (self.cfg / "hooks.json").write_text(
                json.dumps({
                    "upstream-watchdog": {"PreInvocation": [{"type": "command", "command": f"python3 {valid_script}"}]},
                    "harness-gate": {"PreToolUse": [{"type": "command", "command": f"python3 {valid_script}"}]},
                }),
                encoding="utf-8",
            )
            clean_report = diagnose(env, reg, sentinel_active=True)
            self.assertIn("Native lifecycle hooks", "\n".join(clean_report.infos))


class TestGuiSyncAndAuditGate(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_sync_gui_"))
        self.cfg = self.tmp / "cfg"
        self.cfg.mkdir(parents=True)
        (self.cfg / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")

    def tearDown(self) -> None:
        hermetic.reset_approver()
        hermetic.force_rmtree(self.tmp)

    def test_gui_porter_ingest_routes_through_approval_gate_and_blocks_zip(self) -> None:
        from guard import gui
        from guard.audit_log import log_path

        app = gui.AntigravityGuardApp.__new__(gui.AntigravityGuardApp)
        app.porter_bridge = PorterBridge(target_dir=self.cfg)
        app.upstream_bridge = mock.MagicMock()
        app.upstream_bridge.get_model_drift_status.return_value = {
            "active_model": "Gemini 3.1 Pro (High)",
            "model_source": "antigravity_state.pbtxt",
            "tracked_ecosystems": "7",
        }
        app.upstream_bridge.acknowledge_drift.return_value = (True, "Acknowledged")
        app.lbl_upstream_meta = mock.MagicMock()
        app._run_background = lambda work, on_done: on_done(True, work())
        app.refresh_status = mock.MagicMock()

        # 0. Attempting to ingest a .zip archive in GUI shows a Rule 16 error and never invokes approval
        app.ent_porter_source = mock.MagicMock()
        app.ent_porter_source.get.return_value = str(self.tmp / "archive.zip")
        app.current_porter_report = {"is_archive": True, "is_admissible": True}
        with mock.patch("guard.gui.messagebox") as mb_zip:
            app.ingest_porter()
            mb_zip.showerror.assert_called_once()

        rule_file = self.tmp / "gui_rule.md"
        rule_file.write_text("# GUI Rule\nValidate contracts at seams.\n", encoding="utf-8")
        app.ent_porter_source.get.return_value = str(rule_file)
        app.current_porter_report = app.porter_bridge.inspect_source(str(rule_file))

        # 1. When approval is denied, ingest_porter must record approval.refused for 'porter stage'
        hermetic.deny_all()
        with mock.patch("guard.gui.messagebox") as mb:
            app.ingest_porter()
            mb.showinfo.assert_not_called()
        records = [
            json.loads(line)
            for line in log_path().read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertTrue(
            any(r.get("event") == "approval.refused" and r.get("action") == "porter stage" for r in records),
            f"Expected approval.refused for 'porter stage' in audit log, got: {records}",
        )

        # 2. When approval is granted, ingest_porter stages the file and refreshes status
        hermetic.approve_all()
        with mock.patch("guard.gui.messagebox") as mb:
            app.ingest_porter()
            mb.showinfo.assert_called_once()
        app.refresh_status.assert_called_once()

        # 3. Upstream drift acknowledgment refreshes dynamic model label
        with mock.patch("guard.gui.messagebox"):
            app.acknowledge_upstream_drift()
        app.upstream_bridge.acknowledge_drift.assert_called_once()
        app.lbl_upstream_meta.config.assert_called()


class TestPackagingAndBinariesSync(unittest.TestCase):
    def test_build_binaries_collects_scripts_and_package_linux_includes_porter_manifest_and_hooks(self) -> None:
        from installers import build_binaries
        from installers.packaging.package_linux import LinuxPackager

        with (
            mock.patch.object(build_binaries.shutil, "which", return_value="/usr/bin/pyinstaller"),
            mock.patch.object(build_binaries.subprocess, "run", return_value=mock.MagicMock(returncode=1)) as run_mock,
        ):
            build_binaries.main()
            cmd = run_mock.call_args[0][0]
            self.assertIn("scripts", cmd)
            self.assertIn("scripts.code_map", cmd)
            self.assertIn("scripts.meta_audit", cmd)
            self.assertIn("scripts.verify_invariants", cmd)

        with tempfile.TemporaryDirectory() as stage_tmp:
            stage = Path(stage_tmp)
            packager = LinuxPackager(repo_root=REPO_ROOT, arch="amd64", out_dir=stage / "out")
            packager.prepare_payload(stage)

            self.assertTrue((stage / "usr" / "bin" / "agy-porter").is_file())
            self.assertTrue((stage / "usr" / "lib" / "antigravity-guard" / "porter.py").is_file())
            self.assertTrue((stage / "usr" / "share" / "antigravity-harness" / "hooks.json").is_file())
            self.assertTrue((stage / "usr" / "share" / "antigravity-harness" / ".harness" / "manifest.json").is_file())

            with mock.patch("installers.packaging.package_linux.shutil.which", return_value=None):
                spec_path = packager.build_rpm()
            spec_text = spec_path.read_text(encoding="utf-8")
            self.assertIn("/usr/bin/agy-porter", spec_text)


if __name__ == "__main__":
    unittest.main()
