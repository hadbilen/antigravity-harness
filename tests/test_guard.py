"""
tests/test_guard.py — Comprehensive Unit Test Suite for Antigravity Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from guard import __version__
from guard.cli import main as cli_main
from guard.integrity import FileIntegrityMonitor
from guard.os_adapter import OSProtectionAdapter
from guard.porter_bridge import PorterBridge
from guard.snapshot import SnapshotEngine


class TestFileIntegrityMonitor(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_guard_fim_"))
        self.state_file = self.test_dir / ".guard_integrity.json"
        self.monitor = FileIntegrityMonitor(target_dir=self.test_dir, state_file=self.state_file)

        # Create dummy test files
        (self.test_dir / "GEMINI.md").write_text("# Test Constitution", encoding="utf-8")
        skills_dir = self.test_dir / "skills" / "demo"
        skills_dir.mkdir(parents=True)
        (skills_dir / "SKILL.md").write_text("# Demo Skill", encoding="utf-8")

    def tearDown(self):
        # Restore permissions in case test left it read-only
        try:
            for root, dirs, files in os.walk(self.test_dir):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o777)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o666)
            shutil.rmtree(self.test_dir, ignore_errors=True)
        except Exception:
            pass

    def test_baseline_and_verify_clean(self):
        count, path = self.monitor.save_baseline()
        self.assertEqual(count, 2)
        self.assertTrue(Path(path).is_file())

        report = self.monitor.verify()
        self.assertTrue(report.is_intact)
        self.assertEqual(len(report.modified), 0)
        self.assertEqual(len(report.added), 0)
        self.assertEqual(len(report.deleted), 0)

    def test_detect_modified_file(self):
        self.monitor.save_baseline()
        (self.test_dir / "GEMINI.md").write_text("# Tampered Constitution", encoding="utf-8")

        report = self.monitor.verify()
        self.assertFalse(report.is_intact)
        self.assertIn("GEMINI.md", report.modified)

    def test_detect_added_file(self):
        self.monitor.save_baseline()
        (self.test_dir / "unauthorized.txt").write_text("rogue data", encoding="utf-8")

        report = self.monitor.verify()
        self.assertFalse(report.is_intact)
        self.assertIn("unauthorized.txt", report.added)

    def test_detect_deleted_file(self):
        self.monitor.save_baseline()
        (self.test_dir / "skills" / "demo" / "SKILL.md").unlink()

        report = self.monitor.verify()
        self.assertFalse(report.is_intact)
        self.assertIn("skills/demo/SKILL.md", report.deleted)

    def test_save_baseline_while_locked(self):
        adapter = OSProtectionAdapter(target_dir=self.test_dir)
        adapter.lock()
        self.assertTrue(adapter.is_locked())
        try:
            count, path = self.monitor.save_baseline()
            self.assertEqual(count, 2)
            self.assertTrue(adapter.is_locked())
        finally:
            adapter.unlock()

    def test_isolated_trust_anchor(self):
        isolated_dir = Path(tempfile.mkdtemp(prefix="test_isolated_anchor_"))
        isolated_file = isolated_dir / "custom_anchor.json"
        try:
            custom_monitor = FileIntegrityMonitor(target_dir=self.test_dir, state_file=isolated_file)
            self.assertTrue(custom_monitor.is_isolated)
            cnt, pth = custom_monitor.save_baseline()
            self.assertEqual(cnt, 2)
            self.assertTrue(isolated_file.is_file())
            rep = custom_monitor.verify()
            self.assertTrue(rep.is_intact)
        finally:
            shutil.rmtree(isolated_dir, ignore_errors=True)


class TestSnapshotEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_guard_snap_"))
        self.engine = SnapshotEngine(target_dir=self.test_dir)
        (self.test_dir / "config.json").write_text('{"state": "original"}', encoding="utf-8")

    def tearDown(self):
        try:
            OSProtectionAdapter(target_dir=self.test_dir).unlock()
        except Exception:
            pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_create_and_restore_snapshot(self):
        snap_id, snap_path = self.engine.create_snapshot(label="test_snap")
        self.assertTrue(snap_path.is_dir())
        self.assertIn("test_snap", snap_id)

        # Mutate current state
        (self.test_dir / "config.json").write_text('{"state": "mutated"}', encoding="utf-8")
        (self.test_dir / "new_file.txt").write_text("temp", encoding="utf-8")

        # Restore snapshot
        success, msg = self.engine.restore_snapshot(snap_id)
        self.assertTrue(success)
        restored_content = (self.test_dir / "config.json").read_text(encoding="utf-8")
        self.assertEqual(restored_content, '{"state": "original"}')
        self.assertFalse((self.test_dir / "new_file.txt").exists())

    def test_restore_snapshot_prunes_extraneous_files(self):
        snap_id, _ = self.engine.create_snapshot(label="clean_state")

        # Add an unauthorized file and directory after snapshot was taken
        rogue_file = self.test_dir / "unauthorized_rule.txt"
        rogue_file.write_text("rogue rule", encoding="utf-8")
        rogue_dir = self.test_dir / "rogue_dir"
        rogue_dir.mkdir()
        (rogue_dir / "subfile.txt").write_text("rogue subfile", encoding="utf-8")

        self.assertTrue(rogue_file.exists())
        self.assertTrue(rogue_dir.exists())

        # Restore snapshot
        success, msg = self.engine.restore_snapshot(snap_id)
        self.assertTrue(success)

        # Assert full state restoration: extraneous files and dirs must be PRUNED
        self.assertFalse(rogue_file.exists())
        self.assertFalse(rogue_dir.exists())
        self.assertTrue((self.test_dir / "config.json").exists())

    def test_list_and_prune_snapshots(self):
        for i in range(4):
            self.engine.create_snapshot(label=f"snap_{i}")

        snaps = self.engine.list_snapshots()
        self.assertEqual(len(snaps), 4)

        pruned = self.engine.prune_snapshots(keep=2)
        self.assertEqual(pruned, 2)
        self.assertEqual(len(self.engine.list_snapshots()), 2)

    def test_snapshot_lifecycle_while_locked(self):
        adapter = OSProtectionAdapter(target_dir=self.test_dir)
        adapter.lock()
        self.assertTrue(adapter.is_locked())
        try:
            snap_id, snap_path = self.engine.create_snapshot(label="locked_test")
            self.assertTrue(adapter.is_locked())
            self.assertTrue(snap_path.is_dir())

            # Mutate state by briefly unlocking then relocking to test restore while locked
            adapter.unlock()
            (self.test_dir / "config.json").write_text('{"state": "mutated_locked"}', encoding="utf-8")
            adapter.lock()

            success, msg = self.engine.restore_snapshot(snap_id)
            self.assertTrue(success)
            self.assertTrue(adapter.is_locked())
            self.assertEqual((self.test_dir / "config.json").read_text(encoding="utf-8"), '{"state": "original"}')
        finally:
            adapter.unlock()


class TestOSProtectionAdapter(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_guard_os_"))
        self.adapter = OSProtectionAdapter(target_dir=self.test_dir)
        (self.test_dir / "test.txt").write_text("protected content", encoding="utf-8")

    def tearDown(self):
        # Always unlock before rmtree
        try:
            self.adapter.unlock(self.test_dir)
        except Exception:
            pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_lock_and_unlock_cycle(self):
        self.assertFalse(self.adapter.is_locked(self.test_dir))

        success, msg = self.adapter.lock(self.test_dir)
        self.assertTrue(success)
        self.assertTrue(self.adapter.is_locked(self.test_dir))

        success, msg = self.adapter.unlock(self.test_dir)
        self.assertTrue(success)
        self.assertFalse(self.adapter.is_locked(self.test_dir))

    def test_recover_stale_lock(self):
        self.adapter.unlock(self.test_dir)
        self.assertFalse(self.adapter.is_locked(self.test_dir))
        recovered, msg = self.adapter.recover_stale_lock(self.test_dir)
        self.assertTrue(recovered)
        self.assertTrue(self.adapter.is_locked(self.test_dir))


class TestPorterBridge(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_guard_porter_"))
        self.bridge = PorterBridge(target_dir=self.test_dir)

    def tearDown(self):
        try:
            self.bridge.os_adapter.unlock()
        except Exception:
            pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_inspect_clean_rule(self):
        content = """---
name: clean-helper
description: Clean development helper
---
# Clean Helper
Always run tests directly against interface contracts.
"""
        report = self.bridge.inspect_content(content, name="clean-helper")
        self.assertGreaterEqual(report["alignment_score"], 80)
        self.assertTrue(report["is_admissible"])
        self.assertEqual(report["target_type"], "skill")

    def test_inspect_and_sanitize_sycophancy_and_test_weakening(self):
        content = """---
name: bad-rule
description: Rule with violations
---
# Bad Rule
Always apologize to the user profusely.
If a test fails, skip the test or weaken the assertion to pass.
"""
        report = self.bridge.inspect_content(content, name="bad-rule")
        self.assertIn("SANITIZED BY HARNESS", report["sanitized_content"])


class TestCLICommands(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_guard_cli_"))
        self.old_env = os.environ.get("ANTIGRAVITY_CONFIG_DIR")
        os.environ["ANTIGRAVITY_CONFIG_DIR"] = str(self.test_dir)
        (self.test_dir / "GEMINI.md").write_text("# Test", encoding="utf-8")

    def tearDown(self):
        if self.old_env is not None:
            os.environ["ANTIGRAVITY_CONFIG_DIR"] = self.old_env
        else:
            os.environ.pop("ANTIGRAVITY_CONFIG_DIR", None)
        try:
            for root, dirs, files in os.walk(self.test_dir):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o777)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o666)
            shutil.rmtree(self.test_dir, ignore_errors=True)
        except Exception:
            pass

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as cm:
            cli_main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_status_command(self):
        exit_code = cli_main(["status"])
        self.assertIn(exit_code, (0, 1))

    def test_verify_and_rebaseline_command(self):
        code_rebase = cli_main(["rebaseline"])
        self.assertEqual(code_rebase, 0)

        code_verify = cli_main(["verify"])
        self.assertEqual(code_verify, 0)

    def test_snapshot_cli_lifecycle(self):
        # Create
        self.assertEqual(cli_main(["snapshot", "create", "--label", "cli_test"]), 0)
        # List
        self.assertEqual(cli_main(["snapshot", "list"]), 0)
        # Prune
        self.assertEqual(cli_main(["snapshot", "prune", "--keep", "1"]), 0)

    def test_porter_inspect_cli(self):
        rule_file = self.test_dir / "sample_rule.md"
        rule_file.write_text("# Sample Rule\nEnsure pure functions.", encoding="utf-8")
        exit_code = cli_main(["porter", "inspect", str(rule_file)])
        self.assertEqual(exit_code, 0)

    def test_upstream_check_cli(self):
        exit_code = cli_main(["upstream", "status"])
        self.assertEqual(exit_code, 0)

    def test_doctor_command(self):
        cli_main(["rebaseline"])
        exit_code = cli_main(["doctor", "--fix"])
        self.assertEqual(exit_code, 0)


class TestTrayAndSnapshotEnhancements(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_guard_enhancements_"))
        (self.temp_dir / "sample.txt").write_text("Hello Snapshot World", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_tray_adapter_factory(self):
        from guard.tray import create_tray_adapter, BaseTrayAdapter
        adapter = create_tray_adapter(lambda: None, lambda: None, lambda: None)
        self.assertIsInstance(adapter, BaseTrayAdapter)
        self.assertIsInstance(adapter.is_available, bool)

    def test_shield_icon_generation(self):
        from guard.tray import generate_shield_icon, PIL_AVAILABLE
        if PIL_AVAILABLE:
            img = generate_shield_icon(True, size=64)
            self.assertIsNotNone(img)
            self.assertEqual(img.size, (64, 64))

            img_unlocked = generate_shield_icon(False, size=32)
            self.assertIsNotNone(img_unlocked)
            self.assertEqual(img_unlocked.size, (32, 32))

    def test_snapshot_inspection_and_traversal_guard(self):
        engine = SnapshotEngine(self.temp_dir)
        snap_id, _ = engine.create_snapshot(label="inspect_test")

        files = engine.get_snapshot_files(snap_id)
        self.assertIn("sample.txt", files)

        content = engine.read_snapshot_file(snap_id, "sample.txt")
        self.assertEqual(content, "Hello Snapshot World")

        # Traversal attempt must be rejected and return None
        traversal = engine.read_snapshot_file(snap_id, "../../../etc/passwd")
        self.assertIsNone(traversal)

    def test_gui_design_disabled_tokens(self):
        from guard.gui import BG_DISABLED, TEXT_MUTED, TEXT_DISABLED
        self.assertEqual(BG_DISABLED, "#27272A")
        self.assertEqual(TEXT_MUTED, "#A1A1AA")
        self.assertEqual(TEXT_DISABLED, "#71717A")


class TestV126HardeningAndStartup(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_guard_v126_"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_version_alignment(self):
        import guard
        import porter
        from porter.models import UniversalManifest
        self.assertEqual(guard.__version__, "1.2.9")
        self.assertEqual(porter.__version__, "1.2.9")
        self.assertEqual(UniversalManifest.version, "1.2.9")

    def test_agent_classification_routing(self):
        bridge = PorterBridge(target_dir=self.test_dir)
        agent_content = """# security-verifier
You are an autonomous subagent and auditor responsible for inspecting security boundaries.
Never skip tests. Always be objective.
"""
        src_file = self.test_dir / "sec_verifier.md"
        src_file.write_text(agent_content, encoding="utf-8")

        success, msg = bridge.stage_and_ingest(str(src_file), force=True)
        self.assertTrue(success, f"Stage failed: {msg}")

        # Invariant: Agent must be routed to agents/, never to rules/
        expected_agent = self.test_dir / "agents" / "security-verifier.md"
        wrong_rule = self.test_dir / "rules" / "security-verifier.md"

        self.assertTrue(expected_agent.is_file(), f"Expected agent file {expected_agent} does not exist")
        self.assertFalse(wrong_rule.exists(), f"Agent was mistakenly placed in rules/: {wrong_rule}")

    def test_snapshot_path_traversal_guards(self):
        engine = SnapshotEngine(self.test_dir)
        snap_id, _ = engine.create_snapshot(label="safe_snap")

        # 1. Traversal snap_id in restore_snapshot
        ok, msg = engine.restore_snapshot("../../etc")
        self.assertFalse(ok)
        self.assertIn("Invalid snapshot", msg)

        # 2. Malformed characters in snap_id
        ok, msg = engine.restore_snapshot("snap;rm -rf /")
        self.assertFalse(ok)
        self.assertIn("Invalid snapshot", msg)

        # 3. Traversal in get_snapshot_files
        self.assertEqual(engine.get_snapshot_files("../../outside"), [])

        # 4. Traversal in read_snapshot_file
        self.assertIsNone(engine.read_snapshot_file(snap_id, "../../../../etc/passwd"))
        self.assertIsNone(engine.read_snapshot_file("../../etc", "passwd"))

    def test_ssrf_protection_in_porter_and_bridge(self):
        from porter.net import validate_safe_url
        bridge = PorterBridge(target_dir=self.test_dir)

        # 1. Direct validation tests
        with self.assertRaises(ValueError):
            validate_safe_url("http://127.0.0.1:8080/secret")
        with self.assertRaises(ValueError):
            validate_safe_url("http://localhost:3000/api")
        with self.assertRaises(ValueError):
            validate_safe_url("http://169.254.169.254/latest/meta-data")

        # 2. Bridge inspect_source SSRF rejection
        with self.assertRaises(ValueError):
            bridge.inspect_source("http://127.0.0.1/rogue_rule.md")

    def test_symlink_fim_scan(self):
        # Create external directory mimicking repo skills
        external_dir = Path(tempfile.mkdtemp(prefix="ext_skills_"))
        skill_a = external_dir / "harness"
        skill_a.mkdir(parents=True)
        (skill_a / "SKILL.md").write_text("# Harness Skill Content", encoding="utf-8")

        # Create target config dir with symlink pointing to external_dir
        skills_target = self.test_dir / "skills"
        skills_target.mkdir(parents=True)
        link_dest = skills_target / "harness"
        try:
            link_dest.symlink_to(skill_a, target_is_directory=True)
        except (OSError, NotImplementedError):
            # If symlinks not supported, skip
            shutil.rmtree(external_dir, ignore_errors=True)
            return

        monitor = FileIntegrityMonitor(target_dir=self.test_dir)
        scanned = monitor.scan_directory()

        # Invariant: Files inside symlinked directory must be scanned and hashed
        self.assertIn("skills/harness/SKILL.md", scanned)
        shutil.rmtree(external_dir, ignore_errors=True)

    def test_startup_manager_lifecycle(self):
        from guard.startup import StartupManager
        mgr = StartupManager(target_dir=self.test_dir)
        st = mgr.status()
        self.assertIn("platform", st)
        self.assertIn("mechanism", st)

        # Boot check execution
        ok, msg = mgr.execute_boot_check()
        self.assertIn("[FIM", msg)
        self.assertIn("[LOCK", msg)


class TestV126Bugfixes(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_v126_fixes_"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_porter_import_re_no_name_error(self):
        import subprocess
        import sys
        src_file = self.test_dir / "rule.md"
        src_file.write_text("# Test Rule\nDo not bypass tests.", encoding="utf-8")
        repo_root = Path(__file__).resolve().parent.parent
        res = subprocess.run(
            [sys.executable, str(repo_root / "porter.py"), "import", str(src_file), "--dry-run"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(res.returncode, 0, f"porter.py failed: {res.stderr}")
        self.assertIn("[DRY-RUN]", res.stdout)

    def test_upstream_state_resolution(self):
        from guard.upstream import UpstreamAuditorBridge

        old_file_env = os.environ.get("UPSTREAM_STATE_FILE")
        old_xdg_env = os.environ.get("XDG_STATE_HOME")

        # 1. Custom UPSTREAM_STATE_FILE
        custom_state = self.test_dir / "custom_state.json"
        custom_state.write_text('{"tracked_repositories": {}}', encoding="utf-8")
        try:
            os.environ["UPSTREAM_STATE_FILE"] = str(custom_state)
            bridge = UpstreamAuditorBridge(target_dir=self.test_dir)
            self.assertEqual(bridge.state_file, custom_state.resolve())
        finally:
            if old_file_env is not None:
                os.environ["UPSTREAM_STATE_FILE"] = old_file_env
            else:
                os.environ.pop("UPSTREAM_STATE_FILE", None)

        # 2. Legacy fallback when XDG state does not exist
        try:
            clean_xdg = self.test_dir / "clean_xdg"
            os.environ["XDG_STATE_HOME"] = str(clean_xdg)
            legacy_dir = self.test_dir / "skills" / "upstream-auditor"
            legacy_dir.mkdir(parents=True)
            legacy_file = (legacy_dir / "upstream_state.json").resolve()
            legacy_file.write_text('{"tracked_repositories": {}}', encoding="utf-8")

            bridge_legacy = UpstreamAuditorBridge(target_dir=self.test_dir)
            self.assertEqual(bridge_legacy.state_file, legacy_file)

            # 3. Primary XDG state when it exists
            primary_dir = (clean_xdg / "antigravity-harness").resolve()
            primary_dir.mkdir(parents=True)
            primary_file = (primary_dir / "upstream_state.json").resolve()
            primary_file.write_text('{"tracked_repositories": {}}', encoding="utf-8")

            bridge_primary = UpstreamAuditorBridge(target_dir=self.test_dir)
            self.assertEqual(bridge_primary.state_file, primary_file)
        finally:
            if old_xdg_env is not None:
                os.environ["XDG_STATE_HOME"] = old_xdg_env
            else:
                os.environ.pop("XDG_STATE_HOME", None)

    def test_porter_bridge_relock_failure_detection(self):
        class MockFailingLockAdapter(OSProtectionAdapter):
            def lock(self, target=None):
                return False, "Simulated permission denial"

        adapter = MockFailingLockAdapter(target_dir=self.test_dir)
        bridge = PorterBridge(target_dir=self.test_dir, os_adapter=adapter)
        src = self.test_dir / "test_rule.md"
        src.write_text("# Rule\nObjective rule.", encoding="utf-8")

        success, msg = bridge.stage_and_ingest(str(src), force=True)
        self.assertFalse(success)
        self.assertIn("Re-lock failed", msg)

    def test_fim_verify_without_baseline_returns_false(self):
        monitor = FileIntegrityMonitor(target_dir=self.test_dir)
        (self.test_dir / "file.txt").write_text("hello", encoding="utf-8")
        report = monitor.verify()
        self.assertFalse(report.is_intact)
        self.assertFalse(monitor.state_file.exists())
        self.assertIn("BASELINE MISSING", report.deleted[0])

    def test_manifest_engine_dynamic_version(self):
        from porter.manifest import ManifestEngine
        engine = ManifestEngine()
        manifest = engine.build_manifest()
        self.assertEqual(manifest.version, "1.2.9")

    def test_rapid_snapshot_same_second_no_collision(self):
        engine = SnapshotEngine(target_dir=self.test_dir)
        (self.test_dir / "sample.txt").write_text("v1", encoding="utf-8")
        snap1_id, path1 = engine.create_snapshot(label="snap1")
        snap2_id, path2 = engine.create_snapshot(label="snap2")
        self.assertNotEqual(snap1_id, snap2_id)
        self.assertTrue(path1.is_dir())
        self.assertTrue(path2.is_dir())
        snapshots = engine.list_snapshots()
        self.assertEqual(len(snapshots), 2)

    def test_upstream_auditor_model_drift_status_keys(self):
        from guard.upstream import UpstreamAuditorBridge
        bridge = UpstreamAuditorBridge(target_dir=self.test_dir)
        info = bridge.get_model_drift_status()
        self.assertIn("active_model", info)
        self.assertIn("tracked_ecosystems", info)
        self.assertTrue(str(info["tracked_ecosystems"]).isdigit())


if __name__ == "__main__":
    unittest.main()


