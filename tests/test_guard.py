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


if __name__ == "__main__":
    unittest.main()

