"""
tests/test_protection.py — Regression tests for the Guard protection core:
OS lock semantics, environment registry, integrity monitor, snapshot/restore and leases.
"""

from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)

import json
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from guard.environment import AgentEnvironment, EnvironmentRegistry, RegistryError, make_env_id
from guard.integrity import FileIntegrityMonitor
from guard.lease import LeaseManager
from guard.notifier import GuardNotifier
from guard.os_adapter import OSProtectionAdapter
from guard.snapshot import SnapshotEngine

POSIX = os.name != "nt"
posix_only = unittest.skipUnless(POSIX, "POSIX permission semantics")
not_root = unittest.skipIf(hermetic.IS_ROOT, "root bypasses permission bits")


def _mode(p: Path) -> int:
    return stat.S_IMODE(os.lstat(p).st_mode)


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="agy_protection_"))

    def tearDown(self):
        hermetic.reset_approver()
        hermetic.force_rmtree(self.root)


class TestOSAdapter(TempDirCase):
    @posix_only
    def test_lock_never_modifies_symlink_targets_outside_the_tree(self):
        outside = self.root / "outside.md"
        outside.write_text("repo file", encoding="utf-8")
        os.chmod(outside, 0o664)
        tree = self.root / "tree"
        tree.mkdir()
        (tree / "linked.md").symlink_to(outside)
        (tree / "real.md").write_text("x", encoding="utf-8")

        adapter = OSProtectionAdapter(tree)
        ok, msg = adapter.lock(tree)
        self.assertFalse(ok, "a tree with an external symlink is not fully protected")
        self.assertIn("outside the protected tree", msg)
        self.assertEqual(_mode(outside), 0o664, "the symlink target must never be chmod'ed")
        self.assertFalse(adapter.is_locked(tree))
        self.assertTrue(any("outside" in i for i in adapter.protection_issues(tree)))

    @posix_only
    def test_top_level_symlink_is_reported_not_followed(self):
        outside = self.root / "GEMINI.md"
        outside.write_text("rules", encoding="utf-8")
        tree = self.root / "cfg"
        tree.mkdir()
        (tree / "GEMINI.md").symlink_to(outside)
        adapter = OSProtectionAdapter(tree)
        ok, msg = adapter.lock([tree / "GEMINI.md"])
        self.assertFalse(ok)
        self.assertIn("symlink", msg)
        self.assertTrue(os.access(outside, os.W_OK))

    @posix_only
    def test_unlock_restores_original_modes(self):
        f = self.root / "group_writable.md"
        f.write_text("x", encoding="utf-8")
        os.chmod(f, 0o664)
        adapter = OSProtectionAdapter(self.root)
        self.assertTrue(adapter.lock(self.root)[0])
        self.assertEqual(_mode(f), 0o444)
        self.assertTrue(adapter.unlock(self.root)[0])
        self.assertEqual(_mode(f), 0o664)

    @posix_only
    @not_root
    def test_lock_reports_failure_when_chmod_fails(self):
        (self.root / "a.md").write_text("x", encoding="utf-8")
        adapter = OSProtectionAdapter(self.root)
        with mock.patch("guard.os_adapter.os.chmod", side_effect=PermissionError("denied")):
            ok, msg = adapter.lock(self.root)
        self.assertFalse(ok)
        self.assertIn("PARTIAL LOCK", msg)

    def test_missing_target_fails(self):
        ok, _ = OSProtectionAdapter(self.root).lock(self.root / "nope")
        self.assertFalse(ok)


class TestRegistry(TempDirCase):
    def _registry(self, **kw):
        return EnvironmentRegistry(config_path=self.root / "registry.json", **kw)

    def test_default_location_is_state_dir_not_cwd(self):
        ws = self.root / "ws"
        (ws / ".harness").mkdir(parents=True)
        cwd = os.getcwd()
        try:
            os.chdir(ws)
            reg = EnvironmentRegistry()
        finally:
            os.chdir(cwd)
        self.assertNotIn(str(ws), str(reg.config_path))
        self.assertTrue(str(reg.config_path).startswith(os.environ["XDG_STATE_HOME"]))

    def test_same_folder_name_different_paths_get_different_ids(self):
        a, b = self.root / "one" / "app", self.root / "two" / "app"
        self.assertNotEqual(make_env_id("claude", a), make_env_id("claude", b))
        for ws in (a, b):
            ws.mkdir(parents=True)
            (ws / "CLAUDE.md").write_text("# rules", encoding="utf-8")
        reg = self._registry()
        reg.discover_environments(workspace_dir=a)
        reg.discover_environments(workspace_dir=b)
        claude_envs = [e for e in reg.list_environments() if e.platform_type == "claude"]
        self.assertEqual(len(claude_envs), 2)

    def test_ambiguous_prefix_is_rejected(self):
        reg = self._registry()
        for i in (1, 2):
            reg.register_environment(AgentEnvironment(id=f"claude-x-{i}", name="c", platform_type="claude", root_path=str(self.root)))
        env, err = reg.resolve_environment("claude")
        self.assertIsNone(env)
        self.assertIn("ambiguous", err)
        self.assertEqual(reg.get_environment("claude-x-1").id, "claude-x-1")

    @posix_only
    @not_root
    def test_save_failure_raises_registry_error(self):
        locked = self.root / "locked"
        locked.mkdir()
        os.chmod(locked, 0o555)
        reg = EnvironmentRegistry(config_path=locked / "registry.json")
        with self.assertRaises(RegistryError):
            reg.set_policy("antigravity", "monitored")

    @posix_only
    def test_global_environment_locks_seams_and_root_but_not_runtime_state(self):
        cfg = Path(os.environ["ANTIGRAVITY_CONFIG_DIR"])
        cfg.mkdir(parents=True, exist_ok=True)
        (cfg / "GEMINI.md").write_text("rules", encoding="utf-8")
        (cfg / "skills" / "demo").mkdir(parents=True, exist_ok=True)
        (cfg / "skills" / "demo" / "SKILL.md").write_text("---\nname: demo\n---\n", encoding="utf-8")
        (cfg / "config.json").write_text("{}", encoding="utf-8")
        (cfg / "projects").mkdir(exist_ok=True)
        reg = self._registry()
        try:
            ok, msg = reg.lock("antigravity")
            self.assertTrue(ok, msg)
            self.assertTrue(reg.is_locked("antigravity")["antigravity"])
            self.assertFalse(os.access(cfg / "GEMINI.md", os.W_OK) and not hermetic.IS_ROOT)
            self.assertTrue(os.access(cfg / "config.json", os.W_OK), "Antigravity runtime state stays writable")
            self.assertTrue(os.access(cfg / "projects", os.W_OK))
            self.assertEqual(reg.protection_issues(reg.get_environment("antigravity")), [])
        finally:
            reg.unlock("antigravity")
            hermetic.force_rmtree(cfg)


class TestIntegrity(TempDirCase):
    def test_baseline_lives_outside_the_target(self):
        mon = FileIntegrityMonitor(target_dir=self.root)
        self.assertTrue(mon.is_isolated)
        self.assertFalse(str(mon.state_file).startswith(str(self.root)))

    def test_foreign_environments_get_their_own_baseline(self):
        a = FileIntegrityMonitor(target_dir=self.root / "a")
        b = FileIntegrityMonitor(target_dir=self.root / "b")
        self.assertNotEqual(a.state_file, b.state_file)

    def test_missing_baseline_is_reported_as_missing_not_as_a_deleted_file(self):
        for name in ("GEMINI.md", "DESIGN.md"):
            (self.root / name).write_text("x", encoding="utf-8")
        report = FileIntegrityMonitor(target_dir=self.root).verify()
        self.assertFalse(report.is_intact)
        self.assertEqual(report.baseline_status, "missing")
        self.assertIn("BASELINE MISSING", report.summary())
        self.assertNotIn("deleted", report.summary())

    @posix_only
    @not_root
    def test_unreadable_file_is_reported(self):
        f = self.root / "secret.md"
        f.write_text("x", encoding="utf-8")
        mon = FileIntegrityMonitor(target_dir=self.root)
        mon.save_baseline()
        os.chmod(f, 0)
        try:
            report = mon.verify()
        finally:
            os.chmod(f, 0o644)
        self.assertFalse(report.is_intact)
        self.assertIn("secret.md", report.unreadable)

    @posix_only
    def test_symlink_cycle_in_target_paths_terminates_without_duplicates(self):
        real = self.root / "real"
        real.mkdir()
        (real / "f.txt").write_text("x", encoding="utf-8")
        (real / "loop").symlink_to(real, target_is_directory=True)
        mon = FileIntegrityMonitor(target_dir=self.root, target_paths=[real])
        scanned = mon.scan_directory()
        self.assertEqual([k for k in scanned if k.endswith("f.txt")], ["real/f.txt"])
        self.assertTrue(scanned["real/loop"].startswith("symlink:"))

    def test_installer_backups_are_excluded(self):
        (self.root / "backup_20260101_000000").mkdir()
        (self.root / "backup_20260101_000000" / "old.md").write_text("x", encoding="utf-8")
        (self.root / "GEMINI.md").write_text("x", encoding="utf-8")
        self.assertEqual(list(FileIntegrityMonitor(target_dir=self.root).scan_directory()), ["GEMINI.md"])

    @posix_only
    def test_symlink_retargeting_is_detected(self):
        a, b = self.root / "a.md", self.root / "b.md"
        a.write_text("same", encoding="utf-8")
        b.write_text("same", encoding="utf-8")
        tree = self.root / "tree"
        tree.mkdir()
        (tree / "rule.md").symlink_to(a)
        mon = FileIntegrityMonitor(target_dir=tree)
        mon.save_baseline()
        (tree / "rule.md").unlink()
        (tree / "rule.md").symlink_to(b)
        self.assertIn("rule.md", mon.verify().modified)

    @posix_only
    @not_root
    def test_save_baseline_does_not_unlock_target_when_baseline_is_external(self):
        (self.root / "GEMINI.md").write_text("x", encoding="utf-8")
        adapter = OSProtectionAdapter(self.root)
        adapter.lock(self.root)
        mon = FileIntegrityMonitor(target_dir=self.root, os_adapter=adapter)
        with mock.patch.object(adapter, "unlock", wraps=adapter.unlock) as unlock:
            mon.save_baseline()
        unlock.assert_not_called()
        self.assertTrue(adapter.is_locked(self.root))


class TestSnapshots(TempDirCase):
    def setUp(self):
        super().setUp()
        self.target = self.root / "cfg"
        self.target.mkdir()
        (self.target / "GEMINI.md").write_text("v1", encoding="utf-8")

    @posix_only
    def test_broken_symlink_does_not_crash_snapshot(self):
        (self.target / "dangling").symlink_to(self.root / "does-not-exist")
        engine = SnapshotEngine(self.target)
        snap_id, path = engine.create_snapshot(label="with_link")
        self.assertTrue(os.path.islink(path / "dangling"))

    def test_snapshots_are_stored_outside_the_target(self):
        engine = SnapshotEngine(self.target)
        _, path = engine.create_snapshot()
        self.assertFalse(str(path).startswith(str(self.target)))

    @posix_only
    def test_restore_refuses_to_write_through_destination_symlink(self):
        engine = SnapshotEngine(self.target)
        snap_id, _ = engine.create_snapshot()
        outside = self.root / "repo_GEMINI.md"
        outside.write_text("repo", encoding="utf-8")
        (self.target / "GEMINI.md").unlink()
        (self.target / "GEMINI.md").symlink_to(outside)
        ok, msg = engine.restore_snapshot(snap_id)
        self.assertFalse(ok)
        self.assertIn("symlink", msg)
        self.assertEqual(outside.read_text(encoding="utf-8"), "repo")

    def test_restore_aborts_when_emergency_backup_fails(self):
        engine = SnapshotEngine(self.target)
        snap_id, _ = engine.create_snapshot()
        (self.target / "GEMINI.md").write_text("v2", encoding="utf-8")
        original = engine.create_snapshot

        def failing(label=None, kind="manual"):
            if kind == "pre_rollback":
                raise OSError("disk full")
            return original(label=label, kind=kind)

        with mock.patch.object(engine, "create_snapshot", side_effect=failing):
            ok, msg = engine.restore_snapshot(snap_id)
        self.assertFalse(ok)
        self.assertIn("aborted", msg)
        self.assertEqual((self.target / "GEMINI.md").read_text(encoding="utf-8"), "v2")

    def test_restore_rebaselines_and_backup_has_metadata(self):
        monitor = FileIntegrityMonitor(target_dir=self.target)
        engine = SnapshotEngine(self.target, integrity_monitor=monitor)
        snap_id, _ = engine.create_snapshot()
        (self.target / "GEMINI.md").write_text("v2", encoding="utf-8")
        ok, msg = engine.restore_snapshot(snap_id)
        self.assertTrue(ok, msg)
        self.assertTrue(monitor.verify().is_intact)
        kinds = {s["kind"] for s in engine.list_snapshots()}
        self.assertIn("pre_rollback", kinds)
        self.assertNotIn("unknown", kinds)

    def test_prune_keeps_quota_per_kind(self):
        engine = SnapshotEngine(self.target)
        for i in range(3):
            engine.create_snapshot(label=f"m{i}")
        for i in range(2):
            engine.create_snapshot(label=f"p{i}", kind="pre_rollback")
        engine.prune_snapshots(keep=1)
        kinds = sorted(s["kind"] for s in engine.list_snapshots())
        self.assertEqual(kinds, ["manual", "pre_rollback"])

    def test_tampered_snapshot_is_not_restored(self):
        engine = SnapshotEngine(self.target)
        snap_id, path = engine.create_snapshot()
        (path / "GEMINI.md").write_text("evil", encoding="utf-8")
        ok, msg = engine.restore_snapshot(snap_id)
        self.assertFalse(ok)
        self.assertIn("verification", msg)

    def test_environment_snapshot_excludes_runtime_state(self):
        (self.target / "config.json").write_text('{"token": "x"}', encoding="utf-8")
        reg = EnvironmentRegistry(config_path=self.root / "reg.json")
        env = AgentEnvironment(id="t", name="t", platform_type="antigravity", root_path=str(self.target),
                               governance_paths=["GEMINI.md", "skills"], protect_root=True)
        reg.register_environment(env)
        engine = SnapshotEngine.for_environment(env, reg)
        _, path = engine.create_snapshot()
        self.assertTrue((path / "GEMINI.md").exists())
        self.assertFalse((path / "config.json").exists())


class TestLeaseLifecycle(TempDirCase):
    def setUp(self):
        super().setUp()
        self.adapter = mock.MagicMock(spec=OSProtectionAdapter)
        self.adapter.lock.return_value = (True, "locked")
        self.adapter.unlock.return_value = (True, "unlocked")
        self.adapter.protection_issues.return_value = []
        self.reg = EnvironmentRegistry(config_path=self.root / "reg.json", os_adapter=self.adapter)
        for name in ("env_a", "env_b"):
            (self.root / name).mkdir()
            (self.root / name / "rule.md").write_text("x", encoding="utf-8")
            self.reg.register_environment(AgentEnvironment(id=name, name=name, platform_type="custom",
                                                           root_path=str(self.root / name), governance_paths=["rule.md"]))
        self.lease_file = self.root / "leases.json"
        self.manager = LeaseManager(registry=self.reg, notifier=GuardNotifier(enabled=False, cache_file=self.root / "n.json"),
                                    lease_file=self.lease_file, scheduler=lambda lease, m: (True, "test"))
        self.yes = lambda request: True

    def test_second_lease_does_not_overwrite_the_first(self):
        self.assertTrue(self.manager.request_unlock("env_a", "a", 60, approver=self.yes)[0])
        self.assertTrue(self.manager.request_unlock("env_b", "b", 60, approver=self.yes)[0])
        self.assertEqual(sorted(l.env_id for l in self.manager.list_leases()), ["env_a", "env_b"])

    def test_same_environment_cannot_be_leased_twice(self):
        self.assertTrue(self.manager.request_unlock("env_a", "a", 60, approver=self.yes)[0])
        ok, msg, _ = self.manager.request_unlock("env_a", "again", 60, approver=self.yes)
        self.assertFalse(ok)
        self.assertIn("already", msg)

    def test_duration_is_validated(self):
        for bad in (0, -5, 10_000):
            ok, msg, _ = self.manager.request_unlock("env_a", "x", bad, approver=self.yes)
            self.assertFalse(ok)
            self.assertIn("between", msg)
        self.adapter.unlock.assert_not_called()

    def test_unpersistable_lease_aborts_before_unlock(self):
        blocker = self.root / "not_a_dir"
        blocker.write_text("x", encoding="utf-8")
        manager = LeaseManager(registry=self.reg, notifier=GuardNotifier(enabled=False, cache_file=self.root / "n.json"),
                               lease_file=blocker / "leases.json", scheduler=lambda l, m: (True, ""))
        ok, msg, _ = manager.request_unlock("env_a", "x", 60, approver=self.yes)
        self.assertFalse(ok)
        self.assertIn("persist", msg)
        self.adapter.unlock.assert_not_called()

    def test_failed_relock_keeps_record_and_does_not_rebaseline(self):
        self.assertTrue(self.manager.request_unlock("env_a", "a", 60, approver=self.yes)[0])
        self.adapter.lock.return_value = (False, "denied")
        with mock.patch("guard.lease.FileIntegrityMonitor.save_baseline") as save:
            ok, msg = self.manager.complete_lease("env_a")
        self.assertFalse(ok)
        self.assertIn("FAILED", msg)
        save.assert_not_called()
        self.assertEqual(self.manager.list_leases()[0].state, "close_failed")

    def test_successful_close_writes_change_report_and_baseline(self):
        _, _, lease = self.manager.request_unlock("env_a", "a", 60, approver=self.yes)
        (self.root / "env_a" / "rule.md").write_text("changed", encoding="utf-8")
        ok, msg = self.manager.complete_lease("env_a")
        self.assertTrue(ok, msg)
        report = json.loads((self.root / "lease_reports" / f"{lease.lease_id}.json").read_text(encoding="utf-8"))
        self.assertEqual(report["lease"]["lease_id"], lease.lease_id)
        self.assertEqual(self.manager.list_leases(), [])

    def test_headless_request_is_rejected_without_revealing_a_bypass(self):
        ok, msg, _ = self.manager.request_unlock("env_a", "agent", 60, interactive=False)
        self.assertFalse(ok)
        self.assertNotIn("agy-guard unlock", msg)


@posix_only
class TestLeaseAutoRelock(TempDirCase):
    """End-to-end: the default scheduler relocks after expiry without any further command."""

    def test_expired_lease_is_relocked_by_the_watcher(self):
        env_root = self.root / "env"
        env_root.mkdir()
        rule = env_root / "rule.md"
        rule.write_text("x", encoding="utf-8")
        reg = EnvironmentRegistry(config_path=self.root / "reg.json")
        reg.register_environment(AgentEnvironment(id="auto", name="auto", platform_type="custom",
                                                  root_path=str(env_root), governance_paths=["rule.md"]))
        reg.lock("auto")
        manager = LeaseManager(registry=reg, notifier=GuardNotifier(enabled=False, cache_file=self.root / "n.json"),
                               lease_file=self.root / "leases.json")
        ok, msg, _ = manager.request_unlock("auto", "e2e", 1, approver=lambda r: True)
        self.assertTrue(ok, msg)
        self.assertIn("watcher pid", msg)
        self.assertTrue(os.access(rule, os.W_OK))
        deadline = time.time() + 15
        while time.time() < deadline and (os.stat(rule).st_mode & stat.S_IWUSR):
            time.sleep(0.25)
        self.assertFalse(os.stat(rule).st_mode & stat.S_IWUSR, "lease expiry must relock without a CLI call")
        deadline = time.time() + 5
        while time.time() < deadline and manager.list_leases():
            time.sleep(0.2)
        self.assertEqual(manager.list_leases(), [])


if __name__ == "__main__":
    unittest.main()
