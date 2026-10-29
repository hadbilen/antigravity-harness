"""
tests/test_v140_guard.py — Regression tests for the 1.4.0 Guard remediation:
environment discovery scope, policy/lock honesty, FIM exclusions, lease races and review
of window changes, fail-closed lease store, audit trail, approval gates, boot sentinel.
"""

from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)

import json
import os
import shutil
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from guard.audit_log import log_path
from guard.cli import main as cli_main
from guard.doctor import diagnose
from guard.environment import AgentEnvironment, EnvironmentRegistry
from guard.integrity import FileIntegrityMonitor
from guard.lease import LeaseManager, UnlockLease
from guard.notifier import GuardNotifier
from guard.os_adapter import OSProtectionAdapter
from guard.snapshot import SnapshotEngine
from guard.startup import StartupManager

POSIX = os.name != "nt"
posix_only = unittest.skipUnless(POSIX, "POSIX permission semantics")
not_root = unittest.skipIf(hermetic.IS_ROOT, "root bypasses permission bits")


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="agy_v140_"))

    def tearDown(self):
        hermetic.reset_approver()
        hermetic.force_rmtree(self.root)


def _mock_adapter(lock_ok=True):
    adapter = mock.MagicMock(spec=OSProtectionAdapter)
    adapter.lock.return_value = (lock_ok, "locked" if lock_ok else "denied")
    adapter.unlock.return_value = (True, "unlocked")
    adapter.protection_issues.return_value = []
    adapter.is_locked.return_value = True
    return adapter


class TestDiscoveryScope(TempDirCase):
    def test_home_directory_is_never_a_workspace(self):
        home = Path(os.environ["HOME"])
        (home / ".claude").mkdir(exist_ok=True)
        (home / ".cursor").mkdir(exist_ok=True)
        reg = EnvironmentRegistry(config_path=self.root / "reg.json", os_adapter=_mock_adapter())
        found = reg.discover_environments(workspace_dir=home, register=True)
        self.assertEqual([e.id for e in found], ["antigravity"])
        self.assertIn("home directory", reg.last_discovery_note)
        self.assertEqual({e.id for e in reg.list_environments()}, {"antigravity"})

    def test_other_agents_get_rule_file_whitelist_and_monitored_policy(self):
        ws = self.root / "project"
        (ws / ".claude" / "agents").mkdir(parents=True)
        (ws / ".claude" / "settings.local.json").write_text("{}", encoding="utf-8")
        (ws / "CLAUDE.md").write_text("# rules", encoding="utf-8")
        (ws / ".cursor" / "rules").mkdir(parents=True)
        reg = EnvironmentRegistry(config_path=self.root / "reg.json", os_adapter=_mock_adapter())
        found = {e.platform_type: e for e in reg.discover_environments(workspace_dir=ws, register=False)}
        claude = found["claude"]
        self.assertEqual(claude.policy, "monitored")
        self.assertNotIn(".claude", claude.governance_paths)
        self.assertIn(".claude/agents", claude.governance_paths)
        paths = [str(p) for p in claude.get_governance_paths(existing_only=True)]
        self.assertFalse(any(p.endswith("settings.local.json") for p in paths))
        self.assertEqual(found["cursor"].governance_paths, [".cursor/rules"])

    def test_legacy_broad_seams_are_migrated_on_load(self):
        cfg = self.root / "reg.json"
        cfg.write_text(json.dumps({"environments": [{
            "id": "claude-x", "name": "c", "platform_type": "claude", "root_path": str(self.root),
            "governance_paths": ["CLAUDE.md", ".claude"], "policy": "enforced"}]}), encoding="utf-8")
        reg = EnvironmentRegistry(config_path=cfg, os_adapter=_mock_adapter())
        seams = reg.get_environment("claude-x").governance_paths
        self.assertNotIn(".claude", seams)
        self.assertIn("CLAUDE.md", seams)
        self.assertIn(".claude/skills", seams)


class TestLockHonesty(TempDirCase):
    def setUp(self):
        super().setUp()
        self.adapter = _mock_adapter()
        self.reg = EnvironmentRegistry(config_path=self.root / "reg.json", os_adapter=self.adapter)
        (self.root / "env").mkdir()
        self.reg.register_environment(AgentEnvironment(id="mon", name="mon", platform_type="custom",
                                                       root_path=str(self.root / "env"), governance_paths=["r.md"],
                                                       policy="monitored"))

    def test_explicit_lock_of_non_enforced_environment_is_not_success(self):
        ok, msg = self.reg.lock("mon")
        self.assertFalse(ok)
        self.assertIn("NOT write-protected", msg)

    def test_lock_all_still_skips_quietly(self):
        ok, msg = self.reg.lock(None)
        self.assertIn("Skipped mon", msg)

    @posix_only
    def test_symlinked_config_root_is_refused(self):
        real = self.root / "checkout"
        real.mkdir()
        (real / "GEMINI.md").write_text("x", encoding="utf-8")
        link = self.root / "config-link"
        link.symlink_to(real, target_is_directory=True)
        with mock.patch.dict(os.environ, {"ANTIGRAVITY_CONFIG_DIR": str(link)}):
            reg = EnvironmentRegistry(config_path=self.root / "reg2.json")
            ok, msg = reg.lock("antigravity")
            self.assertFalse(ok)
            self.assertIn("symlink", msg)
            self.assertTrue(os.stat(real / "GEMINI.md").st_mode & stat.S_IWUSR, "link target must stay untouched")


class TestIntegrityScope(TempDirCase):
    def test_backup_prefix_is_only_excluded_at_top_level(self):
        root = self.root / "cfg"
        (root / "skills" / "ok").mkdir(parents=True)
        (root / "skills" / "ok" / "SKILL.md").write_text("a", encoding="utf-8")
        (root / "backup_20260101").mkdir()
        (root / "backup_20260101" / "old.md").write_text("b", encoding="utf-8")
        mon = FileIntegrityMonitor(target_dir=root, state_file=self.root / "b.json")
        mon.save_baseline()
        (root / "skills" / "backup_evil").mkdir()
        (root / "skills" / "backup_evil" / "SKILL.md").write_text("evil", encoding="utf-8")
        (root / "skills" / ".guard_payload.md").write_text("evil", encoding="utf-8")
        (root / "backup_20260101" / "newer.md").write_text("c", encoding="utf-8")
        report = mon.verify()
        self.assertIn("skills/backup_evil/SKILL.md", report.added)
        self.assertIn("skills/.guard_payload.md", report.added)
        self.assertFalse(any(a.startswith("backup_") for a in report.added))

    def test_malformed_baseline_is_reported_corrupt_not_raised(self):
        root = self.root / "cfg"
        root.mkdir()
        state = self.root / "b.json"
        state.write_text(json.dumps({"files": ["not", "a", "map"]}), encoding="utf-8")
        report = FileIntegrityMonitor(target_dir=root, state_file=state).verify()
        self.assertEqual(report.baseline_status, "corrupt")
        self.assertFalse(report.is_intact)


class TestLeaseRaces(TempDirCase):
    def setUp(self):
        super().setUp()
        self.adapter = _mock_adapter()
        self.reg = EnvironmentRegistry(config_path=self.root / "reg.json", os_adapter=self.adapter)
        (self.root / "env_a").mkdir()
        (self.root / "env_a" / "rule.md").write_text("x", encoding="utf-8")
        self.reg.register_environment(AgentEnvironment(id="env_a", name="env_a", platform_type="custom",
                                                       root_path=str(self.root / "env_a"), governance_paths=["rule.md"]))
        self.retries = []
        self.manager = LeaseManager(registry=self.reg, notifier=GuardNotifier(enabled=False, cache_file=self.root / "n.json"),
                                    lease_file=self.root / "leases.json", scheduler=lambda lease, m: (True, "test"),
                                    retry_scheduler=lambda lease, m, delay: (self.retries.append(delay) or True, "retry"))
        self.yes = lambda request: True

    def test_closing_an_old_lease_never_removes_a_newer_record(self):
        _, _, old = self.manager.request_unlock("env_a", "a", 60, approver=self.yes)
        newer = UnlockLease(lease_id="newer001", env_id="env_a", env_name="env_a", reason="b", duration_seconds=60,
                            granted_at=time.time(), expires_at=time.time() + 60)
        self.manager._save({"env_a": newer})
        ok, msg = self.manager.expire_lease(old)
        self.assertTrue(ok)
        self.assertIn("already closed", msg)
        self.assertEqual([l.lease_id for l in self.manager.list_leases()], ["newer001"])

    def test_concurrent_grant_is_refused_under_the_store_lock(self):
        def sneaky_approver(request):
            # Another process wins the race between the pre-check and the insert.
            rival = UnlockLease(lease_id="rival001", env_id="env_a", env_name="env_a", reason="r", duration_seconds=60,
                                granted_at=time.time(), expires_at=time.time() + 60)
            self.manager._save({"env_a": rival})
            return True
        ok, msg, lease = self.manager.request_unlock("env_a", "a", 60, approver=sneaky_approver)
        self.assertFalse(ok)
        self.assertIn("already", msg)
        self.adapter.unlock.assert_not_called()

    def test_unattended_close_leaves_changes_pending_review(self):
        mon = FileIntegrityMonitor.for_environment(self.reg.get_environment("env_a"), os_adapter=self.adapter)
        mon.save_baseline()
        self.manager.request_unlock("env_a", "a", 60, approver=self.yes)
        (self.root / "env_a" / "rule.md").write_text("changed", encoding="utf-8")
        ok, msg = self.manager.complete_lease("env_a")
        self.assertTrue(ok, msg)
        self.assertIn("await review", msg)
        report = mon.verify()
        self.assertEqual(report.baseline_status, "pending_review")
        self.assertIn("[REVIEW]", report.summary())
        # Anything changed AFTER the window is ordinary drift, not "pending review".
        (self.root / "env_a" / "rule.md").write_text("changed again", encoding="utf-8")
        self.assertEqual(mon.verify().baseline_status, "ok")
        self.assertFalse(mon.verify().is_intact)

    def test_human_close_can_accept_window_changes(self):
        mon = FileIntegrityMonitor.for_environment(self.reg.get_environment("env_a"), os_adapter=self.adapter)
        mon.save_baseline()
        self.manager.request_unlock("env_a", "a", 60, approver=self.yes)
        (self.root / "env_a" / "rule.md").write_text("changed", encoding="utf-8")
        ok, msg = self.manager.complete_lease("env_a", approver=self.yes)
        self.assertTrue(ok, msg)
        self.assertIn("accepted", msg)
        self.assertTrue(mon.verify().is_intact)
        self.assertIsNone(mon.load_pending())

    def test_corrupt_lease_store_fails_closed(self):
        (self.root / "leases.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(self.manager.check_and_expire_leases(), [])
        self.adapter.lock.assert_called()
        self.assertFalse((self.root / "leases.json").exists())
        self.assertTrue(list(self.root.glob("leases.json.corrupt-*")))

    def test_lowered_policy_is_reported_not_relocked(self):
        _, _, lease = self.manager.request_unlock("env_a", "a", 60, approver=self.yes)
        self.reg.set_policy("env_a", "monitored")
        self.adapter.lock.reset_mock()
        ok, msg = self.manager.expire_lease(lease)
        self.assertTrue(ok)
        self.assertIn("NOT re-locked", msg)
        self.adapter.lock.assert_not_called()
        self.assertEqual(self.manager.list_leases(), [])

    def test_failed_relock_schedules_bounded_retries(self):
        _, _, lease = self.manager.request_unlock("env_a", "a", 60, approver=self.yes)
        self.adapter.lock.return_value = (False, "denied")
        ok, msg = self.manager.expire_lease(lease)
        self.assertFalse(ok)
        self.assertEqual(self.retries, [60])
        self.assertEqual(self.manager.list_leases()[0].relock_attempts, 1)


class TestAdapterDetails(TempDirCase):
    def test_icacls_deny_parsing_uses_whole_rights(self):
        adapter = OSProtectionAdapter(self.root)
        cases = {"Everyone:(DENY)(RD)": False, "bob:(DENY)(X)": False, "Everyone:(OI)(CI)(DENY)(W,D)": True,
                 "Everyone:(DENY)(WD,AD,DE,DC)": True}
        for line, expected in cases.items():
            with self.subTest(line=line), mock.patch.dict(os.environ, {"USERNAME": ""}), \
                    mock.patch("guard.os_adapter.subprocess.run") as run:
                run.return_value = mock.Mock(returncode=0, stdout=f"C:\\x {line}\n", stderr="")
                self.assertEqual(adapter._windows_dir_denied(self.root), expected)

    @posix_only
    @not_root
    def test_world_write_bit_is_never_restored_from_the_mode_store(self):
        store = self.root / "modes.json"
        adapter = OSProtectionAdapter(self.root, mode_store=store)
        f = self.root / "rule.md"
        f.write_text("x", encoding="utf-8")
        os.chmod(f, 0o644)
        adapter.lock(f)
        data = json.loads(store.read_text(encoding="utf-8"))
        data["modes"][str(f)] = 0o666  # tampered record
        store.write_text(json.dumps(data), encoding="utf-8")
        adapter.unlock(f)
        self.assertFalse(os.stat(f).st_mode & stat.S_IWOTH)


class TestSnapshotsAndSentinel(TempDirCase):
    def test_restore_refuses_snapshot_without_manifest(self):
        target = self.root / "cfg"
        (target / "skills").mkdir(parents=True)
        engine = SnapshotEngine(target_dir=target, snapshots_dir=self.root / "snaps")
        snap_id, snap_dir = engine.create_snapshot(label="x")
        (snap_dir / engine.META_FILE).unlink()
        ok, msg = engine.restore_snapshot(snap_id)
        self.assertFalse(ok)
        self.assertIn("cannot be verified", msg)

    def test_systemd_unit_rejects_control_characters(self):
        mgr = StartupManager(target_dir=self.root / "cfg\nExecStartPre=/bin/true")
        with self.assertRaises(ValueError):
            mgr.render_systemd_unit()

    def test_dollar_is_escaped_only_in_exec_words(self):
        self.assertEqual(StartupManager._systemd_quote("a$b", exec_word=True), '"a$$b"')
        self.assertEqual(StartupManager._systemd_quote("a$b"), '"a$b"')

    def test_boot_drift_evidence_is_deduplicated(self):
        target = Path(os.environ["ANTIGRAVITY_CONFIG_DIR"])
        (target / "skills").mkdir(parents=True, exist_ok=True)
        (target / "GEMINI.md").write_text("rules", encoding="utf-8")
        mgr = StartupManager(target_dir=target)
        mgr.integrity_monitor.save_baseline()
        (target / "GEMINI.md").write_text("tampered", encoding="utf-8")
        with mock.patch("guard.startup.GuardNotifier.notify"):
            _, first = mgr.execute_boot_check()
            _, second = mgr.execute_boot_check()
        self.assertIn("Forensic snapshot", first)
        self.assertIn("Drift unchanged", second)
        self.assertTrue(first.index("[LOCK") < first.index("[FIM"), "the lock is enforced before the integrity check")
        mgr.registry.unlock(mgr.environment.id)
        shutil.rmtree(target, ignore_errors=True)


class TestApprovalGatesAndAudit(TempDirCase):
    def test_weakening_commands_require_a_human(self):
        hermetic.deny_all()
        self.assertEqual(cli_main(["env", "policy", "antigravity", "monitored"]), 3)
        self.assertEqual(cli_main(["notify", "disable"]), 3)
        self.assertEqual(cli_main(["startup", "enable"]), 3)
        self.assertEqual(cli_main(["snapshot", "prune"]), 3)
        # Raising protection needs no approval.
        self.assertEqual(cli_main(["env", "policy", "antigravity", "enforced"]), 0)

    def test_decisions_are_written_to_the_audit_log(self):
        hermetic.deny_all()
        cli_main(["notify", "disable"])
        records = [json.loads(line) for line in log_path().read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(any(r["event"] == "approval.refused" and r["action"] == "notify disable" for r in records))

    def test_notify_send_reports_non_delivery(self):
        # Notifications are disabled in the hermetic environment: nothing is delivered.
        self.assertEqual(cli_main(["notify", "send", "--title", "t", "--message", "m"]), 1)

    def test_doctor_runs_headless(self):
        reg = EnvironmentRegistry(config_path=self.root / "reg.json", os_adapter=_mock_adapter())
        result = diagnose(reg.get_environment("antigravity"), reg, sentinel_active=True)
        self.assertIsInstance(result.warnings, list)
        self.assertNotIn("Boot sentinel is not enabled ('agy-guard startup enable').", result.infos)


class TestInstallerHooks(TempDirCase):
    def test_corrupt_hooks_file_is_left_untouched(self):
        import install

        target = self.root / "cfg"
        target.mkdir()
        (target / "hooks.json").write_text("{broken", encoding="utf-8")
        inst = install.Installer(target, mode="copy")
        with mock.patch.object(inst, "log") as log:
            inst.install_hooks()
        self.assertEqual((target / "hooks.json").read_text(encoding="utf-8"), "{broken")
        self.assertTrue(any("left untouched" in str(c) for c in log.call_args_list))


if __name__ == "__main__":
    unittest.main()
