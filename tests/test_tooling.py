"""
tests/test_tooling.py — Regression tests for graders, installer, boot sentinel, notifier
dispatch, test boundary, provenance and upstream helpers.
"""

from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)

import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from guard.notifier import GuardNotifier, NotificationSeverity
from guard.provenance import RunProvenanceTracker
from guard.startup import StartupManager
from guard.test_boundary import TestBoundaryGuard
from guard.upstream import UpstreamAuditorBridge
from scripts import verify_invariants
from scripts.meta_audit import MetaAuditEngine, contrast_ratio

REPO_ROOT = Path(__file__).resolve().parent.parent


def _git(cwd: Path, *args: str) -> str:
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    return subprocess.check_output(["git", "-C", str(cwd), *args], text=True, env=env, stderr=subprocess.STDOUT)


class TempCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_tooling_"))

    def tearDown(self):
        hermetic.reset_approver()
        hermetic.force_rmtree(self.tmp)


class TestVerifyInvariants(TempCase):
    def test_pipe_to_shell_variants_are_detected(self):
        bad = ["curl -fsSL https://x.sh | bash", "wget -qO- https://x | sh", "curl https://x | sudo -E bash",
               "bash <(curl -s https://x)"]
        for line in bad:
            with self.subTest(line=line):
                self.assertTrue(any(re.search(p, line) for p, _ in verify_invariants.CONSTITUTIONAL_SLOP_PATTERNS))
        self.assertFalse(any(re.search(p, "curl -o file https://x") for p, _ in verify_invariants.CONSTITUTIONAL_SLOP_PATTERNS))

    def test_test_file_detection_is_path_based(self):
        self.assertTrue(verify_invariants.is_test_path("conftest.py"))
        self.assertTrue(verify_invariants.is_test_path("src/app.test.ts"))
        self.assertTrue(verify_invariants.is_test_path("pkg/tests/helpers.py"))
        self.assertFalse(verify_invariants.is_test_path("guard/latest.py"))
        self.assertFalse(verify_invariants.is_test_path("contest.py"))

    def test_unavailable_diff_is_an_error_not_a_pass(self):
        res = subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "verify_invariants.py")],
                             cwd=self.tmp, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 2, res.stdout)

    def test_fenced_markdown_commands_are_checked(self):
        (self.tmp / "doc.md").write_text("Never run `curl | bash`.\n\n```bash\ncurl -fsSL https://x | bash\n```\n", encoding="utf-8")
        violations = verify_invariants.scan_directory(self.tmp)
        self.assertEqual([v[0] for v in violations], ["doc.md:4"])

    def test_skip_decorators_are_caught_but_sample_strings_in_grader_self_tests_are_not(self):
        (self.tmp / "tests").mkdir()
        (self.tmp / "tests" / "test_app.py").write_text(
            "import pytest\n\n@pytest.mark.skip\ndef test_a():\n    pass\n\npytestmark = pytest.mark.skipif(True, reason='x')\n",
            encoding="utf-8")
        (self.tmp / "tests" / "test_porter.py").write_text(
            'SAMPLES = ["Use @pytest.mark.skip on flaky cases.", "curl https://x | bash"]\n\n@pytest.mark.skip\ndef test_b():\n    pass\n',
            encoding="utf-8")
        found = sorted(v[0] for v in verify_invariants.scan_directory(self.tmp))
        self.assertEqual(found, ["tests/test_app.py:3", "tests/test_app.py:7", "tests/test_porter.py:3"])


class TestMetaAudit(TempCase):
    def _skill(self, name: str, fm: str, body: str = "# x\n") -> None:
        d = self.tmp / "skills" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "SKILL.md").write_text(f"---\n{fm}\n---\n{body}", encoding="utf-8")

    def test_pass1_rejects_frontmatter_the_platform_cannot_load(self):
        self._skill("porter", "name: porter\ndescription: Adapter. Invoke when: the user asks")
        engine = MetaAuditEngine(repo_root=self.tmp)
        engine.pass1_schema_validation()
        self.assertTrue(any(f.severity == "CRITICAL" and "Frontmatter error" in f.message for f in engine.findings))

    def test_pass2_flags_broken_links_and_missing_files(self):
        self._skill("a", "name: a\ndescription: d", "See [x](../missing.md) and `antislop.md`.\n")
        engine = MetaAuditEngine(repo_root=self.tmp)
        engine.pass2_cross_references()
        messages = " ".join(f.message for f in engine.findings)
        self.assertIn("missing.md", messages)
        self.assertIn("antislop.md", messages)

    def test_pass5_rejects_readme_examples_that_do_not_parse(self):
        shutil_copy = (REPO_ROOT / "guard" / "cli.py").read_text(encoding="utf-8")
        (self.tmp / "guard").mkdir()
        (self.tmp / "guard" / "cli.py").write_text(shutil_copy, encoding="utf-8")
        (self.tmp / "README.md").write_text(
            "Policies (`enforced`, `exempt`).\n\n```bash\nagy-guard env policy x enforced --bogus\n```\n", encoding="utf-8")
        engine = MetaAuditEngine(repo_root=self.tmp)
        engine.pass5_cli_doc_sync()
        messages = " ".join(f.message for f in engine.findings if f.severity == "CRITICAL")
        self.assertIn("does not parse", messages)
        self.assertIn("exempt", messages)

    def test_pass6_recomputes_design_contrast(self):
        (self.tmp / "DESIGN.md").write_text(
            "## Measured Contrast Pairs\n\n| Pair | Foreground | Background | Ratio | Minimum |\n|---|---|---|---|---|\n"
            "| Border | `#94A3B8` | `#F8FAFC` | 3.10:1 | 3:1 |\n", encoding="utf-8")
        engine = MetaAuditEngine(repo_root=self.tmp)
        engine.pass6_design_contract()
        self.assertEqual(len([f for f in engine.findings if f.severity == "CRITICAL"]), 2)
        self.assertAlmostEqual(contrast_ratio("#94A3B8", "#F8FAFC"), 2.45, places=2)

    def test_strict_mode_fails_on_warnings(self):
        self._skill("vibecoder", "name: vibecoder\ndescription: d", "# no mutex\n")
        res = subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "meta_audit.py"), "--root", str(self.tmp), "--pass", "3", "--strict"],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 1)


class TestInstaller(TempCase):
    def _run(self, *args: str, env_extra=None) -> subprocess.CompletedProcess:
        env = dict(os.environ, ANTIGRAVITY_CONFIG_DIR=str(self.tmp / "cfg"), HOME=str(self.tmp / "home"),
                   XDG_STATE_HOME=str(self.tmp / "state"), XDG_DATA_HOME=str(self.tmp / "data"), USERPROFILE=str(self.tmp / "home"))
        env.update(env_extra or {})
        return subprocess.run([sys.executable, str(REPO_ROOT / "install.py"), *args], capture_output=True, text=True,
                              env=env, stdin=subprocess.DEVNULL, timeout=120)

    def test_copy_install_produces_lockable_real_files_and_external_backups(self):
        cfg = self.tmp / "cfg"
        (cfg / "skills").mkdir(parents=True)
        (cfg / "GEMINI.md").write_text("old rules", encoding="utf-8")
        (cfg / "hooks.json").write_text(json.dumps({"my-hook": {"PreToolUse": []}}), encoding="utf-8")
        res = self._run()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertFalse(os.path.islink(cfg / "GEMINI.md"))
        self.assertEqual((cfg / "GEMINI.md").read_text(encoding="utf-8"), (REPO_ROOT / "GEMINI.md").read_text(encoding="utf-8"))
        self.assertTrue((cfg / "skills" / "harness" / "SKILL.md").is_file())
        self.assertTrue((cfg / "templates" / "HANDOFF.template.md").is_file())
        hooks = json.loads((cfg / "hooks.json").read_text(encoding="utf-8"))
        self.assertIn("my-hook", hooks, "existing hooks must be preserved")
        self.assertIn("upstream-watchdog", hooks)
        self.assertEqual(list(cfg.glob("backup_*")), [], "backups must live outside the config tree")
        backups = list((self.tmp / "state" / "antigravity-harness" / "backups").glob("install_*/GEMINI.md"))
        self.assertEqual(len(backups), 1)
        self.assertIn("[LOCKED]", res.stdout)
        if os.name != "nt":
            launcher = (self.tmp / "home" / ".local" / "bin" / "agy-guard").read_text(encoding="utf-8")
            self.assertIn("antigravity-harness launcher", launcher)

    def test_reinstall_over_locked_scope_requires_human_confirmation(self):
        self.assertEqual(self._run().returncode, 0)
        res = self._run()
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)

    @unittest.skipUnless(os.name != "nt", "symlinks")
    def test_legacy_symlinked_hooks_are_replaced_not_written_through(self):
        cfg = self.tmp / "cfg"
        cfg.mkdir()
        repo_hooks = self.tmp / "repo_hooks.json"
        repo_hooks.write_text("{}", encoding="utf-8")
        (cfg / "hooks.json").symlink_to(repo_hooks)
        self.assertEqual(self._run().returncode, 0)
        self.assertEqual(repo_hooks.read_text(encoding="utf-8"), "{}")
        self.assertFalse(os.path.islink(cfg / "hooks.json"))

    @unittest.skipUnless(os.name != "nt", "POSIX permissions and symlinks")
    def test_legacy_leftovers_of_old_guard_are_moved_out_of_the_config_tree(self):
        cfg = self.tmp / "cfg"
        old_backup = cfg / "backup_20260101_000000" / "skills" / "x"
        old_backup.mkdir(parents=True)
        (old_backup / "SKILL.md").write_text("old", encoding="utf-8")
        snaps = cfg / ".guard_snapshots" / "snap_1"
        snaps.mkdir(parents=True)
        (snaps / "config.json").write_text('{"token": "redacted"}', encoding="utf-8")
        (cfg / ".guard_integrity.json").write_text("{}", encoding="utf-8")
        checkout = self.tmp / "old-checkout"
        (checkout / "guard").mkdir(parents=True)
        (checkout / "guard" / "__init__.py").write_text("", encoding="utf-8")
        (checkout / "porter.py").write_text("", encoding="utf-8")
        (cfg / "guard").symlink_to(checkout / "guard", target_is_directory=True)
        (cfg / "porter.py").symlink_to(checkout / "porter.py")
        (cfg / "projects").mkdir()
        # The pre-1.3.1 Guard left whole trees read-only (directories included).
        for root, dirs, _files in os.walk(cfg / "backup_20260101_000000", topdown=False):
            os.chmod(root, 0o555)
        for root, dirs, _files in os.walk(cfg / ".guard_snapshots", topdown=False):
            os.chmod(root, 0o555)

        res = self._run("--no-lock")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        state = self.tmp / "state" / "antigravity-harness"
        for name in ("backup_20260101_000000", ".guard_snapshots", ".guard_integrity.json", "guard", "porter.py"):
            self.assertFalse(os.path.lexists(cfg / name), name)
        self.assertTrue((state / "backups" / "backup_20260101_000000" / "skills" / "x" / "SKILL.md").is_file())
        moved = list((state / "legacy").glob("config_*/.guard_snapshots/snap_1/config.json"))
        self.assertEqual(len(moved), 1)
        self.assertEqual(stat.S_IMODE(os.stat(moved[0].parents[2]).st_mode), 0o700)
        self.assertTrue((checkout / "guard" / "__init__.py").is_file(), "the old checkout itself is never touched")
        self.assertTrue((cfg / "projects").is_dir(), "runtime state is left alone")

    def test_unsupported_platform_gets_no_foreign_binary(self):
        spec = importlib.util.spec_from_file_location("agy_install", REPO_ROOT / "install.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with mock.patch.object(module, "SYSTEM", "FreeBSD"):
            installer = module.Installer(self.tmp / "cfg", "copy", dry_run=True)
            self.assertFalse(installer.install_binary())


class TestStartupRendering(TempCase):
    def test_paths_with_spaces_are_quoted(self):
        target = self.tmp / "my config"
        target.mkdir()
        mgr = StartupManager(target_dir=target)
        with mock.patch.object(mgr, "get_guard_argv", return_value=["/opt/my tools/agy-guard", "boot-check"]):
            unit = mgr.render_systemd_unit()
            plist = mgr.render_launchd_plist()
        self.assertIn('ExecStart="/opt/my tools/agy-guard" "boot-check"', unit)
        self.assertIn(f'Environment="ANTIGRAVITY_CONFIG_DIR={target}"', unit)
        self.assertIn("<string>/opt/my tools/agy-guard</string>", plist)

    def test_boot_check_quarantines_drift_without_rebaselining(self):
        target = self.tmp / "cfg"
        target.mkdir()
        (target / "GEMINI.md").write_text("v1", encoding="utf-8")
        mgr = StartupManager(target_dir=target)
        mgr.integrity_monitor.save_baseline()
        (target / "GEMINI.md").chmod(0o644)
        (target / "GEMINI.md").write_text("tampered", encoding="utf-8")
        with mock.patch("guard.startup.GuardNotifier.notify") as notify:
            ok, msg = mgr.execute_boot_check()
        self.assertFalse(ok)
        self.assertIn("[QUARANTINE]", msg)
        self.assertEqual(notify.call_args.kwargs["severity"], NotificationSeverity.CRITICAL)
        self.assertFalse(mgr.integrity_monitor.verify().is_intact, "drift must not be silently accepted")


class TestNotifierDispatch(unittest.TestCase):
    def setUp(self):
        self.cache = Path(tempfile.mkdtemp(prefix="agy_notify_")) / "cache.json"

    def tearDown(self):
        hermetic.force_rmtree(self.cache.parent)

    def _notifier(self, system: str) -> GuardNotifier:
        n = GuardNotifier(cache_file=self.cache, enabled=True)
        n.system = system
        n.terminal_only = False
        return n

    def test_force_does_not_override_disabled(self):
        n = GuardNotifier(cache_file=self.cache, enabled=False)
        with mock.patch("sys.stderr.write") as write:
            self.assertFalse(n.notify("T", "M", severity=NotificationSeverity.CRITICAL, force=True))
        write.assert_not_called()

    def test_wayland_without_notify_send_falls_back_cleanly(self):
        n = self._notifier("linux")
        with mock.patch.dict(os.environ, {"WAYLAND_DISPLAY": "wayland-0"}, clear=False), \
                mock.patch("shutil.which", return_value=None), mock.patch("subprocess.run") as run, \
                mock.patch("sys.stderr.write"):
            self.assertTrue(n.notify("T", "M", force=True))
        run.assert_not_called()

    def test_windows_message_is_passed_as_data(self):
        n = self._notifier("windows")
        payload = '"; Remove-Item C:\\ -Recurse; $(calc) "'
        with mock.patch("shutil.which", return_value="powershell.exe"), \
                mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
            n.notify("Title", payload, force=True)
        args, kwargs = run.call_args
        self.assertNotIn(payload, " ".join(args[0]))
        self.assertEqual(kwargs["env"]["AGY_NOTIFY_MESSAGE"], payload)

    def test_macos_message_is_passed_as_argv(self):
        n = self._notifier("darwin")
        payload = 'x\\" & do shell script "id" & "'
        with mock.patch("shutil.which", return_value="/usr/bin/osascript"), \
                mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
            n.notify("Title", payload, force=True)
        argv = run.call_args.args[0]
        self.assertEqual(argv[-1], payload)
        self.assertFalse(any(payload in a for a in argv[:-1]))

    def test_failed_native_command_falls_back_to_terminal(self):
        n = self._notifier("linux")
        with mock.patch.dict(os.environ, {"DISPLAY": ":0"}), mock.patch("shutil.which", return_value="/usr/bin/notify-send"), \
                mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1)), mock.patch("sys.stderr.write") as write:
            self.assertTrue(n.notify("T", "M", force=True))
        write.assert_called()

    def test_cache_is_bounded(self):
        n = GuardNotifier(cache_file=self.cache, enabled=True)
        n.terminal_only = True
        with mock.patch("sys.stderr.write"):
            for i in range(n.CACHE_MAX_ENTRIES + 20):
                n._cache[f"k{i}"] = 1e12 + i
            n.notify("final", "x")
        self.assertLessEqual(len(json.loads(self.cache.read_text(encoding="utf-8"))["last_sent"]), n.CACHE_MAX_ENTRIES)


class TestBoundaryExtras(TempCase):
    def setUp(self):
        super().setUp()
        (self.tmp / "tests").mkdir()
        self.test_file = self.tmp / "tests" / "test_x.py"
        self.test_file.write_text("def test_a():\n    assert 1 == 1\n", encoding="utf-8")
        self.guard = TestBoundaryGuard(workspace_dir=self.tmp)

    def test_tdd_allows_appending_tests(self):
        self.guard.snapshot()
        self.test_file.write_text(self.test_file.read_text() + "\ndef test_b():\n    assert 2 == 2\n", encoding="utf-8")
        report = self.guard.verify(mode="tdd")
        self.assertTrue(report.is_intact, report.violations)
        self.assertEqual(report.extended, ["tests/test_x.py"])
        self.assertFalse(self.guard.verify(mode="bugfix").is_intact)

    def test_tdd_blocks_appended_skip_markers(self):
        self.guard.snapshot()
        self.test_file.write_text("import pytest\n@pytest.mark.skip\n" + self.test_file.read_text(), encoding="utf-8")
        report = self.guard.verify(mode="tdd")
        self.assertFalse(report.is_intact)
        self.assertTrue(any("weakening" in v for v in report.violations))

    def test_colocated_tests_are_tracked(self):
        (self.tmp / "src").mkdir()
        (self.tmp / "src" / "app.test.ts").write_text("it('x', () => {})\n", encoding="utf-8")
        (self.tmp / "src" / "app.ts").write_text("export const x = 1\n", encoding="utf-8")
        files = self.guard.discover_files()
        self.assertIn("src/app.test.ts", files)
        self.assertNotIn("src/app.ts", files)

    def test_baseline_from_git_ref(self):
        _git(self.tmp, "init", "-q")
        _git(self.tmp, "add", "-A")
        _git(self.tmp, "commit", "-qm", "base")
        self.test_file.write_text("def test_a():\n    pass\n", encoding="utf-8")
        report = self.guard.verify(mode="tdd", base_ref="HEAD")
        self.assertFalse(report.is_intact)
        self.assertEqual(report.baseline_source, "git:HEAD")

    def test_zero_passes_is_rejected(self):
        with self.assertRaises(ValueError):
            self.guard.run_reproducible([sys.executable, "-c", "pass"], passes=0)

    def test_windows_command_rewrite_uses_current_interpreter(self):
        self.assertEqual(TestBoundaryGuard.windows_command("python3 -m unittest"), f'"{sys.executable}" -m unittest')
        self.assertEqual(TestBoundaryGuard.windows_command(["python3", "-V"]), [sys.executable, "-V"])

    def test_baseline_is_stored_outside_the_workspace(self):
        _, path = self.guard.snapshot()
        self.assertFalse(str(path).startswith(str(self.tmp)))


class TestProvenanceExtras(TempCase):
    def test_renames_secrets_and_commands(self):
        _git(self.tmp, "init", "-q")
        (self.tmp / "a.txt").write_text("x", encoding="utf-8")
        _git(self.tmp, "add", "-A")
        _git(self.tmp, "commit", "-qm", "base")
        _git(self.tmp, "mv", "a.txt", "b.txt")
        tracker = RunProvenanceTracker(workspace_dir=self.tmp)
        with mock.patch.dict(os.environ, {"BYPASS_TOKEN": "s3cr3t-value-123", "FORCE_COLOR": "1", "MOCK_API": "true"}):
            manifest = tracker.generate_manifest(test_command=f'"{sys.executable}" -c "pass"', reproducibility_passes=2)
        self.assertIn("a.txt -> b.txt", manifest.files_modified)
        self.assertEqual(manifest.environment_overrides["BYPASS_TOKEN"], "<redacted>")
        self.assertNotIn("FORCE_COLOR", manifest.environment_overrides)
        self.assertEqual(manifest.environment_overrides["MOCK_API"], "true")
        self.assertEqual(len(manifest.tools_executed), 1)
        self.assertNotIn("IN TACT", manifest.to_markdown())


class TestUpstreamHelpers(unittest.TestCase):
    def test_model_status_is_not_invented(self):
        info = UpstreamAuditorBridge(target_dir=Path(tempfile.gettempdir())).get_model_drift_status()
        self.assertNotIn("Gemini", info["active_model"])
        self.assertNotIn("architecture", info)

    def test_invalid_repository_ids_are_not_requested(self):
        bridge = UpstreamAuditorBridge(target_dir=Path(tempfile.gettempdir()))
        state = {"tracked_repositories": {"evil": {"repo": "a/b/../../x?y", "branch": "main", "last_synced_commit": "1"}}}
        with mock.patch.object(bridge, "load_state", return_value=state), mock.patch("urllib.request.urlopen") as urlopen:
            results = bridge.check_repositories()
        urlopen.assert_not_called()
        self.assertEqual(results[0]["status"], "Invalid repository id")

    def test_watcher_only_ignores_same_generation_tier_switches(self):
        spec = importlib.util.spec_from_file_location("watcher", REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py")
        watcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(watcher)
        self.assertTrue(watcher.is_pro_flash_switch("gemini 3.8 pro", "gemini 3.8 flash"))
        self.assertFalse(watcher.is_pro_flash_switch("gemini 3 pro", "gemini 4 pro"))


if __name__ == "__main__":
    unittest.main()
