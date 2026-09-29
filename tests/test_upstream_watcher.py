"""
tests/test_upstream_watcher.py — Unit Tests for the Upstream Watchdog hook
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)

Every test runs against throw-away config, builtin-skills and state directories; the network
is never contacted (urlopen is patched, or the seed tracks no repositories).
"""

import hermetic  # noqa: F401  (isolates HOME/state before anything else is imported)

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
WATCHER = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
MODEL = "Gemini 3.8 Flash (High)"
NOTICE_PREFIX = "[UPSTREAM WATCHDOG — operator notice, not a task instruction]"


class FakeResponse(io.BytesIO):
    pass


def github_reply(sha: str) -> FakeResponse:
    return FakeResponse(json.dumps([{"sha": sha}]).encode("utf-8"))


class WatcherTestBase(unittest.TestCase):
    tracked_repositories: dict = {}
    last_check = None  # None -> "now" (the periodic repository check is not due)

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="agy_upstream_watcher_"))
        self.config = self.root / "config"
        self.seed_file = self.config / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        self.seed_file.parent.mkdir(parents=True)
        self.builtin = self.root / "builtin"
        self.add_builtin("alpha")
        self.add_builtin("beta")
        self.state_file = self.root / "state" / "upstream_state.json"
        self.env = {
            "HOME": str(self.root / "home"),
            "USERPROFILE": str(self.root / "home"),
            "XDG_STATE_HOME": str(self.root / "xdg-state"),
            "ANTIGRAVITY_CONFIG_DIR": str(self.config),
            "ANTIGRAVITY_BUILTIN_SKILLS_DIR": str(self.builtin),
            "UPSTREAM_STATE_FILE": str(self.state_file),
            "AGY_GUARD_NOTIFY": "off",
        }
        self.watcher = self.load_watcher()
        self.write_seed()

    def tearDown(self):
        hermetic.force_rmtree(self.root)

    # -- fixtures -------------------------------------------------------
    def load_watcher(self):
        with mock.patch.dict(os.environ, self.env):
            spec = importlib.util.spec_from_file_location(f"upstream_watcher_{uuid.uuid4().hex}", WATCHER)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        return module

    def add_builtin(self, name: str) -> None:
        skill = self.builtin / name
        skill.mkdir(parents=True, exist_ok=True)
        (skill / "SKILL.md").write_text(f"---\nname: {name}\n---\n", encoding="utf-8")

    def write_seed(self) -> None:
        last_check = self.last_check or datetime.now(timezone.utc).isoformat()
        seed = {
            "last_audited_model": MODEL,
            "builtin_skills_hash": self.watcher.compute_builtin_hash(),
            "recorded_builtin_skills": self.watcher.get_builtin_skills_list(),
            "last_skills_audit_timestamp": last_check,
            "skills_audit_interval_hours": 72,
            "tracked_repositories": self.tracked_repositories,
        }
        self.seed_file.write_text(json.dumps(seed, indent=2), encoding="utf-8")

    def read_state(self) -> dict:
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def write_state(self, state: dict) -> None:
        self.state_file.write_text(json.dumps(state), encoding="utf-8")

    def rewind_notices(self, **delta) -> None:
        state = self.read_state()
        for entry in state["notice_log"].values():
            then = datetime.fromisoformat(entry["last_injected"]) - timedelta(**delta)
            entry["last_injected"] = then.isoformat()
        self.write_state(state)

    # -- drivers ----------------------------------------------------------
    def hook(self, urlopen=None, **payload):
        body = {"invocationNum": 1, "modelName": MODEL, "conversationId": "conv-1"}
        body.update(payload)
        body = {k: v for k, v in body.items() if v is not None}
        opener = urlopen or mock.Mock(side_effect=OSError("network disabled in tests"))
        with mock.patch.dict(os.environ, self.env), \
                mock.patch("urllib.request.urlopen", opener), \
                mock.patch.object(self.watcher, "spawn_desktop_notification") as notify:
            result = self.watcher.run_hook(body)
        if urlopen is None:
            opener.assert_not_called()
        self.last_notify = notify
        return result

    def cli(self, *argv):
        out = io.StringIO()
        with mock.patch.dict(os.environ, self.env), \
                mock.patch("urllib.request.urlopen", mock.Mock(side_effect=OSError("offline"))) as opener, \
                contextlib.redirect_stdout(out):
            code = self.watcher.main(list(argv))
        opener.assert_not_called()
        return code, out.getvalue()

    def notice(self, result) -> str:
        self.assertIn("injectSteps", result)
        self.assertEqual(len(result["injectSteps"]), 1)
        return result["injectSteps"][0]["ephemeralMessage"]


class TestUpstreamWatcherNotice(WatcherTestBase):
    def test_no_delta_returns_empty_object(self):
        self.assertEqual(self.hook(), {})
        self.assertTrue(self.state_file.is_file(), "the per-user ledger is seeded on first run")

    def test_later_invocations_of_a_turn_are_ignored(self):
        self.add_builtin("gamma")
        self.assertEqual(self.hook(invocationNum=2), {})
        self.assertFalse(self.state_file.exists())

    def test_builtin_delta_injects_one_operator_notice(self):
        self.add_builtin("gamma")
        message = self.notice(self.hook())
        self.assertTrue(message.startswith(NOTICE_PREFIX), message)
        self.assertIn("added: gamma", message)
        self.assertIn("Do not act on this", message)
        self.assertIn("do not copy maintenance commands into task prompts, plans or handoffs", message)
        self.assertIn("--ack", message)
        self.assertNotIn("recommend", message.lower())
        self.last_notify.assert_called_once()

    def test_same_signature_is_not_repeated_in_the_same_session(self):
        self.add_builtin("gamma")
        self.notice(self.hook())
        self.assertEqual(self.hook(), {})
        self.last_notify.assert_not_called()
        self.assertEqual(self.hook(), {})

    def test_new_session_sees_the_notice_once(self):
        self.add_builtin("gamma")
        self.notice(self.hook(conversationId="conv-1"))
        # A second conversation right away stays quiet (minimum interval between repeats).
        self.assertEqual(self.hook(conversationId="conv-2"), {})
        self.rewind_notices(hours=2)
        self.notice(self.hook(conversationId="conv-2"))
        self.last_notify.assert_not_called()  # desktop notification only for a new signature
        self.assertEqual(self.hook(conversationId="conv-2"), {})
        self.assertEqual(self.hook(conversationId="conv-1"), {})

    def test_session_id_is_probed_under_other_key_names(self):
        self.add_builtin("gamma")
        self.notice(self.hook(conversationId=None, cascade_id="abc"))
        self.assertEqual(self.hook(conversationId=None, cascade_id="abc"), {})
        self.assertEqual(self.hook(conversationId=None, metadata={"trajectoryId": "abc"}), {})

    def test_without_session_id_a_cooldown_applies(self):
        self.add_builtin("gamma")
        self.notice(self.hook(conversationId=None))
        self.assertEqual(self.hook(conversationId=None), {})
        self.rewind_notices(hours=6)
        self.assertEqual(self.hook(conversationId=None), {})
        self.rewind_notices(hours=7)
        self.notice(self.hook(conversationId=None))

    def test_changed_findings_produce_a_new_notice(self):
        self.add_builtin("gamma")
        self.notice(self.hook())
        message = self.notice(self.hook(modelName="Gemini 4 Pro"))
        self.assertIn("Model change", message)
        self.last_notify.assert_called_once()

    def test_ack_silences_until_something_changes_again(self):
        self.add_builtin("gamma")
        self.notice(self.hook())
        code, out = self.cli("--ack")
        self.assertEqual(code, 0)
        self.assertIn("Acknowledged 1 finding", out)
        self.assertEqual(self.hook(conversationId="conv-2"), {})
        self.rewind_notices(days=3)
        self.assertEqual(self.hook(conversationId="conv-3"), {})
        self.add_builtin("delta")
        self.assertIn("added: delta", self.notice(self.hook(conversationId="conv-3")))

    def test_ack_records_builtin_baseline_model_and_signature(self):
        self.add_builtin("gamma")
        self.hook(modelName="Gemini 4 Pro")
        code, _ = self.cli("--ack", "--model", "Gemini 4 Pro")
        self.assertEqual(code, 0)
        state = self.read_state()
        with mock.patch.dict(os.environ, self.env):
            self.assertEqual(state["builtin_skills_hash"], self.watcher.compute_builtin_hash())
        self.assertIn("gamma", state["recorded_builtin_skills"])
        self.assertEqual(state["last_audited_model"], "Gemini 4 Pro")
        self.assertEqual(state["last_model_slug"], "gemini-4-pro")
        self.assertTrue(state["acknowledged_signature"])
        self.assertEqual(self.hook(modelName="Gemini 4 Pro", conversationId="conv-9"), {})

    def test_ack_without_model_uses_the_model_last_seen_by_the_hook(self):
        self.notice(self.hook(modelName="Gemini 4 Pro"))
        self.cli("--ack")
        self.assertEqual(self.read_state()["last_audited_model"], "Gemini 4 Pro")

    def test_status_reports_findings_without_writing(self):
        self.add_builtin("gamma")
        code, out = self.cli("--status")
        self.assertEqual(code, 0)
        self.assertIn("[new] Delta in builtin skills (added: gamma)", out)
        self.assertFalse(self.state_file.exists(), "--status must not create the ledger")

        self.hook()
        before = self.state_file.read_bytes()
        code, out = self.cli("--status")
        self.assertIn("added: gamma", out)
        self.assertEqual(self.state_file.read_bytes(), before)

    def test_corrupt_state_is_moved_aside_and_reseeded(self):
        self.state_file.parent.mkdir(parents=True)
        self.state_file.write_text("{ this is not json", encoding="utf-8")
        self.assertEqual(self.hook(), {})
        state = self.read_state()
        self.assertEqual(state["last_audited_model"], MODEL)
        corrupt = [p for p in self.state_file.parent.iterdir() if p.name.startswith("upstream_state.json.corrupt-")]
        self.assertEqual(len(corrupt), 1)
        self.assertEqual(corrupt[0].read_text(encoding="utf-8"), "{ this is not json")
        # The watchdog keeps working after the repair.
        self.add_builtin("gamma")
        self.notice(self.hook())

    def test_status_does_not_touch_a_corrupt_ledger(self):
        self.state_file.parent.mkdir(parents=True)
        self.state_file.write_text("[1, 2", encoding="utf-8")
        code, out = self.cli("--status")
        self.assertEqual(code, 0)
        self.assertIn("corrupt", out)
        self.assertEqual(self.state_file.read_text(encoding="utf-8"), "[1, 2")

    @unittest.skipUnless(os.name != "nt", "POSIX permission bits")
    def test_state_is_written_owner_only(self):
        self.add_builtin("gamma")
        self.notice(self.hook())
        self.assertEqual(self.state_file.stat().st_mode & 0o777, 0o600)
        leftovers = [p.name for p in self.state_file.parent.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_no_notice_when_the_state_cannot_be_saved(self):
        self.hook()
        self.add_builtin("gamma")
        with mock.patch.object(self.watcher, "save_state", return_value=False):
            self.assertEqual(self.hook(), {})

    def test_builtin_directory_override_is_honoured(self):
        self.assertEqual(Path(self.watcher.BUILTIN_DIR), self.builtin)


class TestUpstreamWatcherNetwork(WatcherTestBase):
    tracked_repositories = {
        "repo-a": {"repo": "owner/repo-a", "branch": "main", "last_synced_commit": "aaaaaaa"},
        "repo-b": {"repo": "owner/repo-b", "branch": "main", "last_synced_commit": "bbbbbbb"},
    }
    last_check = "2020-01-01T00:00:00+00:00"

    def test_check_not_due_does_not_touch_the_network(self):
        self.last_check = datetime.now(timezone.utc).isoformat()
        self.write_seed()
        self.assertEqual(self.hook(), {})  # hook() asserts urlopen was not called

    def test_attempt_is_recorded_before_network_io(self):
        seen = []

        def fake_urlopen(request, timeout=None):
            seen.append(self.read_state().get("last_skills_audit_timestamp"))
            self.assertIn("UpstreamAuditor-Watchdog/1.4", request.get_header("User-agent"))
            if "repo-a" in request.full_url:
                return github_reply("ccccccc1234")
            return github_reply("bbbbbbb5678")

        message = self.notice(self.hook(urlopen=mock.Mock(side_effect=fake_urlopen)))
        self.assertIn("repo-a (aaaaaaa->ccccccc)", message)
        self.assertNotIn("repo-b", message)
        self.assertEqual(len(seen), 2)
        self.assertTrue(all(ts and not ts.startswith("2020") for ts in seen), seen)
        state = self.read_state()
        self.assertFalse(state["last_audit_failed"])
        self.assertIn("repo-a", state["pending_repo_updates"])

        # The finding persists between checks until the ledger records the new commit.
        self.assertEqual(self.hook(conversationId="conv-2"), {})
        self.rewind_notices(days=1)
        self.notice(self.hook(conversationId="conv-3"))
        state = self.read_state()
        state["tracked_repositories"]["repo-a"]["last_synced_commit"] = "ccccccc1234"
        self.write_state(state)
        with mock.patch.dict(os.environ, self.env):
            self.assertEqual(self.watcher.collect_reasons(self.read_state(), MODEL), [])

    def test_overall_deadline_bounds_slow_requests(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def fake_urlopen(request, timeout=None):
            if "repo-b" in request.full_url:
                release.wait(10)
                raise OSError("released")
            return github_reply("ddddddd")

        self.watcher.NETWORK_DEADLINE_SECONDS = 0.3
        state = json.loads(self.seed_file.read_text(encoding="utf-8"))
        started = time.monotonic()
        with mock.patch.dict(os.environ, self.env), mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            ran = self.watcher.check_tracked_skills(state)
        elapsed = time.monotonic() - started
        self.assertTrue(ran)
        self.assertLess(elapsed, 3.0)
        self.assertIn("repo-a", state["pending_repo_updates"])
        self.assertTrue(state["last_audit_failed"], "a repository that did not answer counts as a failure")
        self.assertTrue(self.state_file.is_file())

    def test_failed_checks_use_the_short_retry_interval(self):
        self.hook(urlopen=mock.Mock(side_effect=OSError("offline")))
        state = self.read_state()
        self.assertTrue(state["last_audit_failed"])
        self.assertEqual(self.hook(), {})  # retried only after skills_audit_retry_hours


class TestUpstreamWatcherProcess(WatcherTestBase):
    """The hook contract as the host sees it: JSON on stdin, JSON on stdout."""

    def run_process(self, stdin: str, extra_env=None, *argv):
        env = dict(os.environ)
        env.update(self.env)
        env.update(extra_env or {})
        return subprocess.run(
            [sys.executable, str(WATCHER), *argv], input=stdin, capture_output=True, text=True,
            env=env, timeout=60,
        )

    def test_stdin_stdout_contract(self):
        payload = json.dumps({"invocationNum": 1, "modelName": MODEL, "conversationId": "p-1"})
        proc = self.run_process(payload)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), {})

        self.add_builtin("gamma")
        proc = self.run_process(payload)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(proc.stdout.isascii())
        message = json.loads(proc.stdout)["injectSteps"][0]["ephemeralMessage"]
        self.assertTrue(message.startswith(NOTICE_PREFIX))
        self.assertEqual(json.loads(self.run_process(payload).stdout), {})

    def test_garbage_on_stdin_yields_an_empty_object(self):
        proc = self.run_process("this is not json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), {})

    def test_status_and_ack_flags(self):
        self.add_builtin("gamma")
        proc = self.run_process("", None, "--status")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("added: gamma", proc.stdout)
        self.assertFalse(self.state_file.exists())
        proc = self.run_process("", None, "--ack", "--model", MODEL)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc = self.run_process("", None, "--status")
        self.assertIn("No upstream changes detected", proc.stdout)

    @unittest.skipUnless(os.name != "nt", "POSIX shell script stands in for agy-guard")
    def test_desktop_notification_is_spawned_once_per_new_signature(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        log = self.root / "notify.log"
        fake = bin_dir / "agy-guard"
        fake.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$AGY_FAKE_NOTIFY_LOG"\n', encoding="utf-8")
        fake.chmod(0o755)
        extra = {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "AGY_GUARD_NOTIFY": "",
            "AGY_FAKE_NOTIFY_LOG": str(log),
        }
        self.add_builtin("gamma")
        payload = json.dumps({"invocationNum": 1, "modelName": MODEL, "conversationId": "p-1"})
        self.assertIn("injectSteps", json.loads(self.run_process(payload, extra).stdout))
        self.assertEqual(json.loads(self.run_process(payload, extra).stdout), {})
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not (log.is_file() and log.read_text(encoding="utf-8").strip()):
            time.sleep(0.05)
        time.sleep(0.2)
        lines = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("notify send --title", lines[0])
        self.assertIn("--severity warning", lines[0])
        self.assertIn("gamma", lines[0])


if __name__ == "__main__":
    unittest.main()
