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


def _wrap_safe_fetch(opener):
    import urllib.request

    def _fake_safe_fetch(url, user_agent="", timeout=10.0, max_bytes=10_000_000, deadline=None, headers=None):
        req_headers = {"User-Agent": user_agent} if user_agent else {}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, headers=req_headers)
        with opener(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("Response exceeded max_bytes")
        return raw.decode("utf-8", errors="replace")

    return _fake_safe_fetch


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
                mock.patch("porter.net.safe_fetch_url", side_effect=_wrap_safe_fetch(opener)), \
                mock.patch.object(self.watcher, "spawn_desktop_notification") as notify:
            result = self.watcher.run_hook(body)
        if urlopen is None:
            opener.assert_not_called()
        self.last_notify = notify
        return result

    def cli(self, *argv):
        out = io.StringIO()
        opener = mock.Mock(side_effect=OSError("offline"))
        with mock.patch.dict(os.environ, self.env), \
                mock.patch("urllib.request.urlopen", opener), \
                mock.patch("porter.net.safe_fetch_url", opener), \
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
        self.assertIn("First-seen signature:", message)
        self.assertIn("Upstream Notice:", message)
        self.assertIn("--ack", message)
        self.assertNotIn("recommend", message.lower())
        self.last_notify.assert_called_once()
        self.assertNotIn("First-seen signature:", self.watcher.build_notice(["added: gamma"], first_time=False))

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

    def test_seed_reconciles_existing_state_when_seed_is_newer(self):
        now = datetime.now(timezone.utc)
        t_old = (now - timedelta(hours=14)).isoformat()
        t_new = (now - timedelta(hours=1)).isoformat()
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.write_state({
            "last_audited_model": MODEL,
            "builtin_skills_hash": self.watcher.compute_builtin_hash(),
            "recorded_builtin_skills": self.watcher.get_builtin_skills_list(),
            "last_audit_timestamp": t_old,
            "last_skills_audit_timestamp": t_old,
            "skills_audit_interval_hours": 72,
            "tracked_repositories": {
                "ecc": {
                    "repo": "affaan-m/everything-claude-code",
                    "branch": "main",
                    "last_synced_commit": "76aaa77",
                    "target_skills": ["security-review"],
                }
            },
            "pending_repo_updates": {
                "ecc": {"recorded": "76aaa77", "remote": "6f1881aeafa3c48f"}
            },
        })
        seed = json.loads(self.seed_file.read_text(encoding="utf-8"))
        seed["last_audit_timestamp"] = t_new
        seed["last_skills_audit_timestamp"] = t_new
        seed["tracked_repositories"] = {
            "ecc": {
                "repo": "affaan-m/everything-claude-code",
                "branch": "main",
                "last_synced_commit": "6f1881a",
                "target_skills": ["security-review", "agents/build-error-resolver.md"],
            }
        }
        self.seed_file.write_text(json.dumps(seed, indent=2), encoding="utf-8")

        self.assertEqual(self.hook(), {})
        state = self.read_state()
        self.assertEqual(state["tracked_repositories"]["ecc"]["last_synced_commit"], "6f1881a")
        self.assertIn("agents/build-error-resolver.md", state["tracked_repositories"]["ecc"]["target_skills"])
        self.assertEqual(state.get("pending_repo_updates"), {})
        self.assertEqual(state["last_audit_timestamp"], t_new)


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
        with mock.patch.dict(os.environ, self.env), \
                mock.patch("porter.net.safe_fetch_url", side_effect=_wrap_safe_fetch(fake_urlopen)):
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

    def test_release_track_and_path_filter_support(self):
        self.tracked_repositories = {
            "rea": {
                "repo": "morluto/rea",
                "branch": "main",
                "track": "release",
                "last_synced_commit": "rea-agents-6.5.0",
            },
            "rea-current": {
                "repo": "morluto/rea-current",
                "branch": "main",
                "track": "release",
                "last_synced_commit": "rea-agents-6.7.0",
            },
            "semver-tag": {
                "repo": "owner/semver",
                "branch": "main",
                "track": "release",
                "last_synced_commit": "v1.0",
            },
            "path-scoped": {
                "repo": "garrytan/gstack",
                "branch": "main",
                "path": "review/SKILL.md",
                "last_synced_commit": "1111111",
            },
        }
        self.write_seed()
        requested_urls = []

        def fake_urlopen(request, timeout=None):
            requested_urls.append(request.full_url)
            if "morluto/rea/releases/latest" in request.full_url:
                return FakeResponse(json.dumps({"tag_name": "rea-agents-6.7.0"}).encode("utf-8"))
            if "morluto/rea-current/releases/latest" in request.full_url:
                return FakeResponse(json.dumps({"tag_name": "rea-agents-6.7.0"}).encode("utf-8"))
            if "owner/semver/releases/latest" in request.full_url:
                return FakeResponse(json.dumps({"tag_name": "v1.0.1"}).encode("utf-8"))
            if "garrytan/gstack/commits" in request.full_url and "path=review%2FSKILL.md" in request.full_url:
                return github_reply("22222229999")
            raise AssertionError(f"Unexpected URL: {request.full_url}")

        message = self.notice(self.hook(urlopen=mock.Mock(side_effect=fake_urlopen)))
        self.assertEqual(len(requested_urls), 4)
        # Non-hex release tags preserve their full string (never truncated to 'rea-age->rea-age')
        self.assertIn("rea (rea-agents-6.5.0->rea-agents-6.7.0)", message)
        # Up-to-date non-hex release tag is excluded from notice and pending_repo_updates
        self.assertNotIn("rea-current", message)
        self.assertNotIn("rea-current", self.read_state()["pending_repo_updates"])
        # Non-hex prefix ('v1.0' vs 'v1.0.1') must not false-match as up-to-date
        self.assertIn("semver-tag (v1.0->v1.0.1)", message)
        # Hex commit SHAs on path-filtered queries still format as 7-char SHAs
        self.assertIn("path-scoped (1111111->2222222)", message)
        # Path traversal, leading/trailing slash, dot segments, query injection, or unknown track mode rejected before network I/O
        for bad_info in (
            {"repo": "owner/repo", "branch": "main", "path": "../etc/passwd"},
            {"repo": "owner/repo", "branch": "main", "path": "/etc/passwd"},
            {"repo": "owner/repo", "branch": "main", "path": "./skills"},
            {"repo": "owner/repo", "branch": "main", "path": "skills//sub"},
            {"repo": "owner/repo", "branch": "main", "path": "a?b=1"},
            {"repo": "owner/repo", "branch": "main", "track": "unknown"},
        ):
            self.assertIsNone(self.watcher.fetch_remote_head(bad_info), bad_info)



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


class TestUpstreamWatcherSeedEnvReconciliation(WatcherTestBase):
    def test_seed_reconciles_builtin_hash_and_preserves_newer_local_ack(self):
        now = datetime.now(timezone.utc)
        t_old = (now - timedelta(hours=6)).isoformat()
        t_seed = (now - timedelta(hours=1)).isoformat()
        t_ack_newer = (now - timedelta(minutes=10)).isoformat()

        old_hash = self.watcher.compute_builtin_hash()
        old_builtins = self.watcher.get_builtin_skills_list()
        self.add_builtin("run-workflow")
        new_hash = self.watcher.compute_builtin_hash()
        new_builtins = self.watcher.get_builtin_skills_list()
        self.assertNotEqual(old_hash, new_hash)

        # 1. Seed newer than state (and no newer local ack) reconciles builtin hash & recorded skills
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.write_state(
            {
                "last_audited_model": MODEL,
                "builtin_skills_hash": old_hash,
                "recorded_builtin_skills": old_builtins,
                "last_audit_timestamp": t_old,
                "last_skills_audit_timestamp": t_old,
                "skills_audit_interval_hours": 72,
                "tracked_repositories": {},
            }
        )
        seed = json.loads(self.seed_file.read_text(encoding="utf-8"))
        seed["builtin_skills_hash"] = new_hash
        seed["recorded_builtin_skills"] = new_builtins
        seed["last_audit_timestamp"] = t_seed
        seed["last_skills_audit_timestamp"] = t_seed
        self.seed_file.write_text(json.dumps(seed, indent=2), encoding="utf-8")

        self.assertEqual(self.hook(), {})
        reconciled = self.read_state()
        self.assertEqual(reconciled["builtin_skills_hash"], new_hash)
        self.assertIn("run-workflow", reconciled["recorded_builtin_skills"])

        # 2. Operator `--ack` newer than seed is NOT overwritten by older shipped seed metadata
        self.add_builtin("local-preview")
        acked_hash = self.watcher.compute_builtin_hash()
        acked_builtins = self.watcher.get_builtin_skills_list()
        reconciled["builtin_skills_hash"] = acked_hash
        reconciled["recorded_builtin_skills"] = acked_builtins
        reconciled["last_audit_timestamp"] = t_old
        reconciled["last_ack_timestamp"] = t_ack_newer
        self.write_state(reconciled)

        self.assertEqual(self.hook(), {})
        preserved = self.read_state()
        self.assertEqual(preserved["builtin_skills_hash"], acked_hash)
        self.assertIn("local-preview", preserved["recorded_builtin_skills"])

    def test_seed_reconciles_model_fields_clears_stale_seen_model_and_resets_expired_failed_timer(self):
        now = datetime.now(timezone.utc)
        t_expired = (now - timedelta(hours=96)).isoformat()
        t_old_audit = (now - timedelta(hours=48)).isoformat()
        t_seed = (now - timedelta(hours=1)).isoformat()

        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.write_state(
            {
                "last_audited_model": "Gemini 3.0 Legacy",
                "last_seen_model": "Gemini 3.0 Legacy",
                "last_model_slug": "gemini-3-0-legacy",
                "last_pbtxt_model": "Gemini 3.0 Legacy",
                "builtin_skills_hash": self.watcher.compute_builtin_hash(),
                "recorded_builtin_skills": self.watcher.get_builtin_skills_list(),
                "last_audit_timestamp": t_old_audit,
                "last_skills_audit_timestamp": t_expired,
                "last_audit_failed": True,
                "skills_audit_interval_hours": 72,
                "tracked_repositories": {
                    "anthropics/skills": {
                        "url": "https://github.com/anthropics/skills",
                        "last_synced_commit": "1111111",
                        "track": "retired-branch",
                        "path": "retired/path",
                        "target_skills": ["old-skill"],
                    }
                },
            }
        )
        seed = json.loads(self.seed_file.read_text(encoding="utf-8"))
        seed["last_audited_model"] = MODEL
        seed["last_model_slug"] = "gemini-4-argon"
        seed["last_pbtxt_model"] = MODEL
        seed["last_audit_timestamp"] = t_seed
        seed["last_skills_audit_timestamp"] = t_seed
        seed["tracked_repositories"] = {
            "anthropics/skills": {
                "url": "https://github.com/anthropics/skills",
                "last_synced_commit": "2222222",
                "target_skills": ["new-skill"],
            }
        }
        self.seed_file.write_text(json.dumps(seed, indent=2), encoding="utf-8")

        fetch_calls = []
        with mock.patch.object(
            self.watcher, "_fetch_all", side_effect=lambda *a, **kw: fetch_calls.append(1) or {}
        ):
            self.assertEqual(self.hook(modelName="auto"), {})
        self.assertEqual(fetch_calls, [], "Fresh seed skills timestamp should suppress immediate network re-fetch")

        reconciled = self.read_state()
        self.assertEqual(reconciled["last_audited_model"], MODEL)
        self.assertEqual(reconciled["last_model_slug"], "gemini-4-argon")
        self.assertEqual(reconciled["last_pbtxt_model"], MODEL)
        self.assertEqual(reconciled["last_seen_model"], MODEL)
        self.assertFalse(reconciled["last_audit_failed"])
        self.assertEqual(reconciled["last_skills_audit_timestamp"], t_seed)
        repo_entry = reconciled["tracked_repositories"]["anthropics/skills"]
        self.assertEqual(repo_entry["last_synced_commit"], "2222222")
        self.assertEqual(repo_entry["target_skills"], ["new-skill"])
        self.assertNotIn("track", repo_entry)
        self.assertNotIn("path", repo_entry)

        # Model-less `cmd_ack("")` after an `"auto"` turn must NOT resurrect the stale pre-seed `last_seen_model`
        rc = self.watcher.cmd_ack("")
        self.assertEqual(rc, 0)
        after_ack = self.read_state()
        self.assertEqual(after_ack["last_audited_model"], MODEL)
        self.assertEqual(self.hook(modelName=MODEL), {})

    def test_reconcile_and_collect_reasons_survive_corrupt_tracked_repos_and_builtin_list(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.write_state(
            {
                "last_audited_model": MODEL,
                "builtin_skills_hash": "0" * 64,
                "recorded_builtin_skills": "corrupt-non-list",
                "tracked_repositories": ["corrupt-non-dict"],
            }
        )
        state, _ = self.watcher.load_state()
        self.assertIsInstance(state["tracked_repositories"], dict)
        corrupt_runtime = {
            "last_audited_model": MODEL,
            "builtin_skills_hash": "0" * 64,
            "recorded_builtin_skills": ["alpha", 123, None],
            "tracked_repositories": ["corrupt-non-dict"],
            "skills_audit_interval_hours": 72,
        }
        self.assertFalse(self.watcher.check_tracked_skills(corrupt_runtime))
        reasons = self.watcher.collect_reasons(corrupt_runtime, payload_model=MODEL)
        self.assertTrue(any("builtin" in r for r in reasons), reasons)


if __name__ == "__main__":
    unittest.main()
