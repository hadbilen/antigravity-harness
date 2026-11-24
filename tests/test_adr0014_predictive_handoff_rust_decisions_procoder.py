"""
tests/test_adr0014_predictive_handoff_rust_decisions_procoder.py — Hermetic seam tests
for ADR-0014 Campaign `2026-11-22-predictive-handoff-rust-decisions-procoder`.

W1 coverage:
  - AC-1: Dynamic, fixed-threshold-free, two-tier predictive context-window handoff advisory
          in `guard/hooks/pre_invocation.py` + `guard/agy_hooks.py` facade & `inv=2` latency.
  - AC-2: Antigravity `builtin/.checksum` bundle drift watchdog (`builtin_bundle_checksum`)
          and `model_compaction_ceilings` / `MC-01` seed/fallback/reconciliation parity.

W2 coverage:
  - AC-3: `rust-harden` `--greenfield` mode & `greenfield-architecture.md` (`0` frontmatter B,
          valid Edition 2024 / `[workspace.lints]` / `clippy.toml` / publish-age TOML),
          `rustify` §1 sequential post-parity handoff (`Anti-Mixing Sequencing Rule`),
          and calibrated `SKILL_HINTS["rust-harden"]` greenfield routing preserving negative controls.
  - AC-4: Structured Decision Provenance (`Proposed By`, `Approved By`, `Authority`) in
          `skills/harness/references/adr.md` & `docs/adr/template.md` (`ADR-0001..0013` compat),
          opt-in `<= 150`-line `templates/DECISIONS.template.md`, `KNOWN_EXTERNAL_MD` Pass 2 seam,
          `context-and-artifacts.md` & `retro/SKILL.md` integration, Porter export parity, and
          technical anti-slop gate.

W3 coverage:
  - AC-5: `procoder` archival to opt-in `templates/procoder.SKILL.template.md` (`21 -> 20` skills,
          aggregate frontmatter `<= 10,200 / 10,800` B, Porter parity, Apache-2.0 attribution),
          `CONSOLIDATED_SKILL_SLUGS` stale-install pruning across `install.py` and `agy-guard init`,
          global `pre_invocation` / `MODE_SKILLS` / `tracked_repositories` (`9 -> 8`) cleanup, and
          retired `"procoder"` upstream ledger reconciliation preserving custom user repos.
  - AC-6: `docs/adr/0014-*.md` structured Provenance header, `docs/adr/README.md` indexing, and
          `check_synthetic_markers.py --profile technical` gate over `W3` Markdown deliverables.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
for _p in (str(TESTS_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hermetic  # noqa: E402, F401  (isolates HOME/state before any harness module import)
from guard import upstream as guard_upstream  # noqa: E402

WATCHER_PATH = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
SEED_PATH = REPO_ROOT / "skills" / "upstream-auditor" / "upstream_state.seed.json"
CHECK_SKILLS_SH = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "check_skills.sh"


def _bash_exe() -> str:
    if os.name == "nt":
        for cand in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"):
            if os.path.isfile(cand):
                return cand
    return shutil.which("bash") or "bash"


def _load_watcher(env: dict[str, str]):
    with mock.patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(f"upstream_watcher_adr0014_{uuid.uuid4().hex}", WATCHER_PATH)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


class TestW1BuiltinBundleChecksumAndCalibration(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="agy_adr0014_w1_ac2_"))
        self.cfg_dir = self.root / "config"
        self.seed_file = self.cfg_dir / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        self.seed_file.parent.mkdir(parents=True, exist_ok=True)
        self.builtin_root = self.root / "antigravity" / "builtin"
        self.builtin_skills = self.builtin_root / "skills"
        self.builtin_skills.mkdir(parents=True, exist_ok=True)
        (self.builtin_skills / "native_swarm").mkdir(parents=True, exist_ok=True)
        (self.builtin_skills / "native_swarm" / "SKILL.md").write_text("---\nname: native_swarm\n---\n", encoding="utf-8")
        self.checksum_file = self.builtin_root / ".checksum"
        self.checksum_file.write_text(
            "builtin:1111111111111111111111111111111111111111111111111111111111111111",
            encoding="utf-8",
        )
        self.state_file = self.root / "state" / "upstream_state.json"
        self.env = {
            "HOME": str(self.root / "home"),
            "USERPROFILE": str(self.root / "home"),
            "XDG_STATE_HOME": str(self.root / "xdg-state"),
            "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
            "ANTIGRAVITY_BUILTIN_SKILLS_DIR": str(self.builtin_skills),
            "UPSTREAM_STATE_FILE": str(self.state_file),
            "AGY_GUARD_NOTIFY": "off",
        }
        self.watcher = _load_watcher(self.env)
        now_iso = datetime.now(timezone.utc).isoformat()
        seed = {
            "last_audited_model": "Gemini 4 Neon (XHigh)",
            "last_model_slug": "gemini-4-neon-xhigh",
            "builtin_skills_hash": self.watcher.compute_builtin_hash(),
            "builtin_bundle_checksum": "builtin:1111111111111111111111111111111111111111111111111111111111111111",
            "recorded_builtin_skills": self.watcher.get_builtin_skills_list(),
            "model_compaction_ceilings": {
                "gemini-4-neon-xhigh": 512000,
                "claude-opus": 180000,
                "default": 200000,
            },
            "last_audit_timestamp": now_iso,
            "last_skills_audit_timestamp": now_iso,
            "skills_audit_interval_hours": 72,
            "tracked_repositories": {},
        }
        self.seed_file.write_text(json.dumps(seed, indent=2), encoding="utf-8")

    def tearDown(self) -> None:
        hermetic.force_rmtree(self.root)

    def _run_watcher_hook(self, **payload) -> dict:
        body = {
            "hookEventName": "SessionStart",
            "modelName": "Gemini 4 Neon (XHigh)",
            "conversationId": "conv-bundle-1",
        }
        body.update(payload)
        with mock.patch.dict(os.environ, self.env, clear=False), mock.patch.object(
            self.watcher, "spawn_desktop_notification"
        ):
            return self.watcher.run_hook(body)

    def test_builtin_checksum_drift_triggers_first_seen_session_start_notice_even_when_skills_unchanged(self) -> None:
        # 1. Baseline matching checksum is silent
        self.assertEqual(self._run_watcher_hook(conversationId="conv-clean"), {})

        # 2. Simulate bundled plugin update under builtin/plugins/swarm changing ONLY builtin/.checksum
        (self.builtin_root / "plugins" / "swarm").mkdir(parents=True, exist_ok=True)
        (self.builtin_root / "plugins" / "swarm" / "agent.js").write_text("// updated\n", encoding="utf-8")
        new_checksum = "builtin:2222222222222222222222222222222222222222222222222222222222222222"
        self.checksum_file.write_text(new_checksum, encoding="utf-8")

        res = self._run_watcher_hook(conversationId="conv-drift")
        self.assertIn("injectSteps", res, res)
        sm = res["injectSteps"][0]["systemMessage"]
        self.assertEqual(sm["systemMessage"], "")
        md = sm["metadata"]["user_markdown"]
        self.assertIn("builtin/.checksum", md)
        self.assertIn("First-seen signature:", md)

        # 3. Same session does not repeat
        self.assertEqual(self._run_watcher_hook(conversationId="conv-drift"), {})

        # 4. --ack records new builtin_bundle_checksum and silences subsequent sessions
        with mock.patch.dict(os.environ, self.env, clear=False):
            rc = self.watcher.cmd_ack("Gemini 4 Neon (XHigh)")
        self.assertEqual(rc, 0)
        acked = json.loads(self.state_file.read_text(encoding="utf-8"))
        self.assertEqual(acked.get("builtin_bundle_checksum"), new_checksum)
        self.assertEqual(self._run_watcher_hook(conversationId="conv-after-ack"), {})

    def test_missing_builtin_checksum_degrades_cleanly_across_watcher_and_bridge(self) -> None:
        self.checksum_file.unlink()
        self.assertEqual(self._run_watcher_hook(conversationId="conv-missing"), {})

        with mock.patch.dict(os.environ, self.env, clear=False):
            bridge = guard_upstream.UpstreamAuditorBridge(target_dir=self.cfg_dir)
            summary = bridge.get_summary()
        self.assertEqual(summary["status"], "OK", summary)
        self.assertFalse(summary.get("builtin_bundle_drift"), summary)

    def test_guard_upstream_bridge_detects_and_acknowledges_bundle_checksum_drift(self) -> None:
        new_checksum = "builtin:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        self.checksum_file.write_text(new_checksum, encoding="utf-8")

        with mock.patch.dict(os.environ, self.env, clear=False):
            bridge = guard_upstream.UpstreamAuditorBridge(target_dir=self.cfg_dir)
            summary = bridge.get_summary()
            self.assertEqual(summary["status"], "WARN", summary)
            self.assertEqual(summary.get("builtin_bundle_checksum"), new_checksum, summary)
            self.assertTrue(summary.get("builtin_bundle_drift"), summary)
            self.assertTrue(any("builtin/.checksum" in w for w in summary["warnings"]), summary)

            ok, _msg = bridge.acknowledge_drift(model_name="Gemini 4 Neon (XHigh)")
            self.assertTrue(ok)
            summary_after = bridge.get_summary()
        self.assertEqual(summary_after["status"], "OK", summary_after)
        self.assertFalse(summary_after.get("builtin_bundle_drift"), summary_after)
        saved = json.loads(self.state_file.read_text(encoding="utf-8"))
        self.assertEqual(saved.get("builtin_bundle_checksum"), new_checksum)
        self.assertTrue(saved.get("acknowledged_reasons"), "acknowledge_drift must record acknowledged_reasons fingerprints")
        with mock.patch.dict(os.environ, self.env, clear=False):
            self.assertEqual(
                self.watcher.unacknowledged(
                    saved,
                    self.watcher.collect_reasons(saved, "Gemini 4 Neon (XHigh)", seed=json.loads(SEED_PATH.read_text(encoding="utf-8"))),
                ),
                [],
            )

    def test_seed_fallback_and_three_way_digest_parity_for_checksum_and_compaction_ceilings(self) -> None:
        seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
        self.assertTrue(str(seed.get("builtin_bundle_checksum", "")).startswith("builtin:"))
        ceilings = seed.get("model_compaction_ceilings")
        self.assertIsInstance(ceilings, dict)
        self.assertEqual(ceilings.get("gemini-4-neon-xhigh"), 512000)
        self.assertIn("default", ceilings)

        # Fallback dictionary in guard/upstream.py must mirror seed ceilings & bundle checksum
        empty_cfg = self.root / "empty_cfg"
        empty_cfg.mkdir()
        with mock.patch.dict(
            os.environ,
            {
                "ANTIGRAVITY_CONFIG_DIR": str(empty_cfg),
                "UPSTREAM_STATE_FILE": str(self.root / "absent_state.json"),
            },
            clear=False,
        ):
            fallback = guard_upstream.UpstreamAuditorBridge(target_dir=empty_cfg).load_state()
        self.assertEqual(fallback.get("model_compaction_ceilings"), ceilings)
        self.assertEqual(fallback.get("builtin_bundle_checksum"), seed.get("builtin_bundle_checksum"))

        # Seed digest parity between guard.upstream and upstream_watcher, sensitive to both new keys
        d_bridge = guard_upstream.compute_seed_digest(seed)
        d_watcher = self.watcher._compute_seed_digest(seed)
        self.assertEqual(d_bridge, d_watcher)

        mut_checksum = json.loads(json.dumps(seed))
        mut_checksum["builtin_bundle_checksum"] = "builtin:ffffffff"
        self.assertNotEqual(guard_upstream.compute_seed_digest(mut_checksum), d_bridge)
        self.assertEqual(
            guard_upstream.compute_seed_digest(mut_checksum),
            self.watcher._compute_seed_digest(mut_checksum),
        )

        mut_ceil = json.loads(json.dumps(seed))
        mut_ceil["model_compaction_ceilings"]["gemini-4-neon-xhigh"] = 600000
        self.assertNotEqual(guard_upstream.compute_seed_digest(mut_ceil), d_bridge)
        self.assertEqual(
            guard_upstream.compute_seed_digest(mut_ceil),
            self.watcher._compute_seed_digest(mut_ceil),
        )

        # Verify check_skills.sh delegates seed_digest directly to guard.upstream (single source of truth)
        cs_src = CHECK_SKILLS_SH.read_text(encoding="utf-8")
        self.assertIn("from guard.upstream import", cs_src)
        self.assertIn("compute_seed_digest as seed_digest", cs_src)
        self.assertNotIn("def seed_digest(", cs_src)

        # Reconciliation upgrades legacy state with builtin_bundle_checksum and model_compaction_ceilings
        seed_dt = datetime.fromisoformat(str(seed["last_audit_timestamp"]))
        legacy = {
            "last_audited_model": "Gemini 4 Neon (XHigh)",
            "last_audit_timestamp": (seed_dt - timedelta(days=2)).isoformat(),
            "tracked_repositories": {},
        }
        rec_b, changed_b = guard_upstream.reconcile_state_with_seed(json.loads(json.dumps(legacy)), seed)
        self.assertTrue(changed_b)
        self.assertEqual(rec_b.get("builtin_bundle_checksum"), seed["builtin_bundle_checksum"])
        self.assertEqual(rec_b.get("model_compaction_ceilings"), ceilings)

        rec_w = json.loads(json.dumps(legacy))
        changed_w = self.watcher._reconcile_with_seed(rec_w, seed)
        self.assertTrue(changed_w)
        self.assertEqual(rec_w.get("builtin_bundle_checksum"), seed["builtin_bundle_checksum"])
        self.assertEqual(rec_w.get("model_compaction_ceilings"), ceilings)

    def test_check_skills_sh_surfaces_builtin_bundle_drift_and_degrades_when_missing(self) -> None:
        shim_dir = self.root / "pyshim"
        shim_dir.mkdir()
        (shim_dir / "sitecustomize.py").write_text(
            "import json, sys, types\n"
            "def _fake_fetch(url, **_kw):\n"
            "    return json.dumps([{'sha': 'aaaaaaa000000000000000000000000000000000'}])\n"
            "porter_mod = types.ModuleType('porter')\n"
            "net_mod = types.ModuleType('porter.net')\n"
            "net_mod.safe_fetch_url = _fake_fetch\n"
            "porter_mod.net = net_mod\n"
            "sys.modules['porter'] = porter_mod\n"
            "sys.modules['porter.net'] = net_mod\n",
            encoding="utf-8",
        )
        st_file = self.root / "cs_state.json"
        st_file.write_text(
            json.dumps(
                {
                    "builtin_bundle_checksum": "builtin:1111111111111111111111111111111111111111111111111111111111111111",
                    "tracked_repositories": {
                        "demo": {
                            "repo": "owner/demo",
                            "branch": "main",
                            "last_synced_commit": "aaaaaaa",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        # 1. Changed .checksum emits builtin bundle drift alert and exits 0
        self.checksum_file.write_text(
            "builtin:9999999999999999999999999999999999999999999999999999999999999999",
            encoding="utf-8",
        )
        env = {
            **os.environ,
            **self.env,
            "UPSTREAM_STATE_FILE": str(st_file),
            "PYTHONPATH": str(shim_dir),
        }
        p_drift = subprocess.run([_bash_exe(), str(CHECK_SKILLS_SH)], capture_output=True, text=True, env=env, timeout=15)
        self.assertEqual(p_drift.returncode, 0, p_drift.stderr + p_drift.stdout)
        self.assertIn("builtin/.checksum", p_drift.stdout)
        self.assertNotIn("[OK]", p_drift.stdout, "check_skills.sh must not print [OK] when builtin bundle drift exists")

        # 2. Pre-digest state with newer local last_ack_timestamp preserves locally ack'd checksum (F-16)
        local_ack_cs = "builtin:8888888888888888888888888888888888888888888888888888888888888888"
        seed_dt = datetime.fromisoformat(str(json.loads(self.seed_file.read_text(encoding="utf-8"))["last_audit_timestamp"]))
        ack_state_file = self.root / "cs_ack_state.json"
        ack_state_file.write_text(
            json.dumps(
                {
                    "last_audit_timestamp": (seed_dt - timedelta(days=1)).isoformat(),
                    "last_ack_timestamp": (seed_dt + timedelta(days=1)).isoformat(),
                    "builtin_bundle_checksum": local_ack_cs,
                    "tracked_repositories": {
                        "demo": {"repo": "owner/demo", "branch": "main", "last_synced_commit": "aaaaaaa"}
                    },
                }
            ),
            encoding="utf-8",
        )
        self.checksum_file.write_text(local_ack_cs, encoding="utf-8")
        p_ack = subprocess.run(
            [_bash_exe(), str(CHECK_SKILLS_SH)],
            capture_output=True,
            text=True,
            env={**env, "UPSTREAM_STATE_FILE": str(ack_state_file)},
            timeout=15,
        )
        self.assertEqual(p_ack.returncode, 0, p_ack.stderr + p_ack.stdout)
        self.assertNotIn("builtin/.checksum", p_ack.stdout, "Newer local ack checksum must not be clobbered by older seed")
        self.assertIn("[OK]", p_ack.stdout)

        # 3. Missing default .checksum degrades cleanly without alert and prints [OK]
        self.checksum_file.unlink()
        p_missing = subprocess.run([_bash_exe(), str(CHECK_SKILLS_SH)], capture_output=True, text=True, env=env, timeout=15)
        self.assertEqual(p_missing.returncode, 0, p_missing.stderr + p_missing.stdout)
        self.assertNotIn("builtin/.checksum", p_missing.stdout)
        self.assertIn("[OK]", p_missing.stdout)

        # 4. Symlinked .checksum fails closed (non-zero exit + warning, never silent [OK])
        if os.name != "nt":
            ext_cs = self.root / "ext_cs_target.txt"
            ext_cs.write_text("builtin:deadbeefdeadbeefdeadbeefdeadbeef\n", encoding="utf-8")
            self.checksum_file.symlink_to(ext_cs)
            p_sym = subprocess.run([_bash_exe(), str(CHECK_SKILLS_SH)], capture_output=True, text=True, env=env, timeout=15)
            self.assertNotEqual(p_sym.returncode, 0, "Symlinked .checksum must fail closed in check_skills.sh")
            self.assertNotIn("[OK]", p_sym.stdout)
            self.assertIn("builtin/.checksum", p_sym.stderr)
            self.checksum_file.unlink()

    @unittest.skipUnless(os.name != "nt", "POSIX symlink boundary")
    def test_symlink_builtin_checksum_is_rejected_and_local_ack_preserved(self) -> None:
        secret_file = self.root / "outside_secret.txt"
        secret_file.write_text("builtin:deadbeefdeadbeefdeadbeefdeadbeef\n", encoding="utf-8")
        self.checksum_file.unlink()
        self.checksum_file.symlink_to(secret_file)

        with mock.patch.dict(os.environ, self.env, clear=False):
            self.assertEqual(self.watcher.read_builtin_bundle_checksum(), "")
            self.assertEqual(guard_upstream.read_builtin_bundle_checksum(), "")
            val_w, err_w = self.watcher.read_builtin_bundle_checksum_checked()
            val_g, err_g = guard_upstream.read_builtin_bundle_checksum_checked()
            self.assertEqual(val_w, "")
            self.assertEqual(val_g, "")
            self.assertIn("symlink", str(err_w).lower())
            self.assertIn("symlink", str(err_g).lower())
            summary_sym = guard_upstream.UpstreamAuditorBridge(target_dir=self.cfg_dir).get_summary()
            self.assertEqual(summary_sym["status"], "WARN", summary_sym)
            self.assertEqual(summary_sym.get("builtin_bundle_checksum"), "")
            ok_ack_sym, _ = guard_upstream.UpstreamAuditorBridge(target_dir=self.cfg_dir).acknowledge_drift(
                model_name="Gemini 4 Neon (XHigh)"
            )
            self.assertFalse(ok_ack_sym)
        sym_hook = self._run_watcher_hook(conversationId="conv-symlink")
        sym_sys, sym_md = _extract_step_texts(sym_hook)
        self.assertEqual(sym_sys, [])
        self.assertTrue(any("builtin/.checksum error" in m and "symlink" in m.lower() for m in sym_md), sym_hook)

        # Real file updated locally + acknowledged is preserved across unchanged seed reloads
        self.checksum_file.unlink()
        local_cs = "builtin:3333333333333333333333333333333333333333333333333333333333333333"
        self.checksum_file.write_text(local_cs, encoding="utf-8")
        with mock.patch.dict(os.environ, self.env, clear=False):
            self.assertEqual(self.watcher.cmd_ack("Gemini 4 Neon (XHigh)"), 0)
            # Re-run hook: older seed must NOT clobber newer local ack
            self.assertEqual(self._run_watcher_hook(conversationId="conv-preserve-ack"), {})
            st_after = json.loads(self.state_file.read_text(encoding="utf-8"))
        self.assertEqual(st_after.get("builtin_bundle_checksum"), local_cs)


def _extract_step_texts(resp: dict) -> tuple[list[str], list[str]]:
    sys_msgs: list[str] = []
    user_mds: list[str] = []
    for step in resp.get("injectSteps") or []:
        if not isinstance(step, dict):
            continue
        sm = step.get("systemMessage")
        if isinstance(sm, dict):
            txt = sm.get("systemMessage")
            if isinstance(txt, str) and txt:
                sys_msgs.append(txt)
            meta = sm.get("metadata")
            if isinstance(meta, dict):
                md = meta.get("user_markdown")
                if isinstance(md, str) and md:
                    user_mds.append(md)
    return sys_msgs, user_mds


def _write_transcript(path: Path, entries: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")


def _planner_step(step_index: int, total_tokens: int, *, model: str = "gemini-4-neon-xhigh", cache_ratio: float = 0.7) -> dict:
    cache_read = int(total_tokens * cache_ratio)
    inp = total_tokens - cache_read
    return {
        "step_index": step_index,
        "source": "MODEL",
        "type": "PLANNER_RESPONSE",
        "status": "DONE",
        "model": model,
        "input_tokens": inp,
        "cache_read_tokens": cache_read,
        "output_tokens": 600,
    }


class TestW1PredictiveContextHandoffAdvisory(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="agy_adr0014_w1_ac1_"))
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
                "AGY_GUARD_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
            },
            clear=False,
        )
        self._env_patch.start()
        import guard.agy_hooks as agy_hooks

        self.agy_hooks = agy_hooks

    def tearDown(self) -> None:
        self._env_patch.stop()
        hermetic.force_rmtree(self.root)

    def test_case_a_tier1_yellow_zero_model_tokens_and_no_fixed_percent_cutoff(self) -> None:
        # Moderate active context (350K / 512K) with 15K/step burn + heavy multi-file prompt -> Tier 1 (0 model tokens)
        tx = self.root / "tx_yellow.jsonl"
        _write_transcript(
            tx,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Initial exploration"},
                _planner_step(2, 320_000),
                _planner_step(3, 335_000),
                _planner_step(4, 350_000),
            ],
        )
        heavy_prompt = (
            "Implement the multi-file storage layer redesign across 6 modules and verify all edge cases end-to-end"
        )
        res_yellow = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-yellow",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx),
                "prompt": heavy_prompt,
            }
        )
        self.assertNotIn("decision", res_yellow)
        self.assertIn("injectSteps", res_yellow, res_yellow)
        sys_msgs, user_mds = _extract_step_texts(res_yellow)
        self.assertEqual(sys_msgs, [], f"Tier 1 must consume 0 model tokens, got systemMessage={sys_msgs}")
        self.assertEqual(len(user_mds), 1, res_yellow)
        self.assertIn("[Context Advisory]", user_mds[0])
        self.assertIn("HANDOFF.md", user_mds[0])

        # Dynamic no-fixed-% proof: EXACT same 350K active tokens with lean burn (5K/step) + standard medium prompt -> SILENT
        tx_lean = self.root / "tx_lean.jsonl"
        _write_transcript(
            tx_lean,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Initial exploration"},
                _planner_step(2, 340_000),
                _planner_step(3, 345_000),
                _planner_step(4, 350_000),
            ],
        )
        medium_prompt = (
            "Add a helper that formats the exported timestamp column cleanly in src/formatter.py "
            "and ensure the CLI output aligns the new header column properly"
        )
        res_lean = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-lean",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx_lean),
                "prompt": medium_prompt,
            }
        )
        self.assertEqual(res_lean, {}, f"Same 350K active context with lean burn & medium prompt must stay silent: {res_lean}")

        # Smaller-ceiling model (claude-opus = 180K) triggers dynamically at ~100K (well below Gemini's 350K)
        tx_claude = self.root / "tx_claude.jsonl"
        _write_transcript(
            tx_claude,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Start work"},
                _planner_step(2, 80_000, model="claude-opus-5.5-high"),
                _planner_step(3, 90_000, model="claude-opus-5.5-high"),
                _planner_step(4, 100_000, model="claude-opus-5.5-high"),
            ],
        )
        res_claude = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-claude",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx_claude),
                "prompt": heavy_prompt,
            }
        )
        sys_c, md_c = _extract_step_texts(res_claude)
        self.assertTrue(bool(sys_c or md_c), f"Smaller 180K ceiling model should advise at 100K + heavy prompt: {res_claude}")
        self.assertTrue(
            any("180K" in m for m in sys_c + md_c),
            f"Prefix-matched claude-opus-5.5-high must use 180K ceiling, not 200K fallback: {res_claude}",
        )

        # Discriminating prefix-match control: at 100K active with burn=7.5K (est ~90K), fires on 180K (80K left)
        # and stays silent if prefix matching ever regressed to 200K fallback (100K left >= 90K).
        tx_claude_disc = self.root / "tx_claude_disc.jsonl"
        _write_transcript(
            tx_claude_disc,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Start work"},
                _planner_step(2, 85_000, model="claude-opus-5.5-high"),
                _planner_step(3, 92_500, model="claude-opus-5.5-high"),
                _planner_step(4, 100_000, model="claude-opus-5.5-high"),
            ],
        )
        res_disc = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-claude-disc",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx_claude_disc),
                "prompt": "Refactor the billing module cleanly and add focused unit coverage.",
            }
        )
        sys_d, md_d = _extract_step_texts(res_disc)
        self.assertTrue(any("180K" in m for m in sys_d + md_d), f"Expected 180K prefix match advisory: {res_disc}")

        # Opaque placeholder MODEL_PLACEHOLDER_M535 maps to gemini-4-neon-xhigh (512K) instead of 200K fallback
        tx_ph = self.root / "tx_ph.jsonl"
        _write_transcript(
            tx_ph,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Start work"},
                _planner_step(2, 130_000, model="MODEL_PLACEHOLDER_M535"),
                _planner_step(3, 145_000, model="MODEL_PLACEHOLDER_M535"),
                _planner_step(4, 160_000, model="MODEL_PLACEHOLDER_M535"),
            ],
        )
        res_ph = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-ph",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx_ph),
                "prompt": heavy_prompt,
            }
        )
        self.assertEqual(res_ph, {}, f"M535 (512K ceiling) must not misfire at 160K: {res_ph}")

    def test_case_b_tier2_red_terse_system_message_and_one_time_latch(self) -> None:
        tx = self.root / "tx_red.jsonl"
        _write_transcript(
            tx,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Earlier build step"},
                _planner_step(2, 390_000),
                _planner_step(3, 405_000),
                _planner_step(4, 420_000),
            ],
        )
        heavy_1 = (
            "Implement the multi-file storage layer redesign across 6 modules and verify all edge cases end-to-end"
        )
        res1 = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-red",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx),
                "prompt": heavy_1,
            }
        )
        self.assertNotIn("decision", res1)
        sys_msgs_1, _ = _extract_step_texts(res1)
        handoff_msgs = [m for m in sys_msgs_1 if "[Harness Context Handoff]" in m]
        self.assertEqual(len(handoff_msgs), 1, res1)
        msg = handoff_msgs[0]
        self.assertIn("HANDOFF.md", msg)
        # Terse <= 60 tokens check (conservative word + punctuation bound)
        self.assertLessEqual(len(msg.split()), 45, msg)
        self.assertLessEqual(len(msg), 260, msg)

        # Second distinct heavy turn in the SAME conversation with even higher context must be latched (suppressed)
        _write_transcript(
            tx,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": heavy_1},
                _planner_step(5, 425_000),
                _planner_step(6, 445_000),
            ],
        )
        heavy_2 = (
            "Now overhaul the scheduler architecture across 8 files with full integration verification"
        )
        res2 = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-red",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx),
                "prompt": heavy_2,
            }
        )
        sys_msgs_2, user_mds_2 = _extract_step_texts(res2)
        self.assertFalse(any("[Harness Context Handoff]" in m for m in sys_msgs_2), res2)
        self.assertFalse(any("[Context Advisory]" in m for m in user_mds_2), res2)

    def test_case_c_post_checkpoint_compaction_reset_stays_silent(self) -> None:
        tx = self.root / "tx_checkpoint.jsonl"
        _write_transcript(
            tx,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Long prior work"},
                _planner_step(2, 495_000),
                _planner_step(3, 512_000),
                {
                    "step_index": 4,
                    "source": "SYSTEM",
                    "type": "CHECKPOINT",
                    "status": "DONE",
                    "input_tokens": 12_000,
                    "cache_read_tokens": 506_000,
                    "output_tokens": 7_500,
                },
                _planner_step(5, 30_000),
            ],
        )
        heavy_prompt = (
            "Implement the multi-file storage layer redesign across 6 modules and verify all edge cases end-to-end"
        )
        res = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-cp",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx),
                "prompt": heavy_prompt,
            }
        )
        self.assertEqual(res, {}, f"Post-CHECKPOINT 30K context must stay silent: {res}")

        # CHECKPOINT as very last entry (0 post-checkpoint PLANNER_RESPONSE) also stays silent
        tx_cp_last = self.root / "tx_cp_last.jsonl"
        _write_transcript(
            tx_cp_last,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Long prior work"},
                _planner_step(2, 510_000),
                {
                    "step_index": 3,
                    "source": "SYSTEM",
                    "type": "CHECKPOINT",
                    "status": "DONE",
                    "input_tokens": 15_000,
                    "cache_read_tokens": 505_000,
                },
            ],
        )
        res_last = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-cp-last",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx_cp_last),
                "prompt": heavy_prompt,
            }
        )
        self.assertEqual(res_last, {}, res_last)

    def test_case_d_trivial_tier1_and_last_small_task_suppression(self) -> None:
        tx = self.root / "tx_high.jsonl"
        _write_transcript(
            tx,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Prior work"},
                _planner_step(2, 415_000),
                _planner_step(3, 430_000),
                _planner_step(4, 445_000),
            ],
        )
        # 1. Trivial Tier-1 prompts (EN & TR, including >= 120-char prompts that cannot be masked by length < 120)
        for idx, trivial in enumerate(
            (
                "Fix the typo in README.md line 12",
                "Küçük yazım hatasını düzelt: tek satır yorum güncelle",
                "Please fix the spelling typo in the header comment of the settings template file so the label renders cleanly without changing any surrounding behavior or code.",
                "Lütfen sadece şu yorum satırındaki yazım hatasını ve imla bozukluğunu düzelt; başka hiçbir dosyaya veya mantığa dokunmadan ufak düzeltme uygula.",
            )
        ):
            with self.subTest(trivial=trivial):
                res = self.agy_hooks.handle_pre_invocation(
                    {
                        "conversationId": f"conv-w1-triv-{idx}",
                        "invocationNum": 1,
                        "cwd": str(self.ws_dir),
                        "transcriptPath": str(tx),
                        "prompt": trivial,
                    }
                )
                self.assertEqual(res, {}, (trivial, res))

        # 2. Workspace tasks.md with 1 small remaining item suppresses non-heavy handoff even when prompt >= 120 chars
        ws_last = self.root / "ws_last_item"
        ws_last.mkdir()
        (ws_last / "tasks.md").write_text(
            "# Tasks\n- [x] Build parser\n- [x] Wire CLI\n- [ ] Polish footer spacing\n",
            encoding="utf-8",
        )
        long_non_heavy = (
            "Please finish the final remaining item in tasks.md for the footer layout spacing and check that the "
            "rendered copy aligns cleanly before wrapping up the session."
        )
        self.assertGreaterEqual(len(long_non_heavy), 120)
        res_last_item = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-last-item",
                "invocationNum": 1,
                "cwd": str(ws_last),
                "transcriptPath": str(tx),
                "prompt": long_non_heavy,
            }
        )
        sys_l, md_l = _extract_step_texts(res_last_item)
        self.assertFalse(any("[Harness Context Handoff]" in m for m in sys_l), res_last_item)
        self.assertFalse(any("[Context Advisory]" in m for m in md_l), res_last_item)

        # 2b. Heavy prose or heavy slash prompt against 1 small tasks.md item MUST NOT be suppressed (F-02)
        for tag, heavy_over in (
            ("heavy-prose", "Run a full architectural security audit across all modules and redesign the storage schema cleanly."),
            ("heavy-slash", "/audit --full the authentication and storage boundaries before release."),
        ):
            res_over = self.agy_hooks.handle_pre_invocation(
                {
                    "conversationId": f"conv-w1-last-override-{tag}",
                    "invocationNum": 1,
                    "cwd": str(ws_last),
                    "transcriptPath": str(tx),
                    "prompt": heavy_over,
                }
            )
            s_ov, m_ov = _extract_step_texts(res_over)
            self.assertTrue(
                any("[Harness Context Handoff]" in m for m in s_ov) or any("[Context Advisory]" in m for m in m_ov),
                (tag, res_over),
            )

        # 2c. Negative control: 1 sole heavy/long (>= 220 char) task in tasks.md is NOT classified as small
        ws_one_heavy = self.root / "ws_one_heavy_item"
        ws_one_heavy.mkdir()
        (ws_one_heavy / "tasks.md").write_text(
            "# Tasks\n- [ ] " + ("Complete the storage schema verification pass across subsystems " * 5) + "\n",
            encoding="utf-8",
        )
        res_one_heavy = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-one-heavy-item",
                "invocationNum": 1,
                "cwd": str(ws_one_heavy),
                "transcriptPath": str(tx),
                "prompt": long_non_heavy,
            }
        )
        s_oh, m_oh = _extract_step_texts(res_one_heavy)
        self.assertTrue(
            any("[Harness Context Handoff]" in m for m in s_oh) or any("[Context Advisory]" in m for m in m_oh),
            res_one_heavy,
        )

        # 3. Positive control: tasks.md with 5 remaining unchecked items DOES advise on non-trivial prompt,
        #    yet still suppresses an explicit trivial typo micro-edit (F-02)
        ws_many = self.root / "ws_many_items"
        ws_many.mkdir()
        (ws_many / "tasks.md").write_text(
            "# Tasks\n" + "\n".join(f"- [ ] Implement subsystem slice {i}" for i in range(1, 6)) + "\n",
            encoding="utf-8",
        )
        res_many = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-many-items",
                "invocationNum": 1,
                "cwd": str(ws_many),
                "transcriptPath": str(tx),
                "prompt": "Continue working through the remaining subsystem slices in tasks.md carefully",
            }
        )
        sys_m, md_m = _extract_step_texts(res_many)
        self.assertTrue(
            any("[Harness Context Handoff]" in m for m in sys_m) or any("[Context Advisory]" in m for m in md_m),
            res_many,
        )
        res_many_typo = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-many-typo",
                "invocationNum": 1,
                "cwd": str(ws_many),
                "transcriptPath": str(tx),
                "prompt": "Fix the typo in README.md line 12 without touching any subsystem slices.",
            }
        )
        s_mt, m_mt = _extract_step_texts(res_many_typo)
        self.assertFalse(any("[Harness Context Handoff]" in m for m in s_mt), res_many_typo)
        self.assertFalse(any("[Context Advisory]" in m for m in m_mt), res_many_typo)

    def test_tier1_escalates_to_tier2_unmapped_model_uses_default_and_unpersisted_latch_fails_safe(self) -> None:
        # 1. Escalation: Turn 1 (Yellow) -> Turn 2 (Red) -> Turn 3 (Latched) in the same conversation
        tx = self.root / "tx_escalate.jsonl"
        _write_transcript(
            tx,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Initial step"},
                _planner_step(2, 320_000),
                _planner_step(3, 335_000),
                _planner_step(4, 350_000),
            ],
        )
        p1 = "Implement the multi-file storage layer redesign across 6 modules and verify all edge cases end-to-end"
        r1 = self.agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-w1-esc", "invocationNum": 1, "cwd": str(self.ws_dir), "transcriptPath": str(tx), "prompt": p1}
        )
        sys1, md1 = _extract_step_texts(r1)
        self.assertEqual(sys1, [])
        self.assertEqual(len(md1), 1)

        _write_transcript(
            tx,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": p1},
                _planner_step(5, 405_000),
                _planner_step(6, 420_000),
            ],
        )
        p2 = "Now overhaul the scheduler architecture across 8 files with full integration verification"
        r2 = self.agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-w1-esc", "invocationNum": 1, "cwd": str(self.ws_dir), "transcriptPath": str(tx), "prompt": p2}
        )
        sys2, _ = _extract_step_texts(r2)
        self.assertTrue(any("[Harness Context Handoff]" in m for m in sys2), r2)

        _write_transcript(
            tx,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": p2},
                _planner_step(7, 440_000),
                _planner_step(8, 455_000),
            ],
        )
        p3 = "Migrate the entire telemetry pipeline across 7 modules and validate every contract"
        r3 = self.agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-w1-esc", "invocationNum": 1, "cwd": str(self.ws_dir), "transcriptPath": str(tx), "prompt": p3}
        )
        sys3, md3 = _extract_step_texts(r3)
        self.assertFalse(any("[Harness Context Handoff]" in m for m in sys3), r3)
        self.assertFalse(any("[Context Advisory]" in m for m in md3), r3)

        # 2. Unmapped model falls back conservatively to default (200K ceiling)
        tx_unmapped = self.root / "tx_unmapped.jsonl"
        _write_transcript(
            tx_unmapped,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Start"},
                _planner_step(2, 115_000, model="custom-unknown-llm-v9"),
                _planner_step(3, 130_000, model="custom-unknown-llm-v9"),
            ],
        )
        r_unm = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w1-unmapped",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx_unmapped),
                "prompt": p1,
            }
        )
        sys_u, md_u = _extract_step_texts(r_unm)
        self.assertTrue(
            any("200K" in m for m in sys_u) or any("200K" in m for m in md_u),
            f"Unmapped model should resolve to conservative 200K default ceiling: {r_unm}",
        )

        # 3. Failed state persistence suppresses latched advisory instead of looping without latch
        with mock.patch.object(self.agy_hooks, "atomic_write_json", side_effect=OSError("disk full")):
            r_fail = self.agy_hooks.handle_pre_invocation(
                {
                    "conversationId": "conv-w1-write-fail",
                    "invocationNum": 1,
                    "cwd": str(self.ws_dir),
                    "transcriptPath": str(tx),
                    "prompt": p2,
                }
            )
        sys_f, md_f = _extract_step_texts(r_fail)
        self.assertFalse(any("[Harness Context Handoff]" in m for m in sys_f), r_fail)
        self.assertFalse(any("[Context Advisory]" in m for m in md_f), r_fail)

    def test_case_e_auxiliary_roles_silence_inv2_fast_path_latency_and_facade_line_cap(self) -> None:
        tx = self.root / "tx_aux.jsonl"
        _write_transcript(
            tx,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Prior work"},
                _planner_step(2, 415_000),
                _planner_step(3, 435_000),
                _planner_step(4, 455_000),
            ],
        )
        heavy_prompt = (
            "Implement the multi-file storage layer redesign across 6 modules and verify all edge cases end-to-end"
        )
        for idx, extra in enumerate(
            (
                {"role": "monitor"},
                {"role": "verifier"},
                {"readOnly": True},
                {"invocationNum": 2},
            )
        ):
            with self.subTest(extra=extra):
                payload = {
                    "conversationId": f"conv-w1-aux-{idx}",
                    "invocationNum": 1,
                    "cwd": str(self.ws_dir),
                    "transcriptPath": str(tx),
                    "prompt": heavy_prompt,
                }
                payload.update(extra)
                res = self.agy_hooks.handle_pre_invocation(payload)
                sys_m, user_m = _extract_step_texts(res)
                self.assertFalse(any("[Harness Context Handoff]" in m for m in sys_m), (extra, res))
                self.assertFalse(any("[Context Advisory]" in m for m in user_m), (extra, res))

        # Facade byte-size & line-readability budget (<= 32 KiB, max line <= 160 chars)
        hooks_py = REPO_ROOT / "guard" / "agy_hooks.py"
        hooks_raw = hooks_py.read_bytes()
        hooks_lines = hooks_raw.decode("utf-8").splitlines()
        self.assertLessEqual(len(hooks_raw), 32_768)
        self.assertLessEqual(max((len(line) for line in hooks_lines), default=0), 160)

        # Repeatable inv=2 cold-start median latency < 100 ms (N=5)
        import statistics
        import time

        tx_clean = self.root / "tx_inv2_clean.jsonl"
        _write_transcript(
            tx_clean,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Run checks"},
                _planner_step(2, 455_000),
                {"step_index": 3, "type": "TOOL_RESULT", "status": "DONE", "content": "Ran 12 tests\nOK"},
            ],
        )
        stdin_body = json.dumps(
            {
                "conversationId": "conv-w1-lat",
                "invocationNum": 2,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx_clean),
                "prompt": heavy_prompt,
            }
        )
        timings_ms: list[float] = []
        for _ in range(5):
            t0 = time.perf_counter()
            proc = subprocess.run(
                [sys.executable, str(hooks_py), "pre-invocation"],
                input=stdin_body,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            timings_ms.append((time.perf_counter() - t0) * 1000.0)
            self.assertEqual(json.loads(proc.stdout), {})
        median_ms = statistics.median(timings_ms)
        self.assertLess(median_ms, 100.0, f"pre-invocation inv=2 median cold-start {median_ms:.1f}ms >= 100ms ({timings_ms})")


def _parse_toml_stdlib_fallback(text: str) -> dict[str, object]:
    """Minimal Python 3.10 stdlib fallback parser for flat/dotted tables, strings, bools, ints, and string arrays."""
    import ast

    root: dict[str, object] = {}
    current: dict[str, object] = root
    lines = text.splitlines()
    idx = 0

    def _strip_comment(raw_line: str) -> str:
        in_dq = False
        in_sq = False
        esc = False
        for pos, ch in enumerate(raw_line):
            if esc:
                esc = False
                continue
            if ch == "\\" and in_dq:
                esc = True
                continue
            if ch == '"' and not in_sq:
                in_dq = not in_dq
            elif ch == "'" and not in_dq:
                in_sq = not in_sq
            elif ch == "#" and not in_dq and not in_sq:
                return raw_line[:pos]
        return raw_line

    def _parse_val(raw_val: str) -> object:
        s = raw_val.strip()
        if s == "true":
            return True
        if s == "false":
            return False
        if s.startswith(("[", '"', "'")):
            try:
                return ast.literal_eval(s)
            except (SyntaxError, ValueError) as exc:
                raise ValueError(f"Invalid TOML literal: {s!r}") from exc
        try:
            return int(s)
        except ValueError as exc:
            raise ValueError(f"Unsupported or invalid TOML value: {s!r}") from exc

    def _ensure_table(base: dict[str, object], parts: list[str]) -> dict[str, object]:
        node = base
        for part in parts:
            key = part.strip().strip('"').strip("'")
            if not key:
                raise ValueError(f"Empty TOML table segment in {parts!r}")
            nxt = node.get(key)
            if nxt is None:
                nxt = {}
                node[key] = nxt
            if not isinstance(nxt, dict):
                raise ValueError(f"Conflicting TOML table key: {key!r}")
            node = nxt
        return node

    while idx < len(lines):
        line = _strip_comment(lines[idx]).strip()
        idx += 1
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            header = line[1:-1].strip()
            if not header or header.startswith("["):
                raise ValueError(f"Unsupported TOML header: {line!r}")
            current = _ensure_table(root, header.split("."))
            continue
        if "=" not in line:
            raise ValueError(f"Invalid TOML line (missing '='): {line!r}")
        raw_k, raw_v = line.split("=", 1)
        val_acc = raw_v.strip()
        while val_acc.startswith("[") and not val_acc.endswith("]"):
            if idx >= len(lines):
                raise ValueError(f"Unclosed TOML array for key {raw_k.strip()!r}")
            cont = _strip_comment(lines[idx]).strip()
            idx += 1
            if cont:
                val_acc = f"{val_acc} {cont}"
        key_parts = [p.strip().strip('"').strip("'") for p in raw_k.strip().split(".")]
        if not key_parts or any(not p for p in key_parts):
            raise ValueError(f"Invalid TOML key: {raw_k!r}")
        target = _ensure_table(current, key_parts[:-1]) if len(key_parts) > 1 else current
        if key_parts[-1] in target:
            raise ValueError(f"Duplicate TOML key: {key_parts[-1]!r}")
        target[key_parts[-1]] = _parse_val(val_acc)
    return root


def _load_toml_text(text: str) -> dict[str, object]:
    try:
        import tomllib  # type: ignore[import-not-found]
    except ImportError:
        return _parse_toml_stdlib_fallback(text)
    return tomllib.loads(text)


class TestW2RustHardenGreenfieldAndRustifyPostParity(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="agy_adr0014_w2_ac3_"))
        self.cfg_dir = self.root / "config"
        self.state_dir = self.root / "state"
        self.cfg_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg_dir / "GEMINI.md").write_text("# Hermetic Constitution\n", encoding="utf-8")
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.root / "home"),
                "USERPROFILE": str(self.root / "home"),
                "XDG_STATE_HOME": str(self.state_dir),
                "AGY_GUARD_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
            },
            clear=False,
        )
        self._env_patch.start()
        import guard.agy_hooks as agy_hooks

        self.agy_hooks = agy_hooks

    def tearDown(self) -> None:
        self._env_patch.stop()
        hermetic.force_rmtree(self.root)

    def test_greenfield_reference_zero_frontmatter_valid_toml_and_constitutional_hygiene(self) -> None:
        import re
        from porter.analyzer import SuitabilityAnalyzer
        from porter.sanitizer import find_directives

        gf_path = REPO_ROOT / "skills" / "rust-harden" / "references" / "greenfield-architecture.md"
        self.assertTrue(gf_path.is_file(), "greenfield-architecture.md must exist")
        gf_text = gf_path.read_text(encoding="utf-8")
        # 0 global frontmatter bytes: reference module must not carry YAML frontmatter
        self.assertFalse(gf_text.lstrip().startswith("---"), "reference doc must have 0 frontmatter bytes")

        toml_blocks = re.findall(r"```toml\n(.*?)```", gf_text, re.DOTALL)
        self.assertGreaterEqual(len(toml_blocks), 3, "Expected Cargo.toml, clippy.toml, and .cargo/config.toml blocks")
        parsed_docs = [_load_toml_text(blk) for blk in toml_blocks]
        ws_doc = next((d for d in parsed_docs if "workspace" in d), None)
        self.assertIsNotNone(ws_doc, "Missing [workspace] TOML block")
        assert ws_doc is not None
        self.assertEqual(ws_doc["workspace"]["package"]["edition"], "2024")
        self.assertEqual(ws_doc["workspace"]["package"].get("rust-version"), "1.100.0")
        self.assertIn("lints", ws_doc["workspace"])
        self.assertEqual(ws_doc["workspace"]["lints"]["rust"]["unsafe_op_in_unsafe_fn"], "deny")
        self.assertEqual(ws_doc["workspace"]["lints"]["clippy"]["await_holding_lock"], "deny")

        clippy_doc = next((d for d in parsed_docs if "allow-unwrap-in-tests" in d), None)
        self.assertIsNotNone(clippy_doc)
        assert clippy_doc is not None
        self.assertTrue(clippy_doc["allow-unwrap-in-tests"])
        self.assertTrue(clippy_doc["allow-expect-in-tests"])
        self.assertTrue(clippy_doc["allow-panic-in-tests"])
        self.assertTrue(clippy_doc["allow-indexing-slicing-in-tests"])

        cargo_cfg = next((d for d in parsed_docs if "registry" in d), None)
        self.assertIsNotNone(cargo_cfg)
        assert cargo_cfg is not None
        self.assertEqual(cargo_cfg["registry"]["global-min-publish-age"], "3 days")
        self.assertEqual(cargo_cfg["registries"]["crates-io"]["min-publish-age"], "3 days")
        self.assertEqual(cargo_cfg["resolver"]["incompatible-publish-age"], "deny")
        self.assertIn("CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow", gf_text)

        for needle in (
            "thiserror",
            "anyhow",
            "newtype",
            "typestate",
            "#[expect(",
            "#![forbid(unsafe_code)]",
            "mpsc::channel",
        ):
            self.assertIn(needle, gf_text)

        report = SuitabilityAnalyzer(REPO_ROOT).analyze(gf_text, source_identifier="greenfield-architecture.md")
        self.assertEqual(report.constitutional_score, 100, report.issues)
        self.assertEqual(report.issues, [], report.issues)
        self.assertEqual(find_directives(gf_text), [])

    def test_rust_harden_modes_frontmatter_budget_cursor_export_and_rustify_handoff(self) -> None:
        import re
        from porter.analyzer import SuitabilityAnalyzer
        from porter.emitters import EMITTERS
        from porter.frontmatter import parse_frontmatter
        from porter.manifest import ManifestEngine
        from porter.sanitizer import find_directives

        # No 3rd top-level Rust skill added
        rust_skills = sorted(p.parent.name for p in (REPO_ROOT / "skills").glob("*/SKILL.md") if "rust" in p.parent.name)
        self.assertEqual(rust_skills, ["rust-harden", "rustify"])

        rh_text = (REPO_ROOT / "skills" / "rust-harden" / "SKILL.md").read_text(encoding="utf-8")
        m_fm = re.match(r"\A---\r?\n.*?\r?\n---", rh_text, re.DOTALL)
        self.assertIsNotNone(m_fm)
        assert m_fm is not None
        fm_bytes = len(m_fm.group(0).encode("utf-8"))
        self.assertLessEqual(fm_bytes, 520, f"rust-harden frontmatter exceeded 520 B: {fm_bytes}")
        self.assertIn("default to **Mode 1 (`--internal`)**", rh_text)
        self.assertIn("Mode 3 (`--greenfield`)", rh_text)
        self.assertIn("references/greenfield-architecture.md", rh_text)

        rf_text = (REPO_ROOT / "skills" / "rustify" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Sequential Post-Parity Handoff to `rust-harden`", rf_text)
        self.assertIn("Anti-Mixing Sequencing Rule", rf_text)
        self.assertIn("`--internal`", rf_text)
        self.assertIn("`--contract`", rf_text)

        analyzer = SuitabilityAnalyzer(REPO_ROOT)
        for label, content in (("skills/rust-harden/SKILL.md", rh_text), ("skills/rustify/SKILL.md", rf_text)):
            rep = analyzer.analyze(content, source_identifier=label)
            self.assertEqual(rep.constitutional_score, 100, (label, rep.issues))
            self.assertEqual(rep.issues, [], (label, rep.issues))
            self.assertEqual(find_directives(content), [], label)

        manifest = ManifestEngine(harness_root=REPO_ROOT).build_manifest(deterministic=True)
        out_cursor = self.root / "export_cursor"
        plan, _ = EMITTERS["cursor"].plan(manifest, out_cursor)
        mdc_path = out_cursor / ".cursor" / "rules" / "skill-rust-harden.mdc"
        self.assertIn(mdc_path, plan)
        meta, body = parse_frontmatter(plan[mdc_path])
        self.assertEqual(meta.get("globs"), "**/*.rs, **/Cargo.toml")
        self.assertIn(".cursor/skills/rust-harden/references/greenfield-architecture.md", body)
        self.assertIn(out_cursor / ".cursor" / "skills" / "rust-harden" / "references" / "greenfield-architecture.md", plan)

    def test_pre_invocation_greenfield_rust_routing_positive_and_negative_controls(self) -> None:
        positives = [
            "/rust-harden --greenfield scaffold a new telemetry workspace.",
            "Scaffold rust workspace with core, cli, and ffi crates.",
            "Greenfield rust daemon for bounded event ingestion.",
            "Review this rust crate layout before coding.",
            "Design a new Rust crate for bounded packet parsing.",
            "Yeni rust projesi için workspace mimarisi kur.",
            "Rust crate tasarla ve thiserror/anyhow sınırlarını ayır.",
            "Rust kütüphanesi yaz ve hata sınırlarını ayır.",
        ]
        for idx, prompt in enumerate(positives):
            with self.subTest(pos_idx=idx, prompt=prompt):
                res = self.agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-w2-gf-pos-{idx}", "invocationNum": 1, "prompt": prompt}
                )
                sys_msgs, _ = _extract_step_texts(res)
                joined = "\n".join(sys_msgs)
                self.assertIn("`rust-harden`", joined, f"Expected rust-harden for `{prompt}`, got: {res}")
                self.assertNotIn("`rustify`", joined, f"Greenfield prompt `{prompt}` collided with rustify: {joined}")

        # Negative controls: bare Cargo.toml workspace, routine single-file .rs edit, locked CLI negative, file paths
        cargo_ws = self.root / "bare_cargo_ws"
        (cargo_ws / "src").mkdir(parents=True)
        (cargo_ws / "Cargo.toml").write_text('[package]\nname = "demo"\nedition = "2024"\n', encoding="utf-8")
        (cargo_ws / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        self.assertEqual(
            self.agy_hooks.handle_pre_invocation(
                {
                    "conversationId": "conv-w2-neg-bare-cargo",
                    "invocationNum": 1,
                    "cwd": str(cargo_ws),
                    "prompt": "Add a --verbose flag in src/main.rs.",
                }
            ),
            {},
        )
        strict_negatives = [
            "Rename parse_row to parse_record in src/utils.rs.",
            "Create a brand new Rust 2024 CLI crate using Cargo and clap.",
            "Inspect src/greenfield/rust_workspace.py and crates/rust-harden/lib.rs.",
            "Let us go back to Rust 2024 edition naming conventions later.",
        ]
        for idx, prompt in enumerate(strict_negatives):
            with self.subTest(neg_idx=idx, prompt=prompt):
                res = self.agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-w2-gf-neg-{idx}", "invocationNum": 1, "prompt": prompt}
                )
                self.assertEqual(res, {}, f"Negative control `{prompt}` should stay silent, got: {res}")

        # Cross-language prompts MUST still route to rustify and NEVER rust-harden
        rustify_controls = [
            "Port this C parser to Rust.",
            "Migrate our Go worker into idiomatic Rust.",
            "C/C++'dan Rust'a geçiş mimarisi çıkar.",
            "Bu C/C++ sürücüsünü Rust'a çevir.",
        ]
        for idx, prompt in enumerate(rustify_controls):
            with self.subTest(rustify_idx=idx, prompt=prompt):
                res = self.agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-w2-rf-{idx}", "invocationNum": 1, "prompt": prompt}
                )
                sys_msgs, _ = _extract_step_texts(res)
                joined = "\n".join(sys_msgs)
                self.assertIn("`rustify`", joined, f"Expected rustify for `{prompt}`, got: {res}")
                self.assertNotIn("`rust-harden`", joined, f"Cross-language prompt `{prompt}` collided with rust-harden: {joined}")

        # Turkish perf prompt on existing Rust service must NOT trigger rust-harden
        res_perf = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-w2-rust-perf",
                "invocationNum": 1,
                "prompt": "Bu Rust servisinin bellek kullanımını düşür ve kare hızını artır.",
            }
        )
        perf_msgs, _ = _extract_step_texts(res_perf)
        self.assertNotIn("`rust-harden`", "\n".join(perf_msgs), res_perf)


class TestW2DecisionProvenanceAndDecisionsTemplate(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="agy_adr0014_w2_ac4_"))

    def tearDown(self) -> None:
        hermetic.force_rmtree(self.root)

    def test_adr_template_and_reference_define_provenance_preserving_adr0001_to_0013_compat(self) -> None:
        from scripts.meta_audit import MetaAuditEngine

        adr_tmpl = (REPO_ROOT / "docs" / "adr" / "template.md").read_text(encoding="utf-8")
        adr_ref = (REPO_ROOT / "skills" / "harness" / "references" / "adr.md").read_text(encoding="utf-8")

        for doc_name, text in (("docs/adr/template.md", adr_tmpl), ("skills/harness/references/adr.md", adr_ref)):
            with self.subTest(doc=doc_name):
                self.assertIn("**Proposed By**: User | Model (<Model Display Name & Effort>)", text)
                self.assertIn("**Approved By**: User", text)
                self.assertIn("**Authority**: User Constraint | Model Recommendation", text)

        self.assertIn("0001..0013", adr_ref)
        self.assertIn("templates/DECISIONS.template.md", adr_ref)
        self.assertIn("skills/retro/SKILL.md", adr_ref)

        # Verify all 13 pre-provenance historical ADRs exist and remain 100% clean in meta_audit
        historical_adrs = sorted(
            p.name for p in (REPO_ROOT / "docs" / "adr").glob("00[0-1][0-9]-*.md")
            if int(p.name[:4]) <= 13
        )
        self.assertEqual(len(historical_adrs), 13, historical_adrs)
        eng = MetaAuditEngine(REPO_ROOT)
        eng.run_all_passes()
        adr_findings = [f for f in eng.findings if "docs/adr/" in f.target or "ADR" in f.message]
        self.assertEqual(adr_findings, [], adr_findings)

    def test_decisions_template_bounds_opt_in_contract_porter_export_and_doc_integration(self) -> None:
        import re
        from porter.analyzer import SuitabilityAnalyzer
        from porter.emitters import EMITTERS
        from porter.manifest import ManifestEngine
        from porter.sanitizer import find_directives

        tmpl_path = REPO_ROOT / "templates" / "DECISIONS.template.md"
        self.assertTrue(tmpl_path.is_file(), "templates/DECISIONS.template.md must exist")
        tmpl_text = tmpl_path.read_text(encoding="utf-8")
        lines = tmpl_text.splitlines()
        self.assertLessEqual(len(lines), 150, f"DECISIONS.template.md exceeded 150 lines: {len(lines)}")
        self.assertIsNone(
            re.search(r"\.[a-z0-9]+:L\d+", tmpl_text),
            "DECISIONS.template.md must not embed volatile :L<n> line coordinates",
        )
        for needle in (
            "Strictly opt-in",
            "<= 150",
            "Single-Source-of-Truth boundary vs. `docs/adr/`",
            "| Date | Decision | Scope | Origin (User / Model + Effort) | Approved By | Rationale / ADR Link | Status |",
            "`User Constraint`",
            "`Model Recommendation`",
            "`[ACTIVE]`",
            "`[SUPERSEDED",
            "`[REVERTED]`",
            "`[ARCHIVED]`",
        ):
            self.assertIn(needle, tmpl_text)

        report = SuitabilityAnalyzer(REPO_ROOT).analyze(tmpl_text, source_identifier="templates/DECISIONS.template.md")
        self.assertEqual(report.constitutional_score, 100, report.issues)
        self.assertEqual(report.issues, [], report.issues)
        self.assertEqual(find_directives(tmpl_text), [])

        # Porter export parity across claude, cursor, and universal (Codex / AGENTS.md)
        manifest = ManifestEngine(harness_root=REPO_ROOT).build_manifest(deterministic=True)
        self.assertIn("DECISIONS.template.md", manifest.templates)
        index_files = {
            "claude": "CLAUDE.md",
            "cursor": ".cursor/rules/99-harness-index.mdc",
            "universal": "AGENTS.md",
        }
        for target, idx_rel in index_files.items():
            with self.subTest(target=target):
                out_dir = self.root / f"export_{target}"
                EMITTERS[target].emit(manifest, out_dir)
                self.assertEqual(
                    (out_dir / "templates" / "DECISIONS.template.md").read_bytes(),
                    tmpl_path.read_bytes(),
                )
                idx_text = (out_dir / idx_rel).read_text(encoding="utf-8")
                self.assertIn("templates/DECISIONS.template.md", idx_text)

        ctx_text = (REPO_ROOT / "skills" / "harness" / "references" / "context-and-artifacts.md").read_text(encoding="utf-8")
        retro_text = (REPO_ROOT / "skills" / "retro" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("templates/DECISIONS.template.md", ctx_text)
        self.assertIn("`DECISIONS.md`", ctx_text)
        self.assertIn("`DECISIONS.md`", retro_text)
        self.assertIn("Model Recommendation", retro_text)
        self.assertIn("User Constraint", retro_text)

    def test_meta_audit_pass2_recognizes_decisions_md_and_w2_docs_pass_antislop_gate(self) -> None:
        from scripts.meta_audit import KNOWN_EXTERNAL_MD, MetaAuditEngine

        self.assertIn("DECISIONS.md", KNOWN_EXTERNAL_MD)

        mini = self.root / "mini_repo"
        (mini / "skills" / "demo").mkdir(parents=True)
        (mini / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")
        (mini / "skills" / "demo" / "SKILL.md").write_text(
            "---\n"
            "name: demo\n"
            "description: Demo skill. Invoke with /demo. Not for prod (use 'other').\n"
            "---\n\n"
            "# Demo\n\n"
            "Inspect `DECISIONS.md` when opted in.\n",
            encoding="utf-8",
        )
        eng_ok = MetaAuditEngine(mini)
        eng_ok.pass2_cross_references()
        p2_ok = [f.message for f in eng_ok.findings if "Referenced file" in f.message]
        self.assertEqual(p2_ok, [], p2_ok)

        # Negative probe: unapproved ledger name MUST still trigger Pass 2 warning
        (mini / "skills" / "demo" / "SKILL.md").write_text(
            "---\n"
            "name: demo\n"
            "description: Demo skill. Invoke with /demo. Not for prod (use 'other').\n"
            "---\n\n"
            "# Demo\n\n"
            "Inspect `UNREGISTERED_DECISION_LEDGER.md` first.\n",
            encoding="utf-8",
        )
        eng_bad = MetaAuditEngine(mini)
        eng_bad.pass2_cross_references()
        self.assertTrue(
            any("UNREGISTERED_DECISION_LEDGER.md" in f.message for f in eng_bad.findings),
            eng_bad.findings,
        )

        # Anti-slop technical profile gate across all W2 created/edited markdown files
        scanner = REPO_ROOT / "skills" / "ui-refinery" / "scripts" / "check_synthetic_markers.py"
        w2_md_targets = [
            "skills/rust-harden/references/greenfield-architecture.md",
            "skills/rust-harden/SKILL.md",
            "skills/rustify/SKILL.md",
            "skills/harness/references/adr.md",
            "docs/adr/template.md",
            "templates/DECISIONS.template.md",
            "skills/harness/references/context-and-artifacts.md",
            "skills/retro/SKILL.md",
            "README.md",
        ]
        res = subprocess.run(
            [sys.executable, str(scanner), "--profile", "technical", *[str(REPO_ROOT / p) for p in w2_md_targets]],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


class TestW3ProcoderArchivalAndAdr0014(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="agy_adr0014_w3_ac56_"))
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
                "XDG_DATA_HOME": str(self.data_dir),
                "AGY_GUARD_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
                "AGY_GUARD_NOTIFY": "off",
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        hermetic.force_rmtree(self.root)

    def test_procoder_archived_to_opt_in_template_20_skills_frontmatter_reclaimed_and_porter_parity(self) -> None:
        import re
        from porter.analyzer import SuitabilityAnalyzer
        from porter.emitters import EMITTERS
        from porter.frontmatter import parse_frontmatter
        from porter.manifest import ManifestEngine
        from porter.sanitizer import find_directives

        # 1. Global skills/procoder removed -> 20 top-level skills and aggregate frontmatter <= 10,200 B (reclaiming >= 600 B from 10,666 B)
        self.assertFalse((REPO_ROOT / "skills" / "procoder").exists(), "skills/procoder/ must be removed")
        skill_mds = sorted((REPO_ROOT / "skills").glob("*/SKILL.md"))
        skill_names = [p.parent.name for p in skill_mds]
        self.assertEqual(len(skill_names), 20, f"Expected 20 top-level skills, got {len(skill_names)}: {skill_names}")
        self.assertNotIn("procoder", skill_names)

        total_fm_bytes = 0
        for sk_md in skill_mds:
            m = re.match(r"\A---\r?\n.*?\r?\n---", sk_md.read_text(encoding="utf-8"), re.DOTALL)
            self.assertIsNotNone(m, str(sk_md))
            assert m is not None
            total_fm_bytes += len(m.group(0).encode("utf-8"))
        self.assertLessEqual(total_fm_bytes, 10200, f"Aggregate frontmatter {total_fm_bytes} B > 10,200 B target")
        self.assertLessEqual(total_fm_bytes, 10800)
        self.assertGreaterEqual(10666 - total_fm_bytes, 600, f"Expected >= 600 B frontmatter reclamation, reclaimed {10666 - total_fm_bytes} B")

        # 2. Opt-in templates/procoder.SKILL.template.md contract, frontmatter, sanitizer, and Porter export parity
        tmpl_path = REPO_ROOT / "templates" / "procoder.SKILL.template.md"
        self.assertTrue(tmpl_path.is_file(), "templates/procoder.SKILL.template.md must exist")
        tmpl_text = tmpl_path.read_text(encoding="utf-8")
        meta, body = parse_frontmatter(tmpl_text)
        self.assertEqual(meta.get("name"), "procoder")
        self.assertEqual(meta.get("license"), "Apache-2.0")
        self.assertIn(".agents/skills/procoder/SKILL.md", str(meta.get("description", "")))
        self.assertIn(".agents/skills/procoder/SKILL.md", body)
        self.assertIn("THIRD_PARTY_NOTICES.md", tmpl_text)

        report = SuitabilityAnalyzer(REPO_ROOT).analyze(tmpl_text, source_identifier="templates/procoder.SKILL.template.md")
        self.assertEqual(report.constitutional_score, 100, report.issues)
        self.assertEqual(report.issues, [], report.issues)
        self.assertEqual(find_directives(tmpl_text), [])

        manifest = ManifestEngine(harness_root=REPO_ROOT).build_manifest(deterministic=True)
        self.assertEqual(len(manifest.skills), 20)
        self.assertIn("procoder.SKILL.template.md", manifest.templates)
        for target, emitter in EMITTERS.items():
            with self.subTest(target=target):
                out_dir = self.root / f"export_{target}"
                emitter.emit(manifest, out_dir)
                self.assertEqual(
                    (out_dir / "templates" / "procoder.SKILL.template.md").read_bytes(),
                    tmpl_path.read_bytes(),
                )

        # 3. Apache-2.0 attribution retained in THIRD_PARTY_NOTICES.md and installers/packaging/PKGBUILD
        notices = (REPO_ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        self.assertIn("azrtydxb/procoder", notices)
        self.assertIn("templates/procoder.SKILL.template.md", notices)
        self.assertIn("## azrtydxb/procoder (Apache-2.0)", notices)
        self.assertIn("Apache License", notices)

        pkgbuild = (REPO_ROOT / "installers" / "packaging" / "PKGBUILD").read_text(encoding="utf-8")
        self.assertIn("'Apache-2.0'", pkgbuild)
        self.assertIn("templates/procoder.SKILL.template.md", pkgbuild)

    def test_install_and_guard_init_prune_stale_skills_procoder_while_preserving_custom_skills(self) -> None:
        import contextlib
        import io
        import install as harness_install
        from guard import cli as guard_cli
        from guard.environment import CONSOLIDATED_SKILL_SLUGS

        self.assertIn("procoder", CONSOLIDATED_SKILL_SLUGS)

        # 1. install.Installer.install_governance() backs up and removes stale skills/procoder without touching custom user skill
        cfg_inst = self.root / "cfg_install_upgrade"
        stale_procoder = cfg_inst / "skills" / "procoder"
        stale_procoder.mkdir(parents=True, exist_ok=True)
        (stale_procoder / "SKILL.md").write_text("---\nname: procoder\n---\n# Legacy Procoder\n", encoding="utf-8")
        custom_skill = cfg_inst / "skills" / "my-custom-skill"
        custom_skill.mkdir(parents=True, exist_ok=True)
        (custom_skill / "SKILL.md").write_text("---\nname: my-custom-skill\n---\n# Custom\n", encoding="utf-8")

        installer = harness_install.Installer(target_dir=cfg_inst, mode="copy", dry_run=False)
        with contextlib.redirect_stdout(io.StringIO()):
            installer.install_governance()

        self.assertFalse(stale_procoder.exists(), "install.py must prune stale skills/procoder")
        self.assertTrue((installer.backup_dir / "skills" / "procoder" / "SKILL.md").is_file())
        self.assertTrue((cfg_inst / "templates" / "procoder.SKILL.template.md").is_file())
        self.assertEqual((custom_skill / "SKILL.md").read_text(encoding="utf-8"), "---\nname: my-custom-skill\n---\n# Custom\n")

        # 2. agy-guard init backs up and removes stale skills/procoder while preserving custom user skill
        cfg_init = self.root / "cfg_guard_init_upgrade"
        stale_procoder_2 = cfg_init / "skills" / "procoder"
        stale_procoder_2.mkdir(parents=True, exist_ok=True)
        (stale_procoder_2 / "SKILL.md").write_text("---\nname: procoder\n---\n# Legacy Procoder 2\n", encoding="utf-8")
        custom_skill_2 = cfg_init / "skills" / "user-extra"
        custom_skill_2.mkdir(parents=True, exist_ok=True)
        (custom_skill_2 / "SKILL.md").write_text("---\nname: user-extra\n---\n# Keep\n", encoding="utf-8")

        reg_path = self.state_dir / "w3_init_registry.json"
        parser = guard_cli.build_parser()
        args = parser.parse_args(
            ["--registry", str(reg_path), "init", "--source", str(REPO_ROOT), "--target", str(cfg_init), "--no-lock"]
        )
        with mock.patch("guard.cli.request_approval", return_value=True), contextlib.redirect_stdout(io.StringIO()):
            rc = guard_cli.cmd_init(args)
        self.assertEqual(rc, 0)
        self.assertFalse(stale_procoder_2.exists(), "agy-guard init must prune stale skills/procoder")
        self.assertTrue((cfg_init / "templates" / "procoder.SKILL.template.md").is_file())
        self.assertTrue((custom_skill_2 / "SKILL.md").is_file())

        # 3. porter.py import blocks accidental global re-import under slug 'procoder' without --overwrite
        ext_rule = self.root / "external_procoder.md"
        ext_rule.write_text("Verify outputs deterministically before completion.\n", encoding="utf-8")
        fake_root = self.root / "fake_repo"
        (fake_root / "skills" / "harness").mkdir(parents=True, exist_ok=True)
        (fake_root / "skills" / "harness" / "SKILL.md").write_text("---\nname: harness\ndescription: Core.\n---\n", encoding="utf-8")
        res = subprocess.run(
            [sys.executable, str(REPO_ROOT / "porter.py"), "import", str(ext_rule), "--as-skill", "procoder"],
            env={**os.environ, "ANTIGRAVITY_HARNESS_ROOT": str(fake_root)},
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("archived ADR-0014", res.stderr)

    def test_global_procoder_routing_meta_audit_and_upstream_retired_repo_pruning(self) -> None:
        import guard.agy_hooks as agy_hooks
        import guard.hooks.pre_invocation as pi
        from scripts.meta_audit import MODE_SKILLS, MetaAuditEngine

        # 1. pre_invocation drops global procoder hints & distinctive slug (negative controls stay free of skills/procoder/SKILL.md)
        self.assertNotIn("procoder", [entry[0] for entry in pi.SKILL_HINTS])
        self.assertNotIn("procoder", pi._DISTINCTIVE_SKILL_SLUGS)
        for idx, prompt in enumerate(
            (
                "/procoder sprint status",
                "Run procoder backlog seed on .procoder/specs/auth.md",
            )
        ):
            with self.subTest(prompt=prompt):
                res = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-w3-procoder-neg-{idx}", "invocationNum": 1, "prompt": prompt}
                )
                sys_msgs, _ = _extract_step_texts(res)
                self.assertNotIn("skills/procoder/SKILL.md", "\n".join(sys_msgs), res)

        # 2. meta_audit MODE_SKILLS excludes procoder and Pass 3 passes cleanly
        self.assertNotIn("procoder", MODE_SKILLS)
        eng = MetaAuditEngine(REPO_ROOT)
        eng.pass3_directive_collision_and_mutex()
        self.assertEqual(eng.findings, [], eng.findings)

        # 3. Seed & guard/upstream fallback both carry 8 tracked_repositories without procoder
        seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
        self.assertEqual(len(seed["tracked_repositories"]), 8)
        self.assertNotIn("procoder", seed["tracked_repositories"])

        empty_cfg = self.root / "empty_cfg"
        empty_cfg.mkdir()
        with mock.patch.dict(
            os.environ,
            {
                "ANTIGRAVITY_CONFIG_DIR": str(empty_cfg),
                "UPSTREAM_STATE_FILE": str(self.root / "absent_upstream_state.json"),
            },
            clear=False,
        ):
            fallback = guard_upstream.UpstreamAuditorBridge(target_dir=empty_cfg).load_state()
        self.assertEqual(fallback["tracked_repositories"], seed["tracked_repositories"])
        self.assertEqual(len(fallback["tracked_repositories"]), 8)

        # 4. Legacy 9-repo ledger reconciliation prunes retired procoder (and pending_repo_updates) while keeping custom user repos
        legacy_state = {
            "_reconciled_seed_digest": "0000000000000000",
            "last_audited_model": "Gemini 4 Neon (XHigh)",
            "last_audit_timestamp": "2026-11-22T00:10:00+03:00",
            "last_skills_audit_timestamp": "2026-11-22T00:10:00+03:00",
            "tracked_repositories": {
                **json.loads(json.dumps(seed["tracked_repositories"])),
                "procoder": {
                    "repo": "azrtydxb/procoder",
                    "branch": "main",
                    "last_synced_commit": "c0032ee",
                    "target_skills": ["procoder"],
                },
                "my-custom-repo": {
                    "repo": "acme/my-custom-repo",
                    "branch": "main",
                    "last_synced_commit": "abcdef1",
                    "target_skills": ["my-custom-skill"],
                },
            },
            "pending_repo_updates": {
                "procoder": {"recorded": "c0032ee", "remote": "9999999abcdef"},
            },
        }
        rec_b, changed_b = guard_upstream.reconcile_state_with_seed(json.loads(json.dumps(legacy_state)), seed)
        self.assertTrue(changed_b)
        self.assertNotIn("procoder", rec_b["tracked_repositories"])
        self.assertNotIn("procoder", rec_b.get("pending_repo_updates", {}))
        self.assertIn("my-custom-repo", rec_b["tracked_repositories"])

        watcher_env = {
            "HOME": str(self.root / "home"),
            "XDG_STATE_HOME": str(self.state_dir),
            "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
            "UPSTREAM_STATE_FILE": str(self.state_dir / "w3_watcher_state.json"),
            "AGY_GUARD_NOTIFY": "off",
        }
        watcher = _load_watcher(watcher_env)
        rec_w = json.loads(json.dumps(legacy_state))
        changed_w = watcher._reconcile_with_seed(rec_w, seed)
        self.assertTrue(changed_w)
        self.assertNotIn("procoder", rec_w["tracked_repositories"])
        self.assertNotIn("procoder", rec_w.get("pending_repo_updates", {}))
        self.assertIn("my-custom-repo", rec_w["tracked_repositories"])

        # Negative control: empty tracked_repositories seed does NOT prune state entries
        empty_seed = {**seed, "tracked_repositories": {}}
        rec_empty_b, _ = guard_upstream.reconcile_state_with_seed(json.loads(json.dumps(legacy_state)), empty_seed)
        self.assertIn("procoder", rec_empty_b["tracked_repositories"])
        rec_empty_w = json.loads(json.dumps(legacy_state))
        watcher._reconcile_with_seed(rec_empty_w, empty_seed)
        self.assertIn("procoder", rec_empty_w["tracked_repositories"])

        # 5. check_skills.sh in-memory reconciliation also prunes retired procoder before querying GitHub
        shim_dir = self.root / "pyshim_w3"
        shim_dir.mkdir()
        queried_log = self.root / "queried_urls.txt"
        (shim_dir / "sitecustomize.py").write_text(
            "import json, os, sys, threading, types\n"
            f"LOG = {str(queried_log)!r}\n"
            "_LOCK = threading.Lock()\n"
            "def _fake_fetch(url, **_kw):\n"
            "    with _LOCK:\n"
            "        with open(LOG, 'a', encoding='utf-8') as fh:\n"
            "            fh.write(url + '\\n')\n"
            "    if '/releases/latest' in url:\n"
            "        return json.dumps({'tag_name': 'v2.1.0'})\n"
            "    return json.dumps([{'sha': 'aaaaaaa000000000000000000000000000000000'}])\n"
            "porter_mod = types.ModuleType('porter')\n"
            "net_mod = types.ModuleType('porter.net')\n"
            "net_mod.safe_fetch_url = _fake_fetch\n"
            "porter_mod.net = net_mod\n"
            "sys.modules['porter'] = porter_mod\n"
            "sys.modules['porter.net'] = net_mod\n",
            encoding="utf-8",
        )
        cs_state = self.root / "cs_legacy_state.json"
        cs_state.write_text(json.dumps(legacy_state), encoding="utf-8")
        proc_cs = subprocess.run(
            [_bash_exe(), str(CHECK_SKILLS_SH)],
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "HOME": str(self.root / "home"),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
                "ANTIGRAVITY_BUILTIN_SKILLS_DIR": str(self.root / "no_builtin" / "skills"),
                "UPSTREAM_STATE_FILE": str(cs_state),
                "PYTHONPATH": str(shim_dir),
            },
            timeout=20,
        )
        self.assertEqual(proc_cs.returncode, 0, proc_cs.stderr + proc_cs.stdout)
        urls_text = queried_log.read_text(encoding="utf-8") if queried_log.is_file() else ""
        self.assertNotIn("azrtydxb/procoder", urls_text)
        self.assertIn("acme/my-custom-repo", urls_text)

    def test_adr0014_provenance_header_index_and_w3_docs_pass_antislop_gate(self) -> None:
        adr_path = (
            REPO_ROOT
            / "docs"
            / "adr"
            / "0014-predictive-handoff-rust-greenfield-decision-provenance-and-procoder-archival.md"
        )
        self.assertTrue(adr_path.is_file(), "ADR-0014 must exist")
        adr_text = adr_path.read_text(encoding="utf-8")
        for needle in (
            "# ADR-0014:",
            "**Proposed By**: Model (Gemini 4 Neon, XHigh)",
            "**Approved By**: User",
            "**Authority**: Model Recommendation",
            "model_compaction_ceilings",
            "builtin/.checksum",
            "--greenfield",
            "templates/DECISIONS.template.md",
            "templates/procoder.SKILL.template.md",
            "CONSOLIDATED_SKILL_SLUGS",
        ):
            self.assertIn(needle, adr_text)

        adr_index = (REPO_ROOT / "docs" / "adr" / "README.md").read_text(encoding="utf-8")
        self.assertIn("0014-predictive-handoff-rust-greenfield-decision-provenance-and-procoder-archival.md", adr_index)

        scanner = REPO_ROOT / "skills" / "ui-refinery" / "scripts" / "check_synthetic_markers.py"
        w3_md_targets = [
            "templates/procoder.SKILL.template.md",
            "docs/adr/0014-predictive-handoff-rust-greenfield-decision-provenance-and-procoder-archival.md",
            "docs/adr/README.md",
            "skills/harness/SKILL.md",
            "skills/harness/references/marathon.md",
            "skills/harness/references/unlazy.md",
            "skills/harness/references/context-and-artifacts.md",
            "skills/upstream-auditor/SKILL.md",
            "agents/meta-auditor.md",
            "README.md",
        ]
        res = subprocess.run(
            [sys.executable, str(scanner), "--profile", "technical", *[str(REPO_ROOT / p) for p in w3_md_targets]],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


class TestW4PreFlightAuditRemediations(unittest.TestCase):
    """W4 regression & mutation-resilience tests pinning confirmed Pre-flight Audit findings (F-01..F-34)."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="agy_adr0014_w4_"))
        self.cfg_dir = self.root / "cfg"
        self.state_dir = self.root / "state"
        self.ws_dir = self.root / "ws"
        for d in (self.cfg_dir, self.state_dir, self.ws_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.env = {
            "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
            "AGY_GUARD_STATE_DIR": str(self.state_dir),
        }
        self._env_patch = mock.patch.dict(os.environ, self.env, clear=False)
        self._env_patch.start()
        import guard.agy_hooks as agy_hooks
        self.agy_hooks = agy_hooks

    def tearDown(self) -> None:
        self._env_patch.stop()
        hermetic.force_rmtree(self.root)

    def test_w4_f01_rustify_vs_rust_harden_anti_mixing_and_turkish_stem_controls(self) -> None:
        # Cross-language migrations targeting a new/greenfield Rust workspace route solely to rustify (no mixing)
        for idx, prompt in enumerate(
            (
                "Port our C++ engine to a new Rust workspace architecture.",
                "Migrate our Python backend to greenfield Rust.",
                "Bu Go servisini Rust'a taşı ve yeni Rust workspace mimarisi kur.",
            )
        ):
            with self.subTest(migration_idx=idx, prompt=prompt):
                res = self.agy_hooks.handle_pre_invocation(
                    {"conversationId": f"w4-f01-mig-{idx}", "invocationNum": 1, "prompt": prompt}
                )
                sys_msgs, _ = _extract_step_texts(res)
                joined = "\n".join(sys_msgs)
                self.assertIn("`rustify`", joined, res)
                self.assertNotIn("`rust-harden`", joined, res)

        # Turkish bug/legacy/state non-creation prompts must NOT false-trigger rust-harden
        for idx, prompt in enumerate(
            (
                "Bu Rust servisi başlatılamıyor ve panik veriyor.",
                "Eski Rust projesini kurtar.",
                "Rust servisi kurulu ama bağlanmıyor.",
                "Bu Rust servisi yazılım hatası veriyor.",
            )
        ):
            with self.subTest(tr_neg_idx=idx, prompt=prompt):
                res = self.agy_hooks.handle_pre_invocation(
                    {"conversationId": f"w4-f01-trneg-{idx}", "invocationNum": 1, "prompt": prompt}
                )
                sys_msgs, _ = _extract_step_texts(res)
                joined = "\n".join(sys_msgs)
                self.assertNotIn("`rust-harden`", joined, (prompt, joined))

    def test_w4_f03_f04_f05_f06_token_parsing_overflow_redos_model_resolution_and_tier1_cooldown(self) -> None:
        import time
        from guard.hooks import common as hook_common
        from guard.hooks import pre_invocation as pi

        # F-03: camelCase, nested usage.*, cache_creation, cache-only, and non-double-counted inclusive prompt_tokens
        self.assertEqual(
            pi._extract_planner_token_total({"type": "PLANNER_RESPONSE", "inputTokens": 40_000, "cacheReadTokens": 120_000}),
            160_000,
        )
        self.assertEqual(
            pi._extract_planner_token_total({"type": "PLANNER_RESPONSE", "cache_read_tokens": 175_000}),
            175_000,
        )
        self.assertEqual(
            pi._extract_planner_token_total(
                {"type": "PLANNER_RESPONSE", "input_tokens": 5_000, "usage": {"cache_read_input_tokens": 170_000}}
            ),
            175_000,
        )
        self.assertEqual(
            pi._extract_planner_token_total(
                {
                    "type": "PLANNER_RESPONSE",
                    "input_tokens": 5_000,
                    "cache_creation_input_tokens": 100_000,
                    "cache_read_tokens": 20_000,
                }
            ),
            125_000,
        )
        self.assertEqual(
            pi._extract_planner_token_total(
                {"type": "PLANNER_RESPONSE", "usage": {"prompt_tokens": 150_000, "cache_read_tokens": 120_000}}
            ),
            150_000,
        )
        self.assertEqual(pi._extract_planner_token_total({"type": "PLANNER_RESPONSE", "input_tokens": 10**315}), 0)

        # F-04: Huge integer tokens in transcript do NOT raise OverflowError or drop skill/recovery gates
        tx_huge = self.root / "tx_huge.jsonl"
        _write_transcript(
            tx_huge,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "start"},
                {"step_index": 2, "type": "PLANNER_RESPONSE", "input_tokens": 10**315, "model": "claude-opus"},
            ],
        )
        res_huge = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "w4-f04-huge",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx_huge),
                "prompt": "/audit the codebase security boundaries thoroughly",
            }
        )
        sys_h, _ = _extract_step_texts(res_huge)
        self.assertTrue(any("`audit`" in m for m in sys_h), f"Overflow must not drop routing/recovery hints: {res_huge}")

        # F-05: Linear-time _FENCE_RE.sub on 40,000 unclosed fences + exact closed/nested parity
        t0 = time.perf_counter()
        evil = "```x\n" * 40_000
        self.assertEqual(hook_common._FENCE_RE.sub(" ", evil), evil)
        self.assertLess(time.perf_counter() - t0, 0.5)
        self.assertEqual(hook_common._FENCE_RE.sub(" ", "a\n```py\nx\n```\nb"), "a\n \nb")
        self.assertEqual(hook_common._FENCE_RE.sub(" ", "````md\n```\nin\n```\n````\ntail"), " \ntail")

        # F-06: Provider-prefixed, version-infixed Claude, effort-suffixed placeholder & payload modelName preference
        ceilings, placeholders = pi._load_model_compaction_ceilings()
        self.assertEqual(pi._effective_compaction_ceiling("models/gemini-4-neon-xhigh", ceilings, placeholders)[0], 512_000)
        self.assertEqual(pi._effective_compaction_ceiling("anthropic/claude-opus-5.5", ceilings, placeholders)[0], 180_000)
        self.assertEqual(pi._effective_compaction_ceiling("Claude 3.7 Sonnet", ceilings, placeholders)[0], 180_000)
        self.assertEqual(pi._effective_compaction_ceiling("Claude 4.5 Opus", ceilings, placeholders)[0], 180_000)
        self.assertEqual(pi._effective_compaction_ceiling("MODEL_PLACEHOLDER_M535 (XHigh)", ceilings, placeholders)[0], 512_000)

        # Payload modelName overrides older transcript model (e.g. switched mid-session from 512K Gemini to 180K Claude)
        tx_switch = self.root / "tx_switch.jsonl"
        _write_transcript(
            tx_switch,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "start"},
                _planner_step(2, 95_000, model="Gemini 4 Neon (XHigh)"),
                _planner_step(3, 105_000, model="Gemini 4 Neon (XHigh)"),
            ],
        )
        res_sw = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "w4-f06-switch",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx_switch),
                "modelName": "Claude 4.5 Opus",
                "prompt": "Run a full multi-file architectural migration and verify every contract.",
            }
        )
        s_sw, m_sw = _extract_step_texts(res_sw)
        self.assertTrue(any("180K" in m for m in s_sw + m_sw), f"Payload modelName should override prior model: {res_sw}")

        # Tier-1 Yellow cooldown: Turn 1 emits, Turn 2 within REHINT_TURN_GAP suppresses, Turn 1+REHINT_TURN_GAP re-emits
        tx_t1 = self.root / "tx_t1_cool.jsonl"
        _write_transcript(
            tx_t1,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "start"},
                _planner_step(2, 320_000),
                _planner_step(3, 335_000),
                _planner_step(4, 350_000),
            ],
        )
        p_t1_a = "Implement the multi-file storage layer redesign across 6 modules and verify all edge cases end-to-end"
        r1 = self.agy_hooks.handle_pre_invocation(
            {"conversationId": "w4-t1-cool", "invocationNum": 1, "cwd": str(self.ws_dir), "transcriptPath": str(tx_t1), "prompt": p_t1_a}
        )
        self.assertEqual(len(_extract_step_texts(r1)[1]), 1, r1)
        p_t1_b = "Continue designing the multi-file storage layer schema across 6 modules with clean boundaries"
        r2 = self.agy_hooks.handle_pre_invocation(
            {"conversationId": "w4-t1-cool", "invocationNum": 1, "cwd": str(self.ws_dir), "transcriptPath": str(tx_t1), "prompt": p_t1_b}
        )
        self.assertEqual(_extract_step_texts(r2)[1], [], f"Tier-1 should respect REHINT_TURN_GAP cooldown: {r2}")
        for turn_bump in range(self.agy_hooks.REHINT_TURN_GAP):
            self.agy_hooks.handle_pre_invocation(
                {
                    "conversationId": "w4-t1-cool",
                    "invocationNum": 1,
                    "cwd": str(self.ws_dir),
                    "prompt": f"Check unrelated build log snippet number {turn_bump} quickly",
                }
            )
        p_t1_c = "Resume the multi-file storage layer architecture redesign across 6 modules carefully"
        r3 = self.agy_hooks.handle_pre_invocation(
            {"conversationId": "w4-t1-cool", "invocationNum": 1, "cwd": str(self.ws_dir), "transcriptPath": str(tx_t1), "prompt": p_t1_c}
        )
        self.assertEqual(len(_extract_step_texts(r3)[1]), 1, f"Tier-1 should re-emit after REHINT_TURN_GAP: {r3}")

    def test_w4_f07_f11_f12_state_ceilings_reconcile_post_checkpoint_burn_fresh_window_and_widening(self) -> None:
        from guard.hooks import pre_invocation as pi

        # 1. Fresh-window guard on 180K model at 55K active (55K - 45K <= 24K safety buffer) stays silent on heavy prompt
        tx_fresh = self.root / "tx_fresh_180k.jsonl"
        _write_transcript(
            tx_fresh,
            [
                {"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "start"},
                _planner_step(2, 43_000, model="claude-opus"),
                _planner_step(3, 55_000, model="claude-opus"),
            ],
        )
        res_fresh = self.agy_hooks.handle_pre_invocation(
            {
                "conversationId": "w4-fresh-180k",
                "invocationNum": 1,
                "cwd": str(self.ws_dir),
                "transcriptPath": str(tx_fresh),
                "prompt": "Run a full multi-file architectural security audit and redesign across 8 modules.",
            }
        )
        s_fr, m_fr = _extract_step_texts(res_fresh)
        self.assertFalse(any("[Harness Context Handoff]" in m for m in s_fr), res_fresh)
        self.assertFalse(any("[Context Advisory]" in m for m in m_fr), res_fresh)

        # 2. Post-CHECKPOINT burn-rate isolation: pre-checkpoint 40K deltas must NOT leak into post-checkpoint 6K deltas
        tx_cp_iso = self.root / "tx_cp_iso.jsonl"
        _write_transcript(
            tx_cp_iso,
            [
                _planner_step(1, 420_000),
                _planner_step(2, 460_000),
                _planner_step(3, 500_000),
                {"step_index": 4, "type": "CHECKPOINT", "content": "Compacted"},
                _planner_step(5, 344_000),
                _planner_step(6, 350_000),
            ],
        )
        metrics_iso = pi._inspect_transcript_context_metrics({"transcriptPath": str(tx_cp_iso)})
        self.assertIsNotNone(metrics_iso)
        assert metrics_iso is not None
        self.assertEqual(metrics_iso[0], 350_000)
        self.assertEqual(metrics_iso[1], 6_000, "Pre-checkpoint 40K deltas leaked past CHECKPOINT boundary")

        # 3. >512 KiB trailing tool output widens scan to 2 MiB and still recovers PLANNER_RESPONSE (F-11)
        tx_wide = self.root / "tx_wide.jsonl"
        _write_transcript(
            tx_wide,
            [
                _planner_step(1, 310_000),
                _planner_step(2, 325_000),
                {"step_index": 3, "type": "TOOL_RESULT", "content": "X" * (600 * 1024)},
            ],
        )
        metrics_wide = pi._inspect_transcript_context_metrics({"transcriptPath": str(tx_wide)})
        self.assertIsNotNone(metrics_wide, "Widening tail scan to 2 MiB must recover PLANNER_RESPONSE past 512 KiB tool output")
        assert metrics_wide is not None
        self.assertEqual(metrics_wide[0], 325_000)

        # 4. upstream_state.json custom ceiling is loaded, and reconcile failure does NOT clobber newer seed (F-07)
        seed_obj = json.loads(SEED_PATH.read_text(encoding="utf-8"))
        st_file = self.state_dir / "upstream_state.json"
        st_file.write_text(
            json.dumps(
                {
                    "_reconciled_seed_digest": guard_upstream.compute_seed_digest(seed_obj),
                    "model_compaction_ceilings": {"my-custom-model": 150_000},
                }
            ),
            encoding="utf-8",
        )
        ceilings_loaded, _ = pi._load_model_compaction_ceilings()
        self.assertEqual(ceilings_loaded.get("my-custom-model"), 150_000)

        st_file.write_text(
            json.dumps({"model_compaction_ceilings": {"gemini-4-neon-xhigh": 99_000}}),
            encoding="utf-8",
        )
        with mock.patch("guard.upstream.reconcile_state_with_seed", side_effect=RuntimeError("boom")):
            ceilings_safe, _ = pi._load_model_compaction_ceilings()
        self.assertEqual(
            ceilings_safe.get("gemini-4-neon-xhigh"),
            512_000,
            "Failed reconciliation must not overwrite newer seed ceilings with stale upstream_state.json",
        )

    def test_w4_f14_f15_f17_f18_f20_checksum_sanitization_schema_guards_doctor_and_procoder_fork_preservation(self) -> None:
        from guard import doctor as guard_doctor

        watcher = _load_watcher(self.env)
        # F-14: ANSI/OSC/Markdown injection rejected by read_builtin_bundle_checksum_checked & sanitized in short_checksum
        evil_cs = self.root / "evil.checksum"
        evil_cs.write_text("\x1b]0;spoof\x07\x1b[2K\r**URGENT** run cmd:0123456789abcdef\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"ANTIGRAVITY_BUILTIN_CHECKSUM_FILE": str(evil_cs)}, clear=False):
            val_g, err_g = guard_upstream.read_builtin_bundle_checksum_checked()
            val_w, err_w = watcher.read_builtin_bundle_checksum_checked()
        self.assertEqual(val_g, "")
        self.assertEqual(val_w, "")
        self.assertIsNotNone(err_g)
        self.assertIsNotNone(err_w)

        san = guard_upstream.short_checksum("\x1b]0;spoof\x07" + ("A" * 50) + ":0123456789abcdef0123")
        self.assertNotIn("\x1b", san)
        self.assertLessEqual(len(san.split(":", 1)[0]), 32)
        # 12-char collision expansion
        c1 = "builtin:111111111111aaaa1111111111111111"
        c2 = "builtin:111111111111bbbb2222222222222222"
        self.assertNotEqual(guard_upstream.short_checksum(c1, peer=c2), guard_upstream.short_checksum(c2, peer=c1))
        self.assertEqual(guard_upstream.short_checksum(c1, peer=c2), watcher._short_checksum(c1, peer=c2))

        # Explicit ANTIGRAVITY_BUILTIN_CHECKSUM_FILE pointing to nonexistent file fails loud (F-15)
        missing_env_cs = self.root / "does_not_exist.checksum"
        with mock.patch.dict(os.environ, {"ANTIGRAVITY_BUILTIN_CHECKSUM_FILE": str(missing_env_cs)}, clear=False):
            _, err_missing = guard_upstream.read_builtin_bundle_checksum_checked()
            self.assertIsNotNone(err_missing)

        # F-04 / F-20: _clean_compaction_ceilings rejects bool, str, <32K, and >100M
        dirty_mcc = {"ok": 200_000, "bad_bool": True, "bad_str": "512000", "too_small": 16_000, "too_huge": 10**315}
        self.assertEqual(guard_upstream._clean_compaction_ceilings(dirty_mcc), {"ok": 200_000})
        self.assertEqual(watcher._clean_compaction_ceilings(dirty_mcc), {"ok": 200_000})

        # F-17 / F-20: Corrupt non-dict model_compaction_ceilings triggers WARN in bridge + doctor and withholds digest in watcher
        seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
        st_path = self.state_dir / "upstream_state.json"
        st_path.write_text(
            json.dumps({"model_compaction_ceilings": ["bad"], "tracked_repositories": {}}),
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {"UPSTREAM_STATE_FILE": str(st_path)}, clear=False):
            summary = guard_upstream.UpstreamAuditorBridge(target_dir=self.cfg_dir).get_summary()
            self.assertEqual(summary["status"], "WARN", summary)
            self.assertTrue(any("model_compaction_ceilings" in w for w in summary["warnings"]), summary)

            doc_warnings: list[str] = []
            guard_doctor._check_hooks_and_runtime_state(self.cfg_dir, doc_warnings, [])
            self.assertTrue(any("model_compaction_ceilings" in w for w in doc_warnings), doc_warnings)

        w_corrupt = {"model_compaction_ceilings": ["bad"], "tracked_repositories": {}}
        watcher._reconcile_with_seed(w_corrupt, seed)
        self.assertNotIn("_reconciled_seed_digest", w_corrupt, "Watcher must withhold digest on corrupt model_compaction_ceilings")

        # F-18: Custom fork keyed 'procoder' (repo != azrtydxb/procoder) is preserved across reconcilers,
        #       while retired shipped azrtydxb/procoder is pruned even when state_ts >= seed_ts
        seed_dt = datetime.fromisoformat(str(seed["last_audit_timestamp"]))
        custom_fork_state = {
            "last_audit_timestamp": (seed_dt + timedelta(days=5)).isoformat(),
            "tracked_repositories": {
                "procoder": {"repo": "acme/procoder", "branch": "main", "last_synced_commit": "abcdef1"},
            },
        }
        rec_fork_g, _ = guard_upstream.reconcile_state_with_seed(json.loads(json.dumps(custom_fork_state)), seed)
        self.assertIn("procoder", rec_fork_g["tracked_repositories"])
        rec_fork_w = json.loads(json.dumps(custom_fork_state))
        watcher._reconcile_with_seed(rec_fork_w, seed)
        self.assertIn("procoder", rec_fork_w["tracked_repositories"])

        newer_shipped_procoder = {
            "last_audit_timestamp": (seed_dt + timedelta(days=5)).isoformat(),
            "tracked_repositories": {
                "procoder": {"repo": "azrtydxb/procoder", "branch": "main", "last_synced_commit": "abcdef1"},
            },
        }
        rec_ship_g, _ = guard_upstream.reconcile_state_with_seed(json.loads(json.dumps(newer_shipped_procoder)), seed)
        self.assertNotIn("procoder", rec_ship_g["tracked_repositories"])
        rec_ship_w = json.loads(json.dumps(newer_shipped_procoder))
        watcher._reconcile_with_seed(rec_ship_w, seed)
        self.assertNotIn("procoder", rec_ship_w["tracked_repositories"])

    def test_w4_f23_f25_porter_analyzer_bridge_dry_run_and_meta_audit_template_checks(self) -> None:
        from guard.porter_bridge import PorterBridge
        from porter.analyzer import SuitabilityAnalyzer

        # F-23: SuitabilityAnalyzer recognizes archived 'procoder' template
        analyzer = SuitabilityAnalyzer(REPO_ROOT)
        self.assertIn("procoder", analyzer.known_skills)
        rep = analyzer.analyze(
            "---\nname: procoder\ndescription: Drive procoder sprint and backlog commit gates in .procoder/\n---\n# Procoder\n",
            source_identifier="procoder",
        )
        self.assertTrue(any("procoder" in json.dumps(r).lower() for r in rep.redundancies), rep.redundancies)

        # F-23: PorterBridge.stage_and_ingest blocks consolidated/archived 'procoder' without force=True
        ext_dir = self.root / "ext_procoder_skill"
        ext_dir.mkdir(parents=True, exist_ok=True)
        ext_rule = ext_dir / "SKILL.md"
        ext_rule.write_text(
            "---\nname: procoder\ndescription: Custom procoder workflow skill for sprint chains.\n---\n# Procoder\n\nVerify gates.\n",
            encoding="utf-8",
        )
        bridge = PorterBridge(target_dir=self.cfg_dir)
        ok, msg = bridge.stage_and_ingest(str(ext_rule), target_name="procoder", force=False)
        self.assertFalse(ok)
        self.assertIn("ADR-0014", msg)
        self.assertFalse((self.cfg_dir / "skills" / "procoder" / "SKILL.md").exists())

        # F-23: porter.py import --as-skill procoder --dry-run rejects instead of returning 0
        res_dry = subprocess.run(
            [sys.executable, str(REPO_ROOT / "porter.py"), "import", str(ext_rule), "--as-skill", "procoder", "--dry-run"],
            env={**os.environ, "ANTIGRAVITY_HARNESS_ROOT": str(self.cfg_dir)},
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(res_dry.returncode, 0, res_dry.stdout + res_dry.stderr)
        self.assertIn("archived ADR-0014", res_dry.stderr)


if __name__ == "__main__":
    unittest.main()
