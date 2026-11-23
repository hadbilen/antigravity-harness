from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
for _p in (str(TESTS_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hermetic  # noqa: E402, F401  # must precede repository imports per ADR-0010

from guard import agy_hooks
from guard.hooks import pre_tool_use
from guard.upstream import UpstreamAuditorBridge, compute_seed_digest, reconcile_state_with_seed
from porter.analyzer import SuitabilityAnalyzer
from porter.emitters import EMITTERS
from porter.frontmatter import parse_frontmatter
from porter.manifest import ManifestEngine
from porter.sanitizer import find_directives
from scripts.meta_audit import MetaAuditEngine

_ANALYZER = SuitabilityAnalyzer(REPO_ROOT)
_WATCHER_PATH = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
_CHECK_SKILLS_SH = REPO_ROOT / "skills" / "upstream-auditor" / "scripts" / "check_skills.sh"


def _bash_exe() -> str:
    if os.name == "nt":
        for cand in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"):
            if os.path.isfile(cand):
                return cand
    return shutil.which("bash") or "bash"


def _assert_constitutionally_clean(case: unittest.TestCase, label: str, text: str) -> None:
    report = _ANALYZER.analyze(text, source_identifier=label)
    case.assertEqual(report.constitutional_score, 100, f"{label}: {report.issues}")
    case.assertEqual(report.issues, [], f"{label}: {report.issues}")
    case.assertEqual(find_directives(text), [], f"{label} tripped sanitizer")


def _load_watcher_module(name: str = "adr0012_upstream_watcher"):
    spec = importlib.util.spec_from_file_location(name, _WATCHER_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _TempCase(unittest.TestCase):
    _tmp_prefix = "agy-adr0012-"

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix=self._tmp_prefix)
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def _patch_env(self, updates: dict[str, str], *, pop_keys: tuple[str, ...] = ()) -> None:
        patcher = mock.patch.dict(os.environ, updates, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        for key in pop_keys:
            os.environ.pop(key, None)


class TestAdr0012TemplatesAndMetaAuditSeam(_TempCase):
    _tmp_prefix = "agy-adr0012-tmpl-"

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = ManifestEngine(harness_root=REPO_ROOT).build_manifest(deterministic=True)

    def test_repostate_vulkan_and_handoff_templates_bounds_contracts_and_porter_parity(self) -> None:
        repostate_path = REPO_ROOT / "templates" / "REPOSTATE.template.md"
        vulkan_path = REPO_ROOT / "templates" / "vulkan.SKILL.template.md"
        handoff_path = REPO_ROOT / "templates" / "HANDOFF.template.md"
        adr_path = REPO_ROOT / "docs" / "adr" / "0012-repostate-vulkan-template-low-friction-ux-and-rustify-patterns.md"
        adr_index = (REPO_ROOT / "docs" / "adr" / "README.md").read_text(encoding="utf-8")

        self.assertTrue(repostate_path.is_file())
        self.assertTrue(vulkan_path.is_file())
        self.assertTrue(handoff_path.is_file())
        self.assertTrue(adr_path.is_file())
        self.assertIn("0012-repostate-vulkan-template-low-friction-ux-and-rustify-patterns.md", adr_index)

        repostate_text = repostate_path.read_text(encoding="utf-8")
        repostate_lines = repostate_text.splitlines()
        self.assertLessEqual(len(repostate_lines), 150, f"REPOSTATE.template.md exceeded 150 lines: {len(repostate_lines)}")
        self.assertIn("Last Verified Commit", repostate_text)
        self.assertIn("Point to files; copy nothing", repostate_text)
        for heading in (
            "## 1. Current State Snapshot",
            "## 2. Planned Roadmap",
            "## 3. Compact Milestone Ledger",
        ):
            self.assertIn(heading, repostate_text)
        self.assertIsNone(
            re.search(r"\.[a-z0-9]+:L\d+", repostate_text),
            "REPOSTATE.template.md must not embed volatile :L<n> line coordinates",
        )

        handoff_text = handoff_path.read_text(encoding="utf-8")
        self.assertIn("## Completed Windows Log", handoff_text)
        self.assertIn("| Window | Date | Status | Delivered Artifacts & Verified Gates | Exit Criteria Progress |", handoff_text)

        vulkan_text = vulkan_path.read_text(encoding="utf-8")
        meta, body = parse_frontmatter(vulkan_text)
        self.assertEqual(meta.get("name"), "vulkan")
        self.assertIn("Not for", str(meta.get("description", "")))
        for needle in (
            "VK_KHR_dynamic_rendering",
            "VK_KHR_synchronization2",
            "VK_SEMAPHORE_TYPE_TIMELINE",
            "VUID-vkQueueSubmit-pSignalSemaphores-00067",
            "VK_ERROR_DEVICE_LOST",
            "VK_ERROR_SURFACE_LOST_KHR",
            "vkGetPhysicalDeviceProperties",
            "$VULKAN_SDK",
            "vk.xml",
            "spirv-val",
            "VK_LAYER_KHRONOS_validation",
            "VK_KHRONOS_VALIDATION_VALIDATE_SYNC=true",
            "VK_EXT_debug_utils",
            "Lavapipe",
            "VK_ICD_FILENAMES",
            "skills/rust-harden/references/game-and-realtime.md",
        ):
            self.assertIn(needle, body)

        for label, text in (
            ("REPOSTATE.template.md", repostate_text),
            ("vulkan.SKILL.template.md", vulkan_text),
            ("HANDOFF.template.md", handoff_text),
        ):
            with self.subTest(template=label):
                _assert_constitutionally_clean(self, label, text)

        for tmpl_name in ("REPOSTATE.template.md", "vulkan.SKILL.template.md", "HANDOFF.template.md"):
            self.assertIn(tmpl_name, self.manifest.templates)
        for target, emitter in EMITTERS.items():
            with self.subTest(target=target):
                out = self.tmp / f"export_{target}"
                emitter.emit(self.manifest, out)
                for tmpl_name in ("REPOSTATE.template.md", "vulkan.SKILL.template.md", "HANDOFF.template.md"):
                    self.assertEqual(
                        (out / "templates" / tmpl_name).read_bytes(),
                        (REPO_ROOT / "templates" / tmpl_name).read_bytes(),
                    )

    def test_meta_audit_pass2_recognizes_repostate_and_rejects_undeclared_ledger(self) -> None:
        mini = self.tmp / "mini_repo"
        (mini / "skills" / "demo").mkdir(parents=True)
        (mini / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")
        (mini / "skills" / "demo" / "SKILL.md").write_text(
            "---\n"
            "name: demo\n"
            "description: Demo skill. Invoke with /demo. Not for prod (use 'other').\n"
            "---\n\n"
            "# Demo\n\n"
            "Inspect `REPOSTATE.md` when present at project root.\n",
            encoding="utf-8",
        )
        eng_clean = MetaAuditEngine(mini)
        eng_clean.pass2_cross_references()
        clean_msgs = [f.message for f in eng_clean.findings if "Referenced file" in f.message]
        self.assertEqual(clean_msgs, [], clean_msgs)

        # Negative control: an unapproved markdown filename must still be flagged by Pass 2.
        (mini / "skills" / "demo" / "SKILL.md").write_text(
            "---\n"
            "name: demo\n"
            "description: Demo skill. Invoke with /demo. Not for prod (use 'other').\n"
            "---\n\n"
            "# Demo\n\n"
            "Inspect `UNDECLARED_REPOSTATE_WORKLOG.md` when present.\n",
            encoding="utf-8",
        )
        eng_bad = MetaAuditEngine(mini)
        eng_bad.pass2_cross_references()
        self.assertTrue(
            any("UNDECLARED_REPOSTATE_WORKLOG.md" in f.message for f in eng_bad.findings),
            f"Expected Pass 2 finding for undeclared .md reference, got: {eng_bad.findings}",
        )

    def test_frontmatter_ceiling_and_21_top_level_skills_without_rust_anything_skill(self) -> None:
        skill_dirs = sorted(p.parent.name for p in (REPO_ROOT / "skills").glob("*/SKILL.md"))
        self.assertEqual(len(skill_dirs), 20, f"Expected 20 top-level skills, got {len(skill_dirs)}: {skill_dirs}")
        self.assertNotIn("rust-anything", skill_dirs)
        self.assertFalse((REPO_ROOT / "skills" / "rust-anything").exists())

        total_fm_bytes = 0
        for sk_md in sorted((REPO_ROOT / "skills").glob("*/SKILL.md")):
            m = re.match(r"\A---\r?\n.*?\r?\n---", sk_md.read_text(encoding="utf-8"), re.DOTALL)
            self.assertIsNotNone(m, str(sk_md))
            assert m is not None
            total_fm_bytes += len(m.group(0).encode("utf-8"))
        self.assertLessEqual(
            total_fm_bytes,
            10800,
            f"Aggregate skills/*/SKILL.md frontmatter exceeded 10,800 B cap: {total_fm_bytes}",
        )


class TestAdr0012LowFrictionUxAndGuardSafetySeam(_TempCase):
    _tmp_prefix = "agy-adr0012-ux-"

    def setUp(self) -> None:
        super().setUp()
        self.fake_state = self.tmp / "state"
        self.fake_cfg = self.tmp / "cfg"
        self.fake_state.mkdir(parents=True, exist_ok=True)
        self.fake_cfg.mkdir(parents=True, exist_ok=True)
        (self.fake_cfg / "GEMINI.md").write_text("# Test Constitution\n", encoding="utf-8")
        self._patch_env(
            {
                "AGY_GUARD_STATE_DIR": str(self.fake_state),
                "ANTIGRAVITY_STATE_DIR": str(self.fake_state),
                "ANTIGRAVITY_CONFIG_DIR": str(self.fake_cfg),
            }
        )

    def test_low_friction_ux_directives_and_marathon_window_log_contracts(self) -> None:
        checks = {
            "skills/harness/SKILL.md": (
                "Reversible-First Default Rule",
                "3-Class Hard Ask Gate",
                "RequestFeedback: false",
                "--auto",
                "REPOSTATE.md",
                "templates/vulkan.SKILL.template.md",
            ),
            "skills/harness/references/marathon.md": (
                "## Completed Windows Log",
                "Wk (Resumed)",
                "REPOSTATE.md",
                "single `ask_question` round",
                "Gemini 4 Neon (XHigh)",
                "Gemini 4 Carbon (High)",
            ),
            "skills/harness/references/adr.md": (
                "Reversible-First",
                "without pausing for a low-stakes confirmation",
            ),
            "skills/deep-grill/SKILL.md": (
                "Frontier-Batch",
                "Explicit `/deep-grill` Invocation (One at a Time)",
                "lacking `ask_question`",
            ),
            "skills/audit/SKILL.md": (
                "REPOSTATE.md",
                "explicitly invoked `/audit`",
                "<= 1 MB",
            ),
        }
        for rel_path, needles in checks.items():
            text = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
            with self.subTest(doc=rel_path):
                _assert_constitutionally_clean(self, rel_path, text)
                for needle in needles:
                    self.assertIn(needle, text)

    def test_guard_layer_a_remains_strict_under_autonomous_context(self) -> None:
        ws = self.tmp / "ws_no_auth"
        ws.mkdir(parents=True)
        benign_file = ws / "src" / "app.py"
        benign_file.parent.mkdir(parents=True)
        benign_file.write_text("x = 1\n", encoding="utf-8")

        # 0. Benign control: non-governance workspace edit passes with allow.
        res_ok = agy_hooks.handle_pre_tool_use(
            {
                "modelName": "Gemini 4 Neon (XHigh)",
                "effort": "xhigh",
                "workspace": str(ws),
                "toolCall": {
                    "name": "edit_file",
                    "args": {"Path": str(benign_file)},
                },
            }
        )
        self.assertEqual(res_ok.get("decision"), "allow", res_ok)

        # 1. Direct write to ~/.gemini/config/GEMINI.md must still be denied by Governance Shield.
        res_cfg = agy_hooks.handle_pre_tool_use(
            {
                "modelName": "Gemini 4 Neon (XHigh)",
                "effort": "xhigh",
                "toolCall": {
                    "name": "edit_file",
                    "args": {"Path": str(self.fake_cfg / "GEMINI.md")},
                },
            }
        )
        self.assertEqual(res_cfg.get("decision"), "deny", res_cfg)
        self.assertIn("Harness Governance Shield", res_cfg.get("reason", ""))

        # 2. Writing `## Authorized Test Modifications` into tasks.md must still trigger force_ask (Rule 9).
        tasks_path = ws / "tasks.md"
        res_tasks = agy_hooks.handle_pre_tool_use(
            {
                "modelName": "Gemini 4 Neon (XHigh)",
                "effort": "xhigh",
                "workspace": str(ws),
                "toolCall": {
                    "name": "write_file",
                    "args": {
                        "Path": str(tasks_path),
                        "Content": "# Tasks\n\n## Authorized Test Modifications\n- `tests/test_core.py`: auto\n",
                    },
                },
            }
        )
        self.assertEqual(res_tasks.get("decision"), "force_ask", res_tasks)
        self.assertIn("Harness Test Boundary", res_tasks.get("reason", ""))

        # 3. Destructive remote git push must still trigger force_ask (Rule 12).
        res_push = agy_hooks.handle_pre_tool_use(
            {
                "modelName": "Gemini 4 Neon (XHigh)",
                "effort": "xhigh",
                "workspace": str(ws),
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "git push --force origin main"},
                },
            }
        )
        self.assertEqual(res_push.get("decision"), "force_ask", res_push)
        self.assertIn("Force-pushing", res_push.get("reason", ""))


class TestAdr0012RestrictedModelAllowlistSeam(_TempCase):
    _tmp_prefix = "agy-adr0012-model-"

    def setUp(self) -> None:
        super().setUp()
        self.fake_state = self.tmp / "state"
        self.fake_cfg = self.tmp / "cfg"
        self.fake_state.mkdir(parents=True, exist_ok=True)
        self.fake_cfg.mkdir(parents=True, exist_ok=True)
        self._patch_env(
            {
                "AGY_GUARD_STATE_DIR": str(self.fake_state),
                "ANTIGRAVITY_STATE_DIR": str(self.fake_state),
                "ANTIGRAVITY_CONFIG_DIR": str(self.fake_cfg),
            },
            pop_keys=("ANTIGRAVITY_PBTXT_FILE", "UPSTREAM_STATE_FILE"),
        )

    def test_seed_and_fallback_restrict_allowlist_to_neon_xhigh_and_carbon_high(self) -> None:
        seed_path = REPO_ROOT / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        seed = json.loads(seed_path.read_text(encoding="utf-8"))

        self.assertEqual(seed.get("last_audited_model"), "Gemini 4 Neon (XHigh)")
        self.assertEqual(seed.get("last_model_slug"), "gemini-4-neon-xhigh")
        self.assertEqual(seed.get("last_pbtxt_model"), "MODEL_PLACEHOLDER_M535")
        self.assertGreaterEqual(str(seed.get("last_audit_timestamp", "")), "2026-11-21")
        self.assertGreaterEqual(str(seed.get("last_skills_audit_timestamp", "")), "2026-11-21")
        self.assertEqual(
            seed.get("approved_customization_models"),
            ["gemini-4-neon-xhigh", "gemini-4-carbon-high"],
        )
        self.assertEqual(
            seed.get("known_placeholder_models"),
            {
                "MODEL_PLACEHOLDER_M535": "Gemini 4 Neon (XHigh)",
                "MODEL_PLACEHOLDER_M427": "Gemini 4 Carbon (High)",
            },
        )

        # Fallback dictionary in guard/upstream.py must mirror allowlist, placeholders, and full tracked_repositories dicts.
        bridge = UpstreamAuditorBridge(target_dir=self.fake_cfg)
        fallback = bridge.load_state()
        self.assertEqual(fallback.get("approved_customization_models"), seed.get("approved_customization_models"))
        self.assertEqual(fallback.get("known_placeholder_models"), seed.get("known_placeholder_models"))
        self.assertEqual(fallback.get("tracked_repositories"), seed.get("tracked_repositories"))
        self.assertEqual(len(seed.get("tracked_repositories", {})), 8)

    def test_pre_tool_use_enforces_neon_xhigh_and_carbon_high_only(self) -> None:
        seed_dest = self.fake_cfg / "skills" / "upstream-auditor"
        seed_dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            REPO_ROOT / "skills" / "upstream-auditor" / "upstream_state.seed.json",
            seed_dest / "upstream_state.seed.json",
        )
        empty_repo = self.tmp / "empty_repo"
        empty_repo.mkdir()

        # Patch REPO_ROOT to an empty dir so config_dir seed lookup is genuinely exercised.
        with mock.patch.object(agy_hooks, "REPO_ROOT", empty_repo):
            # Positive controls: concrete Neon (XHigh) and Carbon (High) pass governance write gate.
            for payload in (
                {"modelName": "Gemini 4 Neon (XHigh)", "effort": "xhigh"},
                {"modelName": "Gemini 4 Carbon (High)", "effort": "high"},
            ):
                with self.subTest(allowed=payload):
                    res = agy_hooks.handle_pre_tool_use(
                        {
                            **payload,
                            "toolCall": {"name": "edit_file", "args": {"Path": "skills/rustify/SKILL.md"}},
                        }
                    )
                    self.assertEqual(res.get("decision"), "allow", (payload, res))

            # Known opaque placeholders fail closed (force_ask) with concrete seed mapping diagnostics.
            for placeholder_id, expected_label in (
                ("MODEL_PLACEHOLDER_M535", "Gemini 4 Neon (XHigh)"),
                ("MODEL_PLACEHOLDER_M427", "Gemini 4 Carbon (High)"),
            ):
                with self.subTest(mapped_placeholder=placeholder_id):
                    res = agy_hooks.handle_pre_tool_use(
                        {
                            "modelName": placeholder_id,
                            "toolCall": {"name": "edit_file", "args": {"Path": "skills/rustify/SKILL.md"}},
                        }
                    )
                    self.assertEqual(res.get("decision"), "force_ask", (placeholder_id, res))
                    self.assertIn("known_placeholder_models", res.get("reason", ""))
                    self.assertIn(expected_label, res.get("reason", ""))
                    self.assertNotIn("unmapped", res.get("reason", "").lower())

            # Negative controls: Hydrogen, Argon, Opus, GPT-5.4, and unknown placeholders fail closed (force_ask).
            for payload in (
                {"modelName": "Gemini 4 Hydrogen (XHigh)", "effort": "xhigh"},
                {"modelName": "Gemini 4 Argon (High)", "effort": "high"},
                {"modelName": "Claude Opus 5.5 (High)", "effort": "high"},
                {"modelName": "GPT-5.4 (High)", "effort": "high"},
                {"modelName": "MODEL_PLACEHOLDER_M999"},
            ):
                with self.subTest(blocked=payload):
                    res = agy_hooks.handle_pre_tool_use(
                        {
                            **payload,
                            "toolCall": {"name": "edit_file", "args": {"Path": "skills/rustify/SKILL.md"}},
                        }
                    )
                    self.assertEqual(res.get("decision"), "force_ask", (payload, res))
                    if payload.get("modelName") == "MODEL_PLACEHOLDER_M999":
                        self.assertIn("unmapped", res.get("reason", "").lower())
                        self.assertNotIn("matches seed", res.get("reason", ""))

    def test_pre_tool_use_no_seed_fallback_and_stale_host_state_reconciliation(self) -> None:
        empty_repo = self.tmp / "no_seed_repo"
        empty_cfg = self.tmp / "no_seed_cfg"
        empty_repo.mkdir()
        empty_cfg.mkdir()

        # 1. No-seed fallback must allow Neon (XHigh) and Carbon (High) and reject retired Hydrogen.
        with mock.patch.object(agy_hooks, "REPO_ROOT", empty_repo), mock.patch.object(
            pre_tool_use, "configured_config_dir", return_value=empty_cfg
        ), mock.patch.object(pre_tool_use, "config_dir", return_value=empty_cfg):
            top_name, allowed = pre_tool_use._catalog_top_model_spec()
            self.assertEqual(top_name, "Gemini 4 Neon (XHigh)")
            self.assertIn("gemini-4-neon-xhigh", allowed)
            self.assertIn("gemini-4-carbon-high", allowed)
            self.assertNotIn("gemini-4-hydrogen-xhigh", allowed)
            res_hyd = agy_hooks.handle_pre_tool_use(
                {
                    "modelName": "Gemini 4 Hydrogen (XHigh)",
                    "effort": "xhigh",
                    "toolCall": {"name": "edit_file", "args": {"Path": "skills/rustify/SKILL.md"}},
                }
            )
            self.assertEqual(res_hyd.get("decision"), "force_ask", res_hyd)

        # 2. Stale pre-upgrade host upstream_state.json holding retired Hydrogen is reconciled in memory
        #    so Hydrogen is immediately blocked post-upgrade without waiting for upstream_watcher.
        stale_state = {
            "last_audited_model": "Gemini 4 Hydrogen (XHigh)",
            "last_model_slug": "gemini-4-hydrogen-xhigh",
            "last_audit_timestamp": "2026-11-16T10:00:00+03:00",
            "last_ack_timestamp": "2026-11-18T12:00:00+03:00",
            "approved_customization_models": ["gemini-4-hydrogen-xhigh", "gemini-4-argon-high", "claude-opus-5.5-high"],
        }
        (self.fake_state / "upstream_state.json").write_text(json.dumps(stale_state), encoding="utf-8")
        res_post_upgrade = agy_hooks.handle_pre_tool_use(
            {
                "modelName": "Gemini 4 Hydrogen (XHigh)",
                "effort": "xhigh",
                "toolCall": {"name": "edit_file", "args": {"Path": "skills/rustify/SKILL.md"}},
            }
        )
        self.assertEqual(res_post_upgrade.get("decision"), "force_ask", res_post_upgrade)

    def test_seed_reconciliation_upgrades_retired_models_and_adds_rust_anything(self) -> None:
        seed = json.loads(
            (REPO_ROOT / "skills" / "upstream-auditor" / "upstream_state.seed.json").read_text(encoding="utf-8")
        )
        eight_repos = {k: v for k, v in seed["tracked_repositories"].items() if k != "rust-anything"}
        self.assertEqual(len(eight_repos), 7)

        legacy_templates = [
            (
                "old_digest_ledger",
                {
                    "_reconciled_seed_digest": "0000000000000000",
                    "last_audited_model": "Gemini 4 Hydrogen (XHigh)",
                    "last_model_slug": "gemini-4-hydrogen-xhigh",
                    "last_seen_model": "Gemini 4 Argon (High)",
                    "approved_customization_models": [
                        "gemini-4-hydrogen-xhigh",
                        "gemini-4-argon-high",
                        "claude-opus-5.5-high",
                        "orchestrator-carbon-high",
                    ],
                    "last_pbtxt_model": "MODEL_PLACEHOLDER_M528",
                    "known_placeholder_models": {
                        "MODEL_PLACEHOLDER_M417": "Gemini 4 Argon (High)",
                        "MODEL_PLACEHOLDER_M528": "Gemini 4 Hydrogen (XHigh)",
                    },
                    "last_audit_timestamp": "2026-11-16T10:00:00+03:00",
                    "last_skills_audit_timestamp": "2026-11-15T19:05:00+03:00",
                    "tracked_repositories": dict(eight_repos),
                },
            ),
            (
                "pre_digest_with_newer_ack",
                {
                    "last_audited_model": "Gemini 4 Hydrogen (XHigh)",
                    "last_model_slug": "gemini-4-hydrogen-xhigh",
                    "last_seen_model": "Gemini 4 Argon (High)",
                    "approved_customization_models": [
                        "gemini-4-hydrogen-xhigh",
                        "gemini-4-argon-high",
                        "claude-opus-5.5-high",
                    ],
                    "last_pbtxt_model": "MODEL_PLACEHOLDER_M528",
                    "known_placeholder_models": {
                        "MODEL_PLACEHOLDER_M417": "Gemini 4 Argon (High)",
                        "MODEL_PLACEHOLDER_M528": "Gemini 4 Hydrogen (XHigh)",
                    },
                    "last_audit_timestamp": "2026-11-16T10:00:00+03:00",
                    "last_skills_audit_timestamp": "2026-11-15T19:05:00+03:00",
                    "last_ack_timestamp": "2026-11-18T12:00:00+03:00",
                    "tracked_repositories": dict(eight_repos),
                },
            ),
        ]

        uw = _load_watcher_module()
        expected_acm = ["gemini-4-neon-xhigh", "gemini-4-carbon-high"]
        expected_kpm = {
            "MODEL_PLACEHOLDER_M535": "Gemini 4 Neon (XHigh)",
            "MODEL_PLACEHOLDER_M427": "Gemini 4 Carbon (High)",
        }

        for label, base_state in legacy_templates:
            with self.subTest(reconciler="guard.upstream", case=label):
                merged, changed = reconcile_state_with_seed(json.loads(json.dumps(base_state)), seed)
                self.assertTrue(changed)
                self.assertEqual(merged.get("last_audited_model"), "Gemini 4 Neon (XHigh)")
                self.assertEqual(merged.get("last_model_slug"), "gemini-4-neon-xhigh")
                self.assertNotEqual(merged.get("last_seen_model"), "Gemini 4 Argon (High)")
                self.assertEqual(merged.get("approved_customization_models"), expected_acm)
                self.assertEqual(merged.get("known_placeholder_models"), expected_kpm)
                self.assertEqual(merged["tracked_repositories"].get("rust-anything"), seed["tracked_repositories"]["rust-anything"])

            with self.subTest(reconciler="upstream_watcher", case=label):
                uw_state = json.loads(json.dumps(base_state))
                changed_uw = uw._reconcile_with_seed(uw_state, seed)
                self.assertTrue(changed_uw)
                self.assertEqual(uw_state.get("last_audited_model"), "Gemini 4 Neon (XHigh)")
                self.assertEqual(uw_state.get("last_model_slug"), "gemini-4-neon-xhigh")
                self.assertNotEqual(uw_state.get("last_seen_model"), "Gemini 4 Argon (High)")
                self.assertEqual(uw_state.get("approved_customization_models"), expected_acm)
                self.assertEqual(uw_state.get("known_placeholder_models"), expected_kpm)
                self.assertEqual(uw_state["tracked_repositories"].get("rust-anything"), seed["tracked_repositories"]["rust-anything"])


class TestAdr0012RustifyPatternsAndGameRealtimeSeam(_TempCase):
    _tmp_prefix = "agy-adr0012-rust-"

    def test_rustify_absorbs_rust_anything_patterns_without_weakening_cpp_or_formal_gates(self) -> None:
        skill_text = (REPO_ROOT / "skills" / "rustify" / "SKILL.md").read_text(encoding="utf-8")
        managed_text = (REPO_ROOT / "skills" / "rustify" / "references" / "managed-go-python.md").read_text(
            encoding="utf-8"
        )

        for label, text in (("rustify/SKILL.md", skill_text), ("managed-go-python.md", managed_text)):
            with self.subTest(doc=label):
                _assert_constitutionally_clean(self, label, text)

        # Preserved C++ / #![no_std] / miri / ASan / UBSan / cargo kani gates + Stage 5 bounds in SKILL.md
        for preserved in (
            "#[cxx::bridge]",
            "#![no_std]",
            "cargo +nightly miri test",
            "AddressSanitizer",
            "UndefinedBehaviorSanitizer",
            "cargo kani",
            "BLOCKED",
            "-Xcheck:jni",
            "--expose-gc",
            "// INFALLIBLE:",
            "#[expect(clippy::expect_used, reason = \"...\")]",
            "#[expect(lint, reason = \"...\")]",
            "MSRV < 1.81",
            "approved_in",
            "=2.1.0 --locked",
            "fallback rate",
            "kill switch",
            "post-lift reshape",
        ):
            self.assertIn(preserved, skill_text)
        self.assertIsNotNone(re.search(r"(?<!\d)0%", skill_text))
        self.assertIsNotNone(re.search(r"3x\b[^\n]{0,60}\b50\b", skill_text))

        # Canonical managed/dynamic runtime & rust-anything v2.1.0 patterns in managed-go-python.md
        for absorbed in (
            "napi-rs",
            "wasm",
            "Ruby",
            "Java",
            "--batch",
            "FnIndex",
            "UTF-16",
            "fancy-regex",
            "backtrack_limit",
            "Turkish",
            "Kelvin",
            "char::is_alphanumeric",
            "indexmap",
            "known-diffs.jsonl",
            '"expected"',
            '"approved_in"',
            "`values`",
            "`order`",
            "`lines`",
            "fallback rate",
            "kill switch",
            "catch_unwind",
            "post-lift reshape",
            "=2.1.0 --locked",
        ):
            self.assertIn(absorbed, managed_text)
        self.assertIsNotNone(re.search(r"(?<!\d)0%", managed_text))

    def test_rust_harden_game_and_realtime_profile_and_cursor_export(self) -> None:
        skill_path = REPO_ROOT / "skills" / "rust-harden" / "SKILL.md"
        game_path = REPO_ROOT / "skills" / "rust-harden" / "references" / "game-and-realtime.md"
        self.assertTrue(game_path.is_file())

        skill_text = skill_path.read_text(encoding="utf-8")
        game_text = game_path.read_text(encoding="utf-8")

        m_fm = re.match(r"\A---\r?\n.*?\r?\n---", skill_text, re.DOTALL)
        self.assertIsNotNone(m_fm)
        assert m_fm is not None
        self.assertLessEqual(len(m_fm.group(0).encode("utf-8")), 520)

        for label, text in (("rust-harden/SKILL.md", skill_text), ("game-and-realtime.md", game_text)):
            with self.subTest(doc=label):
                _assert_constitutionally_clean(self, label, text)

        for needle in (
            "references/game-and-realtime.md",
            "#[expect(lint, reason = \"...\")]",
            "#[expect(clippy::expect_used, reason = \"...\")]",
            "// INFALLIBLE:",
            "TS/JS, Ruby, or Java/Kotlin",
        ):
            self.assertIn(needle, skill_text)

        for needle in (
            "clippy::large_enum_variant",
            "1,000",
            "--test-threads=1",
            "realloc",
            "Generational Arena",
            "Rc<RefCell<",
            "Arc<Mutex<",
            "HashMap",
            "total_cmp",
            "NaN",
            "clamp",
            "Drop",
            "VUID-vkDestroySurfaceKHR-surface-01266",
            "Outdated",
            "Lost",
            "Timeout",
            "OutOfMemory",
            "SPSC",
            "heap deallocation",
            "try_reserve_exact",
            "MAX_NESTING_DEPTH",
            "MAX_DECOMPRESSED_BYTES",
            "fsync",
            "schema_version",
        ):
            self.assertIn(needle, game_text)

        manifest = ManifestEngine(harness_root=REPO_ROOT).build_manifest(deterministic=True)
        out_dir = self.tmp / "cursor_export"
        EMITTERS["cursor"].emit(manifest, out_dir)
        mdc_path = out_dir / ".cursor" / "rules" / "skill-rust-harden.mdc"
        support_path = out_dir / ".cursor" / "skills" / "rust-harden" / "references" / "game-and-realtime.md"
        self.assertTrue(mdc_path.is_file())
        self.assertTrue(support_path.is_file())
        self.assertEqual(support_path.read_bytes(), game_path.read_bytes())

        mdc_text = mdc_path.read_text(encoding="utf-8")
        mdc_meta, _ = parse_frontmatter(mdc_text)
        self.assertEqual(mdc_meta.get("globs"), "**/*.rs, **/Cargo.toml")
        self.assertIn(".cursor/skills/rust-harden/references/game-and-realtime.md", mdc_text)
        self.assertNotIn("./references/game-and-realtime.md", mdc_text)

    def test_pre_invocation_rustify_routing_covers_ts_ruby_java_without_intra_rust_collision(self) -> None:
        fake_state = self.tmp / "pre_inv_state"
        fake_state.mkdir()
        self._patch_env(
            {"AGY_GUARD_STATE_DIR": str(fake_state), "ANTIGRAVITY_STATE_DIR": str(fake_state)}
        )
        for idx, prompt in enumerate(
            (
                "Migrate TypeScript parser to Rust using napi-rs",
                "Port our Ruby pricing module to Rust",
                "Java'dan Rust'a taşı",
                "Rust FFI bindings for Java/Kotlin",
            ),
            1,
        ):
            with self.subTest(rustify_prompt=prompt):
                out = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"adr0012-rustify-{idx}", "prompt": prompt}
                )
                self.assertIn("injectSteps", out, (prompt, out))
                sys_msg = out["injectSteps"][0]["systemMessage"]["systemMessage"]
                self.assertIn("`rustify`", sys_msg, (prompt, out))

        # Negative control: intra-Rust hardening must route to rust-harden, not rustify.
        out_harden = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "adr0012-rust-harden-neg",
                "prompt": "Harden this Rust crate to remove unwrap and clone debt",
            }
        )
        self.assertIn("injectSteps", out_harden, out_harden)
        harden_msg = out_harden["injectSteps"][0]["systemMessage"]["systemMessage"]
        self.assertIn("`rust-harden`", harden_msg, out_harden)
        self.assertNotIn("`rustify`", harden_msg, out_harden)

    def test_rust_anything_release_tracking_and_third_party_notice(self) -> None:
        seed = json.loads(
            (REPO_ROOT / "skills" / "upstream-auditor" / "upstream_state.seed.json").read_text(encoding="utf-8")
        )
        entry = seed.get("tracked_repositories", {}).get("rust-anything")
        self.assertEqual(
            entry,
            {
                "repo": "erkamyaman/rust-anything",
                "branch": "main",
                "track": "release",
                "last_synced_commit": "v2.1.0",
                "target_skills": ["rustify", "rust-harden"],
            },
        )

        notices = (REPO_ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        self.assertIn("erkamyaman/rust-anything", notices)
        self.assertIn("Copyright (c) 2026 Erkam Yaman (erkamyaman)", notices)

        # Runtime check_repositories seam for "track": "release" (Up-to-date vs. Updates Available)
        state_file = self.tmp / "state_ra.json"
        state_file.write_text(
            json.dumps(
                {
                    "tracked_repositories": {
                        "rust-anything": dict(entry),
                        "rust-anything-stale": {
                            **entry,
                            "repo": "erkamyaman/rust-anything-stale",
                            "last_synced_commit": "v2.0.0",
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        def fake_fetch(url, user_agent="", timeout=10.0, max_bytes=10_000_000, deadline=None, headers=None):
            if "erkamyaman/rust-anything/releases/latest" in url or "erkamyaman/rust-anything-stale/releases/latest" in url:
                return json.dumps({"tag_name": "v2.1.0", "name": "v2.1.0"})
            raise AssertionError(f"Unexpected URL: {url}")

        with mock.patch.dict(
            os.environ,
            {"ANTIGRAVITY_CONFIG_DIR": str(self.tmp / "cfg"), "UPSTREAM_STATE_FILE": str(state_file)},
        ):
            bridge = UpstreamAuditorBridge(target_dir=self.tmp / "cfg")
            with mock.patch("porter.net.safe_fetch_url", side_effect=fake_fetch):
                rows = {r["name"]: r for r in bridge.check_repositories()}

        self.assertEqual(rows["rust-anything"]["local_sha"], "v2.1.0")
        self.assertEqual(rows["rust-anything"]["remote_sha"], "v2.1.0")
        self.assertEqual(rows["rust-anything"]["status"], "Up-to-date")
        self.assertEqual(rows["rust-anything-stale"]["local_sha"], "v2.0.0")
        self.assertEqual(rows["rust-anything-stale"]["remote_sha"], "v2.1.0")
        self.assertEqual(rows["rust-anything-stale"]["status"], "Updates Available")

    def test_check_skills_sh_seed_digest_parity_and_release_tracking(self) -> None:
        seed = json.loads(
            (REPO_ROOT / "skills" / "upstream-auditor" / "upstream_state.seed.json").read_text(encoding="utf-8")
        )
        shipped_digest = compute_seed_digest(seed)

        # Build a state already stamped with guard.upstream.compute_seed_digest(seed) and a newer local
        # commit on anti-slop; check_skills.sh must produce the identical digest (not overwrite anti-slop)
        # while verifying UP TO DATE, UPDATE FOUND, prefix non-match (v2.1 vs v2.1.0), and INVALID TAG.
        state_file = self.tmp / "check_skills_state.json"
        state_payload = {
            "_reconciled_seed_digest": shipped_digest,
            "last_audit_timestamp": seed["last_audit_timestamp"],
            "tracked_repositories": {
                "anti-slop": {
                    "repo": "miqdadbadjuber/anti-slop",
                    "branch": "main",
                    "last_synced_commit": "9999999",
                    "target_skills": ["antislop"],
                },
                "rust-anything": {
                    "repo": "erkamyaman/rust-anything",
                    "branch": "main",
                    "track": "release",
                    "last_synced_commit": "v2.1.0",
                    "target_skills": ["rustify", "rust-harden"],
                },
                "ra-stale": {
                    "repo": "erkamyaman/ra-stale",
                    "branch": "main",
                    "track": "release",
                    "last_synced_commit": "v2.0.0",
                    "target_skills": ["rustify"],
                },
                "ra-prefix": {
                    "repo": "erkamyaman/ra-prefix",
                    "branch": "main",
                    "track": "release",
                    "last_synced_commit": "v2.1",
                    "target_skills": ["rustify"],
                },
                "ra-bad-tag": {
                    "repo": "erkamyaman/ra-bad-tag",
                    "branch": "main",
                    "track": "release",
                    "last_synced_commit": "v2.1.0",
                    "target_skills": ["rustify"],
                },
            },
        }
        state_file.write_text(json.dumps(state_payload), encoding="utf-8")

        shim_dir = self.tmp / "pyshim"
        shim_dir.mkdir()
        (shim_dir / "sitecustomize.py").write_text(
            "import json, sys, types\n"
            "def _fake_fetch(url, **_kw):\n"
            "    if '/miqdadbadjuber/anti-slop/' in url:\n"
            "        return json.dumps([{'sha': '9999999abcdef0123456789abcdef01234567890'}])\n"
            "    if '/erkamyaman/ra-bad-tag/releases/latest' in url:\n"
            "        return json.dumps({'tag_name': 'v2.1.0;evil'})\n"
            "    if '/releases/latest' in url:\n"
            "        return json.dumps({'tag_name': 'v2.1.0'})\n"
            "    return json.dumps([{'sha': '0123456789abcdef0123456789abcdef01234567'}])\n"
            "porter_mod = types.ModuleType('porter')\n"
            "net_mod = types.ModuleType('porter.net')\n"
            "net_mod.safe_fetch_url = _fake_fetch\n"
            "porter_mod.net = net_mod\n"
            "sys.modules['porter'] = porter_mod\n"
            "sys.modules['porter.net'] = net_mod\n",
            encoding="utf-8",
        )

        env = os.environ.copy()
        env.update(
            {
                "ANTIGRAVITY_CONFIG_DIR": str(self.tmp / "cfg"),
                "AGY_GUARD_STATE_DIR": str(self.tmp / "state"),
                "UPSTREAM_STATE_FILE": str(state_file),
                "PYTHONPATH": str(shim_dir),
            }
        )
        # 1. Clean run (all valid tags) exits 0, preserves newer local anti-slop SHA 9999999 (digest parity),
        #    and classifies UP TO DATE, UPDATE FOUND, and prefix non-match (v2.1 vs v2.1.0).
        clean_state_file = self.tmp / "check_skills_clean.json"
        clean_payload = json.loads(json.dumps(state_payload))
        clean_payload["tracked_repositories"].pop("ra-bad-tag")
        clean_state_file.write_text(json.dumps(clean_payload), encoding="utf-8")

        env_clean = {**env, "UPSTREAM_STATE_FILE": str(clean_state_file)}
        proc_clean = subprocess.run(
            [_bash_exe(), str(_CHECK_SKILLS_SH)],
            capture_output=True,
            text=True,
            env=env_clean,
            timeout=15,
            check=False,
        )
        self.assertEqual(proc_clean.returncode, 0, proc_clean.stderr + proc_clean.stdout)
        lines_clean = {line.split("|")[0].strip(): line for line in proc_clean.stdout.splitlines() if "|" in line}
        self.assertIn("9999999", lines_clean["anti-slop"])
        self.assertIn("UP TO DATE", lines_clean["anti-slop"])
        self.assertIn("UP TO DATE", lines_clean["rust-anything"])
        self.assertIn("UPDATE FOUND", lines_clean["ra-stale"])
        self.assertIn("UPDATE FOUND", lines_clean["ra-prefix"])

        # 2. Malformed remote tag fails closed with exit code 1 and INVALID TAG status.
        proc_bad = subprocess.run(
            [_bash_exe(), str(_CHECK_SKILLS_SH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
            check=False,
        )
        self.assertEqual(proc_bad.returncode, 1, proc_bad.stderr + proc_bad.stdout)
        lines_bad = {line.split("|")[0].strip(): line for line in proc_bad.stdout.splitlines() if "|" in line}
        self.assertIn("INVALID TAG", lines_bad["ra-bad-tag"])


if __name__ == "__main__":
    unittest.main()
