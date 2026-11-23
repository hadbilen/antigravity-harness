"""
Hermetic regression tests for Fable 5.2 Audit Campaign Window 3 (AC-5 & AC-6):
  - 3.1: `skills/harness/SKILL.md` decompressed (<= 220 chars/line, zero > 400-char walls),
         rare swarm orchestration details moved to `references/multi-agent-orchestration.md`.
  - 3.2: `disable-model-invocation: true` on explicit-only skills (`audit`, `retro`, `chisle`,
         `upstream-auditor`) and Pass 1 boolean schema validation in `scripts/meta_audit.py`.
  - 3.3: Installed-layout-safe paths in skills & `guard/hooks/pre_invocation.py`, Pass 2
         enforcement in `scripts/meta_audit.py`, and clean Porter export sanitization.
  - 3.4: Multi-language `agents/build-error-resolver.md` (TS/JS, Rust/Cargo, Python, Go,
         Kotlin/Gradle, QML/CMake) with read-only schema intact.
  - 5.6: `skills/antislop/scripts/check_ui_slop.py` (`UI-3`) CSS gradient stop HSL hue-range
         detection replacing 5 hardcoded hexes (`#667eea -> #764ba2` caught; cobalt/slate/teal clean).
  - 5.8: Calibrated Turkish routing in `guard/hooks/pre_invocation.py` (`"Bu projeyi hızlandır"`,
         `"migration yaz"`, `"Testler neden kırmızı?"`), pasted audit/review & read-only
         meta-question false-positive suppression, and trimmed dead patterns.
  - 7.1–7.3: Standardized 3-sentence plain-language operator headers on `PreToolUse` `force_ask`
         prompts (including exact test path + diff summary for `## Authorized Test Modifications`)
         and templates, parallel-session ledger hygiene in `context-and-artifacts.md`, and
         readable byte-budgeted `guard/agy_hooks.py` (<= 32 KiB, <= 160 chars/line).
  - 6.1, 9, 10, 11.3, 13: `docs/adr/0015-*.md` structured Provenance + trade-off analyses,
         `docs/benchmark-protocol.md` executable A/B scoring protocol, and `§4` baseline log
         in `skills/upstream-auditor/references/model-calibration-matrix.md`.
"""

from __future__ import annotations

import ast
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

import hermetic  # noqa: E402, F401 — isolates HOME / XDG_* / ANTIGRAVITY_CONFIG_DIR before repo imports


class TestFableW3SkillsAndAgents(unittest.TestCase):
    def test_3_1_harness_skill_decompressed_and_swarm_details_moved(self) -> None:
        skill_path = REPO_ROOT / "skills" / "harness" / "SKILL.md"
        swarm_ref = REPO_ROOT / "skills" / "harness" / "references" / "multi-agent-orchestration.md"
        text = skill_path.read_text(encoding="utf-8")
        lines = text.splitlines()

        self.assertLessEqual(len(text.encode("utf-8")), 28_672)
        long_lines = [(idx + 1, len(ln)) for idx, ln in enumerate(lines) if len(ln) > 220]
        self.assertEqual(long_lines, [], f"Lines exceeding 220 chars in skills/harness/SKILL.md: {long_lines}")
        wall_lines = [(idx + 1, len(ln)) for idx, ln in enumerate(lines) if len(ln) > 400]
        self.assertEqual(wall_lines, [])

        # Rare swarm details live in references/multi-agent-orchestration.md, not in core SKILL.md
        self.assertNotIn("swarm_pane", text)
        self.assertIn("references/multi-agent-orchestration.md", text)
        swarm_text = swarm_ref.read_text(encoding="utf-8")
        self.assertIn("swarm_pane", swarm_text)
        self.assertIn("`swarm_monitor`", swarm_text)

    def test_3_2_disable_model_invocation_on_explicit_skills_and_meta_audit_schema(self) -> None:
        from porter.frontmatter import parse_frontmatter
        from scripts.meta_audit import MetaAuditEngine

        explicit_only = {"audit", "retro", "chisle", "upstream-auditor"}
        auto_routed_sample = {"harness", "diagnosing-bugs", "refactoring", "sweetspot", "antislop"}

        for name in sorted(explicit_only):
            meta, _ = parse_frontmatter((REPO_ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8"))
            self.assertIs(meta.get("disable-model-invocation"), True, f"{name} must set disable-model-invocation: true")

        for name in sorted(auto_routed_sample):
            meta, _ = parse_frontmatter((REPO_ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8"))
            self.assertNotIn("disable-model-invocation", meta, f"{name} must remain model-invokable")

        # Negative control: meta_audit Pass 1 rejects non-boolean disable-model-invocation
        with tempfile.TemporaryDirectory(prefix="agy_w3_dmi_") as td:
            tmp = Path(td)
            skill_dir = tmp / "skills" / "demo"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                "---\n"
                "name: demo\n"
                "description: Demo skill for schema check.\n"
                "disable-model-invocation: \"yes\"\n"
                "---\n\n# Demo\n",
                encoding="utf-8",
            )
            engine = MetaAuditEngine(repo_root=tmp)
            engine.pass1_schema_validation()
            criticals = [f for f in engine.findings if f.severity == "CRITICAL"]
            self.assertTrue(
                any("disable-model-invocation" in f.message for f in criticals),
                f"Expected CRITICAL for non-boolean disable-model-invocation, got: {criticals}",
            )

    def test_3_3_installed_layout_paths_in_hooks_meta_audit_and_porter(self) -> None:
        from guard.hooks import pre_invocation
        from porter.sanitizer import ConstitutionalSanitizer
        from scripts.meta_audit import MetaAuditEngine

        # PreInvocation emits installed-layout-safe paths for external user workspaces
        with tempfile.TemporaryDirectory(prefix="agy_w3_ext_ws_") as td:
            ext_ws = Path(td) / "user-app"
            ext_ws.mkdir()
            custom_cfg = Path(td) / "custom_agy_cfg"
            custom_skill = custom_cfg / "skills" / "sweetspot" / "SKILL.md"
            custom_skill.parent.mkdir(parents=True)
            custom_skill.write_text("---\nname: sweetspot\ndescription: x\n---\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"ANTIGRAVITY_CONFIG_DIR": str(custom_cfg)}, clear=False):
                resolved = pre_invocation._resolve_hint_skill_path("skills/sweetspot/SKILL.md", [ext_ws])
            self.assertEqual(resolved, str(custom_skill))

            with mock.patch.dict(os.environ, {"ANTIGRAVITY_CONFIG_DIR": str(Path(td) / "empty_cfg")}, clear=False):
                resolved_default = pre_invocation._resolve_hint_skill_path("skills/sweetspot/SKILL.md", [ext_ws])
            self.assertEqual(resolved_default, "~/.gemini/config/skills/sweetspot/SKILL.md")

        # Inside the harness repo checkout itself, repo-relative paths still resolve cleanly
        self.assertEqual(
            pre_invocation._resolve_hint_skill_path("skills/sweetspot/SKILL.md", [REPO_ROOT]),
            "skills/sweetspot/SKILL.md",
        )

        # meta_audit Pass 2 catches bare repo-relative harness paths while allowing installed-layout & relative links
        with tempfile.TemporaryDirectory(prefix="agy_w3_paths_") as td:
            tmp = Path(td)
            skill_dir = tmp / "skills" / "demo"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                "---\n"
                "name: demo\n"
                "description: Demo installed-layout path check.\n"
                "---\n\n"
                "Bad template ref: `templates/HANDOFF.template.md`.\n"
                "Bad skill ref: `skills/harness/SKILL.md`.\n"
                "Bad guard ref: `guard/hooks/pre_invocation.py`.\n"
                "Bad harness script ref: `scripts/meta_audit.py`.\n"
                "Good installed template: `~/.gemini/config/templates/HANDOFF.template.md`.\n"
                "Good installed runtime: `~/.local/share/antigravity-harness/runtime/guard/hooks/pre_invocation.py`.\n"
                "Good relative sibling link: [ref](references/sub.md).\n",
                encoding="utf-8",
            )
            engine = MetaAuditEngine(repo_root=tmp)
            engine._check_installed_layout_skill_paths("Pass 2 (Cross-References)")
            warnings = [f for f in engine.findings if f.severity == "WARNING"]
            msgs = "\n".join(f.message for f in warnings)
            self.assertEqual(len(warnings), 4, f"Expected exactly 4 bare-path warnings, got:\n{msgs}")
            for token in (
                "templates/HANDOFF.template.md",
                "skills/harness/SKILL.md",
                "guard/hooks/pre_invocation.py",
                "scripts/meta_audit.py",
            ):
                self.assertIn(token, msgs)

        # Porter sanitizer strips ~/.local/share/antigravity-harness/runtime/ for portable exports
        exported = ConstitutionalSanitizer.sanitize_for_export(
            "Run `python3 ~/.local/share/antigravity-harness/runtime/scripts/verify_invariants.py --all` "
            "and inspect `~/.local/share/antigravity-harness/runtime/guard/hooks/pre_invocation.py`.",
            target="claude",
        )
        self.assertNotIn("~/.local/share/antigravity-harness/runtime/", exported)
        self.assertIn("scripts/verify_invariants.py", exported)
        self.assertIn("guard/hooks/pre_invocation.py", exported)

    def test_3_4_build_error_resolver_multilanguage_coverage_and_readonly_schema(self) -> None:
        from porter.frontmatter import parse_frontmatter

        agent_path = REPO_ROOT / "agents" / "build-error-resolver.md"
        meta, body = parse_frontmatter(agent_path.read_text(encoding="utf-8"))
        self.assertIs(meta.get("mainAgent"), False)
        self.assertIs(meta.get("subagent"), True)
        self.assertIs(meta.get("inheritMcp"), False)
        self.assertEqual(meta.get("access"), "read-only")
        self.assertEqual(meta.get("tools"), ["read_file"])

        for expected_ecosystem in ("TypeScript", "Rust", "Cargo", "Python", "Go", "Kotlin", "Gradle", "QML", "CMake"):
            self.assertIn(expected_ecosystem, body, f"Missing {expected_ecosystem} diagnostics in build-error-resolver.md")


class TestFableW3UiSlopAndRouting(unittest.TestCase):
    def test_5_6_ui3_hsl_gradient_hue_range_catches_ai_purple_and_allows_clean_palettes(self) -> None:
        import importlib.util

        script_path = REPO_ROOT / "skills" / "antislop" / "scripts" / "check_ui_slop.py"
        spec = importlib.util.spec_from_file_location("check_ui_slop_w3", script_path)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        sys.modules["check_ui_slop_w3"] = mod
        spec.loader.exec_module(mod)

        positive_cases = {
            "classic_indigo_purple_hex": ".hero { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }",
            "rgb_violet_pink": ".banner { background-image: linear-gradient(90deg, rgb(102, 126, 234), rgb(118, 75, 162)); }",
            "hsl_magenta_purple": ".cta { background: radial-gradient(circle, hsl(272, 80%, 58%), hsl(315, 76%, 54%)); }",
            "named_purple_indigo": ".badge { background: linear-gradient(to right, indigo, violet); }",
            "tailwind_purple_utility": '<div class="bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500">Hi</div>',
        }
        for label, snippet in positive_cases.items():
            with self.subTest(positive=label):
                report = mod.scan_text(snippet, path=f"{label}.css", mode="utility")
                ui3 = [f for f in report.findings if f.rule_id == "UI-3"]
                self.assertGreaterEqual(len(ui3), 1, f"Expected UI-3 finding for {label}, got {report.findings}")

        negative_cases = {
            "cobalt_blue": ".btn { background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); }",
            "neutral_slate": ".panel { background: linear-gradient(180deg, #f8fafc 0%, #e2e8f0 100%); }",
            "emerald_teal": ".ok { background: linear-gradient(90deg, #0d9488, #10b981); }",
            "warm_amber": ".warn { background: linear-gradient(90deg, #f59e0b, #ef4444); }",
            "charcoal_low_sat": ".dark { background: linear-gradient(180deg, hsl(250, 10%, 14%), hsl(265, 12%, 20%)); }",
        }
        for label, snippet in negative_cases.items():
            with self.subTest(negative=label):
                report = mod.scan_text(snippet, path=f"{label}.css", mode="utility")
                ui3 = [f for f in report.findings if f.rule_id == "UI-3"]
                self.assertEqual(ui3, [], f"False-positive UI-3 finding on {label}: {ui3}")

    def test_5_8_turkish_routing_calibration_pasted_suppression_and_dead_patterns(self) -> None:
        from guard.hooks import pre_invocation

        def _hint_text(out: dict) -> str:
            steps = out.get("injectSteps") or []
            return " ".join(
                str((step.get("systemMessage") or {}).get("systemMessage") or "")
                for step in steps
                if isinstance(step, dict)
            ).strip()

        with tempfile.TemporaryDirectory(prefix="agy_w3_route_") as td:
            ws = Path(td)

            # 1. Calibrated Turkish positive controls
            tr_cases = [
                ("Bu projeyi hızlandır", "sweetspot", "conv_w3_tr_speed"),
                ("migration yaz", "database-migrations", "conv_w3_tr_mig"),
                ("Testler neden kırmızı?", "diagnosing-bugs", "conv_w3_tr_red"),
            ]
            for prompt, expected_skill, conv_id in tr_cases:
                with self.subTest(turkish_positive=prompt):
                    out = pre_invocation.handle_pre_invocation({
                        "conversationId": conv_id,
                        "workspaces": [str(ws)],
                        "prompt": prompt,
                    })
                    msg = _hint_text(out)
                    self.assertIn(f"skills/{expected_skill}/SKILL.md", msg, f"Expected {expected_skill} hint, got: {msg!r}")

            # 2. Pasted audit / review block should NOT trigger skill hints from quoted findings
            pasted_review = (
                "Bu denetim raporunu özetle:\n"
                "---\n"
                "### Findings\n"
                "| ID | Severity | Issue |\n"
                "| F-01 | HIGH | Add database schema migration and rollback script |\n"
                "> [MEDIUM] Replace purple gradient and refactor auth module to Rust via rustify.\n"
            )
            out_pasted = pre_invocation.handle_pre_invocation({
                "conversationId": "conv_w3_pasted_audit",
                "workspaces": [str(ws)],
                "prompt": pasted_review,
            })
            self.assertEqual(_hint_text(out_pasted), "", f"Unexpected hint on pasted review: {out_pasted}")

            # 3. Read-only meta-questions suppress workflow skill hints while allowing diagnostic/guide queries
            meta_questions = [
                "Refactoring nedir?",
                "How does database migration rollback work in theory?",
                "Sabit timestep nedir, düz anlat.",
                "What is a TOCTOU race condition?",
            ]
            for q in meta_questions:
                with self.subTest(readonly_meta=q):
                    out_q = pre_invocation.handle_pre_invocation({
                        "conversationId": f"conv_w3_meta_{abs(hash(q)) % 10000}",
                        "workspaces": [str(ws)],
                        "prompt": q,
                    })
                    self.assertEqual(_hint_text(out_q), "", f"Unexpected hint on meta-question {q!r}: {out_q}")

            # 4. Knowledge-work negative & removed dead pattern stay silent
            for negative in ("Toplantı takvimimi hızlandır.", "vibercoder hakkında ne düşünüyorsun"):
                with self.subTest(negative=negative):
                    out_neg = pre_invocation.handle_pre_invocation({
                        "conversationId": f"conv_w3_neg_{abs(hash(negative)) % 10000}",
                        "workspaces": [str(ws)],
                        "prompt": negative,
                    })
                    self.assertEqual(_hint_text(out_neg), "", f"Unexpected hint on {negative!r}: {out_neg}")


class TestFableW3OperatorErgonomicsAndDocs(unittest.TestCase):
    def test_7_1_pre_tool_use_force_ask_operator_header_and_authorized_test_diff(self) -> None:
        from guard.hooks import pre_tool_use

        with tempfile.TemporaryDirectory(prefix="agy_w3_force_ask_") as td:
            ws = Path(td)
            tasks_file = ws / "tasks.md"
            tasks_file.write_text(
                "# Tasks\n\n## Authorized Test Modifications\n\n- None.\n",
                encoding="utf-8",
            )

            # 1. tasks.md ## Authorized Test Modifications mutation -> 3-sentence header + exact path + diff summary
            res_auth = pre_tool_use.handle_pre_tool_use({
                "workspaces": [str(ws)],
                "toolCall": {
                    "name": "edit_file",
                    "args": {
                        "Path": str(tasks_file),
                        "Target": "- None.",
                        "Replacement": "- `tests/test_billing.py`: Approved rounding contract update.",
                    },
                },
            })
            self.assertEqual(res_auth.get("decision"), "force_ask", res_auth)
            reason = res_auth.get("reason", "")
            self.assertTrue(reason.startswith("What changes:"), reason)
            self.assertIn("\nIf approved:", reason)
            self.assertIn("\nIf denied:", reason)
            self.assertIn("tests/test_billing.py", reason)
            self.assertIn("adds `tests/test_billing.py`", reason)

            # 2. Other force_ask paths (e.g. .agents/hooks.json) also carry standardized 3-sentence header
            res_hooks = pre_tool_use.handle_pre_tool_use({
                "workspaces": [str(ws)],
                "toolCall": {
                    "name": "write_file",
                    "args": {
                        "Path": str(ws / ".agents" / "hooks.json"),
                        "Content": "{}",
                    },
                },
            })
            self.assertEqual(res_hooks.get("decision"), "force_ask", res_hooks)
            hooks_reason = res_hooks.get("reason", "")
            self.assertTrue(hooks_reason.startswith("What changes:"), hooks_reason)
            self.assertIn("\nIf approved:", hooks_reason)
            self.assertIn("\nIf denied:", hooks_reason)

    def test_7_1_and_7_2_templates_and_parallel_session_ledger_hygiene(self) -> None:
        handoff_tpl = (REPO_ROOT / "templates" / "HANDOFF.template.md").read_text(encoding="utf-8")
        self.assertIn("Operator Summary (3 lines)", handoff_tpl)
        self.assertIn("What changes:", handoff_tpl)
        self.assertIn("If approved / resumed:", handoff_tpl)
        self.assertIn("If denied / paused:", handoff_tpl)

        ctx_ref = (REPO_ROOT / "skills" / "harness" / "references" / "context-and-artifacts.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Parallel-Conversation & Worktree Ledger Hygiene", ctx_ref)
        self.assertIn("`Campaign ID`", ctx_ref)
        self.assertIn("git worktree", ctx_ref)

    def test_7_3_agy_hooks_facade_readable_byte_budget_and_no_compressed_wall(self) -> None:
        from guard import agy_hooks

        facade_path = REPO_ROOT / "guard" / "agy_hooks.py"
        raw_bytes = facade_path.read_bytes()
        lines = raw_bytes.decode("utf-8").splitlines()
        max_len = max((len(ln) for ln in lines), default=0)

        self.assertEqual(agy_hooks.FACADE_MAX_BYTES, 32_768)
        self.assertEqual(agy_hooks.FACADE_MAX_LINE_LENGTH, 160)
        self.assertLessEqual(len(raw_bytes), agy_hooks.FACADE_MAX_BYTES)
        self.assertLessEqual(max_len, agy_hooks.FACADE_MAX_LINE_LENGTH)

    def test_adr0015_benchmark_protocol_and_calibration_matrix_executable(self) -> None:
        adr_path = REPO_ROOT / "docs" / "adr" / "0015-external-audit-hardening-host-contract-parity-and-measurement.md"
        adr_text = adr_path.read_text(encoding="utf-8")
        for marker in ("**Proposed By**:", "**Approved By**:", "**Authority**:", "6.1", "11.3", "ADR-0014"):
            self.assertIn(marker, adr_text)
        self.assertIn("0015-external-audit-hardening-host-contract-parity-and-measurement.md",
                      (REPO_ROOT / "docs" / "adr" / "README.md").read_text(encoding="utf-8"))

        # Calibration matrix §4 baseline entry present
        matrix_text = (
            REPO_ROOT / "skills" / "upstream-auditor" / "references" / "model-calibration-matrix.md"
        ).read_text(encoding="utf-8")
        self.assertIn("## 4. Recorded Calibration Baselines & Empirical Evidence Log", matrix_text)
        self.assertIn("docs/benchmark-protocol.md", matrix_text)

        # Benchmark protocol defines BM-01..BM-10 and its scoring snippet parses in Python 3.10 & runs cleanly
        bench_text = (REPO_ROOT / "docs" / "benchmark-protocol.md").read_text(encoding="utf-8")
        for idx in range(1, 11):
            self.assertIn(f"`BM-{idx:02d}`", bench_text)

        m = re.search(r"python3 - benchmark_runs\.jsonl <<'PY'\n(.*?)\nPY", bench_text, re.DOTALL)
        self.assertIsNotNone(m, "Expected executable heredoc scoring snippet in docs/benchmark-protocol.md")
        assert m is not None
        snippet = m.group(1)
        ast.parse(snippet, feature_version=(3, 10))

        with tempfile.TemporaryDirectory(prefix="agy_w3_bench_") as td:
            jsonl = Path(td) / "benchmark_runs.jsonl"
            jsonl.write_text(
                "\n".join([
                    json.dumps({
                        "task_id": "BM-01", "tier": 2, "condition": "OFF", "repo": "demo", "base_sha": "abc1234",
                        "model": "Gemini 4 Neon (XHigh)", "acceptance_pass": 0, "rule9_intact": 0,
                        "stop_gate_strikes": 0, "auditor_confirmed_defects": 2, "user_corrections": 1,
                        "wall_clock_sec": 80, "total_tokens": 30000,
                    }),
                    json.dumps({
                        "task_id": "BM-01", "tier": 2, "condition": "ON", "repo": "demo", "base_sha": "abc1234",
                        "model": "Gemini 4 Neon (XHigh)", "acceptance_pass": 1, "rule9_intact": 1,
                        "stop_gate_strikes": 1, "auditor_confirmed_defects": 0, "user_corrections": 0,
                        "wall_clock_sec": 95, "total_tokens": 36000,
                    }),
                ]) + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, "-", str(jsonl)],
                input=snippet,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("OFF | pairs= 1 | pass=0/1 | rule9=0/1 | strikes=0 | defects=2 | corrections=1 | med_sec=80s | med_tokens=30000", proc.stdout)
            self.assertIn("ON  | pairs= 1 | pass=1/1 | rule9=1/1 | strikes=1 | defects=0 | corrections=0 | med_sec=95s | med_tokens=36000", proc.stdout)
            self.assertIn("+20.0%", proc.stdout)

            # Unpaired OFF/ON row must fail non-zero
            bad_jsonl = Path(td) / "unpaired.jsonl"
            bad_jsonl.write_text(
                json.dumps({
                    "task_id": "BM-01", "tier": 2, "condition": "ON", "repo": "demo", "base_sha": "abc1234",
                    "model": "Gemini 4 Neon (XHigh)", "acceptance_pass": 1, "rule9_intact": 1,
                    "stop_gate_strikes": 0, "auditor_confirmed_defects": 0, "user_corrections": 0,
                    "wall_clock_sec": 95, "total_tokens": 36000,
                }) + "\n",
                encoding="utf-8",
            )
            bad_proc = subprocess.run(
                [sys.executable, "-", str(bad_jsonl)],
                input=snippet,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(bad_proc.returncode, 0)
            self.assertIn("unpaired", bad_proc.stderr.lower())


class TestFableW4AuditRegressionsW3(unittest.TestCase):
    """W4 independent-auditor confirmed defect regressions for Rule 17 shell-subshell, force_ask anti-spoof, UI-3, hints & Pass 2."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_w4_w3_"))
        self.home = self.tmp / "home"
        self.cfg = self.home / ".gemini" / "config"
        self.state = self.tmp / "state"
        self.ext_ws = self.tmp / "external_app"
        self.harness_ws = self.tmp / "harness_repo"
        for d in (self.cfg, self.state, self.ext_ws, self.harness_ws / ".harness"):
            d.mkdir(parents=True, exist_ok=True)
        (self.harness_ws / ".harness" / "manifest.json").write_text("{}", encoding="utf-8")
        self._env = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg),
                "AGY_GUARD_STATE_DIR": str(self.state),
                "AGY_GUARD_NOTIFY": "off",
            },
            clear=False,
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_w4_sbv1_sbv11_cd_harness_subshell_and_symlink_workspace_denied_on_flash(self) -> None:
        from guard import agy_hooks

        # 1. Six cd <harness> && <subshell> -c variants MUST all deny on Flash (SBV-1)
        commands = [
            f"cd '{self.harness_ws}' && sh -c 'echo x > guard/doctor.py'",
            f"cd '{self.harness_ws}' && bash -c 'echo x > GEMINI.md'",
            f"cd '{self.harness_ws}' && /bin/sh -lc 'printf y > .agents/rules/harness-maintainer.md'",
            f"cd '{self.harness_ws}' && python3 -c \"open('guard/doctor.py','w').write('x')\"",
            f"cd '{self.harness_ws}' && sh -c 'cd guard && echo x > doctor.py'",
            f"(cd '{self.harness_ws}' && sh -c 'echo x > skills/harness/SKILL.md')",
        ]
        for cmd in commands:
            with self.subTest(cmd=cmd):
                res = agy_hooks.handle_pre_tool_use(
                    {
                        "modelName": "gemini-3-flash",
                        "workspacePath": str(self.ext_ws),
                        "toolCall": {"name": "run_command", "args": {"CommandLine": cmd}},
                    }
                )
                self.assertEqual(res.get("decision"), "deny", (cmd, res))

        # 2. Symlinked harness workspace path still resolves harness scope and denies Flash (SBV-11)
        if os.name != "nt":
            sym_ws = self.tmp / "sym_harness"
            sym_ws.symlink_to(self.harness_ws)
            res_sym = agy_hooks.handle_pre_tool_use(
                {
                    "modelName": "gemini-3-flash",
                    "workspacePath": str(sym_ws),
                    "toolCall": {"name": "edit_file", "args": {"Path": "guard/doctor.py"}},
                }
            )
            self.assertEqual(res_sym.get("decision"), "deny", res_sym)

    def test_w4_sbv2_sfh11_force_ask_anti_spoof_newline_collapse_and_multi_key_tasks(self) -> None:
        from guard import agy_hooks

        # 1. Destructive rm -rf / containing "## Authorized Test Modifications" in arg MUST NOT spoof tasks.md header
        res_rm = agy_hooks.handle_pre_tool_use(
            {
                "workspacePath": str(self.ext_ws),
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "rm -rf /tmp/demo; git push --force origin main # ## Authorized Test Modifications"},
                },
            }
        )
        self.assertEqual(res_rm.get("decision"), "force_ask", res_rm)
        reason_rm = res_rm.get("reason", "")
        self.assertNotIn("updates `tasks.md` `## Authorized Test Modifications`", reason_rm)
        self.assertIn("What changes:", reason_rm)

        # 2. MCP gdb_console with spoofed string MUST get MCP operator header, never tasks.md header
        res_mcp = agy_hooks.handle_pre_tool_use(
            {
                "workspacePath": str(self.ext_ws),
                "toolCall": {
                    "name": "mcp_rea_rea_gdb_console",
                    "args": {"command": "info ## Authorized Test Modifications"},
                },
            }
        )
        self.assertEqual(res_mcp.get("decision"), "force_ask", res_mcp)
        self.assertIn("MCP tool", res_mcp.get("reason", ""))
        self.assertNotIn("updates `tasks.md`", res_mcp.get("reason", ""))

        # 3. Multi-chunk tasks.md edit surfaces exact modified test paths cleanly (single-line details)
        tasks_p = self.ext_ws / "tasks.md"
        tasks_p.write_text("# Tasks\n\n## Authorized Test Modifications\n- `tests/test_a.py`: existing\n", encoding="utf-8")
        res_t = agy_hooks.handle_pre_tool_use(
            {
                "workspacePath": str(self.ext_ws),
                "toolCall": {
                    "name": "multi_replace_file_content",
                    "args": {
                        "TargetFile": str(tasks_p),
                        "ReplacementChunks": [
                            {
                                "TargetContent": "- `tests/test_a.py`: existing",
                                "ReplacementContent": "- `tests/test_a.py`: existing\n- `tests/test_b.py`: updated contract\n",
                            }
                        ],
                    },
                },
            }
        )
        self.assertEqual(res_t.get("decision"), "force_ask", res_t)
        self.assertIn("tests/test_b.py", res_t.get("reason", ""))

    def test_w4_sfh6_sfh15_cca5_ui_slop_grad_transparent_stop_gate_and_ai_gradient_re(self) -> None:
        import importlib.util
        from guard.hooks import stop_gate

        script_path = REPO_ROOT / "skills" / "antislop" / "scripts" / "check_ui_slop.py"
        spec = importlib.util.spec_from_file_location("check_ui_slop_w4", script_path)
        assert spec is not None and spec.loader is not None
        slop_mod = importlib.util.module_from_spec(spec)
        sys.modules["check_ui_slop_w4"] = slop_mod
        spec.loader.exec_module(slop_mod)
        # 1. grad angle unit (300grad == 270deg purple) caught before rad
        css_grad = ".hero { background: linear-gradient(90deg, hsl(300grad, 80%, 50%), #1e1b4b); }\n"
        self.assertTrue(any(f.rule_id == "UI-3" for f in slop_mod.scan_text(css_grad, path="g.css", mode="utility").findings))

        # 2. Purple fade to transparent still caught
        css_fade = ".glow { background: radial-gradient(circle, #7c3aed, transparent); }\n"
        self.assertTrue(any(f.rule_id == "UI-3" for f in slop_mod.scan_text(css_fade, path="f.css", mode="utility").findings))

        # 3. Stop gate validate_ui_slop_content catches #667eea -> #764ba2 end-to-end
        html_purple = "<!doctype html><html><style>.h{background:linear-gradient(135deg,#667eea,#764ba2)}</style><body>x</body></html>\n"
        findings = stop_gate.validate_ui_slop_content("index.html", html_purple)
        self.assertTrue(any("UI-3" in f for f in findings), findings)

        # 4. Backward-compat AI_GRADIENT_RE still exported and matches CSS gradients
        self.assertTrue(hasattr(slop_mod, "AI_GRADIENT_RE"))
        self.assertIsNotNone(slop_mod.AI_GRADIENT_RE.search(html_purple))

        # 5. Nested parens and symbolic alpha do not raise
        css_var = ".card { background: linear-gradient(90deg, rgb(var(--r), 100, 240 / var(--a)), #ffffff); }\n"
        self.assertIsInstance(slop_mod.scan_text(css_var, path="v.css", mode="utility").findings, list)

    def test_w4_sga6_meta7_taa13_taa14_redaction_hints_pasted_review_and_meta_audit_pass2(self) -> None:
        from guard import agy_hooks
        from guard.hooks import common as h_common
        from scripts.meta_audit import MetaAuditEngine

        def _hint_text(out: dict) -> str:
            steps = out.get("injectSteps") or []
            return " ".join(
                str((step.get("systemMessage") or {}).get("systemMessage") or "")
                for step in steps
                if isinstance(step, dict)
            )

        # 1. Host fixture redaction catches substring secret keys & inline Bearer/CSRF/PAT values (SGA-6)
        san = h_common._sanitize_host_fixture_payload(
            {
                "access_token": "abc",
                "x-api-key": "def",
                "prompt": "Authorization: Bearer supersecret12345 ANTIGRAVITY_CSRF_TOKEN=tok999 ghp_1234567890abcdef",
            }
        )
        self.assertEqual(san["access_token"], "<redacted>")
        self.assertEqual(san["x-api-key"], "<redacted>")
        self.assertNotIn("supersecret12345", san["prompt"])
        self.assertNotIn("tok999", san["prompt"])
        self.assertNotIn("ghp_1234567890abcdef", san["prompt"])

        # 2. Standalone >=4-line pasted diff/table without '---' emits 0 false workflow hints
        pasted = (
            "Bu diffi açıklar mısın?\n"
            "| File | Issue |\n"
            "| :--- | :--- |\n"
            "| db.sql | schema migration rollback |\n"
            "| ui.css | linear-gradient(#667eea, #764ba2) |\n"
        )
        res_pasted = agy_hooks.handle_pre_invocation(
            {"conversationId": "w4-pasted", "workspacePath": str(self.ext_ws), "prompt": pasted}
        )
        self.assertEqual(_hint_text(res_pasted), "", res_pasted)

        # 3. Domain-marker read-only meta-question emits 0 hints
        res_meta = agy_hooks.handle_pre_invocation(
            {"conversationId": "w4-meta", "workspacePath": str(self.ext_ws), "prompt": "What is a purple gradient in CSS?"}
        )
        self.assertEqual(_hint_text(res_meta), "", res_meta)

        # 4. Natural-language audit phrase routes to audit skill with installed-layout-safe path (META-7)
        res_aud = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "w4-audit",
                "workspacePath": str(self.ext_ws),
                "prompt": "Run a security boundary audit on the auth handlers.",
            }
        )
        msg_aud = _hint_text(res_aud)
        self.assertIn("~/.gemini/config/skills/audit/SKILL.md", msg_aud)

        # 5. meta_audit Pass 2 flags bare agents/... path inside GEMINI.md and agents/*.md
        syn_repo = self.tmp / "syn_pass2"
        (syn_repo / "agents").mkdir(parents=True)
        (syn_repo / "GEMINI.md").write_text("# C\nSee `skills/harness/SKILL.md`.\n", encoding="utf-8")
        (syn_repo / "agents" / "demo.md").write_text(
            "---\nname: demo\ndescription: x\naccess: read-only\nmainAgent: false\nsubagent: true\ninheritMcp: false\ntools:\n  - read_file\n---\nSee `porter/net.py`.\n",
            encoding="utf-8",
        )
        eng = MetaAuditEngine(syn_repo)
        eng.pass2_cross_references()
        flagged_targets = {f.target.split(":")[0] for f in eng.findings if "Repo-relative harness path" in f.message}
        self.assertIn("GEMINI.md", flagged_targets)
        self.assertIn("agents/demo.md", flagged_targets)


if __name__ == "__main__":
    unittest.main()
