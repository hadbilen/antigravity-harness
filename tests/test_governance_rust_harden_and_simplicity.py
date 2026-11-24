from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
for _p in (str(TESTS_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hermetic  # noqa: E402, F401  # must precede repository imports per ADR-0010

from guard import agy_hooks
from guard.test_boundary import TestBoundaryGuard
from porter.analyzer import SuitabilityAnalyzer
from porter.emitters import EMITTERS
from porter.emitters.claude import agent_tools
from porter.emitters.cursor import _globs_for
from porter.frontmatter import parse_frontmatter
from porter.manifest import ManifestEngine
from porter.sanitizer import find_directives
from scripts.meta_audit import MetaAuditEngine


class TestGovernanceTemplatesAndManifestSeam(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = ManifestEngine(harness_root=REPO_ROOT).build_manifest(deterministic=True)

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-gov-tmpl-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_architecture_and_security_posture_templates_structure_and_export_parity(self) -> None:
        arch_path = REPO_ROOT / "templates" / "ARCHITECTURE.template.md"
        sec_path = REPO_ROOT / "templates" / "SECURITY_POSTURE.template.md"
        adr_path = REPO_ROOT / "docs" / "adr" / "0011-governance-templates-rust-harden-and-simplicity-auditor.md"
        adr_index = (REPO_ROOT / "docs" / "adr" / "README.md").read_text(encoding="utf-8")

        self.assertTrue(arch_path.is_file())
        self.assertTrue(sec_path.is_file())
        self.assertTrue(adr_path.is_file())
        self.assertIn("0011-governance-templates-rust-harden-and-simplicity-auditor.md", adr_index)

        arch_text = arch_path.read_text(encoding="utf-8")
        arch_lines = arch_text.splitlines()
        self.assertLessEqual(len(arch_lines), 150, f"ARCHITECTURE.template.md exceeded 150 lines: {len(arch_lines)}")
        for heading in (
            "## 1. System Backbone & Entrypoints",
            "## 2. Module Responsibilities & Forbidden Dependency Directions",
            "## 3. State & Data Ownership",
            "## 4. Non-Negotiable System Invariants",
        ):
            self.assertIn(heading, arch_text)
        self.assertIn("FORBIDDEN", arch_text)
        self.assertIn("->", arch_text)
        self.assertIsNone(
            re.search(r"\.[a-z0-9]+:L\d+", arch_text),
            "ARCHITECTURE.template.md must not embed volatile :L<n> line coordinates",
        )

        sec_text = sec_path.read_text(encoding="utf-8")
        self.assertIn("SECURITY.md", sec_text)
        self.assertIn("Security Policy", sec_text)
        self.assertIn("[ENFORCED]", sec_text)
        self.assertIn("[REQUIRED — UNVERIFIED]", sec_text)
        self.assertIn("Enforcing Code Path", sec_text)
        self.assertIn("Verifying Test Path", sec_text)
        self.assertIn("Release Blocker", sec_text)
        for banned_adj in ("`securely`", "`fast`", "`robust`", "`adequate`"):
            self.assertIn(banned_adj, sec_text)

        self.assertIn("ARCHITECTURE.template.md", self.manifest.templates)
        self.assertIn("SECURITY_POSTURE.template.md", self.manifest.templates)
        for target, emitter in EMITTERS.items():
            with self.subTest(target=target):
                out = self.tmp / f"export_{target}"
                emitter.emit(self.manifest, out)
                for tmpl_name in ("ARCHITECTURE.template.md", "SECURITY_POSTURE.template.md"):
                    self.assertEqual(
                        (out / "templates" / tmpl_name).read_bytes(),
                        (REPO_ROOT / "templates" / tmpl_name).read_bytes(),
                    )

    def test_meta_audit_pass2_recognizes_known_external_architecture_and_security_posture(self) -> None:
        mini = self.tmp / "mini_repo"
        (mini / "skills" / "demo").mkdir(parents=True)
        (mini / "GEMINI.md").write_text("# Constitution\n", encoding="utf-8")
        (mini / "skills" / "demo" / "SKILL.md").write_text(
            "---\n"
            "name: demo\n"
            "description: Demo skill. Invoke with /demo. Not for prod (use 'other').\n"
            "---\n\n"
            "# Demo\n\n"
            "Read `ARCHITECTURE.md` and `SECURITY_POSTURE.md` when present.\n",
            encoding="utf-8",
        )
        eng_clean = MetaAuditEngine(mini)
        eng_clean.pass2_cross_references()
        p2_clean_msgs = [f.message for f in eng_clean.findings if "Referenced file" in f.message]
        self.assertEqual(p2_clean_msgs, [], p2_clean_msgs)

        # Negative probe: unapproved bare .md filename MUST still be caught by Pass 2.
        (mini / "skills" / "demo" / "SKILL.md").write_text(
            "---\n"
            "name: demo\n"
            "description: Demo skill. Invoke with /demo. Not for prod (use 'other').\n"
            "---\n\n"
            "# Demo\n\n"
            "Read `NONEXISTENT_UNDECLARED_LEDGER.md` first.\n",
            encoding="utf-8",
        )
        eng_bad = MetaAuditEngine(mini)
        eng_bad.pass2_cross_references()
        self.assertTrue(
            any("NONEXISTENT_UNDECLARED_LEDGER.md" in f.message for f in eng_bad.findings),
            f"Expected Pass 2 warning on unknown .md span, got: {eng_bad.findings}",
        )


class TestRustHardenSkillAndCursorExportSeam(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-rust-harden-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_rust_harden_frontmatter_budget_suitability_and_lint_contracts(self) -> None:
        skill_path = REPO_ROOT / "skills" / "rust-harden" / "SKILL.md"
        async_path = REPO_ROOT / "skills" / "rust-harden" / "references" / "async-and-userspace.md"
        kernel_path = REPO_ROOT / "skills" / "rust-harden" / "references" / "kernel-and-unsafe.md"

        skill_text = skill_path.read_text(encoding="utf-8")
        async_text = async_path.read_text(encoding="utf-8")
        kernel_text = kernel_path.read_text(encoding="utf-8")

        m_fm = re.match(r"\A---\r?\n.*?\r?\n---", skill_text, re.DOTALL)
        self.assertIsNotNone(m_fm)
        assert m_fm is not None
        fm_bytes = len(m_fm.group(0).encode("utf-8"))
        self.assertLessEqual(fm_bytes, 520, f"rust-harden frontmatter exceeded 520 UTF-8 bytes: {fm_bytes}")

        total_fm_bytes = 0
        for sk_md in sorted((REPO_ROOT / "skills").glob("*/SKILL.md")):
            m_any = re.match(r"\A---\r?\n.*?\r?\n---", sk_md.read_text(encoding="utf-8"), re.DOTALL)
            self.assertIsNotNone(m_any, str(sk_md))
            assert m_any is not None
            total_fm_bytes += len(m_any.group(0).encode("utf-8"))
        self.assertLessEqual(total_fm_bytes, 10800, f"Aggregate frontmatter exceeded 10,800 B: {total_fm_bytes}")

        analyzer = SuitabilityAnalyzer(REPO_ROOT)
        for label, content in (
            ("SKILL.md", skill_text),
            ("async-and-userspace.md", async_text),
            ("kernel-and-unsafe.md", kernel_text),
        ):
            with self.subTest(doc=label):
                report = analyzer.analyze(content, source_identifier=label)
                self.assertEqual(report.constitutional_score, 100, f"{label}: {report.issues}")
                self.assertEqual(report.issues, [], f"{label}: {report.issues}")
                self.assertEqual(find_directives(content), [], f"{label} tripped sanitizer")

        for needle in (
            "--internal",
            "--contract",
            "Expand -> Migrate -> Contract",
            "[lints.rust]",
            "unsafe_op_in_unsafe_fn = \"deny\"",
            "static_mut_refs = \"deny\"",
            "[lints.clippy]",
            "undocumented_unsafe_blocks = \"deny\"",
            "multiple_unsafe_ops_per_block = \"deny\"",
            "let_underscore_must_use = \"deny\"",
            "await_holding_lock = \"deny\"",
            "allow-unwrap-in-tests = true",
            "allow-expect-in-tests = true",
        ):
            self.assertIn(needle, skill_text)

        for needle in (
            "tokio::select!",
            "await_holding_lock",
            "mpsc::channel",
            "spawn_blocking",
            "OwnedFd",
            "BorrowedFd",
            "setgroups",
            "setresgid",
            "setresuid",
            "EPERM",
        ):
            self.assertIn(needle, async_text)

        for needle in (
            "#![no_std]",
            "ENOMEM",
            "Framekernel",
            "SpinLockIrqSave",
            "UserSlice",
            "SMAP",
            "PAN",
            "TOCTOU",
            "DmaBuffer",
            "quarantine",
            "large_stack_frames",
            "large_stack_arrays",
            "array-size-threshold = 512",
            "loom",
            "kani",
        ):
            self.assertIn(needle, kernel_text)

    def test_cursor_globs_for_rust_harden_excludes_c_cpp_while_preserving_rustify(self) -> None:
        self.assertEqual(_globs_for("rust-harden"), "**/*.rs, **/Cargo.toml")
        self.assertEqual(
            _globs_for("rustify"),
            "**/*.rs, **/Cargo.toml, **/*.c, **/*.h, **/*.cpp, **/*.cc, **/*.cxx, **/*.hpp, **/*.hh, **/*.hxx",
        )

        manifest = ManifestEngine(harness_root=REPO_ROOT).build_manifest(deterministic=True)
        out_dir = self.tmp / "cursor_out"
        plan, _ = EMITTERS["cursor"].plan(manifest, out_dir)
        mdc_path = out_dir / ".cursor" / "rules" / "skill-rust-harden.mdc"
        self.assertIn(mdc_path, plan)
        meta, body = parse_frontmatter(plan[mdc_path])
        self.assertEqual(meta.get("globs"), "**/*.rs, **/Cargo.toml")
        self.assertIn(".cursor/skills/rust-harden/references/async-and-userspace.md", body)
        self.assertIn(".cursor/skills/rust-harden/references/kernel-and-unsafe.md", body)


class TestSimplicityAuditorAndHookRoutingSeam(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-simplicity-hook-")
        self.tmp = Path(self._tmp.name)
        self.fake_state = self.tmp / "state"
        self.fake_cfg = self.tmp / "cfg"
        self.fake_state.mkdir(parents=True, exist_ok=True)
        self.fake_cfg.mkdir(parents=True, exist_ok=True)
        (self.fake_cfg / "GEMINI.md").write_text("# Test Constitution\n", encoding="utf-8")
        self._saved_env = {
            k: os.environ.get(k)
            for k in ("PLUMB_GUARD_STATE_DIR", "ANTIGRAVITY_STATE_DIR", "ANTIGRAVITY_CONFIG_DIR")
        }
        os.environ["PLUMB_GUARD_STATE_DIR"] = str(self.fake_state)
        os.environ["ANTIGRAVITY_STATE_DIR"] = str(self.fake_state)
        os.environ["ANTIGRAVITY_CONFIG_DIR"] = str(self.fake_cfg)

    def tearDown(self) -> None:
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    @staticmethod
    def _injected_text(res: dict) -> str:
        steps = res.get("injectSteps") or []
        parts = []
        for st in steps:
            sm = st.get("systemMessage")
            if isinstance(sm, dict):
                parts.append(str(sm.get("systemMessage", "")))
            elif sm:
                parts.append(str(sm))
        return "\n".join(parts)

    def test_simplicity_auditor_claude_tools_and_readonly_pre_tool_use_gate(self) -> None:
        agent_path = REPO_ROOT / "agents" / "simplicity-auditor.md"
        raw = agent_path.read_text(encoding="utf-8")
        meta, _ = parse_frontmatter(raw)
        self.assertEqual(meta.get("name"), "simplicity-auditor")
        self.assertEqual(meta.get("access"), "read-only")
        self.assertEqual(agent_tools(raw), ["Read", "Grep", "Glob"])
        self.assertEqual(find_directives(raw), [])
        for needle in (
            "| Severity | Epistemic | Location | Rung / Rule | Concrete Proof | Minimal Removal |",
            ">= 3",
            "<= +5",
            "stepPhysics",
            "newtype",
            "typestate",
        ):
            self.assertIn(needle, raw)

        report = SuitabilityAnalyzer(REPO_ROOT).analyze(raw, source_identifier="agents/simplicity-auditor.md")
        self.assertEqual(report.constitutional_score, 100, report.issues)
        self.assertEqual(report.issues, [])

        # PreToolUse seam 1: redefining simplicity-auditor with write tools MUST be denied.
        res_deny = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-simp-redef",
                "modelName": "Gemini 4 Hydrogen (XHigh)",
                "workspacePaths": [str(REPO_ROOT)],
                "toolCall": {
                    "name": "define_subagent",
                    "args": {
                        "Name": "simplicity-auditor",
                        "Description": "Mutating override attempt",
                        "SystemPrompt": "Edit files directly.",
                        "EnableWriteTools": True,
                    },
                },
            }
        )
        self.assertEqual(res_deny.get("decision"), "deny", res_deny)
        self.assertIn("simplicity-auditor", res_deny.get("reason", ""))

        # PreToolUse seam 2: invoking read-only simplicity-auditor over governance paths is allowed
        # even from a non-flagship session, whereas write-capable `self` on the same prompt is denied.
        res_ro = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-simp-invoke-ro",
                "modelName": "Gemini 4 Flash",
                "workspacePaths": [str(REPO_ROOT)],
                "toolCall": {
                    "name": "invoke_subagent",
                    "args": {
                        "TypeName": "simplicity-auditor",
                        "Role": "Simplicity Auditor",
                        "Prompt": "Inspect skills/rust-harden/SKILL.md and GEMINI.md for YAGNI compliance.",
                    },
                },
            }
        )
        self.assertEqual(res_ro.get("decision"), "allow", res_ro)

        res_self = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-simp-invoke-self",
                "modelName": "Gemini 4 Flash",
                "workspacePaths": [str(REPO_ROOT)],
                "toolCall": {
                    "name": "invoke_subagent",
                    "args": {
                        "TypeName": "self",
                        "Role": "Governance Writer",
                        "Prompt": "Edit skills/rust-harden/SKILL.md and GEMINI.md.",
                    },
                },
            }
        )
        self.assertEqual(res_self.get("decision"), "deny", res_self)

    def test_pre_invocation_routing_disambiguates_rust_harden_rustify_and_simplicity_auditor(self) -> None:
        rust_harden_positives = [
            "/rust-harden audit and clean up ownership debt in this crate.",
            "/rust-harden --contract tighten public panic paths to Result.",
            "Convert this clone-heavy Rust module into idiomatic Rust.",
            "Convert this legacy, clone-heavy Rust module into idiomatic Rust.",
            "Refactor and convert this legacy, clone-heavy Rust module into idiomatic Rust.",
            "Remove rust unwrap and clone debt.",
            "Remove unwrap and clone debt in rust.",
            "Remove production unwrap() and Arc<Mutex> ownership debt in our Rust service.",
            "Narrow unsafe blocks in this #![no_std] Rust kernel driver.",
            "Bu modülde rust kodunu sertleştir ve sahiplik borcunu temizle.",
        ]
        for idx, prompt in enumerate(rust_harden_positives):
            with self.subTest(pos_rust_harden=idx, prompt=prompt):
                res = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-rh-pos-{idx}", "prompt": prompt}
                )
                msg = self._injected_text(res)
                self.assertIn("`rust-harden`", msg, f"Expected rust-harden on `{prompt}`, got: {res}")
                self.assertNotIn("`rustify`", msg, f"Intra-Rust prompt `{prompt}` collided with rustify: {msg}")

        rustify_positives = [
            "Port this C parser to Rust.",
            "Migrate our Go worker into idiomatic Rust.",
            "Convert Python extension module to memory-safe Rust with PyO3.",
        ]
        for idx, prompt in enumerate(rustify_positives):
            with self.subTest(pos_rustify=idx, prompt=prompt):
                res = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-rf-pos-{idx}", "prompt": prompt}
                )
                msg = self._injected_text(res)
                self.assertIn("`rustify`", msg, f"Expected rustify on `{prompt}`, got: {res}")
                self.assertNotIn("`rust-harden`", msg, f"Cross-language prompt `{prompt}` collided with rust-harden: {msg}")

        simplicity_positives = [
            "Run `simplicity-auditor`.",
            "Dispatch simplicity-auditor over this Tier 3 pull request diff.",
            "Run a YAGNI audit and efficiency ladder check on these new helper wrappers.",
            "Yeni eklenen trait katmanları için aşırı mühendislik denetimi yap.",
        ]
        for idx, prompt in enumerate(simplicity_positives):
            with self.subTest(pos_simplicity=idx, prompt=prompt):
                res = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-sa-pos-{idx}", "prompt": prompt}
                )
                msg = self._injected_text(res)
                self.assertIn("`simplicity-auditor`", msg, f"Expected simplicity-auditor on `{prompt}`, got: {res}")

        # Negative controls: bare Cargo.toml workspace, greenfield Rust CLI, and file-path non-collision.
        pure_cargo_ws = self.tmp / "pure_cargo_ws"
        (pure_cargo_ws / "src").mkdir(parents=True)
        (pure_cargo_ws / "Cargo.toml").write_text('[package]\nname = "demo"\nedition = "2024"\n', encoding="utf-8")
        (pure_cargo_ws / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        self.assertEqual(
            agy_hooks.handle_pre_invocation(
                {
                    "conversationId": "conv-neg-cargo-ws",
                    "workspace": str(pure_cargo_ws),
                    "prompt": "Add a --json output flag to main.rs.",
                }
            ),
            {},
        )
        for idx, neg_prompt in enumerate(
            (
                "Create a brand new Rust 2024 CLI crate using Cargo and clap.",
                "Let us go back to Rust 2024 edition naming conventions later.",
                "Remove unnecessary clone and expect calls in Java.",
                "Inspect src/rust-harden/worker.py and app/simplicity-auditor/runner.py.",
            )
        ):
            with self.subTest(neg_idx=idx, prompt=neg_prompt):
                self.assertEqual(
                    agy_hooks.handle_pre_invocation(
                        {"conversationId": f"conv-neg-{idx}", "prompt": neg_prompt}
                    ),
                    {},
                )


class TestAgentSkillIntegrationAndTechnicalAntiSlopGate(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-antislop-tech-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_agent_and_skill_integration_anchors_preserved(self) -> None:
        sfh = (REPO_ROOT / "agents" / "silent-failure-hunter.md").read_text(encoding="utf-8")
        sbv = (REPO_ROOT / "agents" / "security-boundary-verifier.md").read_text(encoding="utf-8")
        audit_md = (REPO_ROOT / "skills" / "audit" / "SKILL.md").read_text(encoding="utf-8")
        harness_md = (REPO_ROOT / "skills" / "harness" / "SKILL.md").read_text(encoding="utf-8")
        marathon_md = (REPO_ROOT / "skills" / "harness" / "references" / "marathon.md").read_text(encoding="utf-8")
        rustify_md = (REPO_ROOT / "skills" / "rustify" / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("let _ =", sfh)
        self.assertIn(".unwrap_or_default()", sfh)
        self.assertIn("### 7. Rust & Systems Memory Boundaries", sbv)
        self.assertIn("UserSlice", sbv)
        self.assertIn("unsafe impl Send", sbv)
        self.assertIn("ARCHITECTURE.md", audit_md)
        self.assertIn("SECURITY_POSTURE.md", audit_md)
        self.assertIn("simplicity-auditor", audit_md)
        self.assertIn("ARCHITECTURE.template.md", harness_md)
        self.assertIn("SECURITY_POSTURE.template.md", harness_md)
        self.assertIn("skills/rust-harden/SKILL.md", harness_md)
        self.assertIn("simplicity-auditor", harness_md)
        self.assertIn("rust-harden", marathon_md)
        self.assertIn("simplicity-auditor", marathon_md)
        self.assertIn("rust-harden", rustify_md)
        self.assertIn("### Six Strictly Prohibited Anti-Patterns (Red Lines)", rustify_md)

        sec_review_md = (REPO_ROOT / "skills" / "audit" / "references" / "security-review.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("SECURITY_POSTURE.md", sec_review_md)

        # Hermetic TestBoundaryGuard seam: authorized tasks.md entry passes, omitted entry fails.
        mini_ws = self.tmp / "tb_ws"
        (mini_ws / "tests").mkdir(parents=True)
        subprocess.run(["git", "init", "-q"], cwd=mini_ws, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=mini_ws, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=mini_ws, check=True)
        tfile = mini_ws / "tests" / "test_inventory.py"
        tfile.write_text("def test_items():\n    assert len(['a', 'b']) == 2\n", encoding="utf-8")
        subprocess.run(["git", "add", "tests/test_inventory.py"], cwd=mini_ws, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "baseline"], cwd=mini_ws, check=True)

        # Contract update (modified line, zero weakening)
        tfile.write_text("def test_items():\n    assert len(['a', 'b', 'c']) == 3\n", encoding="utf-8")
        tb_unauth = TestBoundaryGuard(workspace_dir=mini_ws).verify(mode="tdd", base_ref="HEAD")
        self.assertFalse(tb_unauth.is_intact)
        self.assertTrue(any("tests/test_inventory.py" in v for v in tb_unauth.violations))

        (mini_ws / "tasks.md").write_text(
            "## Authorized Test Modifications\n- `tests/test_inventory.py`: expand expected inventory to 3\n",
            encoding="utf-8",
        )
        parsed_auth = TestBoundaryGuard.load_authorized_from_tasks_md(mini_ws)
        self.assertEqual(parsed_auth, {"tests/test_inventory.py"})
        tb_auth = TestBoundaryGuard(workspace_dir=mini_ws).verify(
            mode="tdd",
            base_ref="HEAD",
            authorized_modifications=parsed_auth,
        )
        self.assertTrue(tb_auth.is_intact, tb_auth.violations)
        self.assertEqual(tb_auth.violations, [])

    def test_technical_anti_slop_profile_passes_all_added_and_edited_markdown_files(self) -> None:
        scanner = REPO_ROOT / "skills" / "ui-refinery" / "scripts" / "check_synthetic_markers.py"
        targets = [
            "docs/adr/0011-governance-templates-rust-harden-and-simplicity-auditor.md",
            "docs/adr/README.md",
            "templates/ARCHITECTURE.template.md",
            "templates/SECURITY_POSTURE.template.md",
            "skills/rust-harden/SKILL.md",
            "skills/rust-harden/references/async-and-userspace.md",
            "skills/rust-harden/references/kernel-and-unsafe.md",
            "agents/simplicity-auditor.md",
            "agents/silent-failure-hunter.md",
            "agents/security-boundary-verifier.md",
            "skills/audit/SKILL.md",
            "skills/audit/references/security-review.md",
            "skills/harness/SKILL.md",
            "skills/harness/references/marathon.md",
            "skills/rustify/SKILL.md",
            "README.md",
        ]
        res = subprocess.run(
            [sys.executable, str(scanner), "--profile", "technical", *[str(REPO_ROOT / p) for p in targets]],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)

        # Negative probe: confirm `--profile technical` fails closed (exit 1) on an em dash.
        bad_md = self.tmp / "bad_prose.md"
        bad_md.write_text("# Bad Heading — Em Dash\n\nThis line has an em dash — which must fail.\n", encoding="utf-8")
        res_bad = subprocess.run(
            [sys.executable, str(scanner), "--profile", "technical", str(bad_md)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_bad.returncode, 1, msg=res_bad.stdout + res_bad.stderr)


if __name__ == "__main__":
    unittest.main()
