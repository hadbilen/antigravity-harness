"""
Hermetic regression tests for Fable 5.2 Audit Campaign Window 2 (AC-3 & AC-4):
  - 1.3, 4.1, 4.2: All 10 `agents/*.md` (`mainAgent: false`, canary-verified read-only `tools:`,
    boilerplate dedup), `meta_audit.py` Pass 1 rejection of unmapped tools, Porter standalone
    baseline injection & Antigravity frontmatter stripping.
  - 1.4, 7.4: Global constitution installed to `rules/plumbwork-constitution.md` (`trigger: always_on`),
    retiring legacy harness `GEMINI.md` and receipt-tracked `MISTAKES.md` while preserving
    unrecorded user files, plus `Manifest` / `meta_audit` split-layout parity.
  - 1.5, 1.6: `guard/doctor.py` hook command executable & script-path verification, `"enabled": false`
    warnings, dual-constitution double-load warning, native `deny` rule `INFO` recommendations,
    and `README.md` emergency disable / fail-open / `--dangerously-skip-permissions` documentation.
  - 2.1–2.6: Slimmed `GEMINI.md`, `.agents/rules/harness-maintainer.md`, `.agents/rules.json`,
    rule `trigger:` validation, closed Tier 1/2 gap, Rule 13 `per fix pass`, and Rule 17 hook
    scoping strictly to harness checkouts & `~/.gemini/config`.
"""

from __future__ import annotations

import json
import os
import shutil
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


class TestFableW2AgentsAndPorter(unittest.TestCase):
    def test_1_3_and_4_2_all_ten_agents_frontmatter_tools_dedup_and_meta_audit_rejects_unmapped(self) -> None:
        from porter.frontmatter import parse_frontmatter
        from scripts.meta_audit import MetaAuditEngine

        agents = sorted((REPO_ROOT / "agents").glob("*.md"))
        self.assertEqual(len(agents), 10)
        for path in agents:
            raw = path.read_text(encoding="utf-8")
            meta, body = parse_frontmatter(raw)
            with self.subTest(agent=path.name):
                self.assertIs(meta.get("mainAgent"), False, meta)
                self.assertIs(meta.get("subagent"), True, meta)
                self.assertIs(meta.get("inheritMcp"), False, meta)
                self.assertEqual(meta.get("access"), "read-only", meta)
                expected_tools = ["read_file", "search_web"] if path.stem == "research" else ["read_file"]
                self.assertEqual(meta.get("tools"), expected_tools, meta)
                self.assertIn("Shared Baseline:", body)
                self.assertNotIn("## Prompt Defense Baseline", body)

        # Negative control: meta_audit Pass 1 rejects unmapped/hang-prone tools & missing mainAgent: false
        with tempfile.TemporaryDirectory(prefix="agy_w2_agent_schema_") as td:
            tmp = Path(td)
            (tmp / "agents").mkdir()
            (tmp / "agents" / "bad-auditor.md").write_text(
                "---\nname: bad-auditor\ndescription: Bad test agent\naccess: read-only\ntools:\n  - read_file\n  - grep_search\n---\n\n# Bad\n",
                encoding="utf-8",
            )
            eng = MetaAuditEngine(tmp)
            eng.pass1_schema_validation()
            crit_msgs = "\n".join(f.message for f in eng.findings if f.severity == "CRITICAL")
            warn_msgs = "\n".join(f.message for f in eng.findings if f.severity == "WARNING")
            self.assertIn("grep_search", crit_msgs)
            self.assertIn("mainAgent: false", warn_msgs)

    def test_4_2_porter_injects_standalone_baseline_and_strips_antigravity_keys(self) -> None:
        from porter.emitters import EMITTERS
        from porter.frontmatter import parse_frontmatter
        from porter.manifest import ManifestEngine

        manifest = ManifestEngine(REPO_ROOT).build_manifest()
        with tempfile.TemporaryDirectory(prefix="agy_w2_porter_") as td:
            base = Path(td)

            # Claude: strips Antigravity-only keys, translates tools, injects standalone baseline, keeps harness/agents verbatim
            claude_out = base / "claude"
            EMITTERS["claude"].emit(manifest, claude_out)
            for agent in manifest.agents:
                native_text = (claude_out / ".claude" / "agents" / f"{agent['name']}.md").read_text(encoding="utf-8")
                meta, body = parse_frontmatter(native_text)
                for agy_only in ("mainAgent", "subagent", "inheritMcp", "inheritCustomizations"):
                    self.assertNotIn(agy_only, meta, (agent["name"], meta))
                self.assertIn("## Prompt Defense & Constitutional Baseline", body)
                verbatim = (claude_out / ".claude" / "harness" / "agents" / f"{agent['name']}.md").read_text(
                    encoding="utf-8"
                )
                self.assertEqual(verbatim, agent["raw"].replace("\r\n", "\n"))

            # Cursor: .cursor/rules/agent-*.mdc carries standalone baseline
            cursor_out = base / "cursor"
            EMITTERS["cursor"].emit(manifest, cursor_out)
            for agent in manifest.agents:
                mdc = (cursor_out / ".cursor" / "rules" / f"agent-{agent['name']}.mdc").read_text(encoding="utf-8")
                self.assertIn("## Prompt Defense & Constitutional Baseline", mdc)

            # Universal / Aider / Generic index files include the shared baseline once
            for target, index_file in (
                ("universal", "AGENTS.md"),
                ("aider", "CONVENTIONS.md"),
                ("generic", "RULES.md"),
            ):
                t_out = base / target
                EMITTERS[target].emit(manifest, t_out)
                idx_text = (t_out / index_file).read_text(encoding="utf-8")
                self.assertIn("## Prompt Defense & Constitutional Baseline", idx_text)


class TestFableW2InstallerAndRulePath(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_w2_inst_"))
        self.home = self.tmp / "home"
        self.cfg = self.home / ".gemini" / "config"
        self.state = self.tmp / "state"
        self.data = self.tmp / "data"
        self.cfg.mkdir(parents=True)
        self.state.mkdir(parents=True)
        self.data.mkdir(parents=True)
        self._env = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg),
                "XDG_STATE_HOME": str(self.state),
                "XDG_DATA_HOME": str(self.data),
                "PLUMB_GUARD_STATE_DIR": str(self.state / "plumbwork"),
                "PLUMB_GUARD_DATA_DIR": str(self.data / "plumbwork"),
                "PLUMB_GUARD_NOTIFY": "off",
            },
            clear=False,
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_1_4_and_7_4_copy_link_uninstall_and_manifest_split_parity(self) -> None:
        import install
        from porter.manifest import ManifestEngine
        from scripts.meta_audit import MetaAuditEngine

        # Seed legacy harness GEMINI.md + receipt-tracked MISTAKES.md + custom user rule
        (self.cfg / "GEMINI.md").write_text(
            "# Antigravity Global Engineering & Behavioral Constitution\nOld content\n",
            encoding="utf-8",
        )
        (self.cfg / "MISTAKES.md").write_text("# Old harness mistakes\n", encoding="utf-8")
        (self.cfg / "rules").mkdir(parents=True, exist_ok=True)
        (self.cfg / "rules" / "user-custom.md").write_text(
            "---\ntrigger: manual\n---\n\n# User Custom\n",
            encoding="utf-8",
        )
        receipt_path = install.state_dir() / "install_receipt.json"
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(
            json.dumps({"target": str(self.cfg), "installed": ["GEMINI.md", "MISTAKES.md"]}),
            encoding="utf-8",
        )

        inst = install.Installer(self.cfg, mode="copy")
        with mock.patch.object(inst, "log"):
            inst.install_governance()
            inst.write_receipt()

        rule_file = self.cfg / "rules" / "plumbwork-constitution.md"
        self.assertTrue(rule_file.is_file())
        rule_text = rule_file.read_text(encoding="utf-8")
        self.assertIn("trigger: always_on", rule_text)
        self.assertIn((REPO_ROOT / "GEMINI.md").read_text(encoding="utf-8").strip(), rule_text)
        self.assertFalse((self.cfg / "GEMINI.md").exists())
        self.assertFalse((self.cfg / "MISTAKES.md").exists())
        self.assertTrue((inst.backup_dir / "GEMINI.md").is_file())
        self.assertTrue((inst.backup_dir / "MISTAKES.md").is_file())
        self.assertTrue((self.cfg / "rules" / "user-custom.md").is_file())
        self.assertTrue((self.cfg / "DESIGN.md").is_file())

        # Installed tree must parse cleanly in ManifestEngine & MetaAuditEngine
        installed_manifest = ManifestEngine(self.cfg).build_manifest()
        self.assertEqual(
            installed_manifest.constitution["raw"].strip(),
            (REPO_ROOT / "GEMINI.md").read_text(encoding="utf-8").strip(),
        )
        eng = MetaAuditEngine(self.cfg)
        eng.pass1_schema_validation()
        eng.pass3_directive_collision_and_mutex()
        self.assertEqual([f for f in eng.findings if f.severity == "CRITICAL"], [], eng.findings)

        # Unrecorded user-authored MISTAKES.md must be preserved on subsequent installs
        (self.cfg / "MISTAKES.md").write_text("# My personal notes\n", encoding="utf-8")
        inst2 = install.Installer(self.cfg, mode="copy")
        with mock.patch.object(inst2, "log"):
            inst2.install_governance()
        self.assertTrue((self.cfg / "MISTAKES.md").is_file())
        self.assertEqual((self.cfg / "MISTAKES.md").read_text(encoding="utf-8"), "# My personal notes\n")

        # Link mode emits @include rule file pointing to repo GEMINI.md
        link_cfg = self.tmp / "link_cfg"
        link_cfg.mkdir()
        inst_link = install.Installer(link_cfg, mode="link")
        with mock.patch.object(inst_link, "log"):
            inst_link.install_governance()
        link_rule = (link_cfg / "rules" / "plumbwork-constitution.md").read_text(encoding="utf-8")
        self.assertIn("trigger: always_on", link_rule)
        self.assertIn("@[Plumbwork Constitution](", link_rule)
        self.assertEqual(
            ManifestEngine(link_cfg).build_manifest().constitution["raw"].strip(),
            (REPO_ROOT / "GEMINI.md").read_text(encoding="utf-8").strip(),
        )

        # Uninstall removes receipt-tracked constitution rule while preserving user-custom.md
        with mock.patch.object(install, "request_approval", return_value=True):
            rc = install.uninstall_harness(self.cfg, dry_run=False)
        self.assertEqual(rc, 0)
        self.assertFalse((self.cfg / "rules" / "plumbwork-constitution.md").exists())
        self.assertTrue((self.cfg / "rules" / "user-custom.md").is_file())

    def test_1_4_and_7_4_guard_cli_init_and_uninstall_parity(self) -> None:
        import argparse
        import guard.cli as guard_cli

        init_cfg = self.tmp / "init_cfg"
        init_cfg.mkdir()
        (init_cfg / "GEMINI.md").write_text(
            "# Antigravity Global Engineering & Behavioral Constitution\nOld pkg rules\n",
            encoding="utf-8",
        )
        ns = argparse.Namespace(
            target=str(init_cfg),
            source=str(REPO_ROOT),
            dry_run=False,
            no_lock=True,
            uninstall=False,
        )
        with mock.patch.object(guard_cli, "request_approval", return_value=True):
            rc = guard_cli.cmd_init(ns)
        self.assertEqual(rc, 0)
        rule_file = init_cfg / "rules" / "plumbwork-constitution.md"
        self.assertTrue(rule_file.is_file())
        self.assertIn("trigger: always_on", rule_file.read_text(encoding="utf-8"))
        self.assertFalse((init_cfg / "GEMINI.md").exists())
        self.assertFalse((init_cfg / "MISTAKES.md").exists())

        ns_un = argparse.Namespace(
            target=str(init_cfg),
            source=str(REPO_ROOT),
            dry_run=False,
            no_lock=True,
            uninstall=True,
        )
        with mock.patch.object(guard_cli, "request_approval", return_value=True):
            rc_un = guard_cli.cmd_init(ns_un)
        self.assertEqual(rc_un, 0)
        self.assertFalse(rule_file.exists())
        self.assertFalse((init_cfg / "rules").exists())


class TestFableW2DoctorHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_w2_doc_"))
        self.home = self.tmp / "home"
        self.cfg = self.home / ".gemini" / "config"
        self.state = self.tmp / "state"
        self.cfg.mkdir(parents=True)
        self.state.mkdir(parents=True)
        self._env = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg),
                "PLUMB_GUARD_STATE_DIR": str(self.state),
                "PLUMB_GUARD_NOTIFY": "off",
            },
            clear=False,
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_1_5_and_1_6_doctor_hook_executables_scripts_disabled_double_load_and_native_deny(self) -> None:
        from guard.doctor import diagnose
        from guard.environment import EnvironmentRegistry
        from guard.integrity import FileIntegrityMonitor
        from guard.os_adapter import OSProtectionAdapter

        adapter = mock.MagicMock(spec=OSProtectionAdapter)
        adapter.protection_issues.return_value = []
        adapter.is_locked.return_value = True

        reg = EnvironmentRegistry(config_path=self.tmp / "reg.json", os_adapter=adapter)
        env = reg.get_environment("antigravity")
        assert env is not None

        # 1. Missing executable, missing .sh / extensionless script, disabled hook group, dual GEMINI.md + rules/
        (self.cfg / "rules").mkdir(parents=True, exist_ok=True)
        (self.cfg / "rules" / "plumbwork-constitution.md").write_text("---\ntrigger: always_on\n---\n# C\n", encoding="utf-8")
        (self.cfg / "GEMINI.md").write_text("# Legacy duplicate\n", encoding="utf-8")
        (self.cfg / "hooks.json").write_text(
            json.dumps(
                {
                    "upstream-watchdog": {
                        "SessionStart": [{"type": "command", "command": "nonexistent_py_bin_w2_xyz hooks/missing.sh"}]
                    },
                    "harness-gate": {
                        "enabled": False,
                        "PreToolUse": [{"type": "command", "command": f"{sys.executable} hooks/missing_extless"}],
                    },
                }
            ),
            encoding="utf-8",
        )
        FileIntegrityMonitor.for_environment(env, os_adapter=adapter).save_baseline()
        rep_bad = diagnose(env, reg, sentinel_active=True)
        joined_w = "\n".join(rep_bad.warnings)
        joined_i = "\n".join(rep_bad.infos)
        self.assertIn("nonexistent_py_bin_w2_xyz", joined_w)
        self.assertIn("hooks/missing.sh", joined_w)
        self.assertIn("hooks/missing_extless", joined_w)
        self.assertIn("'enabled': false", joined_w)
        self.assertIn("double-loading", joined_w)
        self.assertNotIn("Native lifecycle hooks", joined_i)
        self.assertIn("plumb-guard unlock", joined_i)
        self.assertIn("--no-verify", joined_i)

        # 2. Clean config without native deny rules is still healthy (recommendations stay INFO, not WARNING)
        (self.cfg / "GEMINI.md").unlink()
        valid_hook = self.cfg / "valid_hook.py"
        valid_hook.write_text("# ok\n", encoding="utf-8")
        (self.cfg / "hooks.json").write_text(
            json.dumps(
                {
                    "upstream-watchdog": {
                        "SessionStart": [{"type": "command", "command": f'"{sys.executable}" "{valid_hook}"'}]
                    },
                    "harness-gate": {
                        "PreInvocation": [{"type": "command", "command": f'"{sys.executable}" "{valid_hook}"'}],
                        "PreToolUse": [{"type": "command", "command": f'"{sys.executable}" "{valid_hook}"'}],
                        "Stop": [{"type": "command", "command": f'"{sys.executable}" "{valid_hook}"'}],
                    },
                }
            ),
            encoding="utf-8",
        )
        FileIntegrityMonitor.for_environment(env, os_adapter=adapter).save_baseline()
        rep_clean = diagnose(env, reg, sentinel_active=True)
        self.assertTrue(rep_clean.healthy, rep_clean.warnings)
        self.assertIn("Native lifecycle hooks", "\n".join(rep_clean.infos))
        self.assertIn("recommended for defense-in-depth", "\n".join(rep_clean.infos))

        # 3. Adding native deny rules in App config.json + CLI settings.json switches INFO to confirmed
        (self.cfg / "config.json").write_text(
            json.dumps({"userSettings": {"globalPermissionGrants": {"deny": ["command(plumb-guard unlock)"]}}}),
            encoding="utf-8",
        )
        cli_dir = self.home / ".gemini" / "antigravity-cli"
        cli_dir.mkdir(parents=True, exist_ok=True)
        (cli_dir / "settings.json").write_text(
            json.dumps({"permissions": {"deny": ["command(regex:.*--no-verify.*)"]}}),
            encoding="utf-8",
        )
        rep_hardened = diagnose(env, reg, sentinel_active=True)
        self.assertTrue(rep_hardened.healthy, rep_hardened.warnings)
        self.assertIn(
            "Native Antigravity deny rules cover 'plumb-guard unlock' and '--no-verify'.",
            rep_hardened.infos,
        )


class TestFableW2ConstitutionAndRule17Scoping(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_w2_r17_"))
        self.home = self.tmp / "home"
        self.cfg = self.home / ".gemini" / "config"
        self.state = self.tmp / "state"
        self.cfg.mkdir(parents=True)
        self.state.mkdir(parents=True)
        self._env = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg),
                "PLUMB_GUARD_STATE_DIR": str(self.state),
                "PLUMB_GUARD_NOTIFY": "off",
            },
            clear=False,
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_2_1_to_2_6_constitution_split_rules_json_trigger_validation_and_rule17_scoping(self) -> None:
        from guard import agy_hooks
        from porter.frontmatter import parse_frontmatter
        from scripts.meta_audit import MetaAuditEngine

        # 2.1, 2.2, 2.4, 2.5, 2.6: Slimmed GEMINI.md + .agents/rules/harness-maintainer.md + .agents/rules.json
        gemini_text = (REPO_ROOT / "GEMINI.md").read_text(encoding="utf-8")
        self.assertIn("1–2 files with >=20 changed lines", gemini_text)
        self.assertIn("per fix pass", gemini_text)
        self.assertNotIn("Upstream Collisions", gemini_text)
        self.assertNotIn("Self-Audit Invariant", gemini_text)

        maintainer_raw = (REPO_ROOT / ".agents" / "rules" / "harness-maintainer.md").read_text(encoding="utf-8")
        m_meta, m_body = parse_frontmatter(maintainer_raw)
        self.assertEqual(m_meta.get("trigger"), "always_on")
        for needle in ("Upstream Collisions", "External Rule Ingestion", "Self-Audit & Scoped Model Gate", "force_ask"):
            self.assertIn(needle, m_body)

        self.assertFalse((REPO_ROOT / ".agents" / "rules.json").exists())
        self.assertIn("native rule deduplication", (REPO_ROOT / "README.md").read_text(encoding="utf-8"))

        # Invalid rule trigger must be caught by meta_audit Pass 1
        bad_rule_repo = self.tmp / "bad_rule_repo"
        (bad_rule_repo / ".agents" / "rules").mkdir(parents=True)
        (bad_rule_repo / ".agents" / "rules" / "broken.md").write_text(
            "---\ntrigger: alwaysOn\n---\n# Broken\n",
            encoding="utf-8",
        )
        eng = MetaAuditEngine(bad_rule_repo)
        eng.pass1_schema_validation()
        self.assertTrue(
            any(f.severity == "CRITICAL" and "trigger" in f.message for f in eng.findings),
            eng.findings,
        )

        # 2.3: Rule 17 model gate allows external non-harness project AGENTS.md / GEMINI.md / SKILL.md on Flash,
        # while still force-asking external .agents/hooks.json and denying ~/.gemini/config & harness checkouts.
        ext_ws = self.tmp / "external_app"
        ext_ws.mkdir()
        harness_ws = self.tmp / "harness_checkout"
        (harness_ws / ".harness").mkdir(parents=True)
        (harness_ws / ".harness" / "manifest.json").write_text("{}", encoding="utf-8")

        for rel in ("AGENTS.md", "GEMINI.md", "skills/fireball.ts", "skills/local/SKILL.md", ".cursor/rules/team.mdc"):
            with self.subTest(ext_allowed=rel):
                res = agy_hooks.handle_pre_tool_use(
                    {
                        "modelName": "gemini-3-flash",
                        "workspacePath": str(ext_ws),
                        "toolCall": {"name": "edit_file", "args": {"Path": rel}},
                    }
                )
                self.assertEqual(res.get("decision"), "allow", (rel, res))

        # External shell command editing AGENTS.md on Flash -> allow
        res_ext_sh = agy_hooks.handle_pre_tool_use(
            {
                "modelName": "gemini-3-flash",
                "workspacePath": str(ext_ws),
                "toolCall": {"name": "run_command", "args": {"CommandLine": "printf '# team\\n' > AGENTS.md"}},
            }
        )
        self.assertEqual(res_ext_sh.get("decision"), "allow", res_ext_sh)

        # External .agents/hooks.json still triggers force_ask
        res_ext_hooks = agy_hooks.handle_pre_tool_use(
            {
                "modelName": "gemini-3-flash",
                "workspacePath": str(ext_ws),
                "toolCall": {"name": "write_file", "args": {"Path": ".agents/hooks.json", "Content": "{}"}},
            }
        )
        self.assertEqual(res_ext_hooks.get("decision"), "force_ask", res_ext_hooks)

        # Global ~/.gemini/config rules remain hard-denied
        res_cfg = agy_hooks.handle_pre_tool_use(
            {
                "modelName": "Gemini 4 Neon (XHigh)",
                "effort": "xhigh",
                "workspacePath": str(ext_ws),
                "toolCall": {
                    "name": "edit_file",
                    "args": {"Path": str(self.cfg / "rules" / "plumbwork-constitution.md")},
                },
            }
        )
        self.assertEqual(res_cfg.get("decision"), "deny", res_cfg)

        # Harness checkout editing AGENTS.md / GEMINI.md / guard/doctor.py on Flash -> deny
        for rel in ("AGENTS.md", "GEMINI.md", ".agents/rules/harness-maintainer.md", "guard/doctor.py"):
            with self.subTest(harness_denied=rel):
                res_h = agy_hooks.handle_pre_tool_use(
                    {
                        "modelName": "gemini-3-flash",
                        "workspacePath": str(harness_ws),
                        "toolCall": {"name": "edit_file", "args": {"Path": rel}},
                    }
                )
                self.assertEqual(res_h.get("decision"), "deny", (rel, res_h))

    def test_1_5_and_1_6_readme_recovery_fail_open_and_threat_model_docs(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        for needle in (
            '"enabled": false',
            "--dangerously-skip-permissions",
            "fail-open",
            "build-plugins",
            "rules/plumbwork-constitution.md",
            "agents/research.md",
            "plumb-guard unlock",
            "--no-verify",
        ):
            self.assertIn(needle, readme)


class TestFableW4AuditRegressionsW2(unittest.TestCase):
    """W4 independent-auditor confirmed defect regressions for installer, doctor, porter, and archive seams."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_w4_w2_"))
        self.home = self.tmp / "home"
        self.cfg = self.home / ".gemini" / "config"
        self.state = self.tmp / "state"
        self.cfg.mkdir(parents=True)
        self.state.mkdir(parents=True)
        self._env = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg),
                "PLUMB_GUARD_STATE_DIR": str(self.state),
                "PLUMB_GUARD_NOTIFY": "off",
            },
            clear=False,
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_w4_sbv9_sfh13_doctor_empty_harness_gate_env_split_quotes_and_corrupt_cli_settings(self) -> None:
        from guard.doctor import diagnose
        from guard.environment import EnvironmentRegistry
        from guard.integrity import FileIntegrityMonitor
        from guard.os_adapter import OSProtectionAdapter

        adapter = mock.MagicMock(spec=OSProtectionAdapter)
        adapter.protection_issues.return_value = []
        adapter.is_locked.return_value = True
        reg = EnvironmentRegistry(config_path=self.tmp / "reg.json", os_adapter=adapter)
        env = reg.get_environment("antigravity")
        assert env is not None

        (self.cfg / "rules").mkdir(parents=True, exist_ok=True)
        (self.cfg / "rules" / "plumbwork-constitution.md").write_text("---\ntrigger: always_on\n---\n# C\n", encoding="utf-8")
        # 1. Empty harness-gate: {} + env -S missing script + unbalanced quotes + corrupt CLI settings
        (self.cfg / "hooks.json").write_text(
            json.dumps(
                {
                    "upstream-watchdog": {
                        "SessionStart": [
                            {"type": "command", "command": "/usr/bin/env -S python3 -u hooks/missing_env_s.py"},
                            {"type": "command", "command": 'python3 "unterminated.py'},
                        ]
                    },
                    "harness-gate": {},
                }
            ),
            encoding="utf-8",
        )
        cli_dir = self.home / ".gemini" / "antigravity-cli"
        cli_dir.mkdir(parents=True, exist_ok=True)
        (cli_dir / "settings.json").write_text("{corrupt", encoding="utf-8")
        FileIntegrityMonitor.for_environment(env, os_adapter=adapter).save_baseline()

        rep = diagnose(env, reg, sentinel_active=True)
        joined_w = "\n".join(rep.warnings)
        self.assertFalse(rep.healthy)
        self.assertIn("PreInvocation", joined_w)
        self.assertIn("PreToolUse", joined_w)
        self.assertIn("Stop", joined_w)
        self.assertIn("missing_env_s.py", joined_w)
        self.assertIn("unbalanced", joined_w.lower())
        self.assertIn("settings.json", joined_w)

    def test_w4_sbv10_cca2_cca3_cca7_installer_safety_default_audit_root_and_posix_receipt(self) -> None:
        import install
        from guard import cli as guard_cli
        from guard.environment import EnvironmentRegistry
        from guard.os_adapter import OSProtectionAdapter

        # 1. target_dir == source_dir refused cleanly
        with mock.patch.dict(os.environ, {"ANTIGRAVITY_CONFIG_DIR": str(REPO_ROOT)}):
            self.assertNotEqual(install.main(["--no-lock"]), 0)

        # 2. Symlinked target config dir refused cleanly (POSIX)
        if os.name != "nt":
            real_tgt = self.tmp / "real_cfg"
            real_tgt.mkdir()
            sym_tgt = self.tmp / "sym_cfg"
            sym_tgt.symlink_to(real_tgt)
            with mock.patch.dict(os.environ, {"ANTIGRAVITY_CONFIG_DIR": str(sym_tgt)}):
                self.assertNotEqual(install.main(["--no-lock"]), 0)

        # 3. Unrecorded user-authored GEMINI.md is preserved; POSIX receipt uses '/' separators
        tgt = self.tmp / "fresh_install"
        tgt.mkdir()
        (tgt / "GEMINI.md").write_text("# My personal non-harness rules\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"ANTIGRAVITY_CONFIG_DIR": str(tgt)}):
            rc = install.main(["--no-lock"])
        self.assertEqual(rc, 0)
        self.assertTrue((tgt / "GEMINI.md").is_file(), "User-authored non-harness GEMINI.md must be preserved")
        self.assertTrue((tgt / "rules" / "plumbwork-constitution.md").is_file())
        receipt_path = self.state / "install_receipt.json"
        self.assertTrue(receipt_path.is_file())
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        for entry in receipt.get("installed", []):
            self.assertNotIn("\\", entry)

        # 4. _default_audit_root finds installed config containing only rules/plumbwork-constitution.md
        installed_only = self.tmp / "installed_only"
        (installed_only / "rules").mkdir(parents=True)
        (installed_only / "skills").mkdir(parents=True)
        (installed_only / "rules" / "plumbwork-constitution.md").write_text("---\ntrigger: always_on\n---\n", encoding="utf-8")
        fake_runtime_cli = self.tmp / "runtime" / "guard" / "cli.py"
        fake_runtime_cli.parent.mkdir(parents=True, exist_ok=True)
        fake_runtime_cli.write_text("# stub\n", encoding="utf-8")
        with mock.patch.object(guard_cli, "__file__", str(fake_runtime_cli)):
            with mock.patch.object(guard_cli, "config_dir", return_value=installed_only):
                self.assertEqual(guard_cli._default_audit_root(), installed_only)

        # 5. Legacy MISTAKES.md is pruned from persisted global antigravity governance_paths on load
        reg_path = self.tmp / "legacy_reg.json"
        reg_path.write_text(
            json.dumps(
                {
                    "environments": [
                        {
                            "id": "antigravity",
                            "name": "Antigravity Global",
                            "platform_type": "antigravity",
                            "root_path": str(self.cfg),
                            "governance_paths": ["rules/plumbwork-constitution.md", "MISTAKES.md", "skills"],
                            "policy": "enforced",
                            "is_global": True,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        reg = EnvironmentRegistry(config_path=reg_path, os_adapter=mock.MagicMock(spec=OSProtectionAdapter))
        ag_env = reg.get_environment("antigravity")
        assert ag_env is not None
        self.assertNotIn("MISTAKES.md", ag_env.governance_paths)

    def test_w4_sbv5_sbv6_sbv8_sbv13_cca4_cca6_cca9_meta8_porter_manifest_and_archive_hardening(self) -> None:
        import struct
        import subprocess
        import zipfile
        import zlib
        from porter.archive import inspect_zip
        from porter.emitters.claude import ClaudeEmitter
        from porter.emitters.cursor import CursorEmitter
        from porter.frontmatter import parse_frontmatter
        from porter.manifest import ManifestEngine, _read_constitution_text
        from porter.sanitizer import ConstitutionalSanitizer
        from guard import porter_bridge

        # 1. SBV-8: manifest.py refuses @[...](/etc/hostname) escape outside root
        evil_root = self.tmp / "evil_manifest_root"
        evil_root.mkdir()
        (evil_root / "rules").mkdir()
        (evil_root / "rules" / "plumbwork-constitution.md").write_text(
            "---\ntrigger: always_on\n---\n@[Antigravity](/etc/hostname)\n",
            encoding="utf-8",
        )
        self.assertIsNone(_read_constitution_text(evil_root))

        # 2. SBV-5 & SBV-6 & SBV-12: archive.py catches normalized .claude/./settings.json, duplicates, LFH mismatch & truncated deflate
        norm_zip = self.tmp / "norm_exec.zip"
        with zipfile.ZipFile(norm_zip, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr(".claude/./settings.json", '{"hooks": {}}\n')
        rep_norm = inspect_zip(norm_zip, harness_root=self.tmp)
        self.assertFalse(rep_norm.is_safe)
        self.assertTrue(any(h.kind == "EXECUTABLE_CONFIG" for h in rep_norm.hazards), rep_norm.hazards)

        dup_zip = self.tmp / "norm_dup.zip"
        with zipfile.ZipFile(dup_zip, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("a/b.md", "# 1\n")
            zf.writestr("a/./b.md", "# 2\n")
        rep_dup = inspect_zip(dup_zip, harness_root=self.tmp)
        self.assertFalse(rep_dup.is_safe)
        self.assertTrue(any(h.kind == "DUPLICATE_NAME" for h in rep_dup.hazards), rep_dup.hazards)

        trunc_zip = self.tmp / "trunc_deflate.zip"
        with zipfile.ZipFile(trunc_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("rule.md", b"deterministic content " * 50)
        raw_t = bytearray(trunc_zip.read_bytes())
        # Flip LFH compress_type from DEFLATED (8) to STORED (0) to trigger LFH/CD mismatch
        struct.pack_into("<H", raw_t, 8, zipfile.ZIP_STORED)
        trunc_zip.write_bytes(bytes(raw_t))
        rep_t = inspect_zip(trunc_zip, harness_root=self.tmp)
        self.assertFalse(rep_t.is_safe)
        self.assertTrue(any(h.kind == "UNREADABLE_MEMBER" for h in rep_t.hazards), rep_t.hazards)

        # 3. SBV-13: sanitizer strips macOS/Windows/XDG runtime paths
        san = ConstitutionalSanitizer.sanitize_for_export(
            "Run ~/Library/Application Support/plumbwork/runtime/guard/agy_hooks.py or %LOCALAPPDATA%\\plumbwork\\runtime\\porter.py",
            target="claude",
        )
        self.assertNotIn("plumbwork/runtime", san)
        self.assertNotIn("plumbwork\\runtime", san)

        # 4. CCA-6 & META-8: ClaudeEmitter maps search_web -> WebFetch, WebSearch; CursorEmitter rewrites agent-*.mdc skill paths
        manifest = ManifestEngine(REPO_ROOT).build_manifest()
        c_out = self.tmp / "claude_out"
        ClaudeEmitter().emit(manifest, c_out)
        res_meta, _ = parse_frontmatter((c_out / ".claude" / "agents" / "research.md").read_text(encoding="utf-8"))
        self.assertEqual(res_meta.get("tools"), "Read, Grep, Glob, WebFetch, WebSearch")

        cur_out = self.tmp / "cursor_out"
        CursorEmitter().emit(manifest, cur_out)
        agent_mdc = (cur_out / ".cursor" / "rules" / "agent-simplicity-auditor.mdc").read_text(encoding="utf-8")
        self.assertIn(".cursor/skills/harness/SKILL.md", agent_mdc)
        self.assertNotIn("~/.gemini/config/skills/", agent_mdc)

        # 5. CCA-4: PorterBridge.stage_and_ingest & porter.py CLI import emit modern Antigravity agent schema
        from guard.os_adapter import OSProtectionAdapter

        bridge_tgt = self.tmp / "bridge_cfg"
        bridge_tgt.mkdir()
        mock_ad = mock.MagicMock(spec=OSProtectionAdapter)
        mock_ad.is_locked.return_value = False
        mock_ad.unlock.return_value = (True, "ok")
        mock_ad.lock.return_value = (True, "ok")
        bridge = porter_bridge.PorterBridge(target_dir=bridge_tgt, os_adapter=mock_ad)

        agent_src = self.tmp / "incoming_agent.md"
        agent_src.write_text(
            "---\nname: incoming-auditor\nkind: agent\ndescription: Read-only audit helper.\naccess: read-only\n---\n"
            "# Incoming Auditor\nYou are an independent read-only auditor. Inspect files and report findings.\n",
            encoding="utf-8",
        )
        ok_a, msg_a = bridge.stage_and_ingest(str(agent_src), target_name="incoming-auditor", force=True)
        self.assertTrue(ok_a, msg_a)
        sa_meta, _ = parse_frontmatter((bridge_tgt / "agents" / "incoming-auditor.md").read_text(encoding="utf-8"))
        self.assertIs(sa_meta.get("mainAgent"), False)
        self.assertIs(sa_meta.get("subagent"), True)
        self.assertIs(sa_meta.get("inheritMcp"), False)
        self.assertEqual(sa_meta.get("tools"), ["read_file"])

        # Also verify porter.py import --as-agent --dry-run emits full modern schema
        imp_proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "porter.py"),
                "import",
                str(agent_src),
                "--as-agent",
                "cli-imported-auditor",
                "--dry-run",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(imp_proc.returncode, 0, imp_proc.stdout + imp_proc.stderr)
        for tok in ("mainAgent: false", "subagent: true", "inheritMcp: false", "read_file"):
            self.assertIn(tok, imp_proc.stdout)


if __name__ == "__main__":
    unittest.main()
