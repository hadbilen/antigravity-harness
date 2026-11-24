"""
tests/test_w4_preflight_remediation.py — Window 4 8-auditor Tier-3 pre-flight remediation tests.
Part of Plumbwork (https://github.com/hadbilen/plumbwork)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import hermetic

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestW4PreFlightRemediations(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="plumb-w4-remed-"))
        self.home = self.tmp / "home"
        self.cfg = self.home / ".gemini" / "config"
        self.state = self.tmp / "state"
        self.data = self.tmp / "data"
        self.ws = self.tmp / "workspace"
        for d in (self.home, self.cfg, self.state, self.data, self.ws):
            d.mkdir(parents=True, exist_ok=True)
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "LOCALAPPDATA": str(self.home / "AppData" / "Local"),
                "XDG_STATE_HOME": str(self.tmp / "xdg_state"),
                "XDG_DATA_HOME": str(self.tmp / "xdg_data"),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg),
                "PLUMB_GUARD_STATE_DIR": str(self.state),
                "PLUMB_GUARD_DATA_DIR": str(self.data),
                "PLUMB_GUARD_NOTIFY": "off",
            },
            clear=False,
        )
        self._env_patch.start()
        os.environ.pop("PLUMBWORK_SHARE_DIR", None)
        os.environ.pop("PLUMB_GUARD_NO_TRAY", None)

    def tearDown(self) -> None:
        self._env_patch.stop()
        hermetic.force_rmtree(self.tmp)

    def test_sec01_safe_subpath_stop_gate_facade_and_env_override_shield(self) -> None:
        from guard import agy_hooks
        from guard import cli as guard_cli
        from guard.hooks import stop_gate as stop_gate_mod
        from guard.paths import is_safe_regular_subpath

        # 1. is_safe_regular_subpath rejects symlink base_dir, symlink child, and world-writable script
        base = self.tmp / "safe_base"
        rel = Path("skills/ui-refinery/scripts/check_ui_slop.py")
        target = base / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("def scan_text(*a, **kw):\n    return None\n", encoding="utf-8")
        self.assertTrue(is_safe_regular_subpath(base, rel))

        if os.name != "nt":
            sym_base = self.tmp / "sym_base"
            sym_base.symlink_to(base)
            self.assertFalse(is_safe_regular_subpath(sym_base, rel))

            target.chmod(0o666)
            self.assertFalse(is_safe_regular_subpath(base, rel))
            target.chmod(0o644)
            self.assertTrue(is_safe_regular_subpath(base, rel))

        # 2. stop_gate honors agy_hooks.data_dir proxy and reports unsafe/broken existing scanner instead of silent []
        broken_data = self.tmp / "broken_rt_data"
        broken_script = broken_data / "runtime" / rel
        broken_script.parent.mkdir(parents=True, exist_ok=True)
        broken_script.write_text("raise RuntimeError('boom')\n", encoding="utf-8")
        empty_root = self.tmp / "empty_root"
        empty_root.mkdir(exist_ok=True)
        with (
            mock.patch.object(stop_gate_mod, "_UI_SLOP_SCANNER_MOD", None),
            mock.patch.object(stop_gate_mod, "_UI_SLOP_SCANNER_LOADED", False),
            mock.patch.object(stop_gate_mod, "_repo_root", return_value=empty_root),
            mock.patch.object(stop_gate_mod, "config_dir", return_value=empty_root),
            mock.patch.object(stop_gate_mod, "configured_config_dir", return_value=empty_root),
            mock.patch.object(agy_hooks, "data_dir", return_value=broken_data),
        ):
            findings = stop_gate_mod.validate_ui_slop_content("index.html", "<div></div>")
            self.assertTrue(findings, "Broken existing check_ui_slop.py must emit a Stop-gate diagnostic")
            self.assertIn("unavailable", findings[0].lower())

        # 3. _resolve_portable_script rejects unverified plugin pack & world-writable scripts
        evil_share = self.tmp / "evil_share"
        evil_script = evil_share / rel
        evil_script.parent.mkdir(parents=True, exist_ok=True)
        evil_script.write_text("# evil\n", encoding="utf-8")
        fake_cli_file = self.tmp / "fhs_root" / "lib" / "plumb-guard" / "guard" / "cli.py"
        fake_cli_file.parent.mkdir(parents=True, exist_ok=True)
        fake_cli_file.write_text("# stub\n", encoding="utf-8")
        fhs_share_script = self.tmp / "fhs_root" / "share" / "plumbwork" / rel
        fhs_share_script.parent.mkdir(parents=True, exist_ok=True)
        fhs_share_script.write_text("# trusted fhs\n", encoding="utf-8")
        with (
            mock.patch.dict(os.environ, {"PLUMBWORK_SHARE_DIR": str(evil_share)}, clear=False),
            mock.patch.object(guard_cli, "__file__", str(fake_cli_file)),
        ):
            resolved = guard_cli._resolve_portable_script(str(rel))
            self.assertEqual(resolved, fhs_share_script)

        # 4. PreToolUse denies inline env overrides before plumb-guard/plumb-porter, allows benign notify/unittest
        for bad_cmd in (
            "PLUMBWORK_SHARE_DIR=/tmp/evil plumb-guard ui-slop /tmp/x.html",
            "PLUMB_GUARD_DATA_DIR=/tmp/evil plumb-guard status",
            "env PLUMB_GUARD_STATE_DIR=/tmp/evil python3 -m guard verify",
            "export ANTIGRAVITY_CONFIG_DIR=/tmp/evil && plumb-guard doctor",
        ):
            with self.subTest(bad_cmd=bad_cmd):
                res = agy_hooks.handle_pre_tool_use(
                    {
                        "toolName": "run_command",
                        "toolInput": {"CommandLine": bad_cmd},
                        "cwd": str(self.ws),
                        "conversationId": "w4-sec01-bad",
                    }
                )
                self.assertEqual(res.get("decision"), "deny", f"Expected deny for {bad_cmd}: {res}")

        for ok_cmd in (
            "PLUMB_GUARD_NOTIFY=off plumb-guard status",
            "ANTIGRAVITY_CONFIG_DIR=/tmp/x python3 -m unittest tests/test_guard.py",
        ):
            with self.subTest(ok_cmd=ok_cmd):
                res = agy_hooks.handle_pre_tool_use(
                    {
                        "toolName": "run_command",
                        "toolInput": {"CommandLine": ok_cmd},
                        "cwd": str(self.ws),
                        "conversationId": "w4-sec01-ok",
                    }
                )
                self.assertEqual(res.get("decision"), "allow", f"Expected allow for {ok_cmd}: {res}")

    def test_sec02_to_sec08_and_sec11_shell_mcp_swarm_workflow_bypasses(self) -> None:
        from guard import agy_hooks

        # 1. SEC-02 / SEC-03 / SEC-04 / SEC-06 / SEC-07 shell denials
        custom_state_base = self.tmp / "custom_state_dir"
        custom_state_base.mkdir(exist_ok=True)
        with mock.patch.dict(os.environ, {"PLUMB_GUARD_STATE_DIR": str(custom_state_base)}, clear=False):
            deny_cmds = [
                # SEC-02: plumb?porter / plumb[-]porter / plumb*porter glob bypasses
                "/usr/bin/plumb?porter stage /tmp/x.md",
                "/usr/bin/plumb[-]porter stage /tmp/x.md",
                "~/.local/bin/plumb*porter import --force /tmp/x.md",
                # SEC-03: glued redir, expanded home GEMINI.md, custom state dir glob
                "echo x >~/.g*/c*/GEMINI.md",
                f"echo x > {self.home.as_posix()}/.gem*/GEMINI.md",
                f"rm -rf {self.tmp.as_posix()}/custom_state_*/environments.json",
                # SEC-04: globbed plugin directory drop
                "cp -r /tmp/evil_plug ~/.gem*/conf*/plugins/evil-pack",
                "cp -r /tmp/evil_plug ~/.gem*/conf*/plu*ins/evil-pack",
                # SEC-06: var/glob install.py bypass
                "S=install.py; python3 $S",
                "python3 ./in*ll.py",
                # SEC-07: Windows py launcher admin bypass
                "py -3 -m guard unlock",
                "py -3 -m porter stage /tmp/x.md",
                "py -3 -m scripts.verify_invariants --authorize tests/test_x.py",
            ]
            for cmd in deny_cmds:
                with self.subTest(cmd=cmd):
                    res = agy_hooks.handle_pre_tool_use(
                        {
                            "toolName": "run_command",
                            "toolInput": {"CommandLine": cmd},
                            "cwd": str(REPO_ROOT),
                            "conversationId": "w4-sec-shell",
                        }
                    )
                    self.assertEqual(res.get("decision"), "deny", f"Expected deny for {cmd!r}, got {res}")

        # 2. SEC-06 across MCP, subagent delegation, and run_workflow
        res_mcp = agy_hooks.handle_pre_tool_use(
            {
                "toolName": "call_mcp_tool",
                "toolInput": {
                    "ServerName": "shell-srv",
                    "ToolName": "exec_cmd",
                    "Arguments": {"cmd": "G=plumb-guard; $G unlock"},
                },
                "cwd": str(self.ws),
                "conversationId": "w4-sec06-mcp",
            }
        )
        self.assertEqual(res_mcp.get("decision"), "deny", res_mcp)

        res_sub = agy_hooks.handle_pre_tool_use(
            {
                "toolName": "invoke_subagent",
                "toolInput": {
                    "TypeName": "self",
                    "Role": "Helper",
                    "Prompt": "Run /usr/bin/plumb-g* unlock on config",
                },
                "cwd": str(self.ws),
                "conversationId": "w4-sec06-sub",
            }
        )
        self.assertEqual(res_sub.get("decision"), "deny", res_sub)

        res_wf = agy_hooks.handle_pre_tool_use(
            {
                "toolName": "run_workflow",
                "toolInput": {
                    "Script": "def run():\n    return 'G=plumb-guard; $G unlock'\n",
                    "Args": {"cmd": "/usr/bin/plumb-g* unlock"},
                },
                "cwd": str(self.ws),
                "conversationId": "w4-sec06-wf",
            }
        )
        self.assertEqual(res_wf.get("decision"), "deny", res_wf)

        # 3. SEC-08: Rule 17 under Flash model catches python3 -B -m porter manifest & plumb-p* manifest
        for m_cmd in (
            "python3 -B -m porter manifest",
            "py -3 -m porter manifest",
            "/usr/bin/plumb-p* manifest",
            "plumb-porter manifest",
        ):
            with self.subTest(rule17_cmd=m_cmd):
                res_r17 = agy_hooks.handle_pre_tool_use(
                    {
                        "toolName": "run_command",
                        "toolInput": {"CommandLine": m_cmd},
                        "cwd": str(REPO_ROOT),
                        "model": "gemini-flash-worker-agy",
                        "conversationId": "w4-sec08",
                    }
                )
                self.assertEqual(res_r17.get("decision"), "deny", f"Expected Rule 17 deny for {m_cmd}: {res_r17}")

        res_chk = agy_hooks.handle_pre_tool_use(
            {
                "toolName": "run_command",
                "toolInput": {"CommandLine": "plumb-porter manifest --check"},
                "cwd": str(REPO_ROOT),
                "model": "gemini-flash-worker-agy",
                "conversationId": "w4-sec08-ok",
            }
        )
        self.assertEqual(res_chk.get("decision"), "allow", res_chk)

        # 4. SEC-11 & TA-13: agy plugin glob probes catch negated/tagged harness packs while allowing third-party archives
        for ask_cmd in (
            "agy plugin uninstall ui-refiner?-v[!30]*.zip",
            "agy plugin uninstall ui-refiner?-v3.0.0.t[!x]z",
            "agy plugin disable ui-refiner?@latest",
        ):
            with self.subTest(ask_cmd=ask_cmd):
                res_p = agy_hooks.handle_pre_tool_use(
                    {
                        "toolName": "run_command",
                        "toolInput": {"CommandLine": ask_cmd},
                        "cwd": str(self.ws),
                        "conversationId": "w4-sec11",
                    }
                )
                self.assertEqual(res_p.get("decision"), "force_ask", f"Expected force_ask for {ask_cmd}: {res_p}")

        for allow_cmd in (
            "agy plugin uninstall rea-v3.0.0.zip",
            "agy plugin disable custom-*.tar.gz",
        ):
            with self.subTest(allow_cmd=allow_cmd):
                res_p = agy_hooks.handle_pre_tool_use(
                    {
                        "toolName": "run_command",
                        "toolInput": {"CommandLine": allow_cmd},
                        "cwd": str(self.ws),
                        "conversationId": "w4-ta13",
                    }
                )
                self.assertEqual(res_p.get("decision"), "allow", f"Expected allow for {allow_cmd}: {res_p}")

    def test_sec05_sec09_ta06_ta07_ta12_receipt_and_third_party_seams(self) -> None:
        from guard.doctor import _is_harness_contrast_mcp_arg
        from guard.environment import (
            antigravity_plugin_governance_seams,
            extract_receipt_uninstall_entries,
            is_harness_plugin_dir,
            is_legacy_harness_skill_dir,
            migrate_harness_mcp_config,
            resolve_safe_uninstall_entry,
        )

        # 1. SEC-05: poisoned ./plugins, ./hooks.json, bare containers are stripped & blocked
        poisoned_rec = {
            "target": str(self.cfg),
            "installed": ["./plugins", "./hooks.json", "./config.json", "./mcp_config.json", "skills", "sidecars", "../escape", "rules/plumbwork-constitution.md"],
            "installed_plugins": ["ui-refinery"],
        }
        entries = extract_receipt_uninstall_entries(poisoned_rec)
        self.assertEqual(entries, ["rules/plumbwork-constitution.md", "plugins/ui-refinery"])
        for bad_item in ("./plugins", "./hooks.json", "skills", "sidecars", "config.json", "mcp_config.json"):
            self.assertIsNone(resolve_safe_uninstall_entry(self.cfg, self.cfg.resolve(), bad_item))

        # 2. SEC-09: antigravity_plugin_governance_seams does not re-add receipted plugin replaced by third-party or symlink
        third_ui = self.cfg / "plugins" / "ui-refinery"
        third_ui.mkdir(parents=True, exist_ok=True)
        (third_ui / "plugin.json").write_text(
            json.dumps({"name": "ui-refinery", "repository": "https://github.com/other/ui-refinery"}),
            encoding="utf-8",
        )
        rec_file = self.state / "install_receipt.json"
        rec_file.write_text(
            json.dumps({"target": str(self.cfg), "installed_plugins": ["ui-refinery"]}),
            encoding="utf-8",
        )
        self.assertEqual(antigravity_plugin_governance_seams(self.cfg, receipt_path=rec_file), [])

        # 3. TA-06: mismatched URL pairs, dict repository, non-string URL fail closed
        for idx, manifest in enumerate([
            {"name": "ui-refinery", "repository": "https://github.com/hadbilen/plumbwork", "homepage": "https://github.com/other/fork"},
            {"name": "ui-refinery", "repository": "https://github.com/other/fork", "homepage": "https://github.com/hadbilen/plumbwork"},
            {"name": "ui-refinery", "repository": {"url": "https://github.com/other/fork"}},
            {"name": "ui-refinery", "repository": 12345},
        ]):
            pdir = self.tmp / f"plug_neg_{idx}"
            pdir.mkdir(parents=True, exist_ok=True)
            (pdir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            self.assertFalse(is_harness_plugin_dir(pdir, expected_pack="ui-refinery"), f"case {idx} must fail closed")

        # 4. TA-12: is_legacy_harness_skill_dir script-header fallback + symlink refusal
        leg_sk = self.tmp / "leg_skill_script_fb"
        (leg_sk / "scripts").mkdir(parents=True, exist_ok=True)
        (leg_sk / "SKILL.md").write_text("---\nname: antislop\n---\nGeneric prose.\n", encoding="utf-8")
        (leg_sk / "scripts" / "check_ui_slop.py").write_text(
            "# Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)\n",
            encoding="utf-8",
        )
        self.assertTrue(is_legacy_harness_skill_dir(leg_sk))
        if os.name != "nt":
            sym_sk = self.tmp / "leg_skill_sym_script"
            (sym_sk / "scripts").mkdir(parents=True, exist_ok=True)
            (sym_sk / "SKILL.md").write_text("---\nname: antislop\n---\nGeneric prose.\n", encoding="utf-8")
            (sym_sk / "scripts" / "check_ui_slop.py").symlink_to(leg_sk / "scripts" / "check_ui_slop.py")
            self.assertFalse(is_legacy_harness_skill_dir(sym_sk))

        # 5. TA-07: present third-party plugins/antislop & skills/antislop-human MCP preserved
        tp_plug = self.cfg / "plugins" / "antislop"
        (tp_plug / "scripts").mkdir(parents=True, exist_ok=True)
        (tp_plug / "plugin.json").write_text(
            json.dumps({"name": "antislop", "repository": "https://github.com/miqdadbadjuber/anti-slop"}),
            encoding="utf-8",
        )
        tp_plug_script = tp_plug / "scripts" / "contrast-mcp.py"
        tp_plug_script.write_text("# upstream\n", encoding="utf-8")
        tp_hum = self.cfg / "skills" / "antislop-human"
        (tp_hum / "scripts").mkdir(parents=True, exist_ok=True)
        (tp_hum / "SKILL.md").write_text("# Upstream third-party\n", encoding="utf-8")
        tp_hum_script = tp_hum / "scripts" / "contrast-mcp.py"
        tp_hum_script.write_text("# upstream\n", encoding="utf-8")
        self.assertFalse(_is_harness_contrast_mcp_arg(str(tp_plug_script), self.cfg))
        self.assertFalse(_is_harness_contrast_mcp_arg(str(tp_hum_script), self.cfg))

        mcp_file = self.cfg / "mcp_config.json"
        mcp_file.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "third-party-plug": {"command": "python3", "args": [str(tp_plug_script)]},
                        "third-party-hum": {"command": "python3", "args": [str(tp_hum_script)]},
                    }
                }
            ),
            encoding="utf-8",
        )
        migrate_harness_mcp_config(self.cfg, REPO_ROOT, retire_plugin_mcp=True)
        after = json.loads(mcp_file.read_text(encoding="utf-8"))["mcpServers"]
        self.assertIn("third-party-plug", after)
        self.assertIn("third-party-hum", after)

    def test_doctor_legacy_residue_rules_symlink_launchers_and_native_deny(self) -> None:
        from guard.doctor import _check_legacy_residue, _check_native_deny_rules

        # 1. Native deny check rejects legacy agy-guard unlock as sufficient for v3 plumb-guard unlock
        cfg_json = self.cfg / "config.json"
        cfg_json.write_text(
            json.dumps({"userSettings": {"globalPermissionGrants": {"deny": ["agy-guard unlock", "--no-verify"]}}}),
            encoding="utf-8",
        )
        w_n: list[str] = []
        i_n: list[str] = []
        _check_native_deny_rules(self.cfg, i_n, warnings=w_n)
        self.assertTrue(any("plumb-guard unlock" in msg and "recommended" in msg for msg in i_n), i_n)

        # 2. Legacy residue detects legacy launchers, all 7 legacy skill slugs, and receipted plugins/antislop suppression
        local_bin = self.home / ".local" / "bin"
        local_bin.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            (local_bin / "agy-guard").write_text("#!/bin/sh\n", encoding="utf-8")
            (local_bin / "porter").write_text("#!/bin/sh\n# antigravity-harness launcher\n", encoding="utf-8")

        silk_dir = self.cfg / "skills" / "silk-design"
        silk_dir.mkdir(parents=True, exist_ok=True)
        (silk_dir / "SKILL.md").write_text("Run `agy-guard ui-slop`.\n", encoding="utf-8")

        plug_ant = self.cfg / "plugins" / "antislop"
        plug_ant.mkdir(parents=True, exist_ok=True)
        (plug_ant / "plugin.json").write_text(
            json.dumps({"name": "antislop", "repository": "https://github.com/hadbilen/antigravity-harness"}),
            encoding="utf-8",
        )
        (self.state / "install_receipt.json").write_text(
            json.dumps({"target": str(self.cfg), "installed": ["plugins\\antislop"], "installed_plugins": "bad-not-list"}),
            encoding="utf-8",
        )
        warns: list[str] = []
        _check_legacy_residue(self.cfg, warns)
        joined = "\n".join(warns)
        self.assertIn("not a list", joined)
        self.assertNotIn("Unreceipted legacy harness plugin", joined)
        self.assertIn("Unreceipted legacy harness skill", joined)
        self.assertIn("silk-design", joined)
        if os.name != "nt":
            self.assertIn("agy-guard", joined)
            self.assertIn("'porter' alias launcher", joined)

        # 3. Symlinked rules/ directory is refused safely
        if os.name != "nt":
            real_rules = self.tmp / "real_rules"
            real_rules.mkdir()
            (self.cfg / "rules").symlink_to(real_rules)
            w_sym: list[str] = []
            _check_legacy_residue(self.cfg, w_sym)
            self.assertTrue(any("Refusing symlinked rules directory" in m for m in w_sym), w_sym)

    def test_paths_tray_startup_os_adapter_plugins_and_installer_binary(self) -> None:
        import install as root_inst
        from guard.os_adapter import OSProtectionAdapter
        from guard.paths import share_dir_candidates, state_dir, windows_launcher_dir
        from guard.plugins import build_plugin_pack, validate_plugin_dir, validate_svg_logo
        from guard.startup import StartupManager
        from guard.tray import DummyAdapter, create_tray_adapter

        # 1. Whitespace-only env vars do not resolve relative to CWD
        with mock.patch.dict(
            os.environ,
            {"PLUMBWORK_SHARE_DIR": "   ", "PLUMB_GUARD_STATE_DIR": "   ", "LOCALAPPDATA": ""},
            clear=False,
        ):
            self.assertEqual(share_dir_candidates(), [Path("/usr/share/plumbwork")])
            self.assertEqual(state_dir(), Path(os.path.abspath(self.tmp / "xdg_state" / "plumbwork")))
            self.assertEqual(windows_launcher_dir(), Path(os.path.abspath(self.home / "AppData" / "Local" / "Programs" / "plumb-guard")))

        # 2. Padded PLUMBWORK_SHARE_DIR resolves trimmed path ahead of /usr/share/plumbwork
        custom_share = self.tmp / "custom_share"
        with mock.patch.dict(os.environ, {"PLUMBWORK_SHARE_DIR": f"  {custom_share}  "}, clear=False):
            cands = share_dir_candidates()
            self.assertEqual(cands[0], Path(os.path.abspath(custom_share)))
            self.assertEqual(cands[-1], Path("/usr/share/plumbwork"))

        # 3. Tray factory honors PLUMB_GUARD_NO_TRAY=1 on Darwin/Windows and ignores "0"/""
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch.dict(os.environ, {"PLUMB_GUARD_NO_TRAY": "1"}, clear=False):
                ad = create_tray_adapter(lambda: None, lambda: None, lambda: None)
                self.assertIsInstance(ad, DummyAdapter)
                self.assertIn("PLUMB_GUARD_NO_TRAY=1", ad.fallback_reason)
            with mock.patch.dict(os.environ, {"PLUMB_GUARD_NO_TRAY": "0"}, clear=False):
                ad0 = create_tray_adapter(lambda: None, lambda: None, lambda: None)
                self.assertNotIn("PLUMB_GUARD_NO_TRAY=1", ad0.fallback_reason or "")

        # 4. StartupManager resolves runtime guard.py before -m guard.cli when launcher absent
        rt_guard = self.data / "runtime" / "guard.py"
        rt_guard.parent.mkdir(parents=True, exist_ok=True)
        rt_guard.write_text("# runtime guard\n", encoding="utf-8")
        sm = StartupManager(target_dir=self.cfg)
        with mock.patch("shutil.which", return_value=None):
            argv = sm.get_guard_argv()
            self.assertIn(str(rt_guard), argv)
            self.assertNotIn("-m", argv)

        # 5. OSProtectionAdapter._iter_tree & validate_plugin_dir surface unreadable subdirs (chmod 000)
        if os.name != "nt" and not hermetic.IS_ROOT:
            locked_tree = self.tmp / "locked_tree"
            sub = locked_tree / "hidden_sub"
            sub.mkdir(parents=True)
            (sub / "f.txt").write_text("x", encoding="utf-8")
            sub.chmod(0o000)
            try:
                adapter = OSProtectionAdapter(locked_tree)
                issues = adapter.protection_issues(locked_tree)
                self.assertTrue(issues, "Unreadable subdirectory must produce protection issues, not silent pass")
            finally:
                sub.chmod(0o755)

        # 6. validate_plugin_dir rejects fenced # agy-guard comments, non-media-studio /usr/share/plumbwork, and >16 KiB SVG
        out_root = self.tmp / "packs"
        pdir = build_plugin_pack("ui-refinery", REPO_ROOT, out_root / "ui-refinery")
        sk_md = pdir / "skills" / "ui-refinery" / "SKILL.md"
        orig = sk_md.read_text(encoding="utf-8")
        sk_md.write_text(orig + "\n```bash\n# agy-guard status\n```\n", encoding="utf-8")
        res_fc = validate_plugin_dir(pdir, expected_pack="ui-refinery")
        self.assertFalse(res_fc.ok)
        self.assertTrue(any("agy-guard" in e for e in res_fc.errors), res_fc.errors)

        sk_md.write_text(orig + "\nSee `/usr/share/plumbwork/GEMINI.md`.\n", encoding="utf-8")
        res_sh = validate_plugin_dir(pdir, expected_pack="ui-refinery")
        self.assertFalse(res_sh.ok)
        self.assertTrue(any("/usr/share/plumbwork" in e for e in res_sh.errors), res_sh.errors)
        sk_md.write_text(orig, encoding="utf-8")

        big_svg = self.tmp / "big.svg"
        big_svg.write_text("<svg xmlns='http://www.w3.org/2000/svg'>" + ("a" * 17000) + "</svg>", encoding="utf-8")
        svg_errs = validate_svg_logo(big_svg)
        self.assertTrue(any("exceeds" in e for e in svg_errs), svg_errs)

        # 7. Installer.install_binary fails closed on short write
        inst = root_inst.Installer(target_dir=self.cfg, mode="copy", dry_run=False)
        fake_bin = REPO_ROOT / "dist"
        # Exercise short-write detection via patched fdopen file object
        fake_fh = mock.MagicMock()
        fake_fh.__enter__.return_value = fake_fh
        fake_fh.write.return_value = 4
        fake_fh.fileno.return_value = 0
        payload = b"BINARYPAYLOADBYTES"
        import hashlib

        digest = hashlib.sha256(payload).hexdigest()
        local_dist = self.tmp / "local_dist"
        local_dist.mkdir()
        import platform as _plat

        mach = _plat.machine().lower()
        mach = "x86_64" if mach in ("amd64", "x86_64") else ("arm64" if mach in ("arm64", "aarch64") else mach)
        bnames = {
            "Linux": f"plumb-guard-linux-{mach}",
            "Darwin": f"plumb-guard-macos-{mach}",
            "Windows": f"plumb-guard-windows-{mach}.exe",
        }
        bname = bnames.get(_plat.system())
        if bname:
            (local_dist / "dist").mkdir()
            (local_dist / "dist" / bname).write_bytes(payload)
            (local_dist / "dist" / f"{bname}.sha256").write_text(f"{digest}  {bname}\n", encoding="utf-8")
            with (
                mock.patch.object(root_inst, "SCRIPT_DIR", local_dist),
                mock.patch("os.fdopen", return_value=fake_fh),
                mock.patch("os.fsync"),
            ):
                ok_bin = inst.install_binary(expected_sha256=digest)
                self.assertFalse(ok_bin, "Short binary write must fail closed")

    def test_porter_packaging_and_sanitizer_w4_contracts(self) -> None:
        import urllib.request

        from installers.packaging.package_linux import LinuxPackager
        from porter.emitters.aider import AiderEmitter
        from porter.manifest import ManifestEngine
        from porter.net import safe_fetch_url
        from porter.sanitizer import ConstitutionalSanitizer

        # 1. CON-02: Aider emitter uses Plumbwork Porter header
        manifest = ManifestEngine(REPO_ROOT).build_manifest(deterministic=True)
        plan, _ = AiderEmitter.plan(manifest, self.tmp / "aider_out")
        conf = plan[self.tmp / "aider_out" / ".aider.conf.yml"]
        self.assertIn("Plumbwork Porter", conf)
        self.assertNotIn("Antigravity Porter", conf)

        # 2. CON-03: porter/net.py default User-Agent uses Plumb-Porter
        captured_ua = {}

        class _FakeResp:
            status = 200
            headers = {}

            def read(self, _n=-1):
                return b"ok"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class _FakeOpener:
            def open(self, req: urllib.request.Request, timeout=15.0):
                captured_ua["ua"] = req.get_header("User-agent")
                return _FakeResp()

        with (
            mock.patch("porter.net.validate_safe_url"),
            mock.patch("porter.net.build_safe_opener", return_value=_FakeOpener()),
        ):
            safe_fetch_url("https://example.com/rule.md")
        self.assertTrue((captured_ua.get("ua") or "").startswith("Plumb-Porter/"), captured_ua)

        # 3. CON-10: $PLUMB_GUARD_DATA_DIR/runtime/... sanitized in Porter exports
        raw_rt = "Run `$PLUMB_GUARD_DATA_DIR/runtime/guard/agy_hooks.py` and `${PLUMB_GUARD_DATA_DIR}/runtime/scripts/code_map.py`."
        san = ConstitutionalSanitizer.sanitize_for_export(raw_rt, target="universal")
        self.assertNotIn("PLUMB_GUARD_DATA_DIR", san)
        self.assertIn("guard/agy_hooks.py", san)
        self.assertIn("scripts/code_map.py", san)

        # 4. SEC-13: LinuxPackager rejects version string injection
        bad_pkg = LinuxPackager(repo_root=REPO_ROOT, version="3.0.0\n%prep\nwhoami", out_dir=self.tmp / "pkg_out")
        with self.assertRaises(ValueError):
            bad_pkg.validate_inputs()


if __name__ == "__main__":
    unittest.main()
