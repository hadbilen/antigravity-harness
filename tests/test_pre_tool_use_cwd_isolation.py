"""
tests/test_pre_tool_use_cwd_isolation.py: Hermetic regression suite verifying that
`PreToolUse` customization and governance target checks (`_targets_governance_dir`,
`_text_targets_customization`, orchestration/delegation gates, `run_workflow`, and MCP
inspection) never resolve bare or workspace-relative tokens against the hook process's
own `os.getcwd()`, while preserving all Rule 12 and Rule 17 security boundaries.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
for _p in (str(TESTS_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hermetic  # noqa: E402  # must precede repository imports per ADR-0010
from hermetic import force_rmtree  # noqa: E402

from guard import agy_hooks  # noqa: E402
from guard.hooks import pre_tool_use  # noqa: E402

TOP_MODEL = "Gemini 4 Carbon (High)"
NON_FLAGSHIP_MODEL = "Claude Sonnet 4.5 (Medium)"

MONITOR_BRIEF = (
    "You are this swarm's stall monitor. Load the swarm_monitor skill and follow it. "
    "Post only to break a stall."
)
AUTHOR_BRIEF = (
    "Implement item database queries and binary table loaders in Cargo.toml and "
    "crates/ko-db/src/lib.rs."
)


class TestPreToolUseCwdIsolation(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_cwd = Path.cwd()
        self.root = Path(tempfile.mkdtemp(prefix="agy-ptu-cwd-"))
        self.home_dir = self.root / "home"
        self.cfg_dir = self.home_dir / ".gemini" / "config"
        self.state_dir = self.home_dir / ".local" / "state" / "antigravity-harness"
        self.data_dir = self.home_dir / ".local" / "share" / "antigravity-harness"
        self.runtime_dir = self.data_dir / "runtime"
        self.unrelated_cwd = self.root / "unrelated_cwd"

        self.knight_ws = self.root / "Projeler" / "Knight Online"
        (self.knight_ws / "crates" / "ko-db" / "src").mkdir(parents=True)
        (self.knight_ws / "Cargo.toml").write_text("[workspace]\nmembers = ['crates/ko-db']\n", encoding="utf-8")
        (self.knight_ws / "crates" / "ko-db" / "src" / "lib.rs").write_text("pub fn load() {}\n", encoding="utf-8")

        self.second_ext_ws = self.root / "deep" / "nested" / "ws2"
        self.second_ext_ws.mkdir(parents=True)

        self.harness_ws = self.root / "Projeler" / "harness-clone"
        (self.harness_ws / ".harness").mkdir(parents=True)
        (self.harness_ws / ".harness" / "manifest.json").write_text("{}", encoding="utf-8")
        (self.harness_ws / "guard" / "hooks").mkdir(parents=True)
        (self.harness_ws / "guard" / "agy_hooks.py").write_text("# stub\n", encoding="utf-8")
        (self.harness_ws / "skills" / "harness").mkdir(parents=True)

        for d in (self.cfg_dir, self.state_dir, self.runtime_dir, self.unrelated_cwd):
            d.mkdir(parents=True, exist_ok=True)

        # Mirror real `install.py` deployment markers inside `config_dir` and `runtime_dir`
        (self.cfg_dir / ".harness").mkdir(parents=True, exist_ok=True)
        (self.cfg_dir / ".harness" / "manifest.json").write_text("{}", encoding="utf-8")
        (self.runtime_dir / "guard").mkdir(parents=True, exist_ok=True)
        (self.runtime_dir / "guard" / "agy_hooks.py").write_text("# runtime stub\n", encoding="utf-8")

        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home_dir),
                "USERPROFILE": str(self.home_dir),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
                "AGY_GUARD_STATE_DIR": str(self.state_dir),
                "AGY_GUARD_DATA_DIR": str(self.data_dir),
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        os.chdir(self._orig_cwd)
        self._env_patch.stop()
        force_rmtree(self.root)

    def _chdir(self, path: Path) -> None:
        os.chdir(path)

    def _hook_payload(
        self,
        tool_name: str,
        args: dict,
        *,
        ws: Path | None,
        model_name: str = NON_FLAGSHIP_MODEL,
        effort: str = "medium",
        conv_id: str = "conv-cwd-iso",
    ) -> dict:
        payload: dict = {
            "conversationId": conv_id,
            "modelName": model_name,
            "effort": effort,
            "toolCall": {"name": tool_name, "args": args},
        }
        if ws is not None:
            payload["workspacePaths"] = [str(ws)]
            payload["workspacePath"] = str(ws)
        return payload

    def test_external_swarm_add_monitor_and_author_briefs_under_governance_cwd(self) -> None:
        hook_cwds = (
            ("config_dir", agy_hooks.config_dir()),
            ("data_runtime_dir", agy_hooks.data_dir() / "runtime"),
            ("state_dir", agy_hooks.state_dir()),
        )
        brief_cases = (
            ("monitor", MONITOR_BRIEF, []),
            ("author_ko_db", AUTHOR_BRIEF, ["Cargo.toml", "crates/ko-db"]),
            (
                "author_rpg_domain_dirs",
                "Implement knight skills/cleave.rs and guard/shield_wall.rs in crates/ko-combat.",
                ["skills/cleave.rs", "guard/shield_wall.rs"],
            ),
        )

        for cwd_label, hook_cwd in hook_cwds:
            self._chdir(hook_cwd)
            for brief_label, brief_text, task_list in brief_cases:
                if brief_label != "author_rpg_domain_dirs":
                    with self.subTest(cwd=cwd_label, brief=brief_label, ws="none"):
                        self.assertFalse(
                            pre_tool_use._text_targets_customization(
                                brief_text, (), extra_tokens=task_list
                            )
                        )
                with self.subTest(cwd=cwd_label, brief=brief_label, ws="knight_online"):
                    self.assertFalse(
                        pre_tool_use._text_targets_customization(
                            brief_text,
                            [self.knight_ws],
                            extra_tokens=task_list,
                        )
                    )
                    self.assertFalse(
                        pre_tool_use._text_targets_customization(
                            brief_text,
                            [self.knight_ws],
                            fallback_ws=self.knight_ws,
                            effective_cwd=self.knight_ws,
                            extra_tokens=task_list,
                        )
                    )
                    swarm_args: dict = {
                        "action": "add",
                        "name": f"w-{brief_label}",
                        "brief": brief_text,
                    }
                    if task_list:
                        swarm_args["tasks"] = task_list

                    conv_non_flagship = f"conv-{cwd_label}-{brief_label}-nf"
                    res_nf = agy_hooks.handle_pre_tool_use(
                        self._hook_payload(
                            "swarm",
                            swarm_args,
                            ws=self.knight_ws,
                            model_name=NON_FLAGSHIP_MODEL,
                            effort="medium",
                            conv_id=conv_non_flagship,
                        )
                    )
                    self.assertEqual(res_nf, {"decision": "allow"}, (cwd_label, brief_label, res_nf))

                    conv_flash_worker = f"conv-{cwd_label}-{brief_label}-fw"
                    res_fw = agy_hooks.handle_pre_tool_use(
                        self._hook_payload(
                            "swarm",
                            {**swarm_args, "model": "flash"},
                            ws=self.knight_ws,
                            model_name=TOP_MODEL,
                            effort="high",
                            conv_id=conv_flash_worker,
                        )
                    )
                    self.assertEqual(res_fw.get("decision"), "force_ask", (cwd_label, brief_label, res_fw))
                    self.assertNotIn("Rule 17", str(res_fw.get("reason", "")))

                    ledger_path = agy_hooks.state_dir() / "swarm_workers.json"
                    self.assertTrue(ledger_path.is_file(), (cwd_label, brief_label))
                    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
                    self.assertNotIn(conv_non_flagship, ledger)
                    self.assertIn(f"w-{brief_label}", ledger.get(conv_flash_worker, {}).get("downgraded", []))
                    self.assertFalse(ledger.get(conv_flash_worker, {}).get("conv_has_cust", False))

    def test_delegation_workflow_mcp_and_cmd_consistency_under_governance_cwd(self) -> None:
        for cwd_label, hook_cwd in (
            ("config_dir", agy_hooks.config_dir()),
            ("data_runtime_dir", agy_hooks.data_dir() / "runtime"),
        ):
            self._chdir(hook_cwd)
            for ws_label, ws_opt in (("knight_online", self.knight_ws), ("none", None)):
                tool_cases = (
                    (
                        "invoke_subagent",
                        {"TypeName": "self", "Role": "KO DB Worker", "Prompt": f"Edit {AUTHOR_BRIEF}"},
                    ),
                    (
                        "swarm",
                        {"action": "add", "name": "monitor", "brief": MONITOR_BRIEF},
                    ),
                    (
                        "post_message",
                        {"channel": "board", "text": f"@author Edit Cargo.toml and crates/ko-db/src/lib.rs."},
                    ),
                    (
                        "send_message",
                        {"Recipient": "conv-sub-1", "Message": f"{MONITOR_BRIEF} Update crates/ko-db."},
                    ),
                    (
                        "define_subagent",
                        {
                            "Name": "ko-helper",
                            "Description": "Rust crate helper.",
                            "SystemPrompt": AUTHOR_BRIEF,
                            "EnableWriteTools": True,
                        },
                    ),
                    (
                        "schedule",
                        {"DurationSeconds": 60, "IsDaemon": True, "Prompt": MONITOR_BRIEF},
                    ),
                    (
                        "run_workflow",
                        {
                            "Script": (
                                "out = await agent('Inspect Cargo.toml and crates/ko-db.', model='flash')\n"
                            )
                        },
                    ),
                    (
                        "call_mcp_tool",
                        {
                            "ServerName": "rea_rea",
                            "ToolName": "inspect_rust_binary",
                            "Arguments": {"path": "crates/ko-db", "summary": MONITOR_BRIEF},
                        },
                    ),
                )
                for tool_name, args in tool_cases:
                    with self.subTest(cwd=cwd_label, ws=ws_label, tool=tool_name):
                        res = agy_hooks.handle_pre_tool_use(
                            self._hook_payload(
                                tool_name,
                                args,
                                ws=ws_opt,
                                model_name=NON_FLAGSHIP_MODEL,
                                effort="medium",
                                conv_id=f"conv-all-{cwd_label}-{ws_label}-{tool_name}",
                            )
                        )
                        self.assertEqual(res, {"decision": "allow"}, (cwd_label, ws_label, tool_name, res))

            res_cmd = agy_hooks.handle_pre_tool_use(
                self._hook_payload(
                    "run_command",
                    {
                        "CommandLine": (
                            "python3 -c \"from pathlib import Path; Path('crates/ko-db/out.json').write_text('{}')\""
                        )
                    },
                    ws=self.knight_ws,
                    model_name=NON_FLAGSHIP_MODEL,
                    effort="medium",
                    conv_id=f"conv-cmd-{cwd_label}",
                )
            )
            self.assertEqual(res_cmd, {"decision": "allow"}, (cwd_label, res_cmd))

    def test_security_negative_controls_still_trigger_targets_cust_and_rule17_deny(self) -> None:
        cfg = agy_hooks.config_dir()
        rel_escape_gemini = os.path.relpath(cfg / "GEMINI.md", self.knight_ws)
        rel_escape_custom = os.path.relpath(cfg / "custom_policy.yaml", self.knight_ws)
        rel_escape_ws2 = os.path.relpath(cfg / "custom_policy.yaml", self.second_ext_ws)
        rel_harness_ws2 = os.path.relpath(self.harness_ws / "guard" / "agy_hooks.py", self.second_ext_ws)

        external_ws_cust_targets = (
            ("tilde_gemini_md", "~/.gemini/config/GEMINI.md"),
            ("tilde_custom_non_basename", "~/.gemini/config/custom_policy.yaml"),
            ("tilde_win_backslash_gov", r"~\.gemini\config\custom_policy.yaml"),
            ("dollar_home_gov", "$HOME/.gemini/config/custom_policy.yaml"),
            ("braced_home_gov", "${HOME}/.gemini/config/custom_policy.yaml"),
            ("dollar_home_win_bs_gov", r"$HOME\.gemini\config\custom_policy.yaml"),
            ("pct_userprofile_win_bs_gov", r"%USERPROFILE%\.gemini\config\custom_policy.yaml"),
            ("dollar_userprofile_gov", "$USERPROFILE/.gemini/config/custom_policy.yaml"),
            ("antigravity_cfg_env_gov", "$ANTIGRAVITY_CONFIG_DIR/custom_policy.yaml"),
            ("markdown_bold_gov", "**~/.gemini/config/custom_policy.yaml**"),
            ("option_eq_gov", "--config=~/.gemini/config/custom_policy.yaml"),
            ("abs_cfg_gemini", str(cfg / "GEMINI.md")),
            ("abs_cfg_custom_non_basename", str(cfg / "custom_policy.yaml")),
            ("abs_cfg_sentence_dot", f"{cfg}."),
            ("abs_runtime_file", str(agy_hooks.data_dir() / "runtime" / "internal_note.txt")),
            ("dotdot_escape_gemini", rel_escape_gemini),
            ("dotdot_escape_custom_non_basename", rel_escape_custom),
        )
        harness_ws_cust_targets = (
            ("harness_skill_md", "SKILL.md"),
            ("harness_gemini_md", "GEMINI.md"),
            ("harness_hooks_json", "hooks.json"),
        )

        for cwd_label, hook_cwd in (
            ("unrelated_cwd", self.unrelated_cwd),
            ("config_dir", cfg),
            ("data_runtime_dir", agy_hooks.data_dir() / "runtime"),
        ):
            self._chdir(hook_cwd)

            # Multi-root workspace escapes via `handle_pre_tool_use` (`workspaces[1] != ws_ctx`)
            for mr_ref in (rel_escape_ws2, rel_harness_ws2):
                mr_res = agy_hooks.handle_pre_tool_use(
                    {
                        "conversationId": f"conv-mr-{cwd_label}",
                        "modelName": NON_FLAGSHIP_MODEL,
                        "effort": "medium",
                        "workspacePaths": [str(self.knight_ws), str(self.second_ext_ws)],
                        "toolCall": {
                            "name": "swarm",
                            "args": {"action": "add", "name": "mr-w", "brief": f"Inspect {mr_ref} carefully"},
                        },
                    }
                )
                self.assertEqual(mr_res.get("decision"), "deny", (cwd_label, mr_ref, mr_res))
                self.assertIn("Rule 17", str(mr_res.get("reason", "")))

            for target_label, target_ref in external_ws_cust_targets:
                prompt_text = f"Review and align {target_ref} structure"
                with self.subTest(cwd=cwd_label, target=target_label):
                    self.assertTrue(
                        pre_tool_use._text_targets_customization(
                            prompt_text,
                            [self.knight_ws],
                            fallback_ws=self.knight_ws,
                            effective_cwd=self.knight_ws,
                        ),
                        (cwd_label, target_label, prompt_text),
                    )
                    for tool_name, args in (
                        ("swarm", {"action": "add", "name": "sec-w", "brief": prompt_text}),
                        ("invoke_subagent", {"TypeName": "self", "Role": "Worker", "Prompt": prompt_text}),
                        ("post_message", {"channel": "board", "text": f"@worker {prompt_text}"}),
                        ("send_message", {"Recipient": "conv-sec", "Message": prompt_text}),
                        (
                            "define_subagent",
                            {
                                "Name": "sec-sub",
                                "Description": "Helper",
                                "SystemPrompt": prompt_text,
                                "EnableWriteTools": True,
                            },
                        ),
                        ("schedule", {"DurationSeconds": 120, "Prompt": prompt_text}),
                    ):
                        res = agy_hooks.handle_pre_tool_use(
                            self._hook_payload(
                                tool_name,
                                args,
                                ws=self.knight_ws,
                                model_name=NON_FLAGSHIP_MODEL,
                                effort="medium",
                                conv_id=f"conv-sec-{cwd_label}-{target_label}-{tool_name}",
                            )
                        )
                        self.assertEqual(
                            res.get("decision"),
                            "deny",
                            (cwd_label, target_label, tool_name, res),
                        )
                        self.assertIn(
                            "Rule 17",
                            str(res.get("reason", "")),
                            (cwd_label, target_label, tool_name, res),
                        )

            # Harness repository `SKILL.md`, `GEMINI.md`, `hooks.json`, `guard/`, and `skills/` references must still trigger Rule 17 deny
            for target_label, target_ref in harness_ws_cust_targets:
                prompt_text = f"Review and align {target_ref} structure"
                with self.subTest(cwd=cwd_label, harness_target=target_label):
                    self.assertTrue(
                        pre_tool_use._text_targets_customization(
                            prompt_text,
                            [self.harness_ws],
                            fallback_ws=self.harness_ws,
                            effective_cwd=self.harness_ws,
                        ),
                        (cwd_label, target_label, prompt_text),
                    )
                    res_h_target = agy_hooks.handle_pre_tool_use(
                        self._hook_payload(
                            "swarm",
                            {"action": "add", "name": "sec-h", "brief": prompt_text},
                            ws=self.harness_ws,
                            model_name=NON_FLAGSHIP_MODEL,
                            effort="medium",
                            conv_id=f"conv-sec-h-{cwd_label}-{target_label}",
                        )
                    )
                    self.assertEqual(res_h_target.get("decision"), "deny", (cwd_label, target_label, res_h_target))
                    self.assertIn("Rule 17", str(res_h_target.get("reason", "")))
            for h_label, h_ws in (("fixture_harness", self.harness_ws), ("repo_root", REPO_ROOT)):
                for h_ref in ("guard/hooks/pre_tool_use.py", "guard/", "skills/harness/notes.md", "skills/"):
                    h_prompt = f"Review {h_ref} invariants"
                    with self.subTest(cwd=cwd_label, harness=h_label, ref=h_ref):
                        self.assertTrue(
                            pre_tool_use._text_targets_customization(
                                h_prompt,
                                [h_ws],
                                fallback_ws=h_ws,
                                effective_cwd=h_ws,
                            ),
                            (cwd_label, h_label, h_ref),
                        )
                        for tool_name, args in (
                            ("swarm", {"action": "add", "name": "h-w", "brief": h_prompt}),
                            ("invoke_subagent", {"TypeName": "self", "Role": "Worker", "Prompt": h_prompt}),
                            ("post_message", {"channel": "board", "text": f"@worker {h_prompt}"}),
                            ("send_message", {"Recipient": "conv-h", "Message": h_prompt}),
                            (
                                "define_subagent",
                                {
                                    "Name": "h-sub",
                                    "Description": "Helper",
                                    "SystemPrompt": h_prompt,
                                    "EnableWriteTools": True,
                                },
                            ),
                            ("schedule", {"DurationSeconds": 120, "Prompt": h_prompt}),
                        ):
                            res_h = agy_hooks.handle_pre_tool_use(
                                self._hook_payload(
                                    tool_name,
                                    args,
                                    ws=h_ws,
                                    model_name=NON_FLAGSHIP_MODEL,
                                    effort="medium",
                                    conv_id=f"conv-h-{cwd_label}-{h_label}-{tool_name}",
                                )
                            )
                            self.assertEqual(
                                res_h.get("decision"),
                                "deny",
                                (cwd_label, h_label, h_ref, tool_name, res_h),
                            )
                            self.assertIn("Rule 17", str(res_h.get("reason", "")))

    def test_auditor_hardening_rule12_multiroot_workflow_windows_and_cwd_spoofing(self) -> None:
        cfg = agy_hooks.config_dir()
        rel_escape_custom = os.path.relpath(cfg / "custom_policy.yaml", self.knight_ws)
        rel_escape_ws2 = os.path.relpath(cfg / "custom_policy.yaml", self.second_ext_ws)
        root_clamped_escape = "../" * 16 + str(cfg / "custom_policy.yaml").lstrip("/")

        # 1. Non-absolute `base_dir` and relative `payload["cwd"]` never resolve against `os.getcwd()`
        self._chdir(cfg)
        self.assertFalse(pre_tool_use._targets_governance_dir("crates/ko-db", base_dir=Path(".")))
        self.assertFalse(pre_tool_use._targets_governance_dir("C:", base_dir=None))
        rel_cwd_res = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-rel-cwd",
                "modelName": NON_FLAGSHIP_MODEL,
                "effort": "medium",
                "cwd": ".",
                "toolCall": {
                    "name": "swarm",
                    "args": {"action": "add", "name": "monitor", "brief": MONITOR_BRIEF},
                },
            }
        )
        self.assertEqual(rel_cwd_res, {"decision": "allow"}, rel_cwd_res)

        # 2. Lowercase Windows drive URIs and Windows drive-less rooted paths
        fake_win_gov = Path("C:/Users/Runner/.gemini/config")
        with (
            mock.patch.object(pre_tool_use, "_governance_roots", return_value=[fake_win_gov]),
            mock.patch.object(pre_tool_use, "_config_root_candidates", return_value=[fake_win_gov]),
            mock.patch.object(pre_tool_use, "_state_root_candidates", return_value=[]),
        ):
            self.assertTrue(
                pre_tool_use._targets_governance_dir("file://c:/users/runner/.gemini/config/custom_policy.yaml")
            )
            self.assertFalse(
                pre_tool_use._targets_governance_dir("file://c:/users/runner/.gemini/config/sidecars/ok.json")
            )
            FakeRootedWinPath = type(
                "_FakeRootedWinPath",
                (),
                {
                    "is_absolute": lambda self: False,
                    "root": "\\",
                    "drive": "",
                    "__str__": lambda self: r"\Users\Runner\.gemini\config\custom_policy.yaml",
                },
            )
            FakeDriveRoot = type(
                "_FakeDriveRoot",
                (),
                {
                    "is_absolute": lambda self: False,
                    "drive": "C:",
                    "__str__": lambda self: "C:/Users/Runner/.gemini/config",
                },
            )
            orig_targets_gov = pre_tool_use._targets_governance_dir

            def _win_rooted_probe() -> bool:
                with mock.patch.object(pre_tool_use, "_governance_roots", return_value=[FakeDriveRoot()]):
                    seen_drives: list[str] = []
                    fake_exp = FakeRootedWinPath()
                    for r in pre_tool_use._governance_roots():
                        if r.drive and r.drive.upper() not in seen_drives:
                            seen_drives.append(r.drive.upper())
                            if orig_targets_gov(f"{r.drive}{fake_exp}"):
                                return True
                return False

            self.assertTrue(_win_rooted_probe())

        # 3. Switch to `unrelated_cwd` to verify workspace-relative Rule 12 & non-delegation negative controls
        self._chdir(self.unrelated_cwd)

        for r12_prompt in (
            f"Edit {rel_escape_custom} now",
            "Edit **~/.gemini/config/custom_policy.yaml** now",
            "Overwrite --config=~/.gemini/config/custom_policy.yaml",
            f"python3 -c \"from pathlib import Path; Path('{rel_escape_custom}').write_text('x')\"",
        ):
            res_r12 = agy_hooks.handle_pre_tool_use(
                self._hook_payload(
                    "swarm",
                    {"action": "add", "name": "mut-w", "brief": r12_prompt},
                    ws=self.knight_ws,
                    model_name=TOP_MODEL,
                    effort="high",
                )
            )
            self.assertEqual(res_r12.get("decision"), "deny", (r12_prompt, res_r12))
            self.assertIn("Rule 12", str(res_r12.get("reason", "")))

        # Root-clamping `..` traversal with `ws=None` must deny
        res_clamp_w = agy_hooks.handle_pre_tool_use(
            self._hook_payload(
                "write_file",
                {"Path": root_clamped_escape, "Content": "x"},
                ws=None,
                model_name=TOP_MODEL,
                effort="high",
            )
        )
        self.assertEqual(res_clamp_w.get("decision"), "deny", res_clamp_w)

        # `write_to_file`, `call_mcp_tool`, `run_command` (including `Path('.').parent`), and `run_workflow`
        for tool_name, args in (
            ("write_to_file", {"TargetFile": rel_escape_custom, "CodeContent": "x"}),
            (
                "call_mcp_tool",
                {
                    "ServerName": "rea_rea",
                    "ToolName": "inspect_rust_binary",
                    "Arguments": {"path": rel_escape_custom},
                },
            ),
            (
                "call_mcp_tool",
                {
                    "ServerName": "rea_rea",
                    "ToolName": "inspect_rust_binary",
                    "Arguments": {
                        "cmd": f"python3 -c \"from pathlib import Path; Path('{rel_escape_custom}').write_text('x')\""
                    },
                },
            ),
            (
                "run_command",
                {
                    "CommandLine": (
                        "python3 -c \"from pathlib import Path; "
                        "Path('.').parent.parent.joinpath('home/.gemini/config/custom_policy.yaml').write_text('x')\""
                    )
                },
            ),
            (
                "run_command",
                {
                    "CommandLine": (
                        "python3 -c \"from pathlib import Path; "
                        "Path.cwd().parent.parent.joinpath('home/.gemini/config/custom_policy.yaml').write_text('x')\""
                    )
                },
            ),
            (
                "run_workflow",
                {"Cwd": r"~\.gemini\config", "Script": "x = 1\n"},
            ),
        ):
            res_nd = agy_hooks.handle_pre_tool_use(
                self._hook_payload(tool_name, args, ws=self.knight_ws, model_name=TOP_MODEL, effort="high")
            )
            self.assertEqual(res_nd.get("decision"), "deny", (tool_name, args, res_nd))

        # 4. `run_workflow` with `ws=None` fails closed on `guard/` agent, relative `Cwd`/`ScriptPath`, and `payload["Cwd"]`
        for wf_payload in (
            self._hook_payload(
                "run_workflow",
                {"Script": "out = await agent('Modify guard/hooks/pre_tool_use.py', model='flash')\n"},
                ws=None,
                model_name=TOP_MODEL,
                effort="high",
            ),
            self._hook_payload(
                "run_workflow",
                {"Cwd": "rel_sub", "Script": "x = 1\n"},
                ws=None,
                model_name=TOP_MODEL,
                effort="high",
            ),
            self._hook_payload(
                "run_workflow",
                {"ScriptPath": "rel_script.py"},
                ws=None,
                model_name=TOP_MODEL,
                effort="high",
            ),
            {
                "conversationId": "conv-wf-pcwd",
                "modelName": TOP_MODEL,
                "effort": "high",
                "Cwd": str(cfg),
                "toolCall": {"name": "run_workflow", "args": {"Script": "x = 1\n"}},
            },
            {
                "conversationId": "conv-wf-mr-gov",
                "modelName": TOP_MODEL,
                "effort": "high",
                "workspacePaths": [str(self.knight_ws), str(self.second_ext_ws)],
                "toolCall": {
                    "name": "run_workflow",
                    "args": {
                        "Script": f"call_tool('write_file', Path={rel_escape_ws2!r}, Content='x')\n"
                    },
                },
            },
            {
                "conversationId": "conv-wf-mr-cust",
                "modelName": NON_FLAGSHIP_MODEL,
                "effort": "medium",
                "workspacePaths": [str(self.knight_ws), str(self.harness_ws)],
                "toolCall": {
                    "name": "run_workflow",
                    "args": {
                        "Script": "call_tool('write_file', Path='guard/agy_hooks.py', Content='x')\n"
                    },
                },
            },
        ):
            res_wf = agy_hooks.handle_pre_tool_use(wf_payload)
            self.assertEqual(res_wf.get("decision"), "deny", (wf_payload, res_wf))

        # 5. Multi-root MCP target resolution, CWD-key spoofing/conflict defenses, and governance-workspace pathless prompts
        res_mcp_mr = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-mcp-mr",
                "modelName": NON_FLAGSHIP_MODEL,
                "effort": "medium",
                "workspacePaths": [str(self.knight_ws), str(self.harness_ws)],
                "toolCall": {
                    "name": "call_mcp_tool",
                    "args": {
                        "ServerName": "fs",
                        "ToolName": "write_file",
                        "Arguments": {"path": "guard/agy_hooks.py", "content": "# x"},
                    },
                },
            }
        )
        self.assertEqual(res_mcp_mr.get("decision"), "deny", res_mcp_mr)

        res_spoof_write = agy_hooks.handle_pre_tool_use(
            self._hook_payload(
                "write_file",
                {"Path": "guard/hooks/pre_tool_use.py", "Content": "# x", "cwd": str(self.unrelated_cwd)},
                ws=self.harness_ws,
                model_name=NON_FLAGSHIP_MODEL,
                effort="medium",
            )
        )
        self.assertEqual(res_spoof_write.get("decision"), "deny", res_spoof_write)

        res_spoof_input = agy_hooks.handle_pre_tool_use(
            self._hook_payload(
                "send_command_input",
                {"Input": f"echo x > {rel_escape_custom}\n", "cwd": str(self.unrelated_cwd)},
                ws=self.knight_ws,
                model_name=TOP_MODEL,
                effort="high",
            )
        )
        self.assertEqual(res_spoof_input.get("decision"), "deny", res_spoof_input)

        res_conflict_cwd = agy_hooks.handle_pre_tool_use(
            self._hook_payload(
                "run_command",
                {"CommandLine": "echo ok", "cwd": str(self.knight_ws), "Cwd": str(cfg)},
                ws=self.knight_ws,
                model_name=TOP_MODEL,
                effort="high",
            )
        )
        self.assertEqual(res_conflict_cwd.get("decision"), "deny", res_conflict_cwd)

        res_gov_ws_prompt = agy_hooks.handle_pre_tool_use(
            self._hook_payload(
                "invoke_subagent",
                {"TypeName": "self", "Role": "Cleaner", "Prompt": "Edit current policy rules"},
                ws=cfg,
                model_name=NON_FLAGSHIP_MODEL,
                effort="medium",
            )
        )
        self.assertEqual(res_gov_ws_prompt.get("decision"), "deny", res_gov_ws_prompt)


if __name__ == "__main__":
    unittest.main()
