"""
tests/test_marathon_campaign_isolation.py: Hermetic seam suite for Marathon Campaign Isolation
and Stale Ledger Reset (`Campaign: 2026-11-18-marathon-campaign-isolation`, `AC-1..AC-4`).
"""

from __future__ import annotations

import os
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

import hermetic  # noqa: E402  # must precede repository imports per ADR-0010

from guard import agy_hooks  # noqa: E402


def _injected_text(resp: dict) -> str:
    parts: list[str] = []
    if isinstance(resp.get("additionalContext"), str):
        parts.append(resp["additionalContext"])
    steps = resp.get("injectSteps")
    if isinstance(steps, list):
        for step in steps:
            if isinstance(step, dict):
                sm = step.get("systemMessage")
                if isinstance(sm, dict):
                    for key in ("systemMessage", "message"):
                        val = sm.get(key)
                        if isinstance(val, str):
                            parts.append(val)
                elif isinstance(sm, str):
                    parts.append(sm)
    return "\n".join(parts)


class HermeticCampaignIsolationCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-campaign-iso-")
        self.tmp = Path(self._tmp.name)
        self.cfg_dir = self.tmp / "config"
        self.state_dir = self.tmp / "state"
        self.data_dir = self.tmp / "data"
        self.ws_dir = self.tmp / "workspace"
        for d in (self.cfg_dir, self.state_dir, self.data_dir, self.ws_dir):
            d.mkdir(parents=True, exist_ok=True)
        (self.cfg_dir / "GEMINI.md").write_text("# Hermetic Constitution\n", encoding="utf-8")
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.tmp),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
                "PLUMB_GUARD_STATE_DIR": str(self.state_dir),
                "ANTIGRAVITY_STATE_DIR": str(self.state_dir),
                "PLUMB_GUARD_DATA_DIR": str(self.data_dir),
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        hermetic.force_rmtree(self.tmp)
        self._tmp.cleanup()

    def _init_git_repo(self, ws: Path) -> str:
        ws.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(ws)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(ws), "config", "user.email", "tester@example.com"], check=True)
        subprocess.run(["git", "-C", str(ws), "config", "user.name", "Tester"], check=True)
        tests_dir = ws / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        (tests_dir / "test_alpha.py").write_text(
            "import unittest\n\nclass TestAlpha(unittest.TestCase):\n    def test_one(self):\n        self.assertEqual(1, 1)\n",
            encoding="utf-8",
        )
        (tests_dir / "test_beta.py").write_text(
            "import unittest\n\nclass TestBeta(unittest.TestCase):\n    def test_two(self):\n        self.assertEqual(2, 2)\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(ws), "add", "."], check=True)
        subprocess.run(["git", "-C", str(ws), "commit", "-m", "initial commit"], check=True, capture_output=True)
        head = subprocess.run(
            ["git", "-C", str(ws), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        return head.stdout.strip()


class TestAC1CampaignTemplateAndMarathonContract(unittest.TestCase):
    def test_handoff_template_and_marathon_skill_define_campaign_isolation_and_pass_antislop(self) -> None:
        template_path = REPO_ROOT / "templates" / "HANDOFF.template.md"
        marathon_path = REPO_ROOT / "skills" / "harness" / "references" / "marathon.md"
        scanner_path = REPO_ROOT / "skills" / "ui-refinery" / "scripts" / "check_synthetic_markers.py"

        template_text = template_path.read_text(encoding="utf-8")
        marathon_text = marathon_path.read_text(encoding="utf-8")

        self.assertIn("**Campaign ID:** {{YYYY-MM-DD-<topic-slug>}}", template_text)
        self.assertIn("[Campaign:", template_text)
        self.assertNotIn("\u2014", template_text)

        self.assertIn("Campaign ID", marathon_text)
        self.assertIn("[Campaign:", marathon_text)
        self.assertIn("[COMPLETE]", marathon_text)
        self.assertIn("W1", marathon_text)
        self.assertRegex(marathon_text, r"W\(?n\+1\)?")

        proc = subprocess.run(
            [
                sys.executable,
                str(scanner_path),
                "--profile",
                "technical",
                str(template_path),
                str(marathon_path),
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"Synthetic marker scan failed:\n{proc.stdout}\n{proc.stderr}")


class TestAC2PreToolUseSafeStaleAuthReset(HermeticCampaignIsolationCase):
    def _stale_tasks_text(self) -> str:
        return (
            "# Campaign: `2026-11-16-old-campaign`\n\n"
            "- [x] `AC-1`: Done\n\n"
            "## Authorized Test Modifications\n"
            "- `tests/test_alpha.py`: Authorized in old campaign.\n"
            "- `tests/test_beta.py`: Authorized in old campaign.\n"
        )

    def _fresh_tasks_without_auth(self) -> str:
        return (
            "# Campaign: `2026-11-18-new-campaign`\n\n"
            "**Campaign ID:** `2026-11-18-new-campaign`\n\n"
            "- [ ] `AC-1`: Implement fresh feature\n"
        )

    def _fresh_tasks_with_empty_auth(self) -> str:
        return (
            "# Campaign: `2026-11-18-new-campaign`\n\n"
            "**Campaign ID:** `2026-11-18-new-campaign`\n\n"
            "- [ ] `AC-1`: Implement fresh feature\n\n"
            "## Authorized Test Modifications\n"
            "- None\n"
        )

    def _pre_tool_write_tasks(self, ws: Path, content: str) -> dict:
        return agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-ac2",
                "workspace": str(ws),
                "cwd": str(ws),
                "toolCall": {
                    "name": "write_file",
                    "args": {
                        "Path": str(ws / "tasks.md"),
                        "Content": content,
                        "Overwrite": True,
                    },
                },
            }
        )

    def test_clean_reset_allowed_when_handoff_complete_or_absent_and_old_auth_clean(self) -> None:
        head_oid = self._init_git_repo(self.ws_dir)
        (self.ws_dir / "tasks.md").write_text(self._stale_tasks_text(), encoding="utf-8")
        (self.ws_dir / "HANDOFF.md").write_text(
            "# Session Handoff Document\n\n"
            "**Campaign ID:** `2026-11-16-old-campaign`\n"
            "**Status:** [COMPLETE]\n"
            f"**Git Branch / Commit:** `main` @ `{head_oid[:7]}`\n",
            encoding="utf-8",
        )

        # 1. Full write omitting ## Authorized Test Modifications -> allow
        res_omit = self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth())
        self.assertEqual(res_omit, {"decision": "allow"})

        # 2. Full write with empty `None` ## Authorized Test Modifications -> allow
        res_empty = self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_with_empty_auth())
        self.assertEqual(res_empty, {"decision": "allow"})

        # 3. Targeted edit_file clearing the bullets -> allow
        res_edit = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-ac2-edit",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "toolCall": {
                    "name": "edit_file",
                    "args": {
                        "Path": str(self.ws_dir / "tasks.md"),
                        "Target": (
                            "## Authorized Test Modifications\n"
                            "- `tests/test_alpha.py`: Authorized in old campaign.\n"
                            "- `tests/test_beta.py`: Authorized in old campaign.\n"
                        ),
                        "Replacement": "## Authorized Test Modifications\n- None\n",
                    },
                },
            }
        )
        self.assertEqual(res_edit, {"decision": "allow"})

        # 4. HANDOFF.md absent on disk while old_auth tests remain clean in git -> allow
        (self.ws_dir / "HANDOFF.md").unlink()
        res_absent = self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth())
        self.assertEqual(res_absent, {"decision": "allow"})

    def test_dirty_tests_in_progress_handoff_new_auth_and_nongit_fail_closed(self) -> None:
        head_oid = self._init_git_repo(self.ws_dir)
        (self.ws_dir / "tasks.md").write_text(self._stale_tasks_text(), encoding="utf-8")

        # 1. HANDOFF.md is [IN-PROGRESS] (even with a fenced code block mentioning [COMPLETE]) -> force_ask
        (self.ws_dir / "HANDOFF.md").write_text(
            "# Session Handoff Document\n\n"
            "**Campaign ID:** `2026-11-18-active`\n"
            "**Status:** [IN-PROGRESS]\n"
            f"**Git Branch / Commit:** `main` @ `{head_oid[:7]}`\n\n"
            "```markdown\n**Status:** [COMPLETE]\n```\n",
            encoding="utf-8",
        )
        res_in_prog = self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth())
        self.assertEqual(res_in_prog.get("decision"), "force_ask")

        # 2. HANDOFF.md has unfilled template status -> force_ask
        (self.ws_dir / "HANDOFF.md").write_text(
            "# Session Handoff Document\n\n**Status:** {{[COMPLETE] | [IN-PROGRESS]}}\n",
            encoding="utf-8",
        )
        res_tmpl = self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth())
        self.assertEqual(res_tmpl.get("decision"), "force_ask")

        # 3. HANDOFF.md is [COMPLETE], but one of old_auth test files has uncommitted edits -> force_ask
        (self.ws_dir / "HANDOFF.md").write_text(
            "# Session Handoff Document\n\n**Status:** [COMPLETE]\n",
            encoding="utf-8",
        )
        beta_file = self.ws_dir / "tests" / "test_beta.py"
        orig_beta = beta_file.read_text(encoding="utf-8")
        beta_file.write_text(orig_beta + "# uncommitted edit\n", encoding="utf-8")
        res_dirty = self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth())
        self.assertEqual(res_dirty.get("decision"), "force_ask")
        beta_file.write_text(orig_beta, encoding="utf-8")

        # 4. Adding a new test authorization or keeping partial authorization -> force_ask
        res_new_auth = self._pre_tool_write_tasks(
            self.ws_dir,
            "# Campaign: `2026-11-18-new`\n\n## Authorized Test Modifications\n- `tests/test_gamma.py`: sneaky\n",
        )
        self.assertEqual(res_new_auth.get("decision"), "force_ask")

        res_partial = self._pre_tool_write_tasks(
            self.ws_dir,
            "# Campaign: `2026-11-18-new`\n\n## Authorized Test Modifications\n- `tests/test_alpha.py`: partial\n",
        )
        self.assertEqual(res_partial.get("decision"), "force_ask")

        res_prose_new = self._pre_tool_write_tasks(
            self.ws_dir,
            "# Campaign: `2026-11-18-new`\n\n## Authorized Test Modifications\nAll test changes authorized\n",
        )
        self.assertEqual(res_prose_new.get("decision"), "force_ask")

        # 5. Old tasks.md had unparsed non-path prose under Authorized Test Modifications -> force_ask
        (self.ws_dir / "tasks.md").write_text(
            "# Old\n\n## Authorized Test Modifications\nAuthorize all suites broadly\n",
            encoding="utf-8",
        )
        res_unparsed_old = self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth())
        self.assertEqual(res_unparsed_old.get("decision"), "force_ask")

        # 6. Nested subdir/tasks.md inside git repo -> force_ask
        sub = self.ws_dir / "subdir"
        sub.mkdir(exist_ok=True)
        (sub / "tasks.md").write_text(self._stale_tasks_text(), encoding="utf-8")
        res_sub = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-sub",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "toolCall": {
                    "name": "write_file",
                    "args": {"Path": str(sub / "tasks.md"), "Content": self._fresh_tasks_without_auth()},
                },
            }
        )
        self.assertEqual(res_sub.get("decision"), "force_ask")

        # 7. Non-git workspace & fake empty `.git` directory -> force_ask
        nongit_ws = self.tmp / "nongit_ws"
        nongit_ws.mkdir()
        (nongit_ws / "tasks.md").write_text(self._stale_tasks_text(), encoding="utf-8")
        self.assertEqual(
            self._pre_tool_write_tasks(nongit_ws, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        (nongit_ws / ".git").mkdir()
        self.assertEqual(
            self._pre_tool_write_tasks(nongit_ws, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )

    def test_symlinks_unborn_head_linked_worktree_inline_auth_and_workflow_parity(self) -> None:
        head_oid = self._init_git_repo(self.ws_dir)
        (self.ws_dir / "HANDOFF.md").write_text(
            f"# Session Handoff Document\n\n**Status:** [COMPLETE]\n**Git Branch / Commit:** `main` @ `{head_oid[:7]}`\n",
            encoding="utf-8",
        )

        # 1. Inline heading format `## Authorized Test Modifications: [tests/test_alpha.py: reason]`
        (self.ws_dir / "tasks.md").write_text(
            "# Old\n\n## Authorized Test Modifications: [`tests/test_alpha.py`: prior inline]\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()),
            {"decision": "allow"},
        )

        # Unparsed inline tail fails closed
        (self.ws_dir / "tasks.md").write_text(
            "# Old\n\n## Authorized Test Modifications: `tests/test_alpha.py`: ok, ../outside.py: bad\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )

        # Restore clean stale tasks.md
        (self.ws_dir / "tasks.md").write_text(self._stale_tasks_text(), encoding="utf-8")

        # 2. Dual conflicting Status lines outside fences -> force_ask
        (self.ws_dir / "HANDOFF.md").write_text(
            "# Session Handoff Document\n\n**Status:** [COMPLETE]\n**Status:** [IN-PROGRESS]\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )

        # 3. Symlinked HANDOFF.md -> force_ask
        ext_handoff = self.tmp / "external_handoff.md"
        ext_handoff.write_text("# Session Handoff Document\n\n**Status:** [COMPLETE]\n", encoding="utf-8")
        (self.ws_dir / "HANDOFF.md").unlink()
        try:
            (self.ws_dir / "HANDOFF.md").symlink_to(ext_handoff)
            has_symlinks = True
        except OSError:
            has_symlinks = False
        if has_symlinks:
            self.assertEqual(
                self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
                "force_ask",
            )
            (self.ws_dir / "HANDOFF.md").unlink()

        (self.ws_dir / "HANDOFF.md").write_text(
            "# Session Handoff Document\n\n**Status:** [COMPLETE]\n",
            encoding="utf-8",
        )

        # 4. Symlinked tasks.md or symlinked old_auth test path -> force_ask
        if has_symlinks:
            ext_tasks = self.tmp / "external_tasks.md"
            ext_tasks.write_text(self._stale_tasks_text(), encoding="utf-8")
            (self.ws_dir / "tasks.md").unlink()
            (self.ws_dir / "tasks.md").symlink_to(ext_tasks)
            self.assertEqual(
                self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
                "force_ask",
            )
            (self.ws_dir / "tasks.md").unlink()
            (self.ws_dir / "tasks.md").write_text(self._stale_tasks_text(), encoding="utf-8")

            alpha_path = self.ws_dir / "tests" / "test_alpha.py"
            alpha_orig = alpha_path.read_text(encoding="utf-8")
            ext_alpha = self.tmp / "ext_alpha.py"
            ext_alpha.write_text(alpha_orig, encoding="utf-8")
            alpha_path.unlink()
            alpha_path.symlink_to(ext_alpha)
            self.assertEqual(
                self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
                "force_ask",
            )
            alpha_path.unlink()
            alpha_path.write_text(alpha_orig, encoding="utf-8")

        # 5. Staged edit & gitignored untracked file in old_auth -> force_ask
        beta_path = self.ws_dir / "tests" / "test_beta.py"
        beta_orig = beta_path.read_text(encoding="utf-8")
        beta_path.write_text(beta_orig + "# staged\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.ws_dir), "add", "tests/test_beta.py"], check=True)
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        subprocess.run(["git", "-C", str(self.ws_dir), "checkout", "HEAD", "--", "tests/test_beta.py"], check=True)

        (self.ws_dir / ".gitignore").write_text("tests/test_ignored.py\n", encoding="utf-8")
        (self.ws_dir / "tests" / "test_ignored.py").write_text("X = 1\n", encoding="utf-8")
        (self.ws_dir / "tasks.md").write_text(
            "# Old\n\n## Authorized Test Modifications\n- `tests/test_ignored.py`: ignored\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        (self.ws_dir / "tests" / "test_ignored.py").unlink()
        (self.ws_dir / ".gitignore").unlink()
        (self.ws_dir / "tasks.md").write_text(self._stale_tasks_text(), encoding="utf-8")

        # 6. Unborn HEAD (git init with zero commits) -> force_ask
        unborn_ws = self.tmp / "unborn_ws"
        unborn_ws.mkdir()
        subprocess.run(["git", "init", str(unborn_ws)], check=True, capture_output=True)
        (unborn_ws / "tasks.md").write_text(self._stale_tasks_text(), encoding="utf-8")
        self.assertEqual(
            self._pre_tool_write_tasks(unborn_ws, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )

        # 7. Linked git worktree (`workspace:"share"`) honors main_root HANDOFF.md [IN-PROGRESS] vs [COMPLETE]
        wt_dir = self.tmp / "linked_wt"
        subprocess.run(
            ["git", "-C", str(self.ws_dir), "worktree", "add", "-b", "wt-branch", str(wt_dir)],
            check=True,
            capture_output=True,
        )
        (wt_dir / "tasks.md").write_text(self._stale_tasks_text(), encoding="utf-8")
        (self.ws_dir / "HANDOFF.md").write_text(
            "# Session Handoff Document\n\n**Status:** [IN-PROGRESS]\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self._pre_tool_write_tasks(wt_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        (self.ws_dir / "HANDOFF.md").write_text(
            "# Session Handoff Document\n\n**Status:** [COMPLETE]\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self._pre_tool_write_tasks(wt_dir, self._fresh_tasks_without_auth()),
            {"decision": "allow"},
        )

        # 8. `run_workflow` static write_file parity (clean reset allowed; dirty test -> force_ask)
        wf_script = (
            f'call_tool("write_file", Path="{(self.ws_dir / "tasks.md").as_posix()}", '
            f'Content={self._fresh_tasks_without_auth()!r})\n'
        )
        res_wf_clean = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-wf-clean",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "toolCall": {"name": "run_workflow", "args": {"Script": wf_script, "Cwd": str(self.ws_dir)}},
            }
        )
        self.assertEqual(res_wf_clean, {"decision": "allow"})

        beta_path.write_text(beta_orig + "# dirty for wf\n", encoding="utf-8")
        res_wf_dirty = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-wf-dirty",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "toolCall": {"name": "run_workflow", "args": {"Script": wf_script, "Cwd": str(self.ws_dir)}},
            }
        )
        self.assertEqual(res_wf_dirty.get("decision"), "force_ask")
        beta_path.write_text(beta_orig, encoding="utf-8")

    def test_security_boundary_regressions_and_stop_gate_lifecycle(self) -> None:
        from guard.test_boundary import TestBoundaryGuard

        self._init_git_repo(self.ws_dir)
        tasks_file = self.ws_dir / "tasks.md"
        handoff_file = self.ws_dir / "HANDOFF.md"
        alpha_file = self.ws_dir / "tests" / "test_alpha.py"
        alpha_orig = alpha_file.read_text(encoding="utf-8")

        handoff_file.write_text("# Session Handoff Document\n\n**Status:** [COMPLETE]\n", encoding="utf-8")
        tasks_file.write_text(self._stale_tasks_text(), encoding="utf-8")

        # 1. Empty old_string / oldText, snake_case old_text/new_text, and missing-content args -> force_ask (`SBV-01`)
        for bad_args in (
            {"file_path": str(tasks_file), "old_string": "", "new_string": "## Authorized Test Modifications\n- tests/test_alpha.py\n"},
            {"Path": str(tasks_file), "oldText": "", "newText": "X"},
            {"Path": str(tasks_file), "old_text": "# Campaign: `2026-11-16-old-campaign`", "new_text": "## Authorized Test Modifications\n- tests/test_new.py: x"},
            {"Path": str(tasks_file)},
        ):
            res_bad = agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-sbv01",
                    "workspace": str(self.ws_dir),
                    "cwd": str(self.ws_dir),
                    "toolCall": {"name": "edit", "args": bad_args},
                }
            )
            self.assertEqual(res_bad.get("decision"), "force_ask", f"Expected force_ask for {bad_args!r}")

        # 2. Multi-chunk cross-overwrite (`SBV-02`) -> force_ask; clean non-overlapping multi-chunk reset -> allow
        tasks_file.write_text("## Tasks\n- tests/test_alpha.py\nPlaceholder\n", encoding="utf-8")
        res_cross = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-sbv02",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "toolCall": {
                    "name": "multi_replace_file_content",
                    "args": {
                        "TargetFile": str(tasks_file),
                        "ReplacementChunks": [
                            {
                                "StartLine": 3,
                                "EndLine": 3,
                                "TargetContent": "Placeholder",
                                "ReplacementContent": "## Authorized Test Modifications\n- tests/test_alpha.py",
                            },
                            {
                                "StartLine": 2,
                                "EndLine": 2,
                                "TargetContent": "- tests/test_alpha.py",
                                "ReplacementContent": "## Notes",
                            },
                        ],
                    },
                },
            }
        )
        self.assertEqual(res_cross.get("decision"), "force_ask")

        tasks_file.write_text(self._stale_tasks_text(), encoding="utf-8")
        res_clean_multi = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-sbv02-ok",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "toolCall": {
                    "name": "multi_replace_file_content",
                    "args": {
                        "TargetFile": str(tasks_file),
                        "ReplacementChunks": [
                            {"TargetContent": "2026-11-16-old-campaign", "ReplacementContent": "2026-11-18-clean"},
                            {
                                "TargetContent": "- `tests/test_alpha.py`: Authorized in old campaign.\n- `tests/test_beta.py`: Authorized in old campaign.\n",
                                "ReplacementContent": "- None\n",
                            },
                        ],
                    },
                },
            }
        )
        self.assertEqual(res_clean_multi, {"decision": "allow"})

        # 3. Dual-key shadowing (`Content` + `content`, and `ReplacementChunks` + `edits`, `SBV-03`) -> force_ask
        res_dual_content = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-sbv03",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "toolCall": {
                    "name": "write",
                    "args": {
                        "path": str(tasks_file),
                        "Content": self._fresh_tasks_without_auth(),
                        "content": "## Authorized Test Modifications\n- `tests/test_new.py`: hidden\n",
                    },
                },
            }
        )
        self.assertEqual(res_dual_content.get("decision"), "force_ask")

        res_dual_chunks = agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-sbv03-chunks",
                "workspace": str(self.ws_dir),
                "cwd": str(self.ws_dir),
                "toolCall": {
                    "name": "multiedit",
                    "args": {
                        "path": str(tasks_file),
                        "ReplacementChunks": [
                            {
                                "TargetContent": "- `tests/test_alpha.py`: Authorized in old campaign.\n- `tests/test_beta.py`: Authorized in old campaign.\n",
                                "ReplacementContent": "- None\n",
                            }
                        ],
                        "edits": [
                            {
                                "old_string": "- `tests/test_beta.py`: Authorized in old campaign.",
                                "new_string": "- `tests/test_new.py`: injected",
                            }
                        ],
                    },
                },
            }
        )
        self.assertEqual(res_dual_chunks.get("decision"), "force_ask")

        # 4. `run_workflow` two-step split `Append=True` & test-edit + tasks.md reset (`SBV-04`) -> force_ask
        tasks_file.unlink()
        wf_split = (
            f'call_tool("write_to_file", TargetFile="{tasks_file.as_posix()}", Content="## Authorized Test ")\n'
            f'call_tool("write_to_file", TargetFile="{tasks_file.as_posix()}", Content="Modifications\\n- tests/test_alpha.py\\n", Append=True)\n'
        )
        self.assertEqual(
            agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-sbv04-split",
                    "workspace": str(self.ws_dir),
                    "cwd": str(self.ws_dir),
                    "toolCall": {"name": "run_workflow", "args": {"Script": wf_split, "Cwd": str(self.ws_dir)}},
                }
            ).get("decision"),
            "force_ask",
        )
        tasks_file.write_text(self._stale_tasks_text(), encoding="utf-8")
        wf_combo = (
            f'call_tool("write_file", Path="{alpha_file.as_posix()}", Content="# mutated\\n")\n'
            f'call_tool("write_file", Path="{tasks_file.as_posix()}", Content={self._fresh_tasks_without_auth()!r})\n'
        )
        self.assertEqual(
            agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-sbv04-combo",
                    "workspace": str(self.ws_dir),
                    "cwd": str(self.ws_dir),
                    "toolCall": {"name": "run_workflow", "args": {"Script": wf_combo, "Cwd": str(self.ws_dir)}},
                }
            ).get("decision"),
            "force_ask",
        )

        # 5. `--literal-pathspecs` bracketed route `[id]` & `:!` exclude magic (`MA-01`, `SBV-05`) -> force_ask
        bracket_dir = self.ws_dir / "tests" / "[id]"
        bracket_dir.mkdir(parents=True, exist_ok=True)
        bracket_test = bracket_dir / "test_route.py"
        bracket_test.write_text("X = 1\n", encoding="utf-8")
        subprocess.run(["git", "--literal-pathspecs", "-C", str(self.ws_dir), "add", "tests/[id]/test_route.py"], check=True)
        subprocess.run(["git", "-C", str(self.ws_dir), "commit", "-m", "add bracket route test"], check=True, capture_output=True)
        tasks_file.write_text(
            "# Old\n\n## Authorized Test Modifications\n- `tests/[id]/test_route.py`: route\n",
            encoding="utf-8",
        )
        self.assertEqual(self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()), {"decision": "allow"})
        bracket_test.write_text("X = 2  # dirty\n", encoding="utf-8")
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        bracket_test.write_text("X = 1\n", encoding="utf-8")

        alpha_file.write_text(alpha_orig + "# dirty exclude\n", encoding="utf-8")
        tasks_file.write_text(
            "# Old\n\n## Authorized Test Modifications\n- `tests/test_alpha.py`: a\n- `:!tests/test_alpha.py`: magic\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        alpha_file.write_text(alpha_orig, encoding="utf-8")

        # 6. `git update-index --skip-worktree` & `--assume-unchanged` (`SBV-06`) -> force_ask
        tasks_file.write_text(self._stale_tasks_text(), encoding="utf-8")
        for set_flag, unset_flag in (
            ("--skip-worktree", "--no-skip-worktree"),
            ("--assume-unchanged", "--no-assume-unchanged"),
        ):
            subprocess.run(["git", "-C", str(self.ws_dir), "update-index", set_flag, "tests/test_alpha.py"], check=True)
            alpha_file.write_text(alpha_orig + "# hidden dirty\n", encoding="utf-8")
            try:
                self.assertEqual(
                    self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
                    "force_ask",
                )
            finally:
                subprocess.run(["git", "-C", str(self.ws_dir), "update-index", unset_flag, "tests/test_alpha.py"], check=True)
                alpha_file.write_text(alpha_orig, encoding="utf-8")

        # 7. Reverse linked worktree check (`SBV-07`): dirty/active linked worktree blocks resetting main_root/tasks.md
        wt_rev = self.tmp / "wt_reverse"
        subprocess.run(
            ["git", "-C", str(self.ws_dir), "worktree", "add", "-b", "wt-rev", str(wt_rev)],
            check=True,
            capture_output=True,
        )
        (wt_rev / "HANDOFF.md").write_text("# Handoff\n\n**Status:** [IN-PROGRESS]\n", encoding="utf-8")
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        (wt_rev / "HANDOFF.md").write_text("# Handoff\n\n**Status:** [COMPLETE]\n", encoding="utf-8")
        (wt_rev / "tests" / "test_alpha.py").write_text(alpha_orig + "# wt dirty\n", encoding="utf-8")
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        (wt_rev / "tests" / "test_alpha.py").write_text(alpha_orig, encoding="utf-8")
        self.assertEqual(self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()), {"decision": "allow"})

        # 8. Fence-only [COMPLETE] vs outer [COMPLETE]+fenced [IN-PROGRESS], BOM, oversized HANDOFF (`TA-02`, `TA-05`, `SBV-08`)
        handoff_file.write_text("# Draft\n\n```markdown\n**Status:** [COMPLETE]\n```\n", encoding="utf-8")
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        handoff_file.write_text("\ufeff**Status:** [IN-PROGRESS]\n\nHistory:\nStatus: [COMPLETE]\n", encoding="utf-8")
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        handoff_file.write_text("**Status:** [COMPLETE]\n" + ("x" * (513 * 1024)), encoding="utf-8")
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        handoff_file.write_text(
            "# Done\n\n- **Status**: [COMPLETE]\n\n```markdown\n**Status:** [IN-PROGRESS]\n```\n",
            encoding="utf-8",
        )
        self.assertEqual(self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()), {"decision": "allow"})

        # 9. Mixed old_text body: \u2028 + prose, traversal bullet, dash-prefixed, nested .git, HTML comment (`SBV-09`, `TA-03`, `TA-05`)
        for bad_old in (
            "# Old\u2028## Authorized Test Modifications\u2028- `tests/test_alpha.py`: ok\u2028Unparsed hold note\n",
            "# Old\n## Authorized Test Modifications\n- `tests/test_alpha.py`: ok\n- ../outside.py: bad\n",
            "# Old\n## Authorized Test Modifications\n- `-flag.py`: option\n",
        ):
            tasks_file.write_text(bad_old, encoding="utf-8")
            self.assertEqual(
                self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
                "force_ask",
            )
        nested_sub = self.ws_dir / "subrepo"
        (nested_sub / ".git").mkdir(parents=True, exist_ok=True)
        (nested_sub / "test_sub.py").write_text("S = 1\n", encoding="utf-8")
        tasks_file.write_text("# Old\n## Authorized Test Modifications\n- `subrepo/test_sub.py`: sub\n", encoding="utf-8")
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        hermetic.force_rmtree(nested_sub)

        tasks_file.write_text(
            "# Old\n## Authorized Test Modifications\n<!-- note -->\n- `tests/test_alpha.py`: ok\n",
            encoding="utf-8",
        )
        self.assertEqual(self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()), {"decision": "allow"})

        # 10. `file://` URI and percent-encoded `tasks%2Emd` (`SBV-10`)
        encoded_uri = f"file://{self.ws_dir.as_posix()}/tasks%2Emd"
        self.assertEqual(
            agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-uri-add",
                    "workspace": str(self.ws_dir),
                    "cwd": str(self.ws_dir),
                    "toolCall": {
                        "name": "write_file",
                        "args": {"Path": encoded_uri, "Content": "## Authorized Test Modifications\n- `tests/test_new.py`: uri\n"},
                    },
                }
            ).get("decision"),
            "force_ask",
        )
        self.assertEqual(
            agy_hooks.handle_pre_tool_use(
                {
                    "conversationId": "conv-uri-clean",
                    "workspace": str(self.ws_dir),
                    "cwd": str(self.ws_dir),
                    "toolCall": {"name": "write_file", "args": {"Path": encoded_uri, "Content": self._fresh_tasks_without_auth()}},
                }
            ),
            {"decision": "allow"},
        )

        # 11. `PreToolUse -> Stop` lifecycle with stored TestBoundaryGuard snapshot (`TA-01` & `SBV-11`)
        tasks_file.write_text("# Campaign 0 clean baseline\n", encoding="utf-8")
        tbg = TestBoundaryGuard(workspace_dir=self.ws_dir)
        tbg.snapshot()
        tasks_file.write_text(self._stale_tasks_text(), encoding="utf-8")
        alpha_file.write_text(
            "import unittest\n\nclass TestAlpha(unittest.TestCase):\n    def test_one(self):\n        self.assertEqual(2, 2)\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(self.ws_dir), "add", "tests/test_alpha.py"], check=True)
        subprocess.run(["git", "-C", str(self.ws_dir), "commit", "-m", "authorized contract update"], check=True, capture_output=True)
        # Snapshot predates the committed contract change -> PreToolUse fails closed so Stop cannot deadlock
        self.assertEqual(
            self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()).get("decision"),
            "force_ask",
        )
        # Once baseline snapshot is current, PreToolUse allows reset and handle_stop succeeds cleanly
        tbg.snapshot()
        self.assertEqual(self._pre_tool_write_tasks(self.ws_dir, self._fresh_tasks_without_auth()), {"decision": "allow"})
        tasks_file.write_text(self._fresh_tasks_without_auth(), encoding="utf-8")
        stop_res = agy_hooks.handle_stop(
            {
                "conversationId": "conv-uri-clean",
                "workspace": str(self.ws_dir),
                "terminationReason": "NO_TOOL_CALL",
                "lastAssistantMessage": "Reset stale tasks ledger cleanly.",
            }
        )
        self.assertEqual(stop_res, {})


class TestAC3PreInvocationCampaignAndStaleLedgerHint(HermeticCampaignIsolationCase):
    def test_clean_complete_workspace_stays_silent_even_when_head_advances(self) -> None:
        old_head = self._init_git_repo(self.ws_dir)
        (self.ws_dir / "HANDOFF.md").write_text(
            "# Session Handoff Document\n\n"
            "**Campaign ID:** `2026-11-16-finished`\n"
            "**Status:** [COMPLETE]\n"
            f"**Git Branch / Commit:** `main` @ `{old_head[:7]}`\n",
            encoding="utf-8",
        )
        (self.ws_dir / "tasks.md").write_text(
            "# Campaign: `2026-11-16-finished`\n- [x] `AC-1`: Completed\n",
            encoding="utf-8",
        )
        (self.ws_dir / "extra.py").write_text("VALUE = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.ws_dir), "add", "extra.py"], check=True)
        subprocess.run(
            ["git", "-C", str(self.ws_dir), "commit", "-m", "advance head"],
            check=True,
            capture_output=True,
        )

        res = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-clean-complete",
                "workspace": str(self.ws_dir),
                "prompt": "Fix a typo in README.",
            }
        )
        self.assertNotIn("[Harness Recovery & Continuity Gate]", _injected_text(res))

    def test_head_advanced_in_progress_and_complete_with_pending_surface_campaign_and_reset_rule(self) -> None:
        old_head = self._init_git_repo(self.ws_dir)
        (self.ws_dir / "HANDOFF.md").write_text(
            "# Session Handoff Document\n\n"
            "**Campaign ID:** `2026-11-16-adr-0010`\n"
            "**Status:** [IN-PROGRESS]\n"
            f"**Git Branch / Commit:** `main` @ `{old_head[:7]}`\n",
            encoding="utf-8",
        )
        (self.ws_dir / "tasks.md").write_text(
            "# Campaign: `2026-11-16-adr-0010`\n- [x] `AC-1`: Done\n- [ ] `AC-2`: Pending\n",
            encoding="utf-8",
        )
        (self.ws_dir / "next_commit.py").write_text("NEXT = True\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.ws_dir), "add", "next_commit.py"], check=True)
        subprocess.run(
            ["git", "-C", str(self.ws_dir), "commit", "-m", "post-handoff commit"],
            check=True,
            capture_output=True,
        )
        new_head = subprocess.run(
            ["git", "-C", str(self.ws_dir), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        res_stale = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-stale-inprog",
                "workspace": str(self.ws_dir),
                "prompt": "Start unrelated billing refactor.",
            }
        )
        msg_stale = _injected_text(res_stale)
        self.assertIn("[Harness Recovery & Continuity Gate]", msg_stale)
        self.assertIn("`HANDOFF.md` has `Status: [IN-PROGRESS]` (Campaign ID: `2026-11-16-adr-0010`)", msg_stale)
        self.assertIn("Stale ledger boundary: if ", msg_stale)
        self.assertIn(old_head[:7], msg_stale)
        self.assertIn(new_head[:8], msg_stale)
        self.assertIn("W1", msg_stale)
        self.assertIn("Campaign ID", msg_stale)

        # Case 2: HANDOFF.md is [COMPLETE], yet tasks.md still has leftover [ ] checkbox (same campaign)
        (self.ws_dir / "HANDOFF.md").write_text(
            "# Session Handoff Document\n\n"
            "**Campaign ID:** `2026-11-16-adr-0010`\n"
            "**Status:** [COMPLETE]\n"
            f"**Git Branch / Commit:** `main` @ `{new_head[:7]}`\n",
            encoding="utf-8",
        )
        res_leftover = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-complete-leftover",
                "workspace": str(self.ws_dir),
                "prompt": "Implement new CLI subcommand.",
            }
        )
        msg_leftover = _injected_text(res_leftover)
        self.assertIn("[Harness Recovery & Continuity Gate]", msg_leftover)
        self.assertIn("`HANDOFF.md` has `Status: [COMPLETE]` (Campaign ID: `2026-11-16-adr-0010`)", msg_leftover)
        self.assertIn("Stale ledger boundary: if ", msg_leftover)
        self.assertIn("1 `[ ]` pending", msg_leftover)
        self.assertIn("W1", msg_leftover)

        # Case 3: Non-git workspace with Campaign ID in tasks.md never mentions git status / git diff
        nongit_ws = self.tmp / "nongit_campaign_ws"
        nongit_ws.mkdir()
        (nongit_ws / "tasks.md").write_text(
            "**Campaign ID:** `2026-11-18-notes`\n- [ ] Finish summary\n",
            encoding="utf-8",
        )
        res_nongit = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-nongit-campaign",
                "workspace": str(nongit_ws),
                "prompt": "Outline a new project proposal.",
            }
        )
        msg_nongit = _injected_text(res_nongit)
        self.assertIn("[Harness Recovery & Continuity Gate]", msg_nongit)
        self.assertIn("active Campaign ID: `2026-11-18-notes`", msg_nongit)
        self.assertNotIn("Stale ledger boundary", msg_nongit)
        self.assertIn("W1", msg_nongit)
        self.assertNotIn("git status", msg_nongit)
        self.assertNotIn("git diff", msg_nongit)

        # Case 4: Matching short-SHA HEAD (not advanced) and fenced-code Campaign ID are not falsely flagged
        same_head_ws = self.tmp / "same_head_ws"
        same_head = self._init_git_repo(same_head_ws)
        (same_head_ws / "HANDOFF.md").write_text(
            "# Session Handoff Document\n\n"
            "**Status:** [IN-PROGRESS]\n"
            f"**Git Branch / Commit:** `main` @ `{same_head[:7]}`\n\n"
            "```markdown\n**Campaign ID:** `2026-01-01-spoofed`\n```\n",
            encoding="utf-8",
        )
        (same_head_ws / "tasks.md").write_text("- [ ] Continue active window\n", encoding="utf-8")
        res_same = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-same-head",
                "workspace": str(same_head_ws),
                "prompt": "Continue window.",
            }
        )
        msg_same = _injected_text(res_same)
        self.assertIn("[Harness Recovery & Continuity Gate]", msg_same)
        self.assertNotIn("has advanced past", msg_same)
        self.assertNotIn("Stale ledger boundary", msg_same)
        self.assertNotIn("2026-01-01-spoofed", msg_same)
        self.assertIn("W1", msg_same)

    def test_superseding_tasks_campaign_next_row_bom_and_crash_isolation(self) -> None:
        old_head = self._init_git_repo(self.ws_dir)

        # 1. Newer single-window Tier 2 `tasks.md` Campaign ID supersedes prior `[COMPLETE]` HANDOFF.md (`CA-02`)
        #    and `[ ] NEXT` table row triggers unfinished task detection (`CA-03`)
        (self.ws_dir / "HANDOFF.md").write_text(
            "\ufeff# Session Handoff Document\n\n"
            "- **Campaign ID:** `2026-11-15-old-marathon`\n"
            "- **Status:** [COMPLETE]\n"
            f"- **Git Branch / Commit:** `main` @ `{old_head[:7]}`\n",
            encoding="utf-8",
        )
        (self.ws_dir / "tasks.md").write_text(
            "**Campaign ID:** `2026-11-18-tier2-slice`\n\n"
            "| Window | Scope | Status |\n"
            "| :--- | :--- | :--- |\n"
            "| `W1` | Implement slice | `[ ] NEXT` |\n",
            encoding="utf-8",
        )
        res_tier2 = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-tier2-supersede",
                "workspace": str(self.ws_dir),
                "prompt": "Continue working on the slice.",
            }
        )
        msg_tier2 = _injected_text(res_tier2)
        self.assertIn("active Campaign ID: `2026-11-18-tier2-slice`", msg_tier2)
        self.assertNotIn("2026-11-15-old-marathon", msg_tier2)
        self.assertNotIn("Stale ledger boundary", msg_tier2)
        self.assertIn("1 `[ ] NEXT` window(s)", msg_tier2)

        # 2. Active `[IN-PROGRESS]` HANDOFF.md Campaign ID takes precedence over stale tasks.md Campaign ID,
        #    and 200 KiB newline-padded BOM HANDOFF.md scans in linear time (`SBV-08`, `TA-04`)
        (self.ws_dir / "HANDOFF.md").write_text(
            "\ufeff" + ("\n" * (200 * 1024))
            + "- **Campaign ID**: `2026-11-18-handoff-wins`\n"
            + "- **Status**: [IN-PROGRESS]\n",
            encoding="utf-8",
        )
        res_prec = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-handoff-wins",
                "workspace": str(self.ws_dir),
                "prompt": "Resume handoff.",
            }
        )
        msg_prec = _injected_text(res_prec)
        self.assertIn("`HANDOFF.md` has `Status: [IN-PROGRESS]` (Campaign ID: `2026-11-18-handoff-wins`)", msg_prec)

        # 3. Pure `in_flight` crash without `HANDOFF.md` or `tasks.md` omits ledger reset text (`TA-04`)
        crash_ws = self.tmp / "pure_crash_ws"
        self._init_git_repo(crash_ws)
        agy_hooks.handle_pre_tool_use(
            {
                "conversationId": "conv-crash-only",
                "workspace": str(crash_ws),
                "toolCall": {"name": "write_file", "args": {"Path": str(crash_ws / "app.py"), "Content": "Z = 1\n"}},
            }
        )
        res_crash = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-crash-only",
                "workspace": str(crash_ws),
                "prompt": "devam et",
            }
        )
        msg_crash = _injected_text(res_crash)
        self.assertIn("[Harness Recovery & Continuity Gate]", msg_crash)
        self.assertNotIn("reset `tasks.md`", msg_crash)


if __name__ == "__main__":
    unittest.main()
