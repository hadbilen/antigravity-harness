#!/usr/bin/env python3
"""Unit tests for skills/antislop/scripts/check_ui_slop.py."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import hermetic  # noqa: F401  (isolates HOME/state before anything else is imported)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "skills" / "antislop" / "scripts" / "check_ui_slop.py"

_spec = importlib.util.spec_from_file_location("check_ui_slop", SCRIPT)
cus = importlib.util.module_from_spec(_spec)
sys.modules["check_ui_slop"] = cus
_spec.loader.exec_module(cus)


CLEAN_UTILITY_UI = """\
<main class="max-w-5xl mx-auto py-8">
  <header class="border-b border-slate-200 pb-4">
    <h1 class="text-2xl font-semibold text-slate-900">Deployment Ledger</h1>
  </header>
  <section class="grid grid-cols-12 gap-6 pt-6">
    <div class="col-span-8">
      <table class="w-full text-left">
        <tbody>
          <tr class="border-b border-slate-200"><td>v2.4.1</td><td>Healthy</td></tr>
        </tbody>
      </table>
    </div>
    <aside class="col-span-4 border border-slate-200 rounded-lg bg-slate-50 p-4">
      <p class="text-sm text-slate-700">Active workers: 12</p>
      <a href="/workers" class="text-blue-700 underline">Inspect workers</a>
    </aside>
  </section>
</main>
"""

SLOP_BENTO_GRID = """\
<section class="grid grid-cols-3 gap-4">
  <div class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><h3>Fast</h3></div>
  <div class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><h3>Secure</h3></div>
  <div class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><h3>Scalable</h3></div>
</section>
"""

SLOP_NESTED_CARDS = """\
<div class="card rounded-xl border border-slate-200 bg-white p-6 shadow-md">
  <h2>Outer Panel</h2>
  <div class="rounded-lg border border-slate-300 bg-slate-50 p-4 shadow-sm">
    <p>Inner boxed card inside outer boxed card</p>
  </div>
</div>
"""


def rule_ids(text: str, **options) -> set:
    return {f.rule_id for f in cus.scan_text(text, **options).findings}


def run_cli(*args: str, stdin: str = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=30,
    )


class TestUiSlopRules(unittest.TestCase):
    def test_clean_utility_ui_has_zero_findings(self):
        report = cus.scan_text(CLEAN_UTILITY_UI, mode="utility")
        self.assertEqual(report.findings, [])

    def test_ui1_flags_three_cloned_sibling_cards(self):
        self.assertIn("UI-1", rule_ids(SLOP_BENTO_GRID))
        two_cards = "\n".join(SLOP_BENTO_GRID.splitlines()[:3] + ["</section>"])
        self.assertNotIn("UI-1", rule_ids(two_cards))

    def test_ui2_flags_nested_card_in_card_but_exempts_dialog_and_table(self):
        self.assertIn("UI-2", rule_ids(SLOP_NESTED_CARDS))
        jsx_arrow_nested = """\
        <div onClick={() => select(id)} className="card rounded-xl border bg-zinc-900 p-6">
          <div onClick={() => open(id)} className="card rounded-lg border bg-zinc-800 p-4">Nested JSX</div>
        </div>
        """
        self.assertIn("UI-2", rule_ids(jsx_arrow_nested))

        exempt_role_dialog = """\
        <div class="rounded-xl border border-slate-200 bg-white p-6 shadow-md">
          <div role="dialog" class="rounded-lg border border-slate-300 bg-white p-4 shadow-lg">
            <p>Dialog role is exempt.</p>
          </div>
        </div>
        """
        exempt_table_ancestor = """\
        <div class="card rounded-xl border border-slate-200 bg-white p-6 shadow-md">
          <table><tbody><tr><td>
            <div class="card rounded-lg border border-slate-300 bg-slate-50 p-2">Cell badge box</div>
          </td></tr></tbody></table>
        </div>
        """
        exempt_draggable = """\
        <div class="card rounded-xl border border-slate-200 bg-white p-6 shadow-md">
          <div draggable="true" class="card rounded-lg border border-slate-300 bg-slate-50 p-3">Kanban token</div>
        </div>
        """
        self.assertNotIn("UI-2", rule_ids(exempt_role_dialog))
        self.assertNotIn("UI-2", rule_ids(exempt_table_ancestor))
        self.assertNotIn("UI-2", rule_ids(exempt_draggable))

    def test_ui3_flags_purple_gradient_excess_blur_and_decorative_bounce(self):
        gradient = '<div class="bg-gradient-to-r from-purple-500 to-pink-500">Hero</div>'
        css_gradient = ".hero { background: linear-gradient(135deg, #8b5cf6, #ec4899); }"
        self.assertIn("UI-3", rule_ids(gradient))
        self.assertIn("UI-3", rule_ids(css_gradient))

        two_blurs = '<nav class="backdrop-blur-md"></nav><aside class="backdrop-blur-sm"></aside>'
        three_blurs = two_blurs + '<footer class="backdrop-blur-lg"></footer>'
        self.assertNotIn("UI-3", rule_ids(two_blurs))
        self.assertIn("UI-3", rule_ids(three_blurs))

        decorative_bounce = '<span class="animate-bounce">New!</span>'
        status_bounce = '<span role="status" aria-busy="true" class="animate-ping">Loading</span>'
        self.assertIn("UI-3", rule_ids(decorative_bounce, mode="utility"))
        self.assertNotIn("UI-3", rule_ids(status_bounce, mode="utility"))
        self.assertNotIn("UI-3", rule_ids(decorative_bounce, mode="game"))

    def test_ui4_flags_raw_rgb_primaries_in_game_and_canvas_modes(self):
        canvas_snippet = """\
        <canvas id="stage" width="800" height="600"></canvas>
        <script>
          const ctx = document.getElementById("stage").getContext("2d");
          ctx.fillStyle = "#ff0000";
          ctx.strokeStyle = "#00ff00";
        </script>
        """
        self.assertIn("UI-4", rule_ids(canvas_snippet, mode="auto"))
        self.assertNotIn("UI-4", rule_ids(canvas_snippet, mode="utility"))
        self.assertIn("UI-4", rule_ids('<div style="color: #0000ff">HP</div>', mode="game"))
        self.assertNotIn("UI-4", rule_ids('<div style="color: #0000ff">Link</div>', mode="utility"))
        calibrated_game = '<canvas id="stage"></canvas><script>ctx.fillStyle = "#e11d48";</script>'
        self.assertNotIn("UI-4", rule_ids(calibrated_game, mode="game"))

    def test_ui5_flags_dead_links_and_noop_click_handlers(self):
        self.assertIn("UI-5", rule_ids('<a href="#"> Pricing </a>'))
        self.assertIn("UI-5", rule_ids('<a href="javascript:void(0)">Settings</a>'))
        self.assertIn("UI-5", rule_ids("<button onClick={() => {}}>Save</button>"))
        self.assertNotIn("UI-5", rule_ids('<a href="/pricing">Pricing</a><button onClick={save}>Save</button>'))


class TestUiSlopCli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="agy_ui_slop_")
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name: str, text: str) -> Path:
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_cli_exit_codes_and_modes(self):
        clean_path = self.write("clean.html", CLEAN_UTILITY_UI)
        slop_path = self.write("slop.html", SLOP_BENTO_GRID)
        self.write("ignore.py", 'href="#"')
        self.assertEqual(run_cli(str(clean_path)).returncode, 0)
        self.assertEqual(run_cli("--mode", "auto", str(clean_path)).returncode, 0)
        self.assertEqual(run_cli(str(slop_path)).returncode, 1)
        self.assertEqual(run_cli("--mode", "game", "-", stdin='<div style="color: #0000ff">HP</div>').returncode, 1)
        self.assertEqual(run_cli("--mode", "utility", "-", stdin='<div style="color: #0000ff">HP</div>').returncode, 0)
        self.assertEqual(run_cli(str(self.tmp / "missing.html")).returncode, 2)
        self.assertEqual(run_cli("--json", "--summary", str(clean_path)).returncode, 2)

        dir_res = run_cli("--json", str(self.tmp))
        dir_data = json.loads(dir_res.stdout)
        self.assertEqual(sorted(Path(f["path"]).name for f in dir_data["files"]), ["clean.html", "slop.html"])

    def test_cli_json_and_summary_outputs(self):
        res_json = run_cli("--json", "-", stdin=SLOP_NESTED_CARDS)
        self.assertEqual(res_json.returncode, 1)
        payload = json.loads(res_json.stdout)
        self.assertEqual(payload["total_findings"], 1)
        self.assertEqual(payload["files"][0]["findings"][0]["rule_id"], "UI-2")

        res_sum_fail = run_cli("--summary", "-", stdin=SLOP_NESTED_CARDS)
        self.assertEqual(res_sum_fail.returncode, 1)
        self.assertIn("Status: FAIL (Action Required)", res_sum_fail.stdout)
        self.assertIn("UI-2", res_sum_fail.stdout)

        res_sum = run_cli("--summary", "-", stdin=CLEAN_UTILITY_UI)
        self.assertEqual(res_sum.returncode, 0)
        self.assertIn("Status: PASS", res_sum.stdout)

    def test_game_engineering_skill_and_hook_routing(self):
        from guard.agy_hooks import SKILL_HINTS

        game_entries = [entry for entry in SKILL_HINTS if entry[0] == "game-engineering"]
        self.assertEqual(len(game_entries), 1)
        _, rel_path, pattern, _ = game_entries[0]
        self.assertTrue((REPO_ROOT / rel_path).is_file())
        self.assertIsNotNone(pattern.search("Let's build a canvas game with a fixed timestep game loop"))
        self.assertIsNotNone(pattern.search("2B bir canvas oyun geliştirme ve fizik döngüsü kuralım"))
        self.assertIsNone(pattern.search("Update the PostgreSQL database migration schema"))


if __name__ == "__main__":
    unittest.main()
