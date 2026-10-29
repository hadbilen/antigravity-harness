#!/usr/bin/env python3
"""
tests/test_code_map.py — Unit tests for scripts/code_map.py at public API and CLI seams.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scripts.code_map import (
    compute_blast_radius,
    find_callers,
    fts_search,
    gate_syntax,
    main,
    profile_symbol,
    trace_data_flow,
    trace_runtime,
)


class TestCodeMapSeams(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-codemap-")
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_find_callers_ignores_comments_and_string_literals(self) -> None:
        """Catches false-positive caller matches inside comments or docstrings that trip raw grep."""
        src = self.root / "service.py"
        src.write_text(
            '"""Module docstring mentioning charge_card(100) in prose."""\n'
            "# Comment mentioning charge_card(200)\n"
            "def charge_card(amount: int) -> bool:\n"
            '    msg = "charge_card(300) should not match"\n'
            "    return amount > 0\n\n"
            "def checkout(total: int) -> bool:\n"
            "    return charge_card(total)\n",
            encoding="utf-8",
        )
        callers = find_callers("charge_card", [self.root], base_dir=self.root)
        self.assertEqual(len(callers), 1)
        self.assertEqual(callers[0]["enclosing_scope"], "checkout")
        self.assertEqual(callers[0]["line"], 8)
        self.assertEqual(callers[0]["args"], ["total"])

    def test_profile_symbol_resolves_definitions_subclasses_and_callees(self) -> None:
        """Catches missing class inheritance or callee links in symbol profiles."""
        src = self.root / "models.py"
        src.write_text(
            "class BaseValidator:\n"
            "    def validate(self, payload: dict) -> bool:\n"
            "        return check_schema(payload)\n\n"
            "class StrictValidator(BaseValidator):\n"
            "    pass\n\n"
            "def check_schema(data: dict) -> bool:\n"
            "    return bool(data)\n",
            encoding="utf-8",
        )
        prof = profile_symbol("BaseValidator", [self.root], base_dir=self.root)
        self.assertEqual(len(prof["definitions"]), 1)
        self.assertEqual(prof["definitions"][0]["kind"], "class")
        self.assertEqual([s["name"] for s in prof["subclasses"]], ["StrictValidator"])

        method_prof = profile_symbol("BaseValidator.validate", [self.root], base_dir=self.root)
        self.assertEqual(len(method_prof["definitions"]), 1)
        self.assertIn("check_schema", method_prof["definitions"][0]["callees"])

    def test_trace_data_flow_captures_backflow_origins_and_forwardflow_uses(self) -> None:
        """Catches broken backward argument origin tracking or forward return-value consumer tracking."""
        src = self.root / "pipeline.py"
        src.write_text(
            "def sanitize_token(raw: str) -> str:\n"
            "    return raw.strip()\n\n"
            "def handle_request(header: str) -> str:\n"
            "    candidate = header.removeprefix('Bearer ')\n"
            "    clean_tok = sanitize_token(candidate)\n"
            "    audit_record = f'used:{clean_tok}'\n"
            "    return audit_record\n",
            encoding="utf-8",
        )
        flow = trace_data_flow("sanitize_token", [self.root], base_dir=self.root)
        self.assertEqual(flow["call_site_count"], 1)
        back = flow["backflow"][0]
        self.assertEqual(back["enclosing_scope"], "handle_request")
        self.assertIn("candidate", back["arg_origins"])
        self.assertTrue(any("header.removeprefix" in orig for orig in back["arg_origins"]["candidate"]))

        fwd = flow["forwardflow"][0]
        self.assertEqual(fwd["assigned_to"], "clean_tok")
        self.assertFalse(fwd["returned_directly"])
        self.assertTrue(any("audit_record" in use for use in fwd["subsequent_uses"]))

    def test_blast_radius_escalates_tier_when_more_than_eight_files_affected(self) -> None:
        """Catches drift between blast-radius tier classification and GEMINI.md's >8 files Tier 3 rule."""
        (self.root / "core.py").write_text(
            "def parse_token(val: str) -> str:\n    return val\n",
            encoding="utf-8",
        )
        for idx in range(1, 3):
            (self.root / f"caller_{idx}.py").write_text(
                f"from core import parse_token\ndef run_{idx}():\n    return parse_token('x')\n",
                encoding="utf-8",
            )
        tier2 = compute_blast_radius("parse_token", [self.root], base_dir=self.root)
        self.assertEqual(tier2["affected_file_count"], 3)
        self.assertEqual(tier2["tier_recommendation"], "Tier 2")

        for idx in range(3, 10):
            (self.root / f"test_caller_{idx}.py").write_text(
                f"from core import parse_token\ndef test_{idx}():\n    assert parse_token('x') == 'x'\n",
                encoding="utf-8",
            )
        tier3 = compute_blast_radius("parse_token", [self.root], base_dir=self.root)
        self.assertEqual(tier3["affected_file_count"], 10)
        self.assertEqual(tier3["tier_recommendation"], "Tier 3")
        self.assertEqual(len(tier3["affected_test_files"]), 7)

    def test_gate_syntax_validates_python_json_and_svg_entities(self) -> None:
        """Catches unvalidated syntax errors or XML external entity declarations passing the syntax gate."""
        good_py = self.root / "ok.py"
        good_py.write_text("x = 1 + 2\n", encoding="utf-8")
        bad_py = self.root / "broken.py"
        bad_py.write_text("def broken(:\n    pass\n", encoding="utf-8")
        bad_svg = self.root / "xxe.svg"
        bad_svg.write_text('<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg/>', encoding="utf-8")

        ok_res = gate_syntax([good_py], base_dir=self.root)
        self.assertTrue(ok_res["passed"])
        self.assertEqual(ok_res["errors"], [])

        fail_res = gate_syntax([bad_py, bad_svg], base_dir=self.root)
        self.assertFalse(fail_res["passed"])
        self.assertEqual(len(fail_res["errors"]), 2)

        missing_res = gate_syntax([self.root / "nonexistent.py"], base_dir=self.root)
        self.assertFalse(missing_res["passed"])

    def test_trace_runtime_records_calls_inside_comprehensions_and_lambdas(self) -> None:
        """Catches runtime tracer missing calls executed inside list comprehensions or lambdas."""
        script = self.root / "repro.py"
        script.write_text(
            "def double(n: int) -> int:\n"
            "    return n * 2\n\n"
            "def compute(items: list[int]) -> list[int]:\n"
            "    mapper = lambda v: double(v)\n"
            "    return [mapper(x) for x in items]\n\n"
            "if __name__ == '__main__':\n"
            "    compute([3, 5])\n",
            encoding="utf-8",
        )
        trace = trace_runtime(script, root_dir=self.root)
        self.assertIsNone(trace["error"])
        double_calls = [
            e for e in trace["events"]
            if e["event"] == "call" and e["callee"] == "double"
        ]
        self.assertEqual(len(double_calls), 2)
        self.assertEqual(double_calls[0]["args"], {"n": "3"})
        self.assertEqual(double_calls[1]["args"], {"n": "5"})

    def test_fts_search_ranks_relevant_passages_via_bm25(self) -> None:
        """Catches FTS5 search failing to return the chunk matching the query terms."""
        empty_res = fts_search("nonexistent-token", [self.root], base_dir=self.root)
        self.assertEqual(empty_res["chunk_count"], 0)
        self.assertEqual(empty_res["results"], [])

        doc_a = self.root / "auth_spec.md"
        doc_a.write_text(
            "Session tokens use HMAC-SHA256 signatures.\n"
            "Revocation lists are checked on every boundary transition.\n",
            encoding="utf-8",
        )
        doc_b = self.root / "ui_notes.md"
        doc_b.write_text(
            "Buttons use a 4px border radius and neutral slate backgrounds.\n",
            encoding="utf-8",
        )
        res = fts_search("HMAC-SHA256 revocation", [self.root], base_dir=self.root, top_k=3)
        self.assertGreaterEqual(len(res["results"]), 1)
        self.assertEqual(res["results"][0]["file"], "auth_spec.md")
        self.assertIn("HMAC-SHA256", res["results"][0]["snippet"])

    def test_cli_json_subcommands_exit_zero(self) -> None:
        """Catches CLI argument parsing or JSON serialization errors on public subcommands."""
        sample = self.root / "sample.py"
        sample.write_text(
            "def greet(name: str) -> str:\n    return f'hi {name}'\n"
            "def main_entry() -> str:\n    return greet('ada')\n"
            "if __name__ == '__main__':\n    main_entry()\n",
            encoding="utf-8",
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["callers", "greet", str(self.root), "--json"])
        self.assertEqual(rc, 0)
        parsed = json.loads(buf.getvalue())
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["enclosing_scope"], "main_entry")

        trace_buf = io.StringIO()
        with redirect_stdout(trace_buf):
            trace_rc = main(["trace", str(sample), "--json"])
        self.assertEqual(trace_rc, 0)
        trace_parsed = json.loads(trace_buf.getvalue())
        self.assertGreaterEqual(trace_parsed["event_count"], 2)


if __name__ == "__main__":
    unittest.main()
