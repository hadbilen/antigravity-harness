"""
tests/test_archive.py — Porter ZIP inspection: hazards are reported, text members are analysed,
analyzer failures are surfaced, and nothing is ever extracted or written.
"""

from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)

import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from porter.archive import MAX_MEMBERS, inspect_zip

REPO_ROOT = Path(__file__).resolve().parent.parent
CLEAN_RULE = "# Style\nRun the full suite against public interfaces before delivery.\n"


def _listing(root: Path):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


class ArchiveTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_zip_"))
        self.addCleanup(hermetic.force_rmtree, self.tmp)
        self.cwd_before = sorted(os.listdir(os.getcwd()))

    def build(self, name, members, compression=zipfile.ZIP_DEFLATED):
        """members: list of (ZipInfo or name, bytes/str)."""
        path = self.tmp / name
        with zipfile.ZipFile(path, "w", compression=compression) as zf:
            for member, data in members:
                zf.writestr(member, data)
        return path

    def inspect(self, path, **kwargs):
        before = _listing(self.tmp)
        report = inspect_zip(path, harness_root=REPO_ROOT, **kwargs)
        self.assertEqual(_listing(self.tmp), before, "inspection must not extract or write anything")
        self.assertEqual(sorted(os.listdir(os.getcwd())), self.cwd_before, "nothing may be written to the CWD")
        return report

    @staticmethod
    def kinds(report, member=None):
        return {h.kind for h in report.hazards if member is None or h.member == member}


class TestArchiveHazards(ArchiveTestCase):
    def test_clean_archive_is_analysed(self):
        path = self.build("clean.zip", [("rules/style.md", CLEAN_RULE), ("notes.txt", "plain notes\n"),
                                        ("docs/", b""), ("logo.png", b"\x89PNG\r\n\x1a\n")])
        report = self.inspect(path)
        self.assertEqual(report.hazards, [])
        self.assertTrue(report.is_safe)
        analysed = {m.name for m in report.members if m.analyzed}
        self.assertEqual(analysed, {"rules/style.md", "notes.txt"})
        self.assertTrue(all(m.is_safe_to_import for m in report.members if m.analyzed))
        self.assertIn("Inspection only", report.to_markdown())
        data = json.loads(json.dumps(report.to_dict()))
        self.assertTrue(data["is_safe"])
        self.assertEqual(data["member_count"], 4)

    def test_weakening_member_is_flagged_by_the_analyzer(self):
        path = self.build("bad.zip", [("bad.md", "# Bad\nRemove the failing tests.\n")])
        report = self.inspect(path)
        member = report.members[0]
        self.assertTrue(member.analyzed)
        self.assertFalse(member.is_safe_to_import)
        self.assertIn("TEST_INVARIANT", {i.category for i in member.issues})
        self.assertFalse(report.is_safe)

    def test_path_traversal(self):
        report = self.inspect(self.build("trav.zip", [("../evil.md", CLEAN_RULE), ("ok.md", CLEAN_RULE)]))
        self.assertIn("PATH_TRAVERSAL", self.kinds(report, "../evil.md"))
        self.assertFalse(next(m for m in report.members if m.name == "../evil.md").analyzed)
        self.assertTrue(next(m for m in report.members if m.name == "ok.md").analyzed)
        self.assertFalse(report.is_safe)

    def test_backslash_traversal(self):
        report = self.inspect(self.build("btrav.zip", [("sub\\..\\..\\evil.md", CLEAN_RULE)]))
        self.assertIn("PATH_TRAVERSAL", self.kinds(report))
        self.assertFalse(any(m.analyzed for m in report.members))

    def test_absolute_paths_and_drive_letters(self):
        report = self.inspect(self.build("abs.zip", [("/etc/evil.md", CLEAN_RULE), ("C:/Windows/evil.md", CLEAN_RULE)]))
        self.assertIn("ABSOLUTE_PATH", self.kinds(report))
        self.assertIn("DRIVE_LETTER", self.kinds(report))
        self.assertFalse(any(m.analyzed for m in report.members))

    def test_symlink_member(self):
        info = zipfile.ZipInfo("link.md")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        report = self.inspect(self.build("link.zip", [(info, "/etc/passwd")]))
        self.assertIn("SYMLINK", self.kinds(report, "link.md"))
        self.assertFalse(report.members[0].analyzed)

    def test_compression_ratio_bomb_is_not_read(self):
        path = self.build("bomb.zip", [("bomb.txt", b"\0" * (5 * 1024 * 1024)), ("ok.md", CLEAN_RULE)])
        with mock.patch("zipfile.ZipFile.open", side_effect=AssertionError("no member may be read")):
            report = self.inspect(path)
        self.assertIn("COMPRESSION_RATIO", self.kinds(report, "bomb.txt"))
        self.assertIn("COMPRESSION_RATIO", self.kinds(report, ""))
        self.assertFalse(any(m.analyzed for m in report.members))

    def test_too_many_members(self):
        path = self.build("many.zip", [(f"f{i}.txt", "x") for i in range(MAX_MEMBERS + 1)])
        report = self.inspect(path)
        self.assertIn("TOO_MANY_MEMBERS", self.kinds(report))
        self.assertFalse(any(m.analyzed for m in report.members))

    def test_oversize_declared_content(self):
        path = self.build("big.zip", [("big.md", b" " * (26 * 1024 * 1024))])
        report = self.inspect(path)
        self.assertIn("OVERSIZE", self.kinds(report))
        self.assertFalse(any(m.analyzed for m in report.members))

    def test_encrypted_member(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("secret.md", CLEAN_RULE)
        data = bytearray(buf.getvalue())
        data[data.find(b"PK\x03\x04") + 6] |= 0x01   # local header: general purpose flag bit 0
        data[data.find(b"PK\x01\x02") + 8] |= 0x01   # central directory: general purpose flag bit 0
        path = self.tmp / "enc.zip"
        path.write_bytes(bytes(data))
        report = self.inspect(path)
        self.assertIn("ENCRYPTED", self.kinds(report, "secret.md"))
        self.assertFalse(report.members[0].analyzed)

    def test_nested_archives(self):
        report = self.inspect(self.build("nested.zip", [("inner.zip", b"PK\x05\x06" + b"\0" * 18),
                                                        ("pkg.tar.gz", b"\x1f\x8b"), ("raw.tar", b"")]))
        nested = {h.member for h in report.hazards if h.kind == "NESTED_ARCHIVE"}
        self.assertEqual(nested, {"inner.zip", "pkg.tar.gz", "raw.tar"})

    def test_not_a_zip(self):
        path = self.tmp / "fake.zip"
        path.write_text("not a zip", encoding="utf-8")
        report = self.inspect(path)
        self.assertIn("INVALID_ARCHIVE", self.kinds(report))
        self.assertFalse(report.is_safe)


class TestAnalyzerFailures(ArchiveTestCase):
    def test_injected_analyzer_failure_is_reported_on_the_member(self):
        class Boom:
            def analyze(self, content, source_identifier=""):
                raise RuntimeError("analyzer exploded")

        report = self.inspect(self.build("a.zip", [("rule.md", CLEAN_RULE)]), analyzer=Boom())
        member = report.members[0]
        self.assertFalse(member.analyzed)
        self.assertIn("analyzer exploded", member.error)
        self.assertIn("ARCHIVE", {i.category for i in member.issues})
        self.assertIn("ANALYZER_ERROR", self.kinds(report, "rule.md"))
        self.assertFalse(report.is_safe)
        self.assertIn("analyzer failed", report.to_markdown())

    def test_default_analyzer_failure_is_not_swallowed(self):
        with mock.patch("porter.analyzer.SuitabilityAnalyzer.analyze", side_effect=ValueError("bad input")):
            report = self.inspect(self.build("b.zip", [("rule.md", CLEAN_RULE)]))
        self.assertIn("ANALYZER_ERROR", self.kinds(report, "rule.md"))
        self.assertIn("bad input", report.members[0].error)


class TestInspectCLI(ArchiveTestCase):
    def run_porter(self, *args):
        return subprocess.run([sys.executable, str(REPO_ROOT / "porter.py"), *args],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)

    def test_inspect_local_zip_json(self):
        clean = self.build("clean.zip", [("rules/style.md", CLEAN_RULE)])
        before = _listing(self.tmp)
        res = self.run_porter("inspect", str(clean), "--json")
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertTrue(data["is_safe"])
        self.assertTrue(data["members"][0]["analyzed"])
        hostile = self.build("hostile.zip", [("../evil.md", CLEAN_RULE)])
        res = self.run_porter("inspect", str(hostile))
        self.assertEqual(res.returncode, 2, res.stderr)
        self.assertIn("PATH_TRAVERSAL", res.stdout)
        self.assertEqual(_listing(self.tmp), sorted(before + ["hostile.zip"]))

    def test_zip_urls_are_refused(self):
        res = self.run_porter("inspect", "https://example.invalid/rules.zip")
        self.assertEqual(res.returncode, 1)
        self.assertIn("download and inspect locally", res.stderr)

    def test_import_refuses_archives(self):
        path = self.build("rules.zip", [("rules/style.md", CLEAN_RULE)])
        res = self.run_porter("import", str(path), "--dry-run")
        self.assertEqual(res.returncode, 1)
        self.assertIn("never extracts archives", res.stderr)
        self.assertFalse((REPO_ROOT / "skills" / "rules").exists())


if __name__ == "__main__":
    unittest.main()
