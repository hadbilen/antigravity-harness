"""
tests/test_test_boundary.py — Unit Tests for TestBoundaryGuard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from guard.test_boundary import TestBoundaryGuard, TestBoundaryReport


class TestTestBoundaryGuard(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="agy_test_boundary_"))
        self.harness_dir = self.test_dir / ".harness"
        self.harness_dir.mkdir(parents=True)

        # Create dummy project structure
        self.tests_dir = self.test_dir / "tests"
        self.tests_dir.mkdir(parents=True)
        (self.tests_dir / "test_example.py").write_text("def test_ok(): assert True\n", encoding="utf-8")
        (self.tests_dir / "fixtures.json").write_text('{"threshold": 0.001}\n', encoding="utf-8")

        # Create config file
        (self.test_dir / "pytest.ini").write_text("[pytest]\naddopts = -v\n", encoding="utf-8")

        self.guard = TestBoundaryGuard(workspace_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_discover_files(self):
        files = self.guard.discover_files()
        self.assertIn("pytest.ini", files)
        self.assertIn("tests/test_example.py", files)
        self.assertIn("tests/fixtures.json", files)
        self.assertEqual(len(files), 3)

    def test_snapshot_creation(self):
        count, path = self.guard.snapshot()
        self.assertEqual(count, 3)
        self.assertTrue(path.exists())
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], "1.2.9")
        self.assertEqual(data["total_files"], 3)
        self.assertIn("tests/test_example.py", data["files"])

    def test_verify_intact_baseline(self):
        self.guard.snapshot()
        report = self.guard.verify(mode="bugfix")
        self.assertTrue(report.is_intact)
        self.assertEqual(len(report.violations), 0)
        self.assertIn("Test & Config Boundary Verified", report.summary())

    def test_verify_bugfix_modification_blocked(self):
        self.guard.snapshot()
        # Tamper with test assertion
        (self.tests_dir / "test_example.py").write_text("def test_ok(): assert True # tampered\n", encoding="utf-8")

        report = self.guard.verify(mode="bugfix")
        self.assertFalse(report.is_intact)
        self.assertIn("tests/test_example.py", report.modified)
        self.assertTrue(any("modified without authorization" in v for v in report.violations))
        self.assertIn("BLOCKED", report.summary())

    def test_verify_bugfix_fixture_modification_flagged(self):
        self.guard.snapshot()
        # Tamper with fixture threshold
        (self.tests_dir / "fixtures.json").write_text('{"threshold": 0.5}\n', encoding="utf-8")

        report = self.guard.verify(mode="bugfix")
        self.assertFalse(report.is_intact)
        self.assertIn("tests/fixtures.json", report.fixture_modifications)
        self.assertTrue(any("Goodhart Invariant" in v for v in report.violations))

    def test_verify_bugfix_added_file_blocked(self):
        self.guard.snapshot()
        # Add new test in bugfix mode
        (self.tests_dir / "test_new.py").write_text("def test_new(): pass\n", encoding="utf-8")

        report = self.guard.verify(mode="bugfix")
        self.assertFalse(report.is_intact)
        self.assertIn("tests/test_new.py", report.added)
        self.assertTrue(any("New test/config files added in bugfix mode" in v for v in report.violations))

    def test_verify_tdd_added_file_permitted(self):
        self.guard.snapshot()
        # Add new test in tdd mode
        (self.tests_dir / "test_tdd_feature.py").write_text("def test_feature(): pass\n", encoding="utf-8")

        report = self.guard.verify(mode="tdd")
        self.assertTrue(report.is_intact)
        self.assertIn("tests/test_tdd_feature.py", report.added)
        self.assertEqual(len(report.violations), 0)

    def test_verify_tdd_modified_without_auth_blocked(self):
        self.guard.snapshot()
        (self.tests_dir / "test_example.py").write_text("def test_ok(): pass\n", encoding="utf-8")

        report = self.guard.verify(mode="tdd")
        self.assertFalse(report.is_intact)
        self.assertIn("tests/test_example.py", report.modified)

    def test_verify_tdd_modified_with_auth_permitted(self):
        self.guard.snapshot()
        (self.tests_dir / "test_example.py").write_text("def test_ok(): pass\n", encoding="utf-8")

        report = self.guard.verify(mode="tdd", authorized_modifications={"tests/test_example.py"})
        self.assertTrue(report.is_intact)
        self.assertEqual(len(report.violations), 0)

    def test_run_reproducible_success(self):
        success, msg, codes = self.guard.run_reproducible(
            ["python3", "-c", "import sys; sys.exit(0)"],
            passes=2,
        )
        self.assertTrue(success)
        self.assertEqual(codes, [0, 0])
        self.assertIn("Deterministic pass confirmed", msg)

    def test_run_reproducible_failure(self):
        success, msg, codes = self.guard.run_reproducible(
            ["python3", "-c", "import sys; sys.exit(1)"],
            passes=2,
        )
        self.assertFalse(success)
        self.assertEqual(codes, [1])
        self.assertIn("failed with exit code 1", msg)


if __name__ == "__main__":
    unittest.main()
