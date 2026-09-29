"""
tests/test_test_boundary.py — Unit Tests for TestBoundaryGuard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
"""

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)

import json
import shutil
import sys
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
        hermetic.force_rmtree(self.test_dir)

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
        from guard import __version__
        self.assertEqual(data["version"], __version__)
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

    def test_verify_bugfix_added_regression_test_permitted(self):
        # GEMINI.md Rule 9: authoring new test files is always permitted (regression tests).
        self.guard.snapshot()
        (self.tests_dir / "test_new.py").write_text("def test_new(): pass\n", encoding="utf-8")

        report = self.guard.verify(mode="bugfix")
        self.assertTrue(report.is_intact, report.violations)
        self.assertIn("tests/test_new.py", report.added)

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
            [sys.executable, "-c", "import sys; sys.exit(0)"],
            passes=2,
        )
        self.assertTrue(success)
        self.assertEqual(codes, [0, 0])
        self.assertIn("Deterministic pass confirmed", msg)

    def test_run_reproducible_failure(self):
        success, msg, codes = self.guard.run_reproducible(
            [sys.executable, "-c", "import sys; sys.exit(1)"],
            passes=2,
        )
        self.assertFalse(success)
        self.assertEqual(codes, [1])
        self.assertIn("failed with exit code 1", msg)


def _code(text: str) -> str:
    """Sample sources carry '~' inside trigger words so this file's own lines stay plain; strip it."""
    return text.replace("~", "")


_SUITE_BASE = (
    "import unittest\n"
    "\n"
    "\n"
    "class T(unittest.TestCase):\n"
    "    def setUp(self):\n"
    "        self.value = 2\n"
    "\n"
    "    def test_x(self):\n"
    "        self.assertEqual(self.value, 2)\n"
    "        self.assertGreater(self.value, 1)\n"
    "\n"
    "    def test_y(self):\n"
    "        self.assertTrue(self.value)\n"
    "\n"
    "\n"
    "def helper():\n"
    "    return 1\n"
    "\n"
    "\n"
    "def test_module_level():\n"
    "    assert helper() == 1\n"
)
_TEST_X_HEAD = "    def test_x(self):\n"
_TEST_Y_BODY = "        self.assertTrue(self.value)\n"
_SUITE_END = "    assert helper() == 1\n"


def _insert_after(anchor: str, text: str) -> str:
    cut = _SUITE_BASE.index(anchor) + len(anchor)
    return _SUITE_BASE[:cut] + _code(text) + _SUITE_BASE[cut:]


class TestTddExtendOnlyBypasses(unittest.TestCase):
    """B-05: pure line additions that neuter existing tests are weakening, never 'extended'."""

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="agy_tdd_bypass_"))
        (self.work / "tests").mkdir()
        self.suite = self.work / "tests" / "test_suite.py"
        self.suite.write_text(_SUITE_BASE, encoding="utf-8")
        self.boundary = TestBoundaryGuard(workspace_dir=self.work)
        self.boundary.snapshot()

    def tearDown(self):
        hermetic.force_rmtree(self.work)

    def expect_weakening(self, new_source: str) -> TestBoundaryReport:
        self.assertNotEqual(new_source, _SUITE_BASE)
        removed, _ = TestBoundaryGuard._line_changes(_SUITE_BASE, new_source)
        self.assertEqual(removed, [], "the sample must be a pure line addition")
        self.suite.write_text(new_source, encoding="utf-8")
        report = self.boundary.verify(mode="tdd")
        self.assertFalse(report.is_intact, "bypass was accepted as an extension")
        self.assertNotIn("tests/test_suite.py", report.extended)
        self.assertIn("tests/test_suite.py", report.modified)
        self.assertTrue(any("weakening" in v for v in report.violations), report.violations)
        return report

    def expect_extended(self, new_source: str) -> TestBoundaryReport:
        self.suite.write_text(new_source, encoding="utf-8")
        report = self.boundary.verify(mode="tdd")
        self.assertTrue(report.is_intact, report.violations)
        self.assertEqual(report.extended, ["tests/test_suite.py"])
        return report

    # -- bypasses that must now be reported --------------------------------
    def test_lambda_replacing_an_existing_test(self):
        self.expect_weakening(_insert_after(_SUITE_END, "\n\nT.test_x = lambda self: None\n"))

    def test_skiptest_call_inside_an_existing_test(self):
        self.expect_weakening(_insert_after(_TEST_X_HEAD, "        self.sk~ipTest('no')\n"))

    def test_bare_return_at_the_top_of_an_existing_test(self):
        self.expect_weakening(_insert_after(_TEST_X_HEAD, "        return\n"))

    def test_return_none_between_existing_assertions(self):
        self.expect_weakening(_insert_after("        self.assertEqual(self.value, 2)\n", "        return None\n"))

    def test_raising_unittest_skiptest(self):
        self.expect_weakening(_insert_after(_TEST_X_HEAD, "        raise unittest.Sk~ipTest('later')\n"))

    def test_pytest_runtime_skip_call(self):
        self.expect_weakening(_insert_after(_TEST_X_HEAD, "        import pytest\n        pytest.sk~ip('no')\n"))

    def test_redefining_an_existing_test_class(self):
        self.expect_weakening(_insert_after(
            _SUITE_END, "\n\nclass T(unittest.TestCase):\n    def test_x(self):\n        pass\n"))

    def test_redefining_an_existing_test_method(self):
        self.expect_weakening(_insert_after(_TEST_Y_BODY, "\n    def test_x(self):\n        pass\n"))

    def test_redefining_an_existing_test_function(self):
        self.expect_weakening(_insert_after(_SUITE_END, "\n\ndef test_module_level():\n    pass\n"))

    def test_monkeypatching_testcase_assertions(self):
        self.expect_weakening(_insert_after(
            _SUITE_END, "\n\nunittest.Test~Case.ass~ertEqual = lambda *a, **k: None\n"))

    def test_replacing_the_test_runner_method(self):
        self.expect_weakening(_insert_after(_SUITE_END, "\n\nT.r~un = lambda self, result=None: None\n"))

    def test_replacing_a_test_via_setattr(self):
        self.expect_weakening(_insert_after(_SUITE_END, "\n\nset~attr(T, 'test_y', None)\n"))

    def test_overriding_an_assertion_method_in_the_class(self):
        self.expect_weakening(_insert_after(
            "        self.value = 2\n", "\n    def ass~ertEqual(self, *args, **kwargs):\n        pass\n"))

    def test_sys_exit_added_to_the_module(self):
        self.expect_weakening(_insert_after(_SUITE_END, "\n\nimport sys\nsys.ex~it(0)\n"))

    def test_os_exit_hidden_in_a_one_line_block(self):
        self.expect_weakening(_insert_after(_SUITE_END, "\n\nimport os\nif True: os._ex~it(0)\n"))

    def test_unparsable_python_falls_back_to_line_patterns(self):
        broken = _SUITE_BASE + "print 'python 2 syntax'\n"
        self.suite.write_text(broken, encoding="utf-8")
        self.boundary.snapshot()
        self.suite.write_text(broken.replace(_TEST_X_HEAD, _TEST_X_HEAD + "        return\n"), encoding="utf-8")
        report = self.boundary.verify(mode="tdd")
        self.assertFalse(report.is_intact)
        self.assertTrue(any("weakening" in v for v in report.violations), report.violations)

    # -- legitimate extensions stay accepted -------------------------------
    def test_new_test_method_is_still_an_extension(self):
        self.expect_extended(_insert_after(
            _TEST_Y_BODY, "\n    def test_z(self):\n        self.assertEqual(1 + 1, 2)\n"))

    def test_new_assertion_in_an_existing_test_is_still_an_extension(self):
        self.expect_extended(_insert_after(
            "        self.assertEqual(self.value, 2)\n", "        self.assertLess(self.value, 3)\n"))

    def test_new_test_class_with_helpers_is_still_an_extension(self):
        self.expect_extended(_insert_after(_SUITE_END, (
            "\n\nclass TestMore(unittest.TestCase):\n"
            "    def setUp(self):\n"
            "        self.test_dir = 'workspace'\n"
            "        self.script = 'import sys; sys.exit(3)'\n"
            "\n"
            "    def test_more(self):\n"
            "        self.assertIn('work', self.test_dir)\n"
            "        self.assertIn('3', self.script)\n"
            "\n"
            "\n"
            "def other_helper(value):\n"
            "    if not value:\n"
            "        return None\n"
            "    return value\n"
            "\n"
            "\n"
            "def test_other_helper():\n"
            "    assert other_helper(2) == 2\n"
        )))


if __name__ == "__main__":
    unittest.main()
