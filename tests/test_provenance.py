"""
tests/test_provenance.py — Unit Tests for RunProvenanceTracker
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
"""

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from guard.provenance import RunProvenanceManifest, RunProvenanceTracker
from guard.test_boundary import TestBoundaryGuard


class TestRunProvenanceTracker(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="agy_provenance_"))
        self.harness_dir = self.test_dir / ".harness"
        self.harness_dir.mkdir(parents=True)

        # Baseline test setup
        self.tests_dir = self.test_dir / "tests"
        self.tests_dir.mkdir(parents=True)
        (self.tests_dir / "test_sample.py").write_text("def test_x(): assert True\n", encoding="utf-8")

        self.tb_guard = TestBoundaryGuard(workspace_dir=self.test_dir)
        self.tb_guard.snapshot()

        self.tracker = RunProvenanceTracker(workspace_dir=self.test_dir)

    def tearDown(self):
        hermetic.force_rmtree(self.test_dir)

    def test_generate_manifest_basic(self):
        manifest = self.tracker.generate_manifest(mode="bugfix")
        self.assertIsInstance(manifest, RunProvenanceManifest)
        from guard import __version__
        self.assertEqual(manifest.version, __version__)
        self.assertTrue(manifest.test_boundary_verified)
        self.assertTrue(self.tracker.output_file.exists())

        saved = json.loads(self.tracker.output_file.read_text(encoding="utf-8"))
        self.assertEqual(saved["version"], __version__)
        self.assertTrue(saved["test_boundary_verified"])

    def test_detect_environment_overrides(self):
        old_val = os.environ.get("MOCK_AUTH")
        try:
            os.environ["MOCK_AUTH"] = "true"
            manifest = self.tracker.generate_manifest(mode="bugfix")
            self.assertIn("MOCK_AUTH", manifest.environment_overrides)
            self.assertEqual(manifest.environment_overrides["MOCK_AUTH"], "true")
        finally:
            if old_val is not None:
                os.environ["MOCK_AUTH"] = old_val
            else:
                os.environ.pop("MOCK_AUTH", None)

    def test_generate_manifest_with_reproducible_test(self):
        import sys
        manifest = self.tracker.generate_manifest(
             mode="bugfix",
             test_command=f'"{sys.executable}" -c "import sys; sys.exit(0)"',
             reproducibility_passes=2,
         )
        self.assertTrue(manifest.reproducibility_verified)
        self.assertEqual(manifest.reproducibility_runs, 2)
        md = manifest.to_markdown()
        self.assertIn("CONFIRMED (2x)", md)
        self.assertIn("Execution Provenance Manifest", md)


if __name__ == "__main__":
    unittest.main()
