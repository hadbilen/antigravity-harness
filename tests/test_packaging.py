"""
tests/test_packaging.py — Test Native Linux Distribution Package Generator
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from installers.packaging.package_linux import LinuxPackager, REPO_ROOT


class TestLinuxPackaging(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.temp_dir.name) / "dist_test"
        self.packager = LinuxPackager(
            repo_root=REPO_ROOT,
            version="1.3.0",
            arch="amd64",
            out_dir=self.out_dir,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_prepare_payload_fhs_hierarchy(self):
        with tempfile.TemporaryDirectory() as stage_tmp:
            stage = Path(stage_tmp)
            self.packager._prepare_payload(stage)

            # Assert FHS paths
            self.assertTrue((stage / "usr" / "bin" / "agy-guard").exists())
            self.assertTrue((stage / "usr" / "share" / "applications" / "antigravity-guard.desktop").exists())
            self.assertTrue((stage / "usr" / "share" / "icons" / "hicolor" / "scalable" / "apps" / "antigravity-guard.svg").exists())
            self.assertTrue((stage / "usr" / "share" / "antigravity-harness" / "GEMINI.md").exists())
            self.assertTrue((stage / "usr" / "share" / "bash-completion" / "completions" / "agy-guard").exists())

    def test_pure_python_deb_archive_generation(self):
        deb_path = self.packager.build_deb()
        self.assertIsNotNone(deb_path)
        self.assertTrue(deb_path.exists())
        self.assertTrue(deb_path.name.endswith(".deb"))
        self.assertGreater(deb_path.stat().st_size, 1000)

        # Validate ar archive structure
        with open(deb_path, "rb") as f:
            magic = f.read(8)
            self.assertEqual(magic, b"!<arch>\n", "Invalid ar header magic")

            # First entry: debian-binary
            h1 = f.read(60)
            self.assertEqual(len(h1), 60)
            self.assertTrue(h1.startswith(b"debian-binary   "))
            body1 = f.read(4)
            self.assertEqual(body1, b"2.0\n")

            # Second entry: control.tar.gz
            h2 = f.read(60)
            self.assertEqual(len(h2), 60)
            self.assertTrue(h2.startswith(b"control.tar.gz  "))

    def test_rpm_spec_generation(self):
        result_path = self.packager.build_rpm()
        self.assertIsNotNone(result_path)
        self.assertTrue(result_path.exists())
        # If rpmbuild is not available, it returns the generated .spec file
        if result_path.suffix == ".spec":
            content = result_path.read_text(encoding="utf-8")
            self.assertIn("Name:           antigravity-guard", content)
            self.assertIn("Version:        1.3.0", content)
            self.assertIn("/usr/bin/agy-guard", content)

    def test_arch_package_generation(self):
        arch_pkg = self.packager.build_arch()
        self.assertIsNotNone(arch_pkg)
        self.assertTrue(arch_pkg.exists())
        self.assertTrue(
            arch_pkg.name.endswith(".pkg.tar.zst") or arch_pkg.name.endswith(".pkg.tar.xz"),
            f"Unexpected package filename: {arch_pkg.name}",
        )
        self.assertGreater(arch_pkg.stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()
