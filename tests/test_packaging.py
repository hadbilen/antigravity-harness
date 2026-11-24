"""
tests/test_packaging.py — Test Native Linux Distribution Package Generator
Part of Plumbwork (https://github.com/hadbilen/plumbwork)
Zero external dependencies: uses strictly the Python standard library.
"""


from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)

import sys
import tempfile
import unittest
from pathlib import Path

from guard import __version__
from installers.packaging.package_linux import LinuxPackager, REPO_ROOT


class TestLinuxPackaging(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.temp_dir.name) / "dist_test"
        self.packager = LinuxPackager(
            repo_root=REPO_ROOT,
            version=__version__,
            arch="amd64",
            out_dir=self.out_dir,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_prepare_payload_fhs_hierarchy(self):
        with tempfile.TemporaryDirectory() as stage_tmp:
            stage = Path(stage_tmp)
            self.packager.prepare_payload(stage)

            # Assert FHS paths
            self.assertTrue((stage / "usr" / "bin" / "plumb-guard").exists())
            self.assertTrue((stage / "usr" / "share" / "applications" / "plumb-guard.desktop").exists())
            self.assertTrue((stage / "usr" / "share" / "icons" / "hicolor" / "scalable" / "apps" / "plumb-guard.svg").exists())
            self.assertTrue((stage / "usr" / "share" / "plumbwork" / "GEMINI.md").exists())
            self.assertTrue((stage / "usr" / "share" / "bash-completion" / "completions" / "plumb-guard").exists())

    def test_pure_python_deb_archive_generation(self):
        with tempfile.TemporaryDirectory() as tmp_stage:
            stage = Path(tmp_stage) / "stage"
            self.packager.prepare_payload(stage)
            deb_dir = stage / "DEBIAN"
            deb_dir.mkdir(parents=True, exist_ok=True)
            (deb_dir / "control").write_text("Package: test\nVersion: 1.0\nArchitecture: all\nDescription: test\n", encoding="utf-8")

            target_deb = self.out_dir / "pure_test.deb"
            deb_path = self.packager.build_deb_archive(stage, target_deb)
            self.assertIsNotNone(deb_path)
            self.assertTrue(deb_path.exists())

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

    def test_build_deb_package(self):
        deb_path = self.packager.build_deb()
        self.assertIsNotNone(deb_path)
        self.assertTrue(deb_path.exists())
        self.assertTrue(deb_path.name.endswith(".deb"))
        self.assertGreater(deb_path.stat().st_size, 1000)

        with open(deb_path, "rb") as f:
            magic = f.read(8)
            self.assertEqual(magic, b"!<arch>\n", "Invalid ar header magic")

            h1 = f.read(60)
            self.assertTrue(h1.startswith(b"debian-binary   "))
            body1 = f.read(4)
            self.assertEqual(body1, b"2.0\n")

            h2 = f.read(60)
            self.assertTrue(h2.startswith(b"control.tar"))

    def test_rpm_spec_generation(self):
        result_path = self.packager.build_rpm()
        self.assertIsNotNone(result_path)
        self.assertTrue(result_path.exists())
        # If rpmbuild is not available, it returns the generated .spec file
        if result_path.suffix == ".spec":
            content = result_path.read_text(encoding="utf-8")
            self.assertIn("Name:           plumb-guard", content)
            self.assertIn(f"Version:        {__version__}", content)
            self.assertIn("/usr/bin/plumb-guard", content)

    def test_arch_package_generation(self):
        arch_pkg = self.packager.build_arch()
        self.assertIsNotNone(arch_pkg)
        self.assertTrue(arch_pkg.exists())
        self.assertTrue(
            arch_pkg.name.endswith(".pkg.tar.zst") or arch_pkg.name.endswith(".pkg.tar.xz"),
            f"Unexpected package filename: {arch_pkg.name}",
        )
        self.assertGreater(arch_pkg.stat().st_size, 1000)

    def test_cli_argument_parsing(self):
        import subprocess
        pkg_script = Path(__file__).resolve().parent.parent / "installers" / "packaging" / "package_linux.py"
        res = subprocess.run(
            [sys.executable, str(pkg_script), "--all", "--output-dir", str(self.out_dir), "--check-only"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Packaging configuration valid:", res.stdout)
        self.assertIn(f"Version: {__version__}", res.stdout)
        self.assertIn(self.out_dir.name, res.stdout)

    def test_v3_replacement_metadata_across_pkgbuild_deb_rpm_and_arch(self):
        import io
        import subprocess
        import tarfile

        # 1. Arch PKGBUILD: plumb-guard, version 3.0.0, provides/replaces/conflicts, unquoted cd glob
        pkgbuild = (REPO_ROOT / "installers" / "packaging" / "PKGBUILD").read_text(encoding="utf-8")
        self.assertIn("pkgname=plumb-guard", pkgbuild)
        self.assertIn(f"pkgver={__version__}", pkgbuild)
        self.assertIn("provides=('antigravity-guard')", pkgbuild)
        self.assertIn("replaces=('antigravity-guard')", pkgbuild)
        self.assertIn("conflicts=('antigravity-guard')", pkgbuild)
        self.assertIn('cd "$srcdir"/*-"$pkgver"', pkgbuild)
        self.assertNotIn('cd "$srcdir/*-$pkgver"', pkgbuild)

        # 2. Debian .deb control metadata: Package, Provides, Conflicts, Replaces
        deb_path = self.packager.build_deb()
        self.assertIsNotNone(deb_path)
        control_text = ""
        with open(deb_path, "rb") as f:
            self.assertEqual(f.read(8), b"!<arch>\n")
            while True:
                hdr = f.read(60)
                if len(hdr) < 60:
                    break
                name = hdr[:16].decode("ascii").strip().rstrip("/")
                size = int(hdr[48:58].decode("ascii").strip())
                data = f.read(size)
                if size % 2 == 1:
                    f.read(1)
                if name.startswith("control.tar"):
                    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                        for member in tf.getmembers():
                            if member.name.endswith("control"):
                                control_text = tf.extractfile(member).read().decode("utf-8")
                                break
                    break
        self.assertIn("Package: plumb-guard", control_text)
        self.assertIn("Provides: antigravity-guard", control_text)
        self.assertIn("Conflicts: antigravity-guard", control_text)
        self.assertIn("Replaces: antigravity-guard", control_text)

        # 3. RPM .spec metadata: versioned Provides + Obsoletes < 3.0.0 + FHS paths
        rpm_res = self.packager.build_rpm()
        self.assertIsNotNone(rpm_res)
        spec_path = self.out_dir / "plumb-guard.spec"
        self.assertTrue(spec_path.is_file(), f"Expected RPM spec file to be generated at {spec_path}")
        spec_text = spec_path.read_text(encoding="utf-8")
        self.assertIn("Name:           plumb-guard", spec_text)
        self.assertIn("Provides:       antigravity-guard = %{version}-%{release}", spec_text)
        self.assertIn("Obsoletes:      antigravity-guard < 3.0.0", spec_text)
        self.assertIn("/usr/bin/plumb-porter", spec_text)
        self.assertIn("/usr/lib/plumb-guard", spec_text)
        self.assertIn("/usr/share/plumbwork", spec_text)

        # 4. Arch .PKGINFO metadata: singular conflict = antigravity-guard + provides + replaces
        arch_pkg = self.packager.build_arch()
        self.assertIsNotNone(arch_pkg)
        if arch_pkg.name.endswith(".zst"):
            raw_tar = subprocess.check_output(["zstd", "-dc", str(arch_pkg)])
            tf_ctx = tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:")
        else:
            tf_ctx = tarfile.open(arch_pkg, mode="r:xz")
        with tf_ctx as tf:
            pkginfo = tf.extractfile(".PKGINFO").read().decode("utf-8")
        self.assertIn("pkgname = plumb-guard", pkginfo)
        self.assertIn("provides = antigravity-guard", pkginfo)
        self.assertIn("replaces = antigravity-guard", pkginfo)
        self.assertIn("conflict = antigravity-guard", pkginfo)
        self.assertNotIn("conflicts = antigravity-guard", pkginfo)

    def test_plumb_guard_launchers_and_desktop_assets_present(self):
        for rel in (
            "bin/plumb-guard",
            "bin/plumb-guard.bat",
            "bin/plumb-guard.ps1",
            "installers/plumb-guard.desktop",
            "installers/packaging/plumb-guard.svg",
        ):
            self.assertTrue((REPO_ROOT / rel).is_file(), f"Missing W3 launcher/asset: {rel}")
        for retired in (
            "bin/agy-guard",
            "bin/agy-guard.bat",
            "bin/agy-guard.ps1",
            "installers/antigravity-guard.desktop",
            "installers/packaging/antigravity-guard.svg",
        ):
            self.assertFalse((REPO_ROOT / retired).exists(), f"Retired legacy file still exists: {retired}")
        desktop = (REPO_ROOT / "installers" / "plumb-guard.desktop").read_text(encoding="utf-8")
        self.assertIn("Exec=plumb-guard gui", desktop)
        self.assertIn("Icon=plumb-guard", desktop)


if __name__ == "__main__":
    unittest.main()

