"""
tests/test_repo_sync_and_porter_note.py — Regression tests for tozhax/plumbwork sync, dual-owner provenance, and Porter Rule 9 note.
Part of Plumbwork (https://github.com/tozhax/plumbwork)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)

import io
import json
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import install
from guard import __version__
from guard.environment import (
    can_retire_harness_plugin_dir,
    is_harness_plugin_dir,
    is_legacy_harness_skill_dir,
)
from guard.plugins import PLUGIN_AUTHOR, PLUGIN_HOMEPAGE, PLUGIN_REPOSITORY
from installers.packaging.package_linux import LinuxPackager
from porter.emitters import EMITTERS
from porter.manifest import ManifestEngine

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestRepoSyncAndPorterNote(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name).resolve()

    def tearDown(self) -> None:
        self._td.cleanup()

    def test_dual_owner_plugin_provenance_accepts_tozhax_and_legacy_hadbilen_while_rejecting_third_party(self) -> None:
        positive_cases = [
            ("tozhax_repo_only", {"name": "ui-refinery", "repository": "https://github.com/tozhax/plumbwork"}),
            ("tozhax_homepage_only", {"name": "ui-refinery", "homepage": "https://github.com/tozhax/plumbwork"}),
            (
                "tozhax_both",
                {
                    "name": "ui-refinery",
                    "repository": "https://github.com/tozhax/plumbwork",
                    "homepage": "https://github.com/tozhax/plumbwork",
                },
            ),
            ("legacy_hadbilen_repo_only", {"name": "ui-refinery", "repository": "https://github.com/hadbilen/plumbwork"}),
            ("legacy_hadbilen_homepage_only", {"name": "ui-refinery", "homepage": "https://github.com/hadbilen/plumbwork"}),
            (
                "mixed_canonical_and_legacy_owner",
                {
                    "name": "ui-refinery",
                    "repository": "https://github.com/tozhax/plumbwork",
                    "homepage": "https://github.com/hadbilen/plumbwork",
                },
            ),
        ]
        for label, payload in positive_cases:
            with self.subTest(case=label):
                pdir = self.tmp / label
                pdir.mkdir()
                (pdir / "plugin.json").write_text(json.dumps(payload), encoding="utf-8")
                self.assertTrue(is_harness_plugin_dir(pdir, expected_pack="ui-refinery"))
                self.assertTrue(can_retire_harness_plugin_dir(pdir, expected_pack="ui-refinery", in_receipt=True))

        # Historical v2.x antislop plugin under hadbilen/antigravity-harness remains retireable only when allowed + receipted
        legacy_dir = self.tmp / "legacy_antislop"
        legacy_dir.mkdir()
        (legacy_dir / "plugin.json").write_text(
            json.dumps({"name": "antislop", "repository": "https://github.com/hadbilen/antigravity-harness"}),
            encoding="utf-8",
        )
        self.assertTrue(is_harness_plugin_dir(legacy_dir, expected_pack="antislop", allow_legacy_names=True))
        self.assertTrue(
            can_retire_harness_plugin_dir(legacy_dir, expected_pack="antislop", in_receipt=True, allow_legacy_names=True)
        )
        self.assertFalse(
            can_retire_harness_plugin_dir(legacy_dir, expected_pack="antislop", in_receipt=False, allow_legacy_names=True)
        )

        negative_cases = [
            ("other_owner_same_repo", {"name": "ui-refinery", "repository": "https://github.com/other/plumbwork"}),
            ("tozhax_other_repo", {"name": "ui-refinery", "repository": "https://github.com/tozhax/other-repo"}),
            (
                "mixed_tozhax_and_third_party_hp",
                {
                    "name": "ui-refinery",
                    "repository": "https://github.com/tozhax/plumbwork",
                    "homepage": "https://github.com/other/fork",
                },
            ),
            (
                "mixed_third_party_repo_and_tozhax_hp",
                {
                    "name": "ui-refinery",
                    "repository": "https://github.com/other/fork",
                    "homepage": "https://github.com/tozhax/plumbwork",
                },
            ),
        ]
        for label, payload in negative_cases:
            with self.subTest(case=label):
                pdir = self.tmp / label
                pdir.mkdir()
                (pdir / "plugin.json").write_text(json.dumps(payload), encoding="utf-8")
                self.assertFalse(is_harness_plugin_dir(pdir, expected_pack="ui-refinery"))
                self.assertFalse(can_retire_harness_plugin_dir(pdir, expected_pack="ui-refinery", in_receipt=True))

    def test_canonical_repo_and_packaging_metadata_synced_to_tozhax(self) -> None:
        self.assertEqual(PLUGIN_AUTHOR, {"name": "tozhax", "url": "https://github.com/tozhax/plumbwork"})
        self.assertEqual(PLUGIN_HOMEPAGE, "https://github.com/tozhax/plumbwork")
        self.assertEqual(PLUGIN_REPOSITORY, "https://github.com/tozhax/plumbwork")
        self.assertEqual(install.RELEASE_BASE, "https://github.com/tozhax/plumbwork/releases/download")

        manifest = ManifestEngine(REPO_ROOT).build_manifest(deterministic=True)
        self.assertEqual(manifest.metadata.get("author"), "tozhax")
        self.assertEqual(manifest.metadata.get("repository"), "https://github.com/tozhax/plumbwork")

        ci_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('if [ "$REPO" != "tozhax/plumbwork" ]; then', ci_text)
        self.assertNotIn('hadbilen/plumbwork', ci_text)

        pkgbuild = (REPO_ROOT / "installers" / "packaging" / "PKGBUILD").read_text(encoding="utf-8")
        self.assertIn("# Maintainer: tozhax <https://github.com/tozhax>", pkgbuild)
        self.assertIn('url="https://github.com/tozhax/plumbwork"', pkgbuild)
        self.assertIn("https://github.com/tozhax/plumbwork/archive/refs/tags/v$pkgver.tar.gz", pkgbuild)
        self.assertNotIn("hadbilen", pkgbuild.lower())
        self.assertNotIn("had bilen", pkgbuild.lower())

        out_dir = self.tmp / "dist_pkg"
        packager = LinuxPackager(repo_root=REPO_ROOT, version=__version__, arch="amd64", out_dir=out_dir)

        # Verify generated RPM spec
        packager.build_rpm()
        spec_text = (out_dir / "plumb-guard.spec").read_text(encoding="utf-8")
        self.assertIn("URL:            https://github.com/tozhax/plumbwork", spec_text)
        self.assertIn("tozhax <tozhax@users.noreply.github.com>", spec_text)
        self.assertNotIn("hadbilen", spec_text.lower())
        self.assertNotIn("had bilen", spec_text.lower())

        # Verify generated .deb control metadata
        deb_path = packager.build_deb()
        self.assertIsNotNone(deb_path)
        control_text = ""
        if shutil.which("dpkg-deb"):
            control_text = subprocess.check_output(["dpkg-deb", "--field", str(deb_path)], text=True)
        else:
            with open(deb_path, "rb") as fh:
                fh.read(8)
                while True:
                    hdr = fh.read(60)
                    if len(hdr) < 60:
                        break
                    name = hdr[:16].decode("ascii").strip().rstrip("/")
                    size = int(hdr[48:58].decode("ascii").strip())
                    data = fh.read(size)
                    if size % 2 == 1:
                        fh.read(1)
                    if name.startswith("control.tar"):
                        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                            for member in tf.getmembers():
                                if member.name.endswith("control"):
                                    control_text = tf.extractfile(member).read().decode("utf-8")
                                    break
                        break
        self.assertIn("Maintainer: tozhax <https://github.com/tozhax/plumbwork>", control_text)
        self.assertNotIn("hadbilen", control_text.lower())
        self.assertNotIn("had bilen", control_text.lower())

        # Verify generated Arch .PKGINFO
        arch_pkg = packager.build_arch()
        self.assertIsNotNone(arch_pkg)
        if arch_pkg.name.endswith(".zst"):
            raw_tar = subprocess.check_output(["zstd", "-dc", str(arch_pkg)])
            tf_ctx = tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:")
        else:
            tf_ctx = tarfile.open(arch_pkg, mode="r:xz")
        with tf_ctx as tf:
            pkginfo = tf.extractfile(".PKGINFO").read().decode("utf-8")
        self.assertIn("url = https://github.com/tozhax/plumbwork", pkginfo)
        self.assertIn("packager = tozhax <https://github.com/tozhax/plumbwork>", pkginfo)
        self.assertNotIn("hadbilen", pkginfo.lower())
        self.assertNotIn("had bilen", pkginfo.lower())

    def test_porter_export_includes_one_line_test_boundary_note_across_all_targets(self) -> None:
        manifest = ManifestEngine(REPO_ROOT).build_manifest(deterministic=True)
        index_files = {
            "claude": "CLAUDE.md",
            "cursor": ".cursor/rules/99-harness-index.mdc",
            "universal": "AGENTS.md",
            "aider": "CONVENTIONS.md",
            "generic": "RULES.md",
        }
        expected_cmd = "plumb-guard test-boundary verify --mode tdd"
        for target, emitter in EMITTERS.items():
            with self.subTest(target=target):
                out = self.tmp / f"export_{target}"
                emitter.emit(manifest, out)
                self.assertEqual(list(out.rglob("hooks.json")), [])
                text = (out / index_files[target]).read_text(encoding="utf-8")
                hooks_lines = [ln for ln in text.splitlines() if ln.startswith("- `hooks.json`")]
                self.assertEqual(len(hooks_lines), 1, f"Expected one hooks.json bullet in {index_files[target]}")
                self.assertIn("not portable", hooks_lines[0])
                self.assertIn(expected_cmd, hooks_lines[0])

    def test_legacy_skill_provenance_retains_hadbilen_markers(self) -> None:
        for label, url in (
            ("legacy_v3_hadbilen_plumbwork", "https://github.com/hadbilen/plumbwork"),
            ("legacy_v2_hadbilen_harness", "https://github.com/hadbilen/antigravity-harness"),
        ):
            with self.subTest(case=label):
                sdir = self.tmp / label
                sdir.mkdir()
                (sdir / "SKILL.md").write_text(f"---\nname: antislop\n---\nSource: {url}\n", encoding="utf-8")
                self.assertTrue(is_legacy_harness_skill_dir(sdir))

        third_party = self.tmp / "third_party_antislop"
        third_party.mkdir()
        (third_party / "SKILL.md").write_text(
            "---\nname: antislop\n---\nSource: https://github.com/miqdadbadjuber/anti-slop\n",
            encoding="utf-8",
        )
        self.assertFalse(is_legacy_harness_skill_dir(third_party))


if __name__ == "__main__":
    unittest.main()
