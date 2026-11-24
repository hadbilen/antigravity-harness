"""
tests/test_hybrid_plugins.py — Hybrid Modular Plugin Architecture Tests (AC-1..AC-6)
Part of Plumbwork (https://github.com/hadbilen/plumbwork)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import install as harness_install
from guard import __version__ as HARNESS_VERSION
from guard import agy_hooks
from guard import cli as guard_cli
from guard.doctor import diagnose
from guard.environment import (
    ANTIGRAVITY_RUNTIME_ENTRIES,
    EnvironmentRegistry,
    antigravity_plugin_governance_seams,
    default_antigravity_environment,
    migrate_harness_mcp_config,
    sync_antigravity_plugin_seams,
)
from guard.integrity import FileIntegrityMonitor
from guard.os_adapter import OSProtectionAdapter
from guard.plugins import (
    HARNESS_PLUGIN_NAMES,
    PLUGIN_ASSET_FILENAMES,
    PLUGIN_CATALOG,
    PLUGIN_OWNED_SKILL_SLUGS,
    PLUGIN_SKILL_TO_PACK,
    _plugin_assets_dir,
    archive_plugin_pack,
    build_all_plugin_packs,
    build_plugin_pack,
    resolve_local_python_command,
    rewrite_core_for_hybrid,
    rewrite_plugin_markdown,
    validate_plugin_dir,
    validate_plugin_zip,
    validate_svg_logo,
    wcag_contrast_ratio,
)
from guard.startup import StartupManager
from installers import build_binaries
from porter.analyzer import SuitabilityAnalyzer
from porter.manifest import ManifestEngine, is_installed_hybrid_root
from scripts.meta_audit import MetaAuditEngine

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestPluginCatalogAndAdr0016(unittest.TestCase):
    def test_adr0016_exists_and_is_indexed(self) -> None:
        adr = REPO_ROOT / "docs" / "adr" / "0016-hybrid-modular-plugin-architecture.md"
        self.assertTrue(adr.is_file())
        adr_text = adr.read_text(encoding="utf-8")
        for marker in ("C1", "C2", "C3", "C4", "D1", "D10", "ADR-0015", "stop_gate.py"):
            self.assertIn(marker, adr_text)
        index_text = (REPO_ROOT / "docs" / "adr" / "README.md").read_text(encoding="utf-8")
        self.assertIn("0016-hybrid-modular-plugin-architecture.md", index_text)

    def test_catalog_structure_and_mappings(self) -> None:
        self.assertEqual(
            set(PLUGIN_CATALOG.keys()),
            {"ui-refinery", "rust-suite", "media-studio", "game-engineering"},
        )
        self.assertEqual(HARNESS_PLUGIN_NAMES, frozenset(PLUGIN_CATALOG.keys()))
        self.assertEqual(
            PLUGIN_OWNED_SKILL_SLUGS,
            frozenset({"ui-refinery", "vibecoder", "rustify", "rust-harden", "media-studio", "game-engineering"}),
        )
        self.assertEqual(
            PLUGIN_SKILL_TO_PACK,
            {
                "ui-refinery": "ui-refinery",
                "vibecoder": "ui-refinery",
                "rustify": "rust-suite",
                "rust-harden": "rust-suite",
                "media-studio": "media-studio",
                "game-engineering": "game-engineering",
            },
        )
        self.assertEqual(
            PLUGIN_CATALOG["ui-refinery"].extra_files,
            (("DESIGN.md", "skills/ui-refinery/references/DESIGN.md"),),
        )
        self.assertEqual(
            PLUGIN_CATALOG["rust-suite"].extra_files,
            (("templates/vulkan.SKILL.template.md", "skills/rust-harden/assets/vulkan.SKILL.template.md"),),
        )
        self.assertEqual(PLUGIN_CATALOG["media-studio"].extra_files, ())
        self.assertEqual(PLUGIN_CATALOG["game-engineering"].extra_files, ())

    def test_plugin_assets_dir_resolves_meipass_when_frozen(self) -> None:
        self.assertEqual(_plugin_assets_dir(REPO_ROOT), REPO_ROOT / "guard" / "plugin_assets")
        with tempfile.TemporaryDirectory() as tmp:
            fake_meipass = Path(tmp) / "bundle"
            meipass_assets = fake_meipass / "guard" / "plugin_assets"
            meipass_assets.mkdir(parents=True)
            with mock.patch.object(sys, "_MEIPASS", str(fake_meipass), create=True):
                self.assertEqual(_plugin_assets_dir(), meipass_assets)


class TestSvgLogosAndValidator(unittest.TestCase):
    def test_all_four_repo_svg_logos_pass_strict_validator(self) -> None:
        assets_dir = REPO_ROOT / "guard" / "plugin_assets"
        for filename in PLUGIN_ASSET_FILENAMES:
            svg_path = assets_dir / filename
            self.assertTrue(svg_path.is_file(), f"Missing logo asset: {svg_path}")
            self.assertLessEqual(svg_path.stat().st_size, 16 * 1024)
            errs = validate_svg_logo(svg_path)
            self.assertEqual(errs, [], f"Logo {filename} failed validation: {errs}")

    def test_svg_validator_rejects_unsafe_geometry_and_contrast_defects(self) -> None:
        cases = {
            "doctype": (
                '<!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><circle cx="64" cy="64" r="30" fill="#1E6FD9"/></svg>',
                "DOCTYPE/ENTITY",
            ),
            "xml_stylesheet_pi": (
                '<?xml-stylesheet type="text/css" href="https://evil.invalid/x.css"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><circle cx="64" cy="64" r="30" fill="#1E6FD9"/></svg>',
                "processing instruction",
            ),
            "script_tag": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><script>alert(1)</script><circle cx="64" cy="64" r="30" fill="#1E6FD9"/></svg>',
                "Disallowed SVG element <script>",
            ),
            "foreign_object": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><foreignObject/><circle cx="64" cy="64" r="30" fill="#1E6FD9"/></svg>',
                "Disallowed SVG element <foreignobject>",
            ),
            "smil_anchor_set_xss": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><a href="#ok"><set attributeName="href" to="java&#x09;script:alert(1)"/><rect x="20" y="20" width="80" height="80" fill="#1E6FD9"/></a></svg>',
                "Disallowed SVG element <a>",
            ),
            "quoted_external_url": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><rect x="20" y="20" width="80" height="80" fill="#1E6FD9" filter="url(\'https://evil.invalid/f.svg#x\')"/></svg>',
                "Unsafe external/data URI",
            ),
            "javascript_uri_tab": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><rect x="20" y="20" width="80" height="80" fill="#1E6FD9" data-x="java&#x09;script:alert(1)"/></svg>',
                "Unsafe external/data URI",
            ),
            "data_uri": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><rect x="20" y="20" width="80" height="80" fill="#1E6FD9" filter="url(data:text/html,hi)"/></svg>',
                "Unsafe external/data URI",
            ),
            "event_handler": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><circle cx="64" cy="64" r="30" fill="#1E6FD9" onclick="evil()"/></svg>',
                "event handler",
            ),
            "inline_style": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><circle cx="64" cy="64" r="30" fill="#1E6FD9" style="opacity:0.9"/></svg>',
                "Inline style attribute",
            ),
            "transform_disallowed": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><circle cx="64" cy="64" r="30" fill="#1E6FD9" transform="translate(10,0)"/></svg>',
                "transform attribute",
            ),
            "translucent_opacity": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><circle cx="64" cy="64" r="30" fill="#1E6FD9" fill-opacity="0.5"/></svg>',
                "Translucent fill-opacity",
            ),
            "missing_width_height": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><circle cx="64" cy="64" r="30" fill="#1E6FD9"/></svg>',
                'explicit width="128"',
            ),
            "wrong_viewbox": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="128" height="128"><circle cx="32" cy="32" r="10" fill="#1E6FD9"/></svg>',
                "viewBox must be",
            ),
            "out_of_bounds_stroke": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><rect x="12" y="18" width="90" height="90" fill="none" stroke="#1E6FD9" stroke-width="6"/></svg>',
                "exceed required safe box",
            ),
            "out_of_bounds_path": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><path d="M 4 20 L 100 100" fill="none" stroke="#1E6FD9" stroke-width="4"/></svg>',
                "exceed required safe box",
            ),
            "truncated_path_no_crash": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><path d="M 20" fill="#1E6FD9"/></svg>',
                "truncated SVG path",
            ),
            "non_finite_nan": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><circle cx="NaN" cy="64" r="30" fill="#1E6FD9"/></svg>',
                "non-finite",
            ),
            "non_hex_color": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><circle cx="64" cy="64" r="30" fill="royalblue"/></svg>',
                "Non-hex SVG color",
            ),
            "low_contrast_light": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><circle cx="64" cy="64" r="30" fill="#F2F2F2"/></svg>',
                "fails contrast on #FFFFFF",
            ),
            "low_contrast_dark": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><circle cx="64" cy="64" r="30" fill="#18181B"/></svg>',
                "fails contrast on #09090B",
            ),
            "implicit_black_fill": (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128"><circle cx="64" cy="64" r="30"/></svg>',
                "fails contrast on #09090B",
            ),
        }
        with tempfile.TemporaryDirectory() as tmp:
            for name, (payload, expected_substr) in cases.items():
                p = Path(tmp) / f"{name}.svg"
                p.write_text(payload, encoding="utf-8")
                errs = validate_svg_logo(p)
                self.assertTrue(
                    any(expected_substr in e for e in errs),
                    f"Expected SVG case {name!r} to report {expected_substr!r}; got {errs}",
                )

            oversized = Path(tmp) / "oversized.svg"
            pad_comment = "<!-- " + ("a" * 17000) + " -->"
            oversized.write_text(
                f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">{pad_comment}<circle cx="64" cy="64" r="30" fill="#1E6FD9"/></svg>',
                encoding="utf-8",
            )
            self.assertTrue(any("exceeds" in e for e in validate_svg_logo(oversized)))

    def test_wcag_contrast_ratio_matches_reference_anchors(self) -> None:
        self.assertAlmostEqual(wcag_contrast_ratio("#000000", "#FFFFFF"), 21.0, places=2)
        self.assertAlmostEqual(wcag_contrast_ratio("#FFFFFF", "#777777"), 4.48, places=2)


class TestStandaloneBuildArchiveAndValidation(unittest.TestCase):
    def test_all_four_packs_build_validate_and_archive_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_a = Path(tmp) / "run_a"
            out_b = Path(tmp) / "run_b"

            summary_a = build_all_plugin_packs(
                REPO_ROOT,
                out_a,
                create_zip=True,
                validate=True,
                source_date_epoch=1795392000,
            )
            # Mutate file mtimes across distinct years (2020 vs 2025) to prove strict timestamp independence
            for fp in (out_a / "ui-refinery").rglob("*"):
                if fp.is_file():
                    os.utime(fp, (1577836800, 1577836800))  # 2020-01-01
            zip_2020, _ = archive_plugin_pack(out_a / "ui-refinery", Path(tmp) / "repack_2020.zip", source_date_epoch=1795392000)
            for fp in (out_a / "ui-refinery").rglob("*"):
                if fp.is_file():
                    os.utime(fp, (1735689600, 1735689600))  # 2025-01-01
            zip_2025, _ = archive_plugin_pack(out_a / "ui-refinery", Path(tmp) / "repack_2025.zip", source_date_epoch=1795392000)
            self.assertEqual(zip_2020.read_bytes(), zip_2025.read_bytes())
            with zipfile.ZipFile(zip_2025, "r") as zf_chk:
                for info in zf_chk.infolist():
                    self.assertEqual(info.date_time, (2026, 11, 23, 0, 0, 0))
            with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "not-an-int"}):
                with self.assertRaises(ValueError):
                    archive_plugin_pack(out_a / "ui-refinery", Path(tmp) / "bad_epoch.zip")
            with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "100"}):
                zip_pre80, _ = archive_plugin_pack(out_a / "ui-refinery", Path(tmp) / "pre80.zip")
                with zipfile.ZipFile(zip_pre80, "r") as zf_80:
                    self.assertEqual(zf_80.infolist()[0].date_time, (1980, 1, 1, 0, 0, 0))

            for pack_name in PLUGIN_CATALOG:
                self.assertTrue(summary_a[pack_name]["ok"], summary_a[pack_name])
                self.assertTrue(summary_a[pack_name]["dir_validation"]["ok"])
                self.assertTrue(summary_a[pack_name]["zip_validation"]["ok"])

            summary_b = build_all_plugin_packs(
                REPO_ROOT,
                out_b,
                create_zip=True,
                validate=True,
                source_date_epoch=1795392000,
            )
            for pack_name in PLUGIN_CATALOG:
                zip_a = Path(summary_a[pack_name]["zip"])
                zip_b = Path(summary_b[pack_name]["zip"])
                sha_a = Path(summary_a[pack_name]["sha256_file"]).read_text(encoding="utf-8")
                sha_b = Path(summary_b[pack_name]["sha256_file"]).read_text(encoding="utf-8")
                self.assertEqual(zip_a.read_bytes(), zip_b.read_bytes(), f"Non-deterministic zip for {pack_name}")
                self.assertEqual(sha_a, sha_b)
                self.assertIn(f"  {zip_a.name}\n", sha_a)

            # Verify ui-refinery portable MCP config and live bundled contrast-check selftest
            ui_refinery_dir = out_a / "ui-refinery"
            mcp_cfg = json.loads((ui_refinery_dir / "mcp_config.json").read_text(encoding="utf-8"))
            self.assertEqual(
                mcp_cfg,
                {
                    "mcpServers": {
                        "contrast": {
                            "command": "python3",
                            "args": ["${PLUGIN_ROOT}/skills/ui-refinery/scripts/contrast-mcp.py"],
                        }
                    }
                },
            )
            self.assertFalse((ui_refinery_dir / "rules" / "AGENTS.md").exists())
            self.assertTrue((ui_refinery_dir / "skills" / "ui-refinery" / "references" / "DESIGN.md").is_file())
            ui_refinery_skill = (ui_refinery_dir / "skills" / "ui-refinery" / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn("[references/DESIGN.md](./references/DESIGN.md)", ui_refinery_skill)
            self.assertIn("ui-refinery_contrast", ui_refinery_skill)
            ui_refinery_readme = (ui_refinery_dir / "README.md").read_text(encoding="utf-8")
            self.assertIn("MCP server `contrast` (exposed by Antigravity as `ui-refinery_contrast`)", ui_refinery_readme)

            selftest = subprocess.run(
                [sys.executable, str(ui_refinery_dir / "skills" / "ui-refinery" / "scripts" / "contrast-check.py"), "--selftest"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(selftest.returncode, 0, selftest.stdout + selftest.stderr)

            # Verify rust-suite bundles vulkan template exclusively
            self.assertTrue((out_a / "rust-suite" / "skills" / "rust-harden" / "assets" / "vulkan.SKILL.template.md").is_file())
            self.assertFalse((out_a / "game-engineering" / "skills" / "game-engineering" / "assets").exists())

            # Verify media-studio depth-aware relative paths + plugin-layout $HOME fallback
            ms_skill = (out_a / "media-studio" / "skills" / "media-studio" / "SKILL.md").read_text(encoding="utf-8")
            ms_ref = (out_a / "media-studio" / "skills" / "media-studio" / "references" / "salvage-and-enhancement.md").read_text(encoding="utf-8")
            self.assertIn('MEDIA_QC="./scripts/media_qc.py"', ms_skill)
            self.assertIn('MEDIA_QC="../scripts/media_qc.py"', ms_ref)
            self.assertIn("$HOME/.gemini/config/plugins/media-studio/skills/media-studio/scripts/media_qc.py", ms_skill)
            self.assertNotIn("$HOME/.gemini/config/skills/media-studio", ms_skill)
            self.assertNotIn("$HOME/.gemini/config/skills/media-studio", ms_ref)

            # Verify rewrite_plugin_markdown is strictly idempotent across all built plugin markdown files
            for pack_name in PLUGIN_CATALOG:
                pdir = out_a / pack_name
                for md in sorted(pdir.rglob("*.md")):
                    rel = md.relative_to(pdir).as_posix()
                    content = md.read_text(encoding="utf-8")
                    self.assertEqual(rewrite_plugin_markdown(content, pack_name, rel), content, f"Not idempotent: {pack_name}/{rel}")

    def test_local_mcp_python_resolution_frozen_and_non_frozen(self) -> None:
        self.assertEqual(resolve_local_python_command("/custom/bin/py3"), "/custom/bin/py3")
        with mock.patch.object(sys, "frozen", False, create=True):
            self.assertEqual(resolve_local_python_command(None), sys.executable)
        with mock.patch.object(sys, "frozen", True, create=True), mock.patch("guard.plugins.os.name", "nt"), mock.patch(
            "guard.plugins.shutil.which", return_value=None
        ):
            self.assertEqual(resolve_local_python_command(None), "python")
        with mock.patch.object(sys, "frozen", True, create=True), mock.patch("guard.plugins.os.name", "posix"), mock.patch(
            "guard.plugins.shutil.which", return_value="/usr/bin/python3"
        ):
            self.assertEqual(resolve_local_python_command(None), "/usr/bin/python3")

        with tempfile.TemporaryDirectory() as tmp:
            dest = build_plugin_pack(
                "ui-refinery",
                REPO_ROOT,
                Path(tmp) / "ui-refinery",
                portable_mcp=False,
                python_executable="/opt/py/bin/python3",
            )
            mcp = json.loads((dest / "mcp_config.json").read_text(encoding="utf-8"))
            self.assertEqual(mcp["mcpServers"]["contrast"]["command"], "/opt/py/bin/python3")

    def test_atomic_rebuild_overwrites_cleanly_without_leftover_staging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            dest = parent / "game-engineering"
            build_plugin_pack("game-engineering", REPO_ROOT, dest)
            (dest / "stale_marker.txt").write_text("old", encoding="utf-8")

            build_plugin_pack("game-engineering", REPO_ROOT, dest)
            self.assertFalse((dest / "stale_marker.txt").exists())
            self.assertEqual([p.name for p in parent.iterdir()], ["game-engineering"])
            self.assertTrue(validate_plugin_dir(dest, expected_pack="game-engineering").ok)


class TestSecurityAndNegativeValidationControls(unittest.TestCase):
    def test_build_rejects_symlink_target_and_symlink_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # 1. Symlink destination rejected
            real_target = tmp_path / "real"
            real_target.mkdir()
            link_target = tmp_path / "link_dest"
            link_target.symlink_to(real_target)
            with self.assertRaises(ValueError):
                build_plugin_pack("game-engineering", REPO_ROOT, link_target)

            # 2. Regular file destination rejected
            file_target = tmp_path / "file_dest"
            file_target.write_text("not a dir", encoding="utf-8")
            with self.assertRaises(ValueError):
                build_plugin_pack("game-engineering", REPO_ROOT, file_target)

            # 3. Symlink inside skill source rejected
            fake_repo = tmp_path / "fake_repo"
            shutil.copytree(REPO_ROOT / "skills" / "game-engineering", fake_repo / "skills" / "game-engineering")
            shutil.copytree(REPO_ROOT / "guard" / "plugin_assets", fake_repo / "guard" / "plugin_assets")
            (fake_repo / "skills" / "game-engineering" / "evil_link.md").symlink_to(file_target)
            with self.assertRaises(ValueError):
                build_plugin_pack("game-engineering", fake_repo, tmp_path / "out_ge")

    def test_validate_plugin_dir_catches_schema_brand_link_and_standalone_violations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "game-engineering"
            build_plugin_pack("game-engineering", REPO_ROOT, base)
            self.assertTrue(validate_plugin_dir(base, expected_pack="game-engineering").ok)

            # 1. additionalProperties violation
            pj = base / "plugin.json"
            orig_manifest = json.loads(pj.read_text(encoding="utf-8"))
            bad_extra = dict(orig_manifest, unexpectedField=True)
            pj.write_text(json.dumps(bad_extra), encoding="utf-8")
            res = validate_plugin_dir(base, expected_pack="game-engineering")
            self.assertFalse(res.ok)
            self.assertTrue(any("additionalProperties" in e for e in res.errors), res.errors)

            # 2. Banned brand prefix in displayName
            bad_brand = dict(orig_manifest, displayName="Antigravity Game Kit")
            pj.write_text(json.dumps(bad_brand), encoding="utf-8")
            res = validate_plugin_dir(base, expected_pack="game-engineering")
            self.assertFalse(res.ok)
            self.assertTrue(any("banned brand prefix" in e for e in res.errors), res.errors)
            pj.write_text(json.dumps(orig_manifest), encoding="utf-8")

            # 3. Standalone Markdown violations (tilde path, bare scripts/, broken link, mandatory plumb-guard)
            skill_md = base / "skills" / "game-engineering" / "SKILL.md"
            orig_skill = skill_md.read_text(encoding="utf-8")
            skill_md.write_text(
                orig_skill
                + "\nSee ~/.gemini/config/skills/harness/SKILL.md and scripts/foo.py and [dead](./missing.md)\n"
                + "Run `plumb-guard ui-slop index.html`.\n"
                + "```bash\nplumb-guard verify\n```\n",
                encoding="utf-8",
            )
            res = validate_plugin_dir(base, expected_pack="game-engineering")
            self.assertFalse(res.ok)
            joined = "\n".join(res.errors)
            self.assertIn("~/.gemini/config/", joined)
            self.assertIn("bare scripts/...", joined)
            self.assertIn("broken relative markdown link", joined)
            self.assertIn("unqualified mandatory", joined)
            self.assertIn("mandatory uncommented", joined)
            skill_md.write_text(orig_skill, encoding="utf-8")

            # 4. Forbidden __pycache__ artifact
            (base / "skills" / "game-engineering" / "__pycache__").mkdir()
            res = validate_plugin_dir(base, expected_pack="game-engineering")
            self.assertFalse(res.ok)
            self.assertTrue(any("__pycache__" in e for e in res.errors), res.errors)
            (base / "skills" / "game-engineering" / "__pycache__").rmdir()

            # 5. Missing POSIX executable bit on bundled script
            if os.name != "nt":
                ms_dir = Path(tmp) / "media-studio"
                build_plugin_pack("media-studio", REPO_ROOT, ms_dir)
                script_p = ms_dir / "skills" / "media-studio" / "scripts" / "media_qc.py"
                os.chmod(script_p, 0o644)
                res_ms = validate_plugin_dir(ms_dir, expected_pack="media-studio")
                self.assertFalse(res_ms.ok)
                self.assertTrue(any("executable bit" in e for e in res_ms.errors), res_ms.errors)

    def test_validate_plugin_zip_rejects_traversal_symlink_bad_perms_and_bad_sha(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ms_dir = build_plugin_pack("media-studio", REPO_ROOT, tmp_path / "media-studio")
            good_zip, good_sha = archive_plugin_pack(ms_dir, tmp_path / "media-studio.zip")
            self.assertTrue(validate_plugin_zip(good_zip, expected_pack="media-studio", sha256_path=good_sha).ok)

            # 1. Single-space sha256 rejected
            bad_sha = tmp_path / "bad.sha256"
            digest = hashlib.sha256(good_zip.read_bytes()).hexdigest()
            bad_sha.write_text(f"{digest} {good_zip.name}\n", encoding="utf-8")
            res = validate_plugin_zip(good_zip, expected_pack="media-studio", sha256_path=bad_sha)
            self.assertFalse(res.ok)
            self.assertTrue(any("SHA-256" in e for e in res.errors), res.errors)

            # 2. Path traversal entry rejected
            trav_zip = tmp_path / "trav.zip"
            with zipfile.ZipFile(trav_zip, "w") as zf:
                info = zipfile.ZipInfo("media-studio/../escape.txt")
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                zf.writestr(info, b"x")
            res = validate_plugin_zip(trav_zip, expected_pack="media-studio")
            self.assertFalse(res.ok)
            self.assertTrue(any("traversal" in e.lower() for e in res.errors), res.errors)

            # 3. Symlink entry rejected
            sym_zip = tmp_path / "sym.zip"
            with zipfile.ZipFile(sym_zip, "w") as zf:
                info = zipfile.ZipInfo("media-studio/link.txt")
                info.create_system = 3
                info.external_attr = 0o120777 << 16
                zf.writestr(info, b"/etc/passwd")
            res = validate_plugin_zip(sym_zip, expected_pack="media-studio")
            self.assertFalse(res.ok)
            self.assertTrue(any("Symlink" in e for e in res.errors), res.errors)

            # 4. Non-executable script mode or wrong create_system rejected
            perm_zip = tmp_path / "perm.zip"
            with zipfile.ZipFile(good_zip, "r") as src, zipfile.ZipFile(perm_zip, "w") as dst:
                for info in src.infolist():
                    data = src.read(info)
                    clone = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                    clone.create_system = 0 if info.filename.endswith("README.md") else 3
                    clone.external_attr = (0o100644 << 16) if info.filename.endswith("media_qc.py") else info.external_attr
                    dst.writestr(clone, data)
            res = validate_plugin_zip(perm_zip, expected_pack="media-studio")
            self.assertFalse(res.ok)
            joined = "\n".join(res.errors)
            self.assertIn("create_system=0", joined)
            self.assertIn("expected 0o755", joined)


class TestRewriteCoreForHybrid(unittest.TestCase):
    def test_table_driven_rewrites_and_exclusions(self) -> None:
        cases = [
            (
                "skills/harness/SKILL.md",
                "See `~/.gemini/config/skills/rustify/SKILL.md` and `~/.gemini/config/skills/harness/SKILL.md`.",
                "See `~/.gemini/config/plugins/rust-suite/skills/rustify/SKILL.md` and `~/.gemini/config/skills/harness/SKILL.md`.",
            ),
            (
                "DESIGN.md",
                "Pairs with `skills/ui-refinery/references/motion-physics.md` and `skills/vibecoder/SKILL.md`.",
                "Pairs with `plugins/ui-refinery/skills/ui-refinery/references/motion-physics.md` and `plugins/ui-refinery/skills/vibecoder/SKILL.md`.",
            ),
            (
                "skills/upstream-auditor/SKILL.md",
                "Ref `~/.gemini/config/skills/ui-refinery/references/{code-comments,ui}.md`.",
                "Ref `~/.gemini/config/plugins/ui-refinery/skills/ui-refinery/references/{code-comments,ui}.md`.",
            ),
            (
                "skills/upstream-auditor/upstream_state.seed.json",
                '{"tracked": ["skills/ui-refinery/references/motion-physics.md"]}',
                '{"tracked": ["skills/ui-refinery/references/motion-physics.md"]}',
            ),
        ]
        for rel_path, src, expected in cases:
            out = rewrite_core_for_hybrid(src, rel_path)
            self.assertEqual(out, expected, rel_path)
            # Strictly idempotent
            self.assertEqual(rewrite_core_for_hybrid(out, rel_path), expected, f"Non-idempotent: {rel_path}")

    def test_real_repo_core_files_resolve_into_built_packs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "plugins"
            build_all_plugin_packs(REPO_ROOT, out_dir, validate=True)

            core_mds = [REPO_ROOT / "DESIGN.md", REPO_ROOT / "templates" / "vulkan.SKILL.template.md"]
            for p in sorted((REPO_ROOT / "skills").rglob("*.md")):
                if p.relative_to(REPO_ROOT / "skills").parts[0] not in PLUGIN_OWNED_SKILL_SLUGS:
                    core_mds.append(p)

            rewritten_count = 0
            for md in core_mds:
                rel = md.relative_to(REPO_ROOT).as_posix()
                raw = md.read_text(encoding="utf-8")
                rewritten = rewrite_core_for_hybrid(raw, rel)
                self.assertEqual(rewrite_core_for_hybrid(rewritten, rel), rewritten, rel)
                if rewritten != raw:
                    rewritten_count += 1
                # No remaining flat ~/.gemini/config/skills/<plugin-owned>/ paths
                for slug in PLUGIN_OWNED_SKILL_SLUGS:
                    self.assertNotIn(f"~/.gemini/config/skills/{slug}/", rewritten, f"Dead flat path left in {rel}")
            self.assertGreaterEqual(rewritten_count, 9)


class TestBuildPluginsCliAndPyInstallerAssets(unittest.TestCase):
    def test_build_plugins_cli_all_and_single_pack(self) -> None:
        script = REPO_ROOT / "scripts" / "build_plugins.py"
        with tempfile.TemporaryDirectory() as tmp:
            out_all = Path(tmp) / "all"
            res = subprocess.run(
                [sys.executable, str(script), "--out", str(out_all), "--validate", "--zip", "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            payload = json.loads(res.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(set(payload["packs"].keys()), set(PLUGIN_CATALOG.keys()))
            for pack in PLUGIN_CATALOG:
                self.assertTrue((out_all / f"{pack}-v{HARNESS_VERSION}.zip").is_file())
                self.assertTrue((out_all / f"{pack}-v{HARNESS_VERSION}.zip.sha256").is_file())

            out_one = Path(tmp) / "one"
            res_one = subprocess.run(
                [sys.executable, str(script), "--out", str(out_one), "--pack", "ui-refinery", "--validate", "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res_one.returncode, 0, res_one.stdout + res_one.stderr)
            one_payload = json.loads(res_one.stdout)
            self.assertEqual(list(one_payload["packs"].keys()), ["ui-refinery"])

    def test_build_pyinstaller_command_bundles_all_plugin_svg_assets(self) -> None:
        self.assertEqual(
            set(build_binaries.PORTABLE_PLUGIN_ASSETS),
            {f"guard/plugin_assets/{fname}" for fname in PLUGIN_ASSET_FILENAMES},
        )
        _lin_name, lin_cmd = build_binaries.build_pyinstaller_command(REPO_ROOT, "Linux", "x86_64", "/usr/bin/pyinstaller")
        _win_name, win_cmd = build_binaries.build_pyinstaller_command(REPO_ROOT, "Windows", "x86_64", "pyinstaller.exe")
        for fname in PLUGIN_ASSET_FILENAMES:
            self.assertTrue(any(f"{fname}:guard/plugin_assets" in tok for tok in lin_cmd), (fname, lin_cmd))
            self.assertTrue(any(f"{fname};guard/plugin_assets" in tok for tok in win_cmd), (fname, win_cmd))


class _IsolatedHybridEnvMixin:
    """Provides a hermetic HOME/config/state/data sandbox cleaned up with write-release."""

    def _setup_sandbox(self, prefix: str) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix=prefix))
        self.home = self.tmp / "home"
        self.cfg = self.home / ".gemini" / "config"
        self.state = self.tmp / "state"
        self.data = self.tmp / "data"
        self.cfg.mkdir(parents=True)
        self.state.mkdir(parents=True)
        self.data.mkdir(parents=True)
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "LOCALAPPDATA": str(self.tmp / "localappdata"),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg),
                "PLUMB_GUARD_STATE_DIR": str(self.state),
                "PLUMB_GUARD_DATA_DIR": str(self.data),
                "PLUMB_GUARD_NOTIFY": "off",
            },
            clear=False,
        )
        self._env_patch.start()

    def _teardown_sandbox(self) -> None:
        self._env_patch.stop()
        hermetic.force_rmtree(self.tmp)


class TestEnvironmentPluginSeamsAndMcpMigration(_IsolatedHybridEnvMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._setup_sandbox("agy_hyb_env_")

    def tearDown(self) -> None:
        self._teardown_sandbox()

    def test_antigravity_seams_include_existing_or_receipted_packs_and_keep_parent_writable(self) -> None:
        self.assertIn("plugins", ANTIGRAVITY_RUNTIME_ENTRIES)
        self.assertEqual(antigravity_plugin_governance_seams(self.cfg), [])

        # Third-party plugins/rea is never included in antigravity governance paths
        (self.cfg / "plugins" / "rea").mkdir(parents=True)
        (self.cfg / "plugins" / "rea" / "plugin.json").write_text('{"name":"rea"}\n', encoding="utf-8")
        self.assertEqual(antigravity_plugin_governance_seams(self.cfg), [])

        # Existing harness pack joins governance paths; plugins/ root stays excluded
        (self.cfg / "plugins" / "ui-refinery").mkdir(parents=True)
        seams = antigravity_plugin_governance_seams(self.cfg)
        self.assertEqual(seams, ["plugins/ui-refinery"])
        env = default_antigravity_environment(self.cfg)
        self.assertIn("plugins/ui-refinery", env.governance_paths)
        self.assertNotIn("plugins", env.governance_paths)
        self.assertNotIn("plugins/rea", env.governance_paths)

        # Receipted pack stays in scope even if deleted from disk (so FIM catches deletion)
        receipt = self.state / "install_receipt.json"
        receipt.write_text(
            json.dumps(
                {
                    "target": str(self.cfg),
                    "layout": "hybrid",
                    "installed_plugins": ["ui-refinery", "rust-suite", "third-party-ignored"],
                }
            ),
            encoding="utf-8",
        )
        reg = EnvironmentRegistry()
        ag_env = reg.get_environment("antigravity")
        assert ag_env is not None
        self.assertIn("plugins/ui-refinery", ag_env.governance_paths)
        self.assertIn("plugins/rust-suite", ag_env.governance_paths)
        self.assertNotIn("plugins/third-party-ignored", ag_env.governance_paths)

        # Removing packs on disk + flat receipt prunes harness plugin seams cleanly
        shutil.rmtree(self.cfg / "plugins" / "ui-refinery")
        receipt.write_text(
            json.dumps({"target": str(self.cfg), "layout": "flat", "installed_plugins": []}),
            encoding="utf-8",
        )
        pruned = sync_antigravity_plugin_seams(ag_env)
        self.assertEqual(pruned, [])
        self.assertNotIn("plugins/ui-refinery", ag_env.governance_paths)
        self.assertNotIn("plugins/rust-suite", ag_env.governance_paths)

        # Symlinked plugins/ root is not traversed
        if hasattr(os, "symlink"):
            sym_cfg = self.tmp / "sym_plugins_cfg"
            sym_cfg.mkdir()
            outside = self.tmp / "outside_plugins"
            (outside / "ui-refinery").mkdir(parents=True)
            (sym_cfg / "plugins").symlink_to(outside, target_is_directory=True)
            self.assertEqual(antigravity_plugin_governance_seams(sym_cfg, include_receipt=False), [])

    def test_migrate_mcp_retires_all_harness_contrast_variants_and_restores_frozen_safe(self) -> None:
        mcp = self.cfg / "mcp_config.json"
        initial = {
            "mcpServers": {
                "ui-refinery-contrast": {
                    "command": "python3",
                    "args": [str(self.cfg / "skills" / "ui-refinery" / "scripts" / "contrast-mcp.py")],
                },
                "antislop-human": {
                    "command": "python3",
                    "args": [str(self.cfg / "skills" / "antislop-human" / "contrast-mcp.py")],
                },
                "custom-repo-contrast": {
                    "command": "/usr/bin/python3",
                    "args": ["-u", str(REPO_ROOT / "skills" / "ui-refinery" / "scripts" / "contrast-mcp.py")],
                },
                "custom-third-party": {
                    "command": "node",
                    "args": ["/opt/custom/server.js"],
                },
            }
        }
        mcp.write_text(json.dumps(initial), encoding="utf-8")

        # 1. Dry-run populates retired_out without touching mcp_config.json or calling backup_fn
        dry_retired: list[str] = []
        backup_calls: list[Path] = []
        dry_res = migrate_harness_mcp_config(
            self.cfg,
            REPO_ROOT,
            dry_run=True,
            backup_fn=backup_calls.append,
            retire_plugin_mcp=HARNESS_PLUGIN_NAMES,
            retired_out=dry_retired,
        )
        self.assertIs(dry_res, True)
        self.assertEqual(dry_retired, ["ui-refinery-contrast", "antislop-human", "custom-repo-contrast"])
        self.assertEqual(backup_calls, [])
        self.assertEqual(json.loads(mcp.read_text(encoding="utf-8")), initial)

        # 2. Live retirement backs up once, retires all 3 harness keys, keeps third-party untouched
        live_retired: list[str] = []
        live_res = migrate_harness_mcp_config(
            self.cfg,
            REPO_ROOT,
            dry_run=False,
            backup_fn=backup_calls.append,
            retire_plugin_mcp=HARNESS_PLUGIN_NAMES,
            retired_out=live_retired,
        )
        self.assertIs(live_res, True)
        self.assertEqual(live_retired, ["ui-refinery-contrast", "antislop-human", "custom-repo-contrast"])
        self.assertEqual(backup_calls, [mcp])
        after_retire = json.loads(mcp.read_text(encoding="utf-8"))
        self.assertEqual(list(after_retire["mcpServers"].keys()), ["custom-third-party"])

        # Idempotent second call returns strict False
        again = migrate_harness_mcp_config(
            self.cfg,
            REPO_ROOT,
            dry_run=False,
            retire_plugin_mcp=HARNESS_PLUGIN_NAMES,
        )
        self.assertIs(again, False)

        # 3. Retiring sole entry preserves {"mcpServers": {}} (never deletes mcp_config.json)
        sole_cfg = self.tmp / "sole_mcp_cfg"
        sole_cfg.mkdir()
        sole_mcp = sole_cfg / "mcp_config.json"
        sole_mcp.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "only-contrast": {
                            "command": "python3",
                            "args": [str(sole_cfg / "skills" / "antislop-human" / "contrast-mcp.py")],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        self.assertIs(
            migrate_harness_mcp_config(sole_cfg, REPO_ROOT, dry_run=False, retire_plugin_mcp=True),
            True,
        )
        self.assertTrue(sole_mcp.is_file())
        self.assertEqual(json.loads(sole_mcp.read_text(encoding="utf-8")), {"mcpServers": {}})

        # 4. Restore flat keys (non-frozen, frozen POSIX, frozen Windows, and missing mcp_config.json)
        flat_script = self.cfg / "skills" / "ui-refinery" / "scripts" / "contrast-mcp.py"
        flat_script.parent.mkdir(parents=True, exist_ok=True)
        flat_script.write_text("# contrast mcp\n", encoding="utf-8")

        restored_res = migrate_harness_mcp_config(
            self.cfg,
            REPO_ROOT,
            dry_run=False,
            restore_flat_keys=live_retired,
        )
        self.assertIs(restored_res, True)
        restored_servers = json.loads(mcp.read_text(encoding="utf-8"))["mcpServers"]
        for key in live_retired:
            self.assertIn(key, restored_servers)
            self.assertEqual(restored_servers[key]["command"], sys.executable)
            self.assertEqual(restored_servers[key]["args"], [str(flat_script)])
        self.assertIn("custom-third-party", restored_servers)

        # Frozen restore resolves python via shutil.which (never sys.executable frozen binary)
        mcp.unlink()
        with mock.patch.object(sys, "frozen", True, create=True), mock.patch(
            "guard.plugins.shutil.which", return_value="/usr/bin/python3"
        ):
            self.assertIs(
                migrate_harness_mcp_config(
                    self.cfg,
                    REPO_ROOT,
                    dry_run=False,
                    python_executable=sys.executable,
                    restore_flat_keys=["ui-refinery-contrast"],
                ),
                True,
            )
        frozen_which = json.loads(mcp.read_text(encoding="utf-8"))["mcpServers"]["ui-refinery-contrast"]
        self.assertEqual(frozen_which["command"], "/usr/bin/python3")

        # Frozen restore falls back to bare platform interpreter when shutil.which returns None
        mcp.unlink()
        with mock.patch.object(sys, "frozen", True, create=True), mock.patch(
            "guard.plugins.shutil.which", return_value=None
        ):
            self.assertIs(
                migrate_harness_mcp_config(
                    self.cfg,
                    REPO_ROOT,
                    dry_run=False,
                    python_executable=sys.executable,
                    restore_flat_keys=["ui-refinery-contrast"],
                ),
                True,
            )
        frozen_fallback = json.loads(mcp.read_text(encoding="utf-8"))["mcpServers"]["ui-refinery-contrast"]
        self.assertEqual(frozen_fallback["command"], "python" if os.name == "nt" else "python3")

        # 5. Poka-yoke: passing both retire_plugin_mcp and restore_flat_keys fails loudly
        with self.assertRaises(ValueError):
            migrate_harness_mcp_config(
                self.cfg,
                REPO_ROOT,
                retire_plugin_mcp=HARNESS_PLUGIN_NAMES,
                restore_flat_keys=["ui-refinery-contrast"],
            )


class TestHybridInstallAndRoundTrip(_IsolatedHybridEnvMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._setup_sandbox("agy_hyb_inst_")

    def tearDown(self) -> None:
        self._teardown_sandbox()

    def test_opt_in_plugins_upgrade_without_receipt_lock_fim_bootcheck_idempotency_and_flat_revert(self) -> None:
        # Seed a receiptless pre-hybrid Flat installation + custom skill + third-party rea + legacy MCP
        for slug in PLUGIN_OWNED_SKILL_SLUGS:
            sdir = self.cfg / "skills" / slug
            sdir.mkdir(parents=True, exist_ok=True)
            (sdir / "SKILL.md").write_text(f"---\nname: {slug}\ndescription: old\n---\n", encoding="utf-8")
        custom_skill = self.cfg / "skills" / "my-custom-skill"
        custom_skill.mkdir(parents=True, exist_ok=True)
        (custom_skill / "SKILL.md").write_text("---\nname: my-custom-skill\ndescription: keep\n---\n", encoding="utf-8")
        rea_dir = self.cfg / "plugins" / "rea"
        rea_dir.mkdir(parents=True, exist_ok=True)
        (rea_dir / "plugin.json").write_text('{"name":"rea","version":"1.0.0"}\n', encoding="utf-8")
        mcp_path = self.cfg / "mcp_config.json"
        orig_mcp = {
            "mcpServers": {
                "antislop-human": {
                    "command": "python3",
                    "args": [str(self.cfg / "skills" / "antislop-human" / "contrast-mcp.py")],
                },
                "third-party-mcp": {"command": "node", "args": ["/opt/ext/mcp.js"]},
            }
        }
        mcp_path.write_text(json.dumps(orig_mcp), encoding="utf-8")
        self.assertFalse((self.state / "install_receipt.json").exists())

        # 1. Dry-run --plugins writes nothing and preserves all pre-existing files
        dry_buf = io.StringIO()
        with contextlib.redirect_stdout(dry_buf):
            rc_dry = harness_install.main(["--plugins", "--dry-run"])
        self.assertEqual(rc_dry, 0)
        self.assertTrue((self.cfg / "skills" / "ui-refinery" / "SKILL.md").is_file())
        self.assertFalse((self.cfg / "plugins" / "ui-refinery").exists())
        self.assertEqual(json.loads(mcp_path.read_text(encoding="utf-8")), orig_mcp)
        self.assertFalse((self.state / "install_receipt.json").exists())
        self.assertIn("[DRY-RUN]", dry_buf.getvalue())

        # 2. Live --plugins upgrade (without prior receipt)
        with mock.patch.object(harness_install, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ):
            rc_hyb = harness_install.main(["--plugins"])
        self.assertEqual(rc_hyb, 0)

        # Verify 14 core skills + custom skill only; 6 old plugin-owned skills moved to external backup
        installed_skills = {p.name for p in (self.cfg / "skills").iterdir() if p.is_dir()}
        self.assertEqual(len(installed_skills - {"my-custom-skill"}), 14)
        self.assertIn("my-custom-skill", installed_skills)
        self.assertEqual(installed_skills & set(PLUGIN_OWNED_SKILL_SLUGS), set())
        receipt = json.loads((self.state / "install_receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["layout"], "hybrid")
        self.assertEqual(receipt["installed_plugins"], sorted(PLUGIN_CATALOG.keys()))
        self.assertEqual(receipt["retired_mcp_servers"], ["antislop-human"])
        bdir = Path(receipt["backup_dir"])
        for slug in PLUGIN_OWNED_SKILL_SLUGS:
            self.assertTrue((bdir / "skills" / slug / "SKILL.md").is_file(), f"Missing backup for {slug}")

        # Verify 4 packs built & valid; third-party rea preserved & writable; plugins/ parent writable
        for pack in PLUGIN_CATALOG:
            pdir = self.cfg / "plugins" / pack
            self.assertTrue(pdir.is_dir() and not os.path.islink(pdir))
            val = validate_plugin_dir(pdir, expected_pack=pack)
            self.assertTrue(val.ok, f"Pack {pack} failed validation: {val.errors}")
        self.assertTrue((rea_dir / "plugin.json").is_file())
        if os.name != "nt":
            self.assertTrue(os.access(self.cfg / "plugins", os.W_OK))
            self.assertTrue(os.access(rea_dir, os.W_OK))
            self.assertFalse(os.access(self.cfg / "plugins" / "ui-refinery" / "plugin.json", os.W_OK))
            # POSIX 0755 executable bit set on scripts in both skills/ and plugins/
            for script_rel in (
                "skills/upstream-auditor/scripts/upstream_watcher.py",
                "plugins/ui-refinery/skills/ui-refinery/scripts/contrast-mcp.py",
                "plugins/ui-refinery/skills/ui-refinery/scripts/check_ui_slop.py",
                "plugins/media-studio/skills/media-studio/scripts/media_qc.py",
            ):
                mode = (self.cfg / script_rel).stat().st_mode
                self.assertTrue(bool(mode & stat.S_IXUSR), f"Expected +x on {script_rel}")

        # Core files rewritten for hybrid; upstream_state.seed.json excluded
        harness_md = (self.cfg / "skills" / "harness" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("~/.gemini/config/plugins/rust-suite/skills/rustify/SKILL.md", harness_md)
        self.assertNotIn("~/.gemini/config/skills/rustify/", harness_md)
        design_md = (self.cfg / "DESIGN.md").read_text(encoding="utf-8")
        self.assertIn("plugins/ui-refinery/skills/ui-refinery/", design_md)
        seed_installed = (self.cfg / "skills" / "upstream-auditor" / "upstream_state.seed.json").read_bytes()
        seed_repo = (REPO_ROOT / "skills" / "upstream-auditor" / "upstream_state.seed.json").read_bytes()
        self.assertEqual(seed_installed, seed_repo)

        # Global MCP retired ui-refinery-human; plugin MCP pins sys.executable
        mcp_after = json.loads(mcp_path.read_text(encoding="utf-8"))["mcpServers"]
        self.assertNotIn("antislop-human", mcp_after)
        self.assertIn("third-party-mcp", mcp_after)
        plugin_mcp = json.loads((self.cfg / "plugins" / "ui-refinery" / "mcp_config.json").read_text(encoding="utf-8"))
        self.assertEqual(plugin_mcp["mcpServers"]["contrast"]["command"], sys.executable)

        # Single antigravity env locks + FIM verifies + doctor healthy + boot_check clean
        reg = EnvironmentRegistry()
        ag_env = reg.get_environment("antigravity")
        assert ag_env is not None
        for pack in PLUGIN_CATALOG:
            self.assertIn(f"plugins/{pack}", ag_env.governance_paths)
        self.assertTrue(reg.is_locked("antigravity")["antigravity"])
        self.assertEqual(reg.protection_issues(ag_env), [])
        fim = FileIntegrityMonitor.for_environment(ag_env, os_adapter=reg.os_adapter)
        fim_report = fim.verify()
        self.assertTrue(fim_report.is_intact, fim_report.summary())
        baseline_files = json.loads(fim.state_file.read_text(encoding="utf-8"))["files"]
        self.assertIn("plugins/ui-refinery/plugin.json", baseline_files)
        self.assertNotIn("plugins/rea/plugin.json", baseline_files)
        doc_rep = diagnose(ag_env, reg, sentinel_active=True)
        self.assertTrue(doc_rep.healthy, doc_rep.warnings)
        boot_ok, boot_msg = StartupManager(target_dir=self.cfg, registry=reg).execute_boot_check()
        self.assertTrue(boot_ok, boot_msg)

        # 3. Idempotent second --plugins run: zero new backup dir and retired_mcp_servers preserved
        with mock.patch.object(harness_install, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ):
            rc_idem = harness_install.main(["--plugins"])
        self.assertEqual(rc_idem, 0)
        receipt2 = json.loads((self.state / "install_receipt.json").read_text(encoding="utf-8"))
        self.assertIsNone(receipt2["backup_dir"])
        self.assertEqual(receipt2["retired_mcp_servers"], ["antislop-human"])
        self.assertTrue(EnvironmentRegistry().is_locked("antigravity")["antigravity"])

        # 3b. Bare upgrade (no flags) on an existing hybrid profile preserves hybrid layout (no double-load)
        sticky_buf = io.StringIO()
        with mock.patch.object(harness_install, "request_approval", return_value=True), contextlib.redirect_stdout(
            sticky_buf
        ):
            rc_sticky = harness_install.main([])
        self.assertEqual(rc_sticky, 0)
        self.assertIn("Preserving existing hybrid plugin layout", sticky_buf.getvalue())
        self.assertEqual(
            {p.name for p in (self.cfg / "skills").iterdir() if p.is_dir()} & set(PLUGIN_OWNED_SKILL_SLUGS),
            set(),
        )

        # 4. Lossless --flat-skills revert (AC-3)
        with mock.patch.object(harness_install, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ):
            rc_flat = harness_install.main(["--flat-skills"])
        self.assertEqual(rc_flat, 0)

        flat_skills = {p.name for p in (self.cfg / "skills").iterdir() if p.is_dir()}
        self.assertEqual(len(flat_skills - {"my-custom-skill"}), 20)
        for slug in PLUGIN_OWNED_SKILL_SLUGS:
            self.assertIn(slug, flat_skills)
        for pack in PLUGIN_CATALOG:
            self.assertFalse((self.cfg / "plugins" / pack).exists())
        self.assertTrue((rea_dir / "plugin.json").is_file())
        harness_flat_md = (self.cfg / "skills" / "harness" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("~/.gemini/config/skills/rustify/SKILL.md", harness_flat_md)
        self.assertNotIn("plugins/rust-suite", harness_flat_md)

        mcp_restored = json.loads(mcp_path.read_text(encoding="utf-8"))["mcpServers"]
        self.assertIn("antislop-human", mcp_restored)
        self.assertEqual(mcp_restored["antislop-human"]["command"], sys.executable)
        self.assertEqual(
            mcp_restored["antislop-human"]["args"],
            [str(self.cfg.resolve() / "skills" / "ui-refinery" / "scripts" / "contrast-mcp.py")],
        )
        self.assertIn("third-party-mcp", mcp_restored)

        receipt_flat = json.loads((self.state / "install_receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt_flat["layout"], "flat")
        self.assertEqual(receipt_flat["installed_plugins"], [])
        self.assertEqual(receipt_flat["retired_mcp_servers"], [])

        reg_flat = EnvironmentRegistry()
        ag_flat = reg_flat.get_environment("antigravity")
        assert ag_flat is not None
        for pack in PLUGIN_CATALOG:
            self.assertNotIn(f"plugins/{pack}", ag_flat.governance_paths)
        self.assertTrue(reg_flat.is_locked("antigravity")["antigravity"])
        self.assertTrue(FileIntegrityMonitor.for_environment(ag_flat, os_adapter=reg_flat.os_adapter).verify().is_intact)
        self.assertTrue(diagnose(ag_flat, reg_flat, sentinel_active=True).healthy)

    def test_install_link_plugins_real_copies_and_symlink_or_file_collision_handling(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = harness_install.main(["--link", "--plugins", "--no-lock"])
        self.assertEqual(rc, 0)
        self.assertIn("[NOTICE]", buf.getvalue())
        for pack in PLUGIN_CATALOG:
            pdir = self.cfg / "plugins" / pack
            self.assertTrue(pdir.is_dir() and not os.path.islink(pdir))
        self.assertFalse(os.path.islink(self.cfg / "DESIGN.md"))
        self.assertIn("plugins/ui-refinery/skills/ui-refinery/", (self.cfg / "DESIGN.md").read_text(encoding="utf-8"))
        if hasattr(os, "symlink") and os.name != "nt":
            self.assertTrue(os.path.islink(self.cfg / "agents" / "research.md"))

        # Symlink & regular file collision at plugins/<pack> are backed up safely without following
        outside = self.tmp / "outside_pack"
        outside.mkdir()
        (outside / "keep.txt").write_text("do-not-touch", encoding="utf-8")
        shutil.rmtree(self.cfg / "plugins" / "ui-refinery")
        if hasattr(os, "symlink"):
            (self.cfg / "plugins" / "ui-refinery").symlink_to(outside, target_is_directory=True)
        shutil.rmtree(self.cfg / "plugins" / "game-engineering")
        (self.cfg / "plugins" / "game-engineering").write_text("file-collision", encoding="utf-8")

        with contextlib.redirect_stdout(io.StringIO()):
            rc_coll = harness_install.main(["--plugins", "--no-lock"])
        self.assertEqual(rc_coll, 0)
        self.assertEqual((outside / "keep.txt").read_text(encoding="utf-8"), "do-not-touch")
        self.assertTrue((self.cfg / "plugins" / "ui-refinery").is_dir() and not os.path.islink(self.cfg / "plugins" / "ui-refinery"))
        self.assertTrue((self.cfg / "plugins" / "game-engineering").is_dir())

        # Symlinked plugins/ root itself is rejected with exit code 1
        if hasattr(os, "symlink"):
            sym_cfg = self.tmp / "cfg_sym_root"
            sym_cfg.mkdir()
            (sym_cfg / "plugins").symlink_to(outside, target_is_directory=True)
            err_buf = io.StringIO()
            with mock.patch.dict(os.environ, {"ANTIGRAVITY_CONFIG_DIR": str(sym_cfg)}), contextlib.redirect_stdout(
                io.StringIO()
            ), contextlib.redirect_stderr(err_buf):
                rc_sym = harness_install.main(["--plugins", "--no-lock"])
            self.assertEqual(rc_sym, 1)
            self.assertIn("symbolic link or not a directory", err_buf.getvalue())
            self.assertEqual((outside / "keep.txt").read_text(encoding="utf-8"), "do-not-touch")

    def test_install_rollback_restores_state_files_and_removes_newly_created_config_json(self) -> None:
        # Establish clean locked Flat install first
        with mock.patch.object(harness_install, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ):
            self.assertEqual(harness_install.main([]), 0)
        # Remove config.json so the failing --plugins run creates it freshly
        cfg_json = self.cfg / "config.json"
        if cfg_json.exists():
            cfg_json.unlink()

        reg_path = self.state / "environments.json"
        receipt_path = self.state / "install_receipt.json"
        fim_path = self.state / "integrity" / "antigravity.json"
        pending_path = self.state / "integrity" / "antigravity.pending.json"
        pending_path.write_text('{"pending": true}\n', encoding="utf-8")

        before_reg = reg_path.read_bytes()
        before_receipt = receipt_path.read_bytes()
        before_fim = fim_path.read_bytes()
        before_pending = pending_path.read_bytes()
        before_skill = (self.cfg / "skills" / "ui-refinery" / "SKILL.md").read_bytes()

        # Fail right at save_baseline (after plugins, config.json, receipt, and registry.save() have run)
        with mock.patch.object(harness_install, "request_approval", return_value=True), mock.patch.object(
            FileIntegrityMonitor, "save_baseline", side_effect=RuntimeError("simulated baseline write crash")
        ), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                harness_install.main(["--plugins"])

        self.assertFalse(cfg_json.exists(), "Newly created config.json must be removed on rollback")
        self.assertFalse((self.cfg / "plugins").exists(), "Newly created plugins/ must be removed on rollback")
        self.assertEqual((self.cfg / "skills" / "ui-refinery" / "SKILL.md").read_bytes(), before_skill)
        self.assertEqual(reg_path.read_bytes(), before_reg)
        self.assertEqual(receipt_path.read_bytes(), before_receipt)
        self.assertEqual(fim_path.read_bytes(), before_fim)
        self.assertEqual(pending_path.read_bytes(), before_pending)
        reg_after = EnvironmentRegistry()
        self.assertTrue(reg_after.is_locked("antigravity")["antigravity"])
        self.assertTrue(FileIntegrityMonitor.for_environment(reg_after.get_environment("antigravity")).verify().is_intact)


class TestGuardInitHybridUninstallRollbackAndPortableScripts(_IsolatedHybridEnvMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._setup_sandbox("agy_hyb_cli_")

    def tearDown(self) -> None:
        self._teardown_sandbox()

    def test_cmd_init_hybrid_roundtrip_defensive_getattr_and_non_global_target_isolation(self) -> None:
        # 1. Seed a live global Flat install via plumb-guard init
        parser = guard_cli.build_parser()
        mcp_path = self.cfg / "mcp_config.json"
        mcp_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "ui-refinery-contrast": {
                            "command": "python3",
                            "args": [str(self.cfg / "skills" / "antislop-human" / "contrast-mcp.py")],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        with mock.patch.object(guard_cli, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ):
            rc_flat = guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT)]))
        self.assertEqual(rc_flat, 0)

        reg_path = self.state / "environments.json"
        receipt_path = self.state / "install_receipt.json"
        fim_path = self.state / "integrity" / "antigravity.json"
        global_reg_bytes = reg_path.read_bytes()
        global_receipt_bytes = receipt_path.read_bytes()
        global_fim_bytes = fim_path.read_bytes()

        # 2. Non-global --target without --registry (both minimal Namespace without plugin attrs and --plugins) preserves live global state
        sandbox_flat = self.tmp / "sandbox_flat"
        minimal_ns = argparse.Namespace(
            target=str(sandbox_flat),
            source=str(REPO_ROOT),
            dry_run=False,
            no_lock=True,
            uninstall=False,
        )
        with mock.patch.object(guard_cli, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ):
            self.assertEqual(guard_cli.cmd_init(minimal_ns), 0)
        self.assertEqual(reg_path.read_bytes(), global_reg_bytes)
        self.assertEqual(receipt_path.read_bytes(), global_receipt_bytes)
        self.assertEqual(fim_path.read_bytes(), global_fim_bytes)

        sandbox_hyb = self.tmp / "sandbox_hyb"
        with mock.patch.object(guard_cli, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ):
            rc_sb_hyb = guard_cli.cmd_init(
                parser.parse_args(["init", "--source", str(REPO_ROOT), "--target", str(sandbox_hyb), "--plugins"])
            )
        self.assertEqual(rc_sb_hyb, 0)
        for pack in PLUGIN_CATALOG:
            self.assertTrue((sandbox_hyb / "plugins" / pack / "plugin.json").is_file())
            if os.name != "nt":
                self.assertFalse(os.access(sandbox_hyb / "plugins" / pack / "plugin.json", os.W_OK))
        # Live global state files remained 100% untouched
        self.assertEqual(reg_path.read_bytes(), global_reg_bytes)
        self.assertEqual(receipt_path.read_bytes(), global_receipt_bytes)
        self.assertEqual(fim_path.read_bytes(), global_fim_bytes)

        # Non-global --target --uninstall without --registry also preserves live global state
        with mock.patch.object(guard_cli, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ), contextlib.redirect_stderr(io.StringIO()):
            rc_sb_un = guard_cli.cmd_init(
                parser.parse_args(["init", "--source", str(REPO_ROOT), "--target", str(sandbox_hyb), "--uninstall"])
            )
        self.assertEqual(rc_sb_un, 0)
        self.assertEqual(reg_path.read_bytes(), global_reg_bytes)
        self.assertEqual(receipt_path.read_bytes(), global_receipt_bytes)
        self.assertEqual(fim_path.read_bytes(), global_fim_bytes)

        # Programmatic Namespace passing both plugins=True and flat_skills=True fails cleanly with exit 2
        with contextlib.redirect_stderr(io.StringIO()):
            rc_mutex = guard_cli.cmd_init(
                argparse.Namespace(
                    target=str(sandbox_flat),
                    source=str(REPO_ROOT),
                    plugins=True,
                    flat_skills=True,
                )
            )
        self.assertEqual(rc_mutex, 2)

        # 3. Global plumb-guard init --plugins -> idempotent re-run -> --flat-skills lossless revert
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--plugins", "--dry-run"])),
                0,
            )
        self.assertFalse((self.cfg / "plugins" / "ui-refinery").exists())

        with mock.patch.object(guard_cli, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ):
            self.assertEqual(
                guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--plugins"])),
                0,
            )
        rec_hyb = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(rec_hyb["layout"], "hybrid")
        self.assertEqual(rec_hyb["installed_plugins"], sorted(PLUGIN_CATALOG.keys()))
        self.assertEqual(rec_hyb["retired_mcp_servers"], ["ui-refinery-contrast"])
        self.assertEqual(json.loads(mcp_path.read_text(encoding="utf-8")), {"mcpServers": {}})

        # Idempotent re-run keeps retired_mcp_servers and creates zero new backup dir
        with mock.patch.object(guard_cli, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ):
            self.assertEqual(
                guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--plugins"])),
                0,
            )
        rec_hyb2 = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertIsNone(rec_hyb2["backup_dir"])
        self.assertEqual(rec_hyb2["retired_mcp_servers"], ["ui-refinery-contrast"])

        # Lossless --flat-skills revert
        with mock.patch.object(guard_cli, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ):
            self.assertEqual(
                guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--flat-skills"])),
                0,
            )
        self.assertFalse((self.cfg / "plugins").exists())
        self.assertIn("ui-refinery-contrast", json.loads(mcp_path.read_text(encoding="utf-8"))["mcpServers"])
        reg_after = EnvironmentRegistry()
        ag_env = reg_after.get_environment("antigravity")
        assert ag_env is not None
        self.assertTrue(reg_after.is_locked("antigravity")["antigravity"])
        self.assertTrue(FileIntegrityMonitor.for_environment(ag_env, os_adapter=reg_after.os_adapter).verify().is_intact)

    def test_cmd_init_rollback_restores_state_files_and_config_json(self) -> None:
        parser = guard_cli.build_parser()
        with mock.patch.object(guard_cli, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ):
            self.assertEqual(guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT)])), 0)
        cfg_json = self.cfg / "config.json"
        if cfg_json.exists():
            cfg_json.unlink()

        reg_path = self.state / "environments.json"
        receipt_path = self.state / "install_receipt.json"
        fim_path = self.state / "integrity" / "antigravity.json"
        pending_path = self.state / "integrity" / "antigravity.pending.json"
        pending_path.write_text('{"pending": "before"}\n', encoding="utf-8")

        before_reg = reg_path.read_bytes()
        before_receipt = receipt_path.read_bytes()
        before_fim = fim_path.read_bytes()
        before_pending = pending_path.read_bytes()

        with mock.patch.object(guard_cli, "request_approval", return_value=True), mock.patch.object(
            FileIntegrityMonitor, "save_baseline", side_effect=RuntimeError("boom-init-rollback")
        ), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--plugins"]))

        self.assertFalse(cfg_json.exists())
        self.assertFalse((self.cfg / "plugins").exists())
        self.assertTrue((self.cfg / "skills" / "ui-refinery" / "SKILL.md").is_file())
        self.assertEqual(reg_path.read_bytes(), before_reg)
        self.assertEqual(receipt_path.read_bytes(), before_receipt)
        self.assertEqual(fim_path.read_bytes(), before_fim)
        self.assertEqual(pending_path.read_bytes(), before_pending)
        self.assertTrue(EnvironmentRegistry().is_locked("antigravity")["antigravity"])

    def test_dual_uninstall_removes_only_receipt_tracked_packs_and_warns_when_receipt_missing(self) -> None:
        parser = guard_cli.build_parser()
        for label in ("install.py", "plumb-guard init"):
            with self.subTest(uninstaller=label):
                # Clean sandbox cfg for each subtest
                hermetic.force_rmtree(self.cfg)
                self.cfg.mkdir(parents=True)
                hermetic.force_rmtree(self.state)
                self.state.mkdir(parents=True)

                rea_file = self.cfg / "plugins" / "rea" / "plugin.json"
                rea_file.parent.mkdir(parents=True, exist_ok=True)
                rea_file.write_text('{"name":"rea"}\n', encoding="utf-8")

                with mock.patch.object(harness_install, "request_approval", return_value=True), mock.patch.object(
                    guard_cli, "request_approval", return_value=True
                ), contextlib.redirect_stdout(io.StringIO()):
                    if label == "install.py":
                        self.assertEqual(harness_install.main(["--plugins"]), 0)
                        rc_un = harness_install.uninstall_harness(self.cfg, dry_run=False)
                    else:
                        self.assertEqual(
                            guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--plugins"])),
                            0,
                        )
                        rc_un = guard_cli.cmd_init(
                            parser.parse_args(["init", "--source", str(REPO_ROOT), "--uninstall"])
                        )
                self.assertEqual(rc_un, 0)
                for pack in PLUGIN_CATALOG:
                    self.assertFalse((self.cfg / "plugins" / pack).exists(), f"{label} left {pack}")
                self.assertTrue(rea_file.is_file(), f"{label} deleted third-party rea!")

                # Receiptless uninstall preserves plugins/ untouched and emits [WARN]
                with mock.patch.object(harness_install, "request_approval", return_value=True), mock.patch.object(
                    guard_cli, "request_approval", return_value=True
                ), contextlib.redirect_stdout(io.StringIO()):
                    if label == "install.py":
                        self.assertEqual(harness_install.main(["--plugins"]), 0)
                    else:
                        self.assertEqual(
                            guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--plugins"])),
                            0,
                        )
                (self.state / "install_receipt.json").unlink()
                err_buf = io.StringIO()
                with mock.patch.object(harness_install, "request_approval", return_value=True), mock.patch.object(
                    guard_cli, "request_approval", return_value=True
                ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_buf):
                    if label == "install.py":
                        rc_norec = harness_install.uninstall_harness(self.cfg, dry_run=False)
                    else:
                        rc_norec = guard_cli.cmd_init(
                            parser.parse_args(["init", "--source", str(REPO_ROOT), "--uninstall"])
                        )
                self.assertEqual(rc_norec, 0)
                self.assertIn("[WARN]", err_buf.getvalue())
                self.assertTrue((self.cfg / "plugins" / "ui-refinery" / "plugin.json").is_file())
                self.assertTrue(rea_file.is_file())

    def test_resolve_portable_script_finds_hybrid_plugin_scripts(self) -> None:
        build_plugin_pack("ui-refinery", REPO_ROOT, self.cfg / "plugins" / "ui-refinery", portable_mcp=False)
        fake_cli_file = self.tmp / "fake_pkg" / "guard" / "cli.py"
        fake_cli_file.parent.mkdir(parents=True)
        fake_cli_file.write_text("# stub\n", encoding="utf-8")
        with mock.patch.object(guard_cli, "__file__", str(fake_cli_file)):
            ui_slop = guard_cli._resolve_portable_script("skills/ui-refinery/scripts/check_ui_slop.py")
            synth = guard_cli._resolve_portable_script("skills/ui-refinery/scripts/check_synthetic_markers.py")
        self.assertEqual(ui_slop, self.cfg / "plugins" / "ui-refinery" / "skills" / "ui-refinery" / "scripts" / "check_ui_slop.py")
        self.assertEqual(
            synth, self.cfg / "plugins" / "ui-refinery" / "skills" / "ui-refinery" / "scripts" / "check_synthetic_markers.py"
        )


class TestDoctorHybridDiagnostics(_IsolatedHybridEnvMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._setup_sandbox("agy_hyb_doc_")

    def tearDown(self) -> None:
        self._teardown_sandbox()

    def test_doctor_duplicate_skills_stale_contrast_mcp_and_gated_agy_plugin_info(self) -> None:
        adapter = mock.MagicMock(spec=OSProtectionAdapter)
        adapter.protection_issues.return_value = []
        adapter.is_locked.return_value = True

        # Seed valid hooks, constitution, and 2 native deny rules (plumb-guard unlock + --no-verify)
        (self.cfg / "rules").mkdir(parents=True)
        (self.cfg / "rules" / "plumbwork-constitution.md").write_text("---\ntrigger: always_on\n---\n# C\n", encoding="utf-8")
        valid_hook = self.cfg / "valid_hook.py"
        valid_hook.write_text("# ok\n", encoding="utf-8")
        (self.cfg / "hooks.json").write_text(
            json.dumps(
                {
                    "upstream-watchdog": {"SessionStart": [{"type": "command", "command": f'"{sys.executable}" "{valid_hook}"'}]},
                    "harness-gate": {
                        "PreInvocation": [{"type": "command", "command": f'"{sys.executable}" "{valid_hook}"'}],
                        "PreToolUse": [{"type": "command", "command": f'"{sys.executable}" "{valid_hook}"'}],
                        "Stop": [{"type": "command", "command": f'"{sys.executable}" "{valid_hook}"'}],
                    },
                }
            ),
            encoding="utf-8",
        )
        (self.cfg / "config.json").write_text(
            json.dumps(
                {
                    "userSettings": {
                        "globalPermissionGrants": {
                            "deny": ["command(plumb-guard unlock)", "command(regex:.*--no-verify.*)"]
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        # Third-party rea alone does NOT trigger agy plugin INFO
        (self.cfg / "plugins" / "rea").mkdir(parents=True)
        (self.cfg / "plugins" / "rea" / "plugin.json").write_text('{"name":"rea"}\n', encoding="utf-8")

        reg = EnvironmentRegistry(config_path=self.state / "environments.json", os_adapter=adapter)
        env = reg.get_environment("antigravity")
        assert env is not None
        FileIntegrityMonitor.for_environment(env, os_adapter=adapter).save_baseline()

        rep_flat = diagnose(env, reg, sentinel_active=True)
        self.assertTrue(rep_flat.healthy, rep_flat.warnings)
        self.assertIn("Native Antigravity deny rules cover 'plumb-guard unlock' and '--no-verify'.", rep_flat.infos)
        self.assertFalse(any("agy plugin" in info for info in rep_flat.infos), rep_flat.infos)

        # Install ui-refinery plugin pack: existing 2-rule INFO stays intact AND separate agy plugin INFO appears
        build_plugin_pack("ui-refinery", REPO_ROOT, self.cfg / "plugins" / "ui-refinery", portable_mcp=False)
        (self.cfg / "mcp_config.json").write_text(
            json.dumps({"mcpServers": {"unrelated": {"command": "python3", "args": ["/opt/other/contrast-mcp.py"]}}}),
            encoding="utf-8",
        )
        sync_antigravity_plugin_seams(env)
        FileIntegrityMonitor.for_environment(env, os_adapter=adapter).save_baseline()

        rep_hyb = diagnose(env, reg, sentinel_active=True)
        self.assertTrue(rep_hyb.healthy, rep_hyb.warnings)
        self.assertIn("Native Antigravity deny rules cover 'plumb-guard unlock' and '--no-verify'.", rep_hyb.infos)
        self.assertTrue(any("agy plugin" in info and "recommended" in info for info in rep_hyb.infos), rep_hyb.infos)

        # Adding native agy plugin deny rule switches the separate INFO to confirmed coverage
        (self.cfg / "config.json").write_text(
            json.dumps(
                {
                    "userSettings": {
                        "globalPermissionGrants": {
                            "deny": [
                                "command(plumb-guard unlock)",
                                "command(regex:.*--no-verify.*)",
                                "command(regex:.*agy plugin.*)",
                            ]
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        rep_cov = diagnose(env, reg, sentinel_active=True)
        self.assertTrue(rep_cov.healthy, rep_cov.warnings)
        self.assertIn("Native Antigravity deny rules cover 'plumb-guard unlock' and '--no-verify'.", rep_cov.infos)
        self.assertIn(
            "Native Antigravity deny rules cover 'agy plugin' mutations for installed harness plugins.",
            rep_cov.infos,
        )

        # Duplicate skills/<slug> + stale global contrast-mcp.py both trigger warnings
        (self.cfg / "skills" / "ui-refinery").mkdir(parents=True)
        (self.cfg / "skills" / "ui-refinery" / "SKILL.md").write_text("---\nname: ui-refinery\n---\n", encoding="utf-8")
        (self.cfg / "mcp_config.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "stale-flat": {
                            "command": "python3",
                            "args": [str(self.cfg / "skills" / "ui-refinery" / "scripts" / "contrast-mcp.py")],
                        },
                        "stale-legacy": {
                            "command": "python3",
                            "args": [str(self.cfg / "skills" / "antislop-human" / "contrast-mcp.py")],
                        },
                        "unrelated": {
                            "command": "python3",
                            "args": ["/opt/other/contrast-mcp.py"],
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        FileIntegrityMonitor.for_environment(env, os_adapter=adapter).save_baseline()
        rep_warn = diagnose(env, reg, sentinel_active=True)
        self.assertFalse(rep_warn.healthy)
        joined_w = "\n".join(rep_warn.warnings)
        self.assertIn("skills/ui-refinery <-> plugins/ui-refinery/skills/ui-refinery", joined_w)
        self.assertIn("stale-flat", joined_w)
        self.assertIn("stale-legacy", joined_w)
        self.assertNotIn("unrelated", joined_w)

    def test_doctor_check_hybrid_plugins_handles_permission_error_on_probes(self) -> None:
        from guard.doctor import _check_hybrid_plugins

        (self.cfg / "skills" / "ui-refinery").mkdir(parents=True)
        (self.cfg / "plugins" / "unreadable_pack").mkdir(parents=True)
        (self.cfg / "plugins" / "ui-refinery" / "skills" / "ui-refinery").mkdir(parents=True)
        (self.cfg / "plugins" / "ui-refinery" / "mcp_config.json").write_text('{"mcpServers":{}}\n', encoding="utf-8")
        (self.cfg / "mcp_config.json").write_text('{"mcpServers":{}}\n', encoding="utf-8")

        unreadable_pack_skills = self.cfg / "plugins" / "unreadable_pack" / "skills"
        ui_refinery_skill_entry = self.cfg / "plugins" / "ui-refinery" / "skills" / "ui-refinery"
        plugin_mcp = self.cfg / "plugins" / "ui-refinery" / "mcp_config.json"

        orig_is_dir = Path.is_dir
        orig_is_file = Path.is_file

        def _fake_is_dir(p: Path) -> bool:
            if p in (unreadable_pack_skills, ui_refinery_skill_entry):
                raise PermissionError(13, "Permission denied", str(p))
            return orig_is_dir(p)

        def _fake_is_file(p: Path) -> bool:
            if p == plugin_mcp:
                raise PermissionError(13, "Permission denied", str(p))
            return orig_is_file(p)

        warnings: list[str] = []
        infos: list[str] = []
        with mock.patch.object(Path, "is_dir", autospec=True, side_effect=_fake_is_dir), mock.patch.object(
            Path, "is_file", autospec=True, side_effect=_fake_is_file
        ):
            _check_hybrid_plugins(self.cfg, warnings, infos)

        joined_w = "\n".join(warnings)
        self.assertIn(str(unreadable_pack_skills), joined_w)
        self.assertIn(str(ui_refinery_skill_entry), joined_w)
        self.assertIn(str(plugin_mcp), joined_w)
        self.assertIn("Could not inspect", joined_w)

        # Also test pack_dir islink/is_dir raising PermissionError via full diagnose() seam
        adapter = mock.MagicMock(spec=OSProtectionAdapter)
        adapter.protection_issues.return_value = []
        adapter.is_locked.return_value = True
        reg = EnvironmentRegistry(config_path=self.state / "environments.json", os_adapter=adapter)
        env = reg.get_environment("antigravity")
        assert env is not None
        FileIntegrityMonitor.for_environment(env, os_adapter=adapter).save_baseline()

        unreadable_pack_dir = env.get_root() / "plugins" / "unreadable_pack"
        orig_islink = os.path.islink

        def _fake_islink(p: object) -> bool:
            if Path(os.fspath(p)) == unreadable_pack_dir:
                raise PermissionError(13, "Permission denied", str(p))
            return orig_islink(p)

        with mock.patch("guard.doctor.os.path.islink", side_effect=_fake_islink):
            rep = diagnose(env, reg, sentinel_active=True)
        self.assertTrue(any(str(unreadable_pack_dir) in w and "Could not inspect" in w for w in rep.warnings), rep.warnings)


def _extract_pre_invocation_messages(resp: dict) -> str:
    parts: list[str] = []
    for step in resp.get("injectSteps") or []:
        if isinstance(step, dict):
            sm = step.get("systemMessage")
            if isinstance(sm, dict) and isinstance(sm.get("systemMessage"), str):
                parts.append(sm["systemMessage"])
            elif isinstance(sm, str):
                parts.append(sm)
    return "\n".join(parts)


class TestHybridPreToolUseAndShellGuard(_IsolatedHybridEnvMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._setup_sandbox("agy_hyb_ptu_")
        self.ws = self.tmp / "workspace"
        self.ws.mkdir(parents=True)
        (self.cfg / "GEMINI.md").write_text("# Test Constitution\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._teardown_sandbox()

    def test_write_tool_denies_plugins_root_globs_dots_and_harness_packs_while_allowing_third_party(self) -> None:
        denied_targets = [
            str(self.cfg / "plugins"),
            str(self.cfg / "plugins") + "/",
            str(self.cfg / "plugins") + "/.",
            str(self.cfg / "plugins") + "/./ui-refinery/plugin.json",
            str(self.cfg / "plugins" / "ui-refinery"),
            str(self.cfg / "plugins" / "ui-refinery" / "plugin.json"),
            str(self.cfg / "plugins" / "UI-REFINERY" / "plugin.json"),
            str(self.cfg / "plugins" / "rust-suite" / "README.md"),
            str(self.cfg / "plugins" / "media-studio" / "assets" / "logo.svg"),
            str(self.cfg / "plugins" / "game-engineering" / "plugin.json"),
            str(self.cfg / "plugins" / "*"),
            str(self.cfg / "plugins" / "ui-*" / "plugin.json"),
            str(self.cfg / "plugins" / "{ui-refinery,rust-suite}" / "plugin.json"),
            str(self.cfg / "plugins" / "[u]i-refinery" / "plugin.json"),
            str(self.cfg / "plugins" / "?i-refinery" / "plugin.json"),
            str(self.cfg / "plugins" / "$PACK" / "plugin.json"),
            str(self.cfg / "plugins" / "rea" / "skills" / "s" / "SKILL.md"),
            str(self.cfg / "plugins" / "rea" / "evil.py"),
        ]
        for target in denied_targets:
            with self.subTest(denied_target=target):
                res = agy_hooks.handle_pre_tool_use(
                    {"toolCall": {"name": "write_to_file", "args": {"TargetFile": target}}, "cwd": str(self.ws)}
                )
                self.assertEqual(res.get("decision"), "deny", f"Expected deny for {target}, got {res}")

        allowed_targets = [
            str(self.cfg / "plugins" / "rea" / "plugin.json"),
            str(self.cfg / "plugins" / "demo" / "plugin.json"),
            str(self.cfg / "plugins" / "rea" / "data.json"),
        ]
        for target in allowed_targets:
            with self.subTest(allowed_target=target):
                res = agy_hooks.handle_pre_tool_use(
                    {"toolCall": {"name": "write_to_file", "args": {"TargetFile": target}}, "cwd": str(self.ws)}
                )
                self.assertEqual(res, {"decision": "allow"}, f"Expected allow for {target}, got {res}")

    @unittest.skipUnless(os.name != "nt", "POSIX shell syntax tests")
    def test_shell_guard_denies_plugins_root_globs_dots_and_harness_packs_while_allowing_third_party(self) -> None:
        cfg_s = str(self.cfg)
        denied_cmds = [
            f"rm -rf {cfg_s}/plugins",
            f"rm -rf {cfg_s}/plugins/",
            f'rm -rf "{cfg_s}/plugins/"',
            f"rm -rf {cfg_s}/plugins/*",
            f"rm -rf {cfg_s}/plugins/ui-*/plugin.json",
            f'rm -rf "{cfg_s}/plugins/ui-*/plugin.json"',
            f"rm -rf {cfg_s}/plugins/{{ui-refinery,rust-suite}}",
            f"rm -rf {cfg_s}/plugins/[u]i-refinery",
            f"rm -rf {cfg_s}/plugins/?i-refinery",
            f"rm -rf {cfg_s}/plugins/$PACK/plugin.json",
            f"rm -rf {cfg_s}/plugins/.",
            f"rm -rf {cfg_s}/plugins/./ui-refinery",
            f"rm -rf {cfg_s}/plugins/ui-refinery",
            f"echo '{{}}' > {cfg_s}/plugins/ui-refinery/plugin.json",
            f"echo '{{}}' > {cfg_s}/plugins/rust-suite/plugin.json",
            f"echo '{{}}' > {cfg_s}/plugins/media-studio/plugin.json",
            f"echo '{{}}' > {cfg_s}/plugins/game-engineering/plugin.json",
            f"cp /tmp/x {cfg_s}/plugins/rea/skills/s/SKILL.md",
            f"cp /tmp/x {cfg_s}/plugins/rea/mcp_config.json",
            f"cp /tmp/x {cfg_s}/plugins/rea/payload.py",
            f"echo '{{}}' > {cfg_s}/plugins/rea/plugin.json && rm -rf {cfg_s}/plugins/ui-refinery",
        ]
        for cmd in denied_cmds:
            with self.subTest(denied_cmd=cmd):
                res = agy_hooks.handle_pre_tool_use(
                    {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}, "cwd": str(self.ws)}
                )
                self.assertEqual(res.get("decision"), "deny", f"Expected deny for `{cmd}`, got {res}")

        allowed_cmds = [
            f"mkdir -p {cfg_s}/plugins/rea",
            f"echo '{{}}' > {cfg_s}/plugins/rea/plugin.json",
            f"echo '{{}}' > {cfg_s}/plugins/demo/plugin.json",
            f"ls -la {cfg_s}/plugins/ui-refinery",
        ]
        for cmd in allowed_cmds:
            with self.subTest(allowed_cmd=cmd):
                res = agy_hooks.handle_pre_tool_use(
                    {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}, "cwd": str(self.ws)}
                )
                self.assertEqual(res, {"decision": "allow"}, f"Expected allow for `{cmd}`, got {res}")

    def test_shell_guard_trusted_roots_allows_harness_plugin_skill_scripts_only(self) -> None:
        build_plugin_pack("ui-refinery", REPO_ROOT, self.cfg / "plugins" / "ui-refinery", portable_mcp=False)
        harness_script = self.cfg / "plugins" / "ui-refinery" / "skills" / "ui-refinery" / "scripts" / "contrast-check.py"
        res_ok = agy_hooks.handle_pre_tool_use(
            {
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": f'python3 "{harness_script}" "#FFFFFF" "#2563EB"'},
                },
                "cwd": str(self.ws),
            }
        )
        self.assertEqual(res_ok, {"decision": "allow"})

        third_party_script = self.cfg / "plugins" / "rea" / "skills" / "rea" / "scripts" / "tool.py"
        third_party_script.parent.mkdir(parents=True, exist_ok=True)
        third_party_script.write_text("print('hi')\n", encoding="utf-8")
        res_ext = agy_hooks.handle_pre_tool_use(
            {
                "toolCall": {"name": "run_command", "args": {"CommandLine": f'python3 "{third_party_script}"'}},
                "cwd": str(self.ws),
            }
        )
        self.assertEqual(res_ext.get("decision"), "force_ask")

    @unittest.skipUnless(os.name != "nt", "POSIX shell wrapper tests")
    def test_official_agy_plugin_cli_gate_forces_ask_for_harness_packs_and_exempts_rea(self) -> None:
        gated_cmds = [
            "agy plugin disable ui-refinery",
            "agy plugin uninstall rust-suite",
            "agy plugin install ./dist/media-studio-v3.0.0.zip",
            "agy plugin import /tmp/game-engineering",
            "agy plugin install rea",
            "agy plugin import ./rea",
            "/usr/local/bin/agy plugin disable ui-refinery",
            "env FOO=1 agy --profile dev plugin --scope user disable --yes rust-suite",
            'env -S "agy plugin disable ui-refinery"',
            "command agy plugin uninstall media-studio",
            "exec -a agy /opt/bin/agy plugin disable game-engineering",
            "agy plugin disable rea ui-refinery",
            'sh -c "agy plugin disable ui-refinery"',
            "agy plugin disable ui-*",
            "agy plugin disable {ui-refinery,rea}",
        ]
        for cmd in gated_cmds:
            with self.subTest(gated_cmd=cmd):
                res = agy_hooks.handle_pre_tool_use(
                    {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}, "cwd": str(self.ws)}
                )
                self.assertEqual(res.get("decision"), "force_ask", f"Expected force_ask for `{cmd}`, got {res}")
                reason = str(res.get("reason") or "")
                self.assertTrue(reason.startswith("What changes:"), reason)
                self.assertIn("If approved:", reason)
                self.assertIn("If denied:", reason)

        exempt_cmds = [
            "agy plugin disable rea",
            "agy plugin uninstall rea",
            "agy plugin list",
            "agy plugin validate plugins/ui-refinery",
            "agy plugin disable --help",
            "agy plugin install --help",
            "agy plugin import -h",
            "command -v agy",
            'echo "agy plugin disable ui-refinery"',
        ]
        for cmd in exempt_cmds:
            with self.subTest(exempt_cmd=cmd):
                res = agy_hooks.handle_pre_tool_use(
                    {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}, "cwd": str(self.ws)}
                )
                self.assertEqual(res, {"decision": "allow"}, f"Expected allow for `{cmd}`, got {res}")

        # Verify agy_hooks.py budget (<= 32 KiB, <= 160 chars/line) and stop_gate.py untouched invariant
        facade_bytes = (REPO_ROOT / "guard" / "agy_hooks.py").read_bytes()
        self.assertLessEqual(len(facade_bytes), 32_768)
        self.assertLessEqual(max(len(ln) for ln in facade_bytes.decode("utf-8").splitlines()), 160)
        stop_gate_text = (REPO_ROOT / "guard" / "hooks" / "stop_gate.py").read_text(encoding="utf-8")
        self.assertNotIn("plugins/antislop", stop_gate_text)


class TestHybridPreInvocationLiveToggle(_IsolatedHybridEnvMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._setup_sandbox("agy_hyb_pi_")
        self.ws = self.tmp / "workspace"
        self.ws.mkdir(parents=True)

    def tearDown(self) -> None:
        self._teardown_sandbox()

    def _install_hybrid(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            rc = harness_install.main(["--plugins", "--no-lock"])
        self.assertEqual(rc, 0)

    def test_live_config_json_toggle_and_plugin_json_precedence_and_failsafe(self) -> None:
        self._install_hybrid()
        self.assertTrue(agy_hooks._is_harness_plugin_active("rust-suite", self.cfg, [self.ws]))

        # Live config.json toggle disables pack immediately
        cfg_json = self.cfg / "config.json"
        cfg_json.write_text(json.dumps({"plugins": {"rust-suite": {"enabled": False}}}), encoding="utf-8")
        self.assertFalse(agy_hooks._is_harness_plugin_active("rust-suite", self.cfg, [self.ws]))
        self.assertTrue(agy_hooks._is_harness_plugin_active("ui-refinery", self.cfg, [self.ws]))

        # plugin.json["disabled"] disables pack when config.json does not specify enabled
        pj_path = self.cfg / "plugins" / "rust-suite" / "plugin.json"
        orig_pj = json.loads(pj_path.read_text(encoding="utf-8"))
        pj_path.write_text(json.dumps({**orig_pj, "disabled": True}), encoding="utf-8")
        cfg_json.write_text(json.dumps({}), encoding="utf-8")
        self.assertFalse(agy_hooks._is_harness_plugin_active("rust-suite", self.cfg, [self.ws]))

        # config.json enabled=True overrides plugin.json["disabled"]=True
        cfg_json.write_text(json.dumps({"plugins": {"rust-suite": {"enabled": True}}}), encoding="utf-8")
        self.assertTrue(agy_hooks._is_harness_plugin_active("rust-suite", self.cfg, [self.ws]))
        pj_path.write_text(json.dumps(orig_pj), encoding="utf-8")

        # Corrupt JSON fails safe enabled + emits stderr warning
        cfg_json.write_text("{broken json", encoding="utf-8")
        err_corrupt = io.StringIO()
        with contextlib.redirect_stderr(err_corrupt):
            self.assertTrue(agy_hooks._is_harness_plugin_active("rust-suite", self.cfg, [self.ws]))
        self.assertIn("failing safe enabled", err_corrupt.getvalue())

        # Oversized (> 2 MiB) config.json fails safe enabled + emits stderr warning
        cfg_json.write_bytes(b'{"pad":"' + (b"x" * (2 * 1024 * 1024 + 64)) + b'"}')
        err_big = io.StringIO()
        with contextlib.redirect_stderr(err_big):
            self.assertTrue(agy_hooks._is_harness_plugin_active("rust-suite", self.cfg, [self.ws]))
        self.assertIn("oversized", err_big.getvalue().lower())

        # Symlink config.json fails safe enabled + emits stderr warning
        if hasattr(os, "symlink"):
            outside = self.tmp / "outside_cfg.json"
            outside.write_text(json.dumps({"plugins": {"rust-suite": {"enabled": False}}}), encoding="utf-8")
            cfg_json.unlink()
            cfg_json.symlink_to(outside)
            err_sym = io.StringIO()
            with contextlib.redirect_stderr(err_sym):
                self.assertTrue(agy_hooks._is_harness_plugin_active("rust-suite", self.cfg, [self.ws]))
            self.assertIn("symlink", err_sym.getvalue().lower())

    def test_pre_invocation_resolves_plugin_paths_suppresses_disabled_and_removed_and_resumes_cleanly(self) -> None:
        self._install_hybrid()
        # 1. Enabled hybrid packs resolve to ~/.gemini/config/plugins/<pack>/skills/<slug>/...
        r_rust = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-hyb-1", "cwd": str(self.ws), "prompt": "port this C parser to Rust"}
        )
        txt_rust = _extract_pre_invocation_messages(r_rust)
        self.assertIn("~/.gemini/config/plugins/rust-suite/skills/rustify/SKILL.md", txt_rust)
        self.assertNotIn("~/.gemini/config/skills/rustify/SKILL.md", txt_rust)

        r_ui = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-hyb-2", "cwd": str(self.ws), "prompt": "audit ui components for anti-boxification"}
        )
        txt_ui = _extract_pre_invocation_messages(r_ui)
        self.assertIn("~/.gemini/config/plugins/ui-refinery/skills/ui-refinery/references/ui.md", txt_ui)

        # 2. Disable ui-refinery in config.json -> ui-refinery + all 6 sub-hints + vibecoder suppressed and NOT recorded in seen_turns
        (self.cfg / "config.json").write_text(
            json.dumps({"plugins": {"ui-refinery": {"enabled": False}}}), encoding="utf-8"
        )
        sub_prompts = [
            ("/ui-refinery audit design quality", "ui-refinery"),
            ("/ui-audit check sibling symmetry", "ui-audit"),
            ("/copy-polish remove synthetic markers", "copy-polish"),
            ("/a11y-check check wcag contrast", "a11y-check"),
            ("/mobile-layout fix horizontal overflow", "mobile-layout"),
            ("/code-comments clean slop comments", "code-comments"),
            ("/motion-physics kinetic motion showcase", "motion-physics"),
            ("/vibecoder build a single-file html prototype", "vibecoder"),
        ]
        for idx, (prompt, slug) in enumerate(sub_prompts):
            with self.subTest(suppressed_slug=slug):
                res_off = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-off-{idx}", "cwd": str(self.ws), "prompt": prompt}
                )
                self.assertNotIn(f"`{slug}`", _extract_pre_invocation_messages(res_off))

        # Re-enabling in the same conversation fires immediately because suppressed turn did not pollute seen_turns
        res_same_off = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-toggle", "cwd": str(self.ws), "prompt": "audit ui components for anti-boxification"}
        )
        self.assertNotIn("`ui-audit`", _extract_pre_invocation_messages(res_same_off))
        (self.cfg / "config.json").write_text(
            json.dumps({"plugins": {"ui-refinery": {"enabled": True}}}), encoding="utf-8"
        )
        res_same_on = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-toggle", "cwd": str(self.ws), "prompt": "run visual slop audit on these cards"}
        )
        self.assertIn(
            "~/.gemini/config/plugins/ui-refinery/skills/ui-refinery/references/ui.md",
            _extract_pre_invocation_messages(res_same_on),
        )

        # 3. Removed pack in explicit hybrid install is suppressed
        shutil.rmtree(self.cfg / "plugins" / "media-studio")
        res_rem = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-rem-media", "cwd": str(self.ws), "prompt": "master this audio file with ebu r128 lufs"}
        )
        self.assertNotIn("`media-studio`", _extract_pre_invocation_messages(res_rem))

        # 4. Isolated sandbox without hybrid signal keeps flat hints working
        iso_cfg = self.tmp / "iso_cfg"
        iso_cfg.mkdir()
        (iso_cfg / "GEMINI.md").write_text("# Isolated\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"ANTIGRAVITY_CONFIG_DIR": str(iso_cfg)}):
            res_iso = agy_hooks.handle_pre_invocation(
                {"conversationId": "conv-iso-flat", "cwd": str(self.ws), "prompt": "port this C parser to Rust"}
            )
            self.assertIn("`rustify`", _extract_pre_invocation_messages(res_iso))

    def test_pre_invocation_suppresses_workspace_domain_hints_before_seen_turns(self) -> None:
        self._install_hybrid()
        # Workspace carries both game-engineering and rustify markers
        (self.ws / "project.godot").write_text("[application]\n", encoding="utf-8")
        (self.ws / "Cargo.toml").write_text('[package]\nname = "demo"\n[dependencies]\npyo3 = "0.22"\n', encoding="utf-8")
        (self.ws / "bridge.c").write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")

        (self.cfg / "config.json").write_text(
            json.dumps({"plugins": {"game-engineering": {"enabled": False}}}), encoding="utf-8"
        )
        r1 = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-ws-dom",
                "cwd": str(self.ws),
                "prompt": "please review the project structure and build steps here",
            }
        )
        t1 = _extract_pre_invocation_messages(r1)
        self.assertNotIn("`game-engineering`", t1)
        self.assertIn("~/.gemini/config/plugins/rust-suite/skills/rustify/SKILL.md", t1)

        ledger = json.loads((self.state / "hook_hints.json").read_text(encoding="utf-8"))
        conv_state = ledger.get("conv-ws-dom", {})
        self.assertNotIn("game-engineering", conv_state)
        self.assertNotIn("ws_ctx:game-engineering", conv_state)

        # Re-enable game-engineering -> next turn emits workspace-domain hint immediately
        (self.cfg / "config.json").write_text(
            json.dumps({"plugins": {"game-engineering": {"enabled": True}}}), encoding="utf-8"
        )
        r2 = agy_hooks.handle_pre_invocation(
            {
                "conversationId": "conv-ws-dom",
                "cwd": str(self.ws),
                "prompt": "now inspect the remaining modules in this directory",
            }
        )
        t2 = _extract_pre_invocation_messages(r2)
        self.assertIn("~/.gemini/config/plugins/game-engineering/skills/game-engineering/SKILL.md", t2)

    def test_pre_invocation_ui_refinery_contrast_mcp_hint_hybrid_disabled_and_flat(self) -> None:
        self.assertIn("ui-refinery_contrast", agy_hooks._ROUTE_EXPLICIT_SLUGS["route:mcp:ui-refinery-contrast"])

        # 1. Isolated / flat mode preserves ui-refinery-contrast contract
        (self.cfg / "GEMINI.md").write_text("# Flat\n", encoding="utf-8")
        r_flat = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-mcp-flat", "cwd": str(self.ws), "prompt": "check color contrast ratio for buttons"}
        )
        t_flat = _extract_pre_invocation_messages(r_flat)
        self.assertIn('ServerName="ui-refinery-contrast"', t_flat)

        # 2. Active hybrid plugin emits ui-refinery_contrast (both keyword and explicit slug trigger)
        self._install_hybrid()
        r_hyb = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-mcp-hyb", "cwd": str(self.ws), "prompt": "check color contrast ratio for buttons"}
        )
        t_hyb = _extract_pre_invocation_messages(r_hyb)
        self.assertIn('ServerName="ui-refinery_contrast"', t_hyb)
        self.assertNotIn('ServerName="ui-refinery-contrast"', t_hyb)

        r_slug = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-mcp-slug", "cwd": str(self.ws), "prompt": "use ui-refinery_contrast on primary text"}
        )
        self.assertIn('ServerName="ui-refinery_contrast"', _extract_pre_invocation_messages(r_slug))

        # 3. Disabled ui-refinery suppresses MCP hint
        (self.cfg / "config.json").write_text(
            json.dumps({"plugins": {"ui-refinery": {"enabled": False}}}), encoding="utf-8"
        )
        r_off = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-mcp-off", "cwd": str(self.ws), "prompt": "check color contrast ratio for buttons"}
        )
        t_off = _extract_pre_invocation_messages(r_off)
        self.assertNotIn("ui-refinery_contrast", t_off)
        self.assertNotIn("ui-refinery-contrast", t_off)

        # 4. Removed ui-refinery pack suppresses MCP hint
        (self.cfg / "config.json").write_text(json.dumps({}), encoding="utf-8")
        shutil.rmtree(self.cfg / "plugins" / "ui-refinery")
        r_rem = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-mcp-rem", "cwd": str(self.ws), "prompt": "check color contrast ratio for buttons"}
        )
        t_rem = _extract_pre_invocation_messages(r_rem)
        self.assertNotIn("ui-refinery_contrast", t_rem)
        self.assertNotIn("ui-refinery-contrast", t_rem)

    def test_lazy_hint_regex_prefilter_soundness_unicode_and_quantifier_edges(self) -> None:
        import guard.hooks.pre_invocation as pre_inv_mod

        # Restore lazy PEP 562 module dict after inspecting SKILL_HINTS/ECOSYSTEM_ROUTING_HINTS
        had_sh = "SKILL_HINTS" in pre_inv_mod.__dict__
        had_erh = "ECOSYSTEM_ROUTING_HINTS" in pre_inv_mod.__dict__

        def _cleanup_lazy() -> None:
            if not had_sh:
                pre_inv_mod.__dict__.pop("SKILL_HINTS", None)
            if not had_erh:
                pre_inv_mod.__dict__.pop("ECOSYSTEM_ROUTING_HINTS", None)

        self.addCleanup(_cleanup_lazy)

        # 1. Lazy PEP 562 SKILL_HINTS & ECOSYSTEM_ROUTING_HINTS remain re.Pattern tuples with 100% extractability
        self.assertEqual(len(agy_hooks.SKILL_HINTS), len(agy_hooks._SKILL_HINTS_RAW))
        self.assertEqual(len(agy_hooks.ECOSYSTEM_ROUTING_HINTS), len(agy_hooks._ECOSYSTEM_ROUTING_HINTS_RAW))
        for _name, _rel, rx, _summary in agy_hooks.SKILL_HINTS:
            self.assertIsInstance(rx, re.Pattern)
            self.assertIsNotNone(agy_hooks._extract_necessary_literals(rx.pattern))
        for _key, rx, _directive in agy_hooks.ECOSYSTEM_ROUTING_HINTS:
            self.assertIsInstance(rx, re.Pattern)
            self.assertIsNotNone(agy_hooks._extract_necessary_literals(rx.pattern))

        # Clear _match_hint_pattern caches so probes genuinely exercise _extract_necessary_literals cold-start prefiltering
        for cache_attr in ("_rx_cache", "_lit_cache"):
            cdict = getattr(pre_inv_mod._match_hint_pattern, cache_attr, None)
            if isinstance(cdict, dict):
                cdict.clear()

        # 2. Quantifier, metacharacter & fail-safe edge cases (must never produce false negatives)
        self.assertEqual(agy_hooks._extract_necessary_literals(r"ab+c"), ("ab",))
        self.assertTrue(agy_hooks._match_hint_pattern(r"ab+c", "xxabbcxx", "xxabbcxx"))
        self.assertEqual(agy_hooks._extract_necessary_literals(r"abc?"), ("ab",))
        self.assertTrue(agy_hooks._match_hint_pattern(r"abc?", "xxabxx", "xxabxx"))
        self.assertEqual(agy_hooks._extract_necessary_literals(r"foo.bar"), ("foo",))
        self.assertTrue(agy_hooks._match_hint_pattern(r"foo.bar", "fooXbar", "fooxbar"))
        self.assertEqual(agy_hooks._extract_necessary_literals(r"foo\.bar"), ("foo.bar",))
        self.assertEqual(agy_hooks._extract_necessary_literals(r"foo$"), ("foo",))
        self.assertTrue(agy_hooks._match_hint_pattern(r"foo$", "foo", "foo"))
        self.assertIsNone(agy_hooks._extract_necessary_literals(r"(?x)foo bar"))
        self.assertIsNone(agy_hooks._extract_necessary_literals(r"foo(?#comment)bar"))
        self.assertIsNone(agy_hooks._extract_necessary_literals(r"(?(1)foo|bar)"))
        self.assertIsNone(agy_hooks._extract_necessary_literals(r"a|b"))

        # 3. Turkish İ/ı/I/i case-folding parity across _match_hint_pattern vs re.compile(..., re.IGNORECASE)
        probes = (
            "KONTRAST ORANI KONTROLÜ",
            "İLERİ DÜZEY RENK KONTRASTI",
            "BU KOD ÇALIŞMIYOR VE HATA VERİYOR",
            "KÖK NEDEN ANALİZİ YAP",
        )
        for probe in probes:
            norm = probe.replace("İ", "i").replace("ı", "i").casefold()
            for s_name, _s_rel, raw_pat, _s_sum in agy_hooks._SKILL_HINTS_RAW:
                expected = bool(re.compile(raw_pat, re.IGNORECASE).search(probe))
                actual = agy_hooks._match_hint_pattern(raw_pat, probe, norm)
                self.assertEqual(actual, expected, f"Prefilter mismatch for {s_name} on {probe!r}")
            for r_key, raw_pat, _r_dir in agy_hooks._ECOSYSTEM_ROUTING_HINTS_RAW:
                expected = bool(re.compile(raw_pat, re.IGNORECASE).search(probe))
                actual = agy_hooks._match_hint_pattern(raw_pat, probe, norm)
                self.assertEqual(actual, expected, f"Prefilter mismatch for {r_key} on {probe!r}")


class TestPorterAndMetaAuditHybridParity(_IsolatedHybridEnvMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._setup_sandbox("agy_hyb_pa_")

    def tearDown(self) -> None:
        self._teardown_sandbox()

    def _install_hybrid(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            rc = harness_install.main(["--plugins", "--no-lock"])
        self.assertEqual(rc, 0)

    def test_porter_export_uses_canonical_manifest_on_hybrid_and_fails_loudly_if_missing(self) -> None:
        self._install_hybrid()
        self.assertTrue(is_installed_hybrid_root(self.cfg))
        self.assertFalse(is_installed_hybrid_root(REPO_ROOT))

        runtime_porter = self.data / "runtime" / "porter.py"
        self.assertTrue(runtime_porter.is_file(), f"Expected installed runtime porter at {runtime_porter}")

        export_dir = self.tmp / "exported_claude"
        res = subprocess.run(
            [sys.executable, str(runtime_porter), "export", "--target", "claude", "--out", str(export_dir), "--force"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        exported_skills = {p.name for p in (export_dir / ".claude" / "skills").iterdir() if p.is_dir()}
        self.assertEqual(len(exported_skills), 20)
        for slug in PLUGIN_OWNED_SKILL_SLUGS:
            self.assertIn(slug, exported_skills)

        # Removing canonical manifest fails loudly (no silent partial export or inverse-rewriter)
        (self.cfg / ".harness" / "manifest.json").unlink()
        res_fail = subprocess.run(
            [
                sys.executable,
                str(runtime_porter),
                "export",
                "--target",
                "claude",
                "--out",
                str(self.tmp / "fail_out"),
                "--force",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res_fail.returncode, 1, res_fail.stdout + res_fail.stderr)
        self.assertIn("missing canonical manifest", res_fail.stderr.lower())

    def test_manifest_engine_is_up_to_date_hybrid_forward_verification_and_flat_preservation(self) -> None:
        self._install_hybrid()
        engine = ManifestEngine(self.cfg)
        self.assertTrue(engine.is_up_to_date())

        # 1. Tampering an installed core file fails forward byte-for-byte check
        design_path = self.cfg / "DESIGN.md"
        orig_design = design_path.read_bytes()
        design_path.write_bytes(orig_design + b"\n<!-- drift -->\n")
        self.assertFalse(engine.is_up_to_date())
        design_path.write_bytes(orig_design)
        self.assertTrue(engine.is_up_to_date())

        # 2. Tampering a plugin pack skill file fails verification
        rustify_md = self.cfg / "plugins" / "rust-suite" / "skills" / "rustify" / "SKILL.md"
        orig_rustify = rustify_md.read_bytes()
        rustify_md.write_bytes(orig_rustify + b"\n<!-- tampered -->\n")
        self.assertFalse(engine.is_up_to_date())
        rustify_md.write_bytes(orig_rustify)
        self.assertTrue(engine.is_up_to_date())

        # 3. Shadowing copy of a plugin-owned skill inside skills/ fails verification
        shadow = self.cfg / "skills" / "ui-refinery"
        shadow.mkdir(parents=True)
        (shadow / "SKILL.md").write_text("---\nname: ui-refinery\ndescription: dup\n---\n", encoding="utf-8")
        self.assertFalse(engine.is_up_to_date())
        shutil.rmtree(shadow)
        self.assertTrue(engine.is_up_to_date())

        # 4. Missing harness plugin pack fails verification
        shutil.rmtree(self.cfg / "plugins" / "game-engineering")
        self.assertFalse(engine.is_up_to_date())

        # 5. Repo checkout retains strict 20-skill flat digest equality
        self.assertTrue(ManifestEngine(REPO_ROOT).is_up_to_date())

    def test_suitability_analyzer_discovers_all_20_skills_and_consolidated_slugs_in_hybrid(self) -> None:
        self._install_hybrid()
        # Unmanaged third-party plugin must not pollute harness known_skills
        rea_skill = self.cfg / "plugins" / "rea" / "skills" / "reverse-engineer-anything" / "SKILL.md"
        rea_skill.parent.mkdir(parents=True)
        rea_skill.write_text("---\nname: reverse-engineer-anything\ndescription: 3p\n---\n", encoding="utf-8")

        analyzer = SuitabilityAnalyzer(self.cfg)
        repo_skills = {p.name.lower() for p in (REPO_ROOT / "skills").iterdir() if p.is_dir() and (p / "SKILL.md").is_file()}
        self.assertEqual(len(repo_skills), 20)
        for slug in sorted(repo_skills):
            self.assertIn(slug, analyzer.known_skills, f"Missing skill `{slug}` in hybrid SuitabilityAnalyzer")
        for consolidated in (
            "ui-audit",
            "copy-polish",
            "a11y-check",
            "mobile-layout",
            "code-comments",
            "motion-physics",
        ):
            self.assertIn(consolidated, analyzer.known_skills, f"Missing consolidated slug `{consolidated}`")
        self.assertNotIn("reverse-engineer-anything", analyzer.known_skills)

    def test_meta_audit_passes_1_to_7_on_installed_hybrid_profile_and_rejects_dead_core_paths(self) -> None:
        self._install_hybrid()
        # Add noisy runtime directories and third-party plugins/rea with broken markdown/links -> must be excluded
        for rt_rel in ("projects/scratch.md", "sidecars/notes.md", "cache/tmp.md"):
            p = self.cfg / rt_rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("# Broken [link](./does-not-exist.md) `view_file`\n", encoding="utf-8")
        rea_bad = self.cfg / "plugins" / "rea" / "skills" / "broken-3p" / "SKILL.md"
        rea_bad.parent.mkdir(parents=True)
        rea_bad.write_text("no frontmatter [broken](./missing.md) `view_file`\n", encoding="utf-8")

        engine = MetaAuditEngine(repo_root=self.cfg)
        findings = engine.run_all_passes()
        self.assertEqual(
            findings,
            [],
            "Expected 0 findings on installed hybrid profile:\n"
            + "\n".join(f"[{f.severity}] {f.pass_name} {f.target}: {f.message}" for f in findings),
        )

        # Injecting a dead flat ~/.gemini/config/skills/<plugin-owned>/... path into a hybrid core file is rejected as CRITICAL
        harness_md = self.cfg / "skills" / "harness" / "SKILL.md"
        orig_harness = harness_md.read_text(encoding="utf-8")
        harness_md.write_text(
            orig_harness + "\nSee `~/.gemini/config/skills/rustify/SKILL.md` for details.\n",
            encoding="utf-8",
        )
        dead_engine = MetaAuditEngine(repo_root=self.cfg)
        p2_findings = dead_engine.run_pass(2)
        self.assertTrue(
            any(f.severity == "CRITICAL" and "Dead flat plugin-owned skill path" in f.message for f in p2_findings),
            p2_findings,
        )
        p4_findings = MetaAuditEngine(repo_root=self.cfg).run_pass(4)
        self.assertTrue(any(f.severity == "CRITICAL" for f in p4_findings), p4_findings)

        # Repo Pass 5 verifies PLUGIN_CATALOG, SVG logos, build_binaries assets & hook constants parity
        repo_p5 = MetaAuditEngine(repo_root=REPO_ROOT).run_pass(5)
        self.assertEqual(repo_p5, [], repo_p5)

    def test_linux_packaging_bundles_plugin_svg_assets_and_fails_closed_when_missing(self) -> None:
        from guard.plugins import PLUGIN_ASSET_FILENAMES, build_plugin_pack
        from installers.packaging.package_linux import LinuxPackager

        stage = self.tmp / "linux_stage"
        packager = LinuxPackager(repo_root=REPO_ROOT, arch="amd64", out_dir=self.tmp / "pkg_out")
        packager.prepare_payload(stage)

        staged_assets = stage / "usr" / "lib" / "plumb-guard" / "guard" / "plugin_assets"
        for asset_name in PLUGIN_ASSET_FILENAMES:
            svg_file = staged_assets / asset_name
            self.assertTrue(svg_file.is_file(), f"Linux FHS payload missing plugin SVG asset: {svg_file}")
            self.assertEqual(
                svg_file.read_bytes(),
                (REPO_ROOT / "guard" / "plugin_assets" / asset_name).read_bytes(),
            )

        # Building all 4 plugin packs from the staged /usr/share/plumbwork payload succeeds
        staged_share = stage / "usr" / "share" / "plumbwork"
        built_root = self.tmp / "built_from_linux_share"
        for pack_name in sorted(PLUGIN_CATALOG):
            built_dir = build_plugin_pack(pack_name, staged_share, built_root / pack_name)
            self.assertTrue((built_dir / "assets" / "logo.svg").is_file())
            self.assertTrue((built_dir / "plugin.json").is_file())

        # Missing SVG asset in a checkout with guard/plugins.py fails closed during validate_inputs()
        broken_repo = self.tmp / "broken_linux_repo"
        for rel_dir in ("guard/plugin_assets", "porter", "scripts", "templates", "skills", "agents", ".harness"):
            (broken_repo / rel_dir).mkdir(parents=True, exist_ok=True)
        (broken_repo / "guard" / "plugins.py").write_text("# stub\n", encoding="utf-8")
        for req_file in (
            "guard.py",
            "porter.py",
            "GEMINI.md",
            "DESIGN.md",
            "README.md",
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
            "hooks.json",
            ".harness/manifest.json",
        ):
            (broken_repo / req_file).write_text("ok\n", encoding="utf-8")
        broken_packager = LinuxPackager(repo_root=broken_repo, arch="amd64", out_dir=self.tmp / "broken_out")
        with self.assertRaises(FileNotFoundError) as ctx:
            broken_packager.validate_inputs()
        self.assertIn("plugin SVG asset", str(ctx.exception))


class TestW4Tier3AuditRemediationAndRegressionSeam(_IsolatedHybridEnvMixin, unittest.TestCase):
    """Mutation-resilient tests for W4 Tier-3 8-auditor security, contract, silent-failure, and CI findings."""

    def setUp(self) -> None:
        self._setup_sandbox("agy_hyb_w4_")
        self.ws = self.tmp / "workspace"
        self.ws.mkdir()

    def tearDown(self) -> None:
        self._teardown_sandbox()

    def test_security_plugins_shield_backtick_extglob_quoted_and_write_symlink_escape(self) -> None:
        cfg_s = str(self.cfg)
        (self.cfg / "plugins" / "ui-refinery").mkdir(parents=True, exist_ok=True)
        (self.cfg / "plugins" / "ui-refinery" / "plugin.json").write_text("{}", encoding="utf-8")
        (self.cfg / "plugins" / "rea").mkdir(parents=True, exist_ok=True)

        # Write-tool traversal, Win32 trailing-dot/space, and third-party symlink escape into harness pack -> deny
        for bad_target in (
            str(self.cfg / "plugins" / "rea" / ".." / "ui-refinery" / "plugin.json"),
            str(self.cfg / "plugins" / "ui-refinery." / "plugin.json"),
            str(self.cfg / "plugins" / "ui-refinery " / "plugin.json"),
        ):
            res = agy_hooks.handle_pre_tool_use(
                {
                    "toolName": "write_to_file",
                    "cwd": str(self.ws),
                    "toolInput": {"TargetFile": bad_target, "CodeContent": "{}"},
                }
            )
            self.assertEqual(res.get("decision"), "deny", f"Expected deny for write {bad_target!r}: {res}")

        if os.name != "nt":
            sym_escape = self.cfg / "plugins" / "rea" / "escape.json"
            os.symlink(str(self.cfg / "plugins" / "ui-refinery" / "plugin.json"), str(sym_escape))
            res_sym = agy_hooks.handle_pre_tool_use(
                {
                    "toolName": "write_to_file",
                    "cwd": str(self.ws),
                    "toolInput": {"TargetFile": str(sym_escape), "CodeContent": "{}"},
                }
            )
            self.assertEqual(res_sym.get("decision"), "deny", f"Expected deny for symlink escape: {res_sym}")

        # Shell Guard: quoted harness pack, backtick cmd-subst, Bash extglob, Win32 trailing-dot -> deny; quoted third-party -> allow
        for deny_cmd in (
            f'rm -rf "{cfg_s}/plugins/ui-refinery"',
            f'rm -f "{cfg_s}/plugins/ui-refinery/plugin.json"',
            f'chmod -R u+w "{cfg_s}/plugins/`printf ui-refinery`"',
            f"rm -rf {cfg_s}/plugins/`cat<<<ui-refinery`",
            f"shopt -s extglob; chmod -R u+w {cfg_s}/plugins/@(ui-refinery)",
            f"shopt -s extglob; rm -f {cfg_s}/plugins/!(rea)/plugin.json",
            f'rm -f "{cfg_s}/plugins/ui-refinery./plugin.json"',
        ):
            res = agy_hooks.handle_pre_tool_use(
                {
                    "toolName": "run_command",
                    "cwd": str(self.ws),
                    "toolInput": {"CommandLine": deny_cmd},
                }
            )
            self.assertEqual(res.get("decision"), "deny", f"Expected deny for shell `{deny_cmd}`: {res}")

        allow_quoted_3p = agy_hooks.handle_pre_tool_use(
            {
                "toolName": "run_command",
                "cwd": str(self.ws),
                "toolInput": {"CommandLine": f'mkdir -p "{cfg_s}/plugins/rea"'},
            }
        )
        self.assertEqual(allow_quoted_3p.get("decision"), "allow", allow_quoted_3p)

    def test_security_agy_plugin_cli_gate_cross_os_obfuscation_wrappers_and_workspace_script(self) -> None:
        # Cross-OS plugin CLI bypasses (no os.name != "nt" skip)
        for cmd in (
            "agy.exe plugin disable ui-refinery",
            "agy.ps1 plugin uninstall rust-suite",
            "a'g'y plugin disable ui-refinery",
            "agy 'plug''in' uninstall ui-refinery",
            r"agy pl\ugin disable ui-refinery",
            "P=plu; Q=gin; agy $P$Q disable ui-refinery",
            "agy plugin install ./ui-refinery/.",
            "agy plugin install ./ui-refinery/plugin.json",
            "agy plugin import dist/plugins/ui-refinery-3.0.0.zip",
            "agy plugin install ui-refinery@3.0.0",
            "agy plugin import dist/plugins/ui-r*.zip",
            "agy plugin disable {u,x}i-refin{e,z}ry",
            "agy plugin disable --all",
            "agy plugin disable --path=ui-refinery",
            "agy plugin uninstall -- ui-refinery",
            "agy plugin disable $(printf ui-refinery)",
            "printf ui-refinery | xargs agy plugin disable",
            "stdbuf -o L agy plugin disable ui-refinery",
            "env -S'agy plugin disable ui-refinery'",
            "echo agy plugin disable ui-refinery | sh",
        ):
            res = agy_hooks.handle_pre_tool_use(
                {
                    "toolName": "run_command",
                    "cwd": str(self.ws),
                    "toolInput": {"CommandLine": cmd},
                }
            )
            self.assertEqual(res.get("decision"), "force_ask", f"Expected force_ask for `{cmd}`, got {res}")

        # deny takes precedence over force_ask when chained with a Governance Shield violation
        chained = agy_hooks.handle_pre_tool_use(
            {
                "toolName": "run_command",
                "cwd": str(self.ws),
                "toolInput": {"CommandLine": f"agy plugin disable ui-refinery && rm -rf {self.cfg}/plugins/ui-refinery"},
            }
        )
        self.assertEqual(chained.get("decision"), "deny", chained)

        # Third-party literal plugin remains allow
        res_3p = agy_hooks.handle_pre_tool_use(
            {
                "toolName": "run_command",
                "cwd": str(self.ws),
                "toolInput": {"CommandLine": "agy plugin disable rea"},
            }
        )
        self.assertEqual(res_3p.get("decision"), "allow", res_3p)

        # Workspace script executing agy plugin disable ui-refinery triggers force_ask (not allow)
        ws_script = self.ws / "toggle_pack.sh"
        ws_script.write_text("#!/bin/sh\nagy plugin disable ui-refinery\n", encoding="utf-8")
        res_script = agy_hooks.handle_pre_tool_use(
            {
                "toolName": "run_command",
                "cwd": str(self.ws),
                "toolInput": {"CommandLine": "sh ./toggle_pack.sh"},
            }
        )
        self.assertEqual(res_script.get("decision"), "force_ask", res_script)

    def test_pre_invocation_flat_revert_ignores_stale_config_disable_recursion_dos_and_workspace_plugins(self) -> None:
        # 1. Install hybrid, disable ui-refinery in config.json, revert to --flat-skills -> flat skills & MCP still active
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(harness_install.main(["--plugins", "--no-lock"]), 0)
        cfg_json = self.cfg / "config.json"
        cfg_json.write_text(json.dumps({"plugins": {"ui-refinery": {"enabled": False}}}), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(harness_install.main(["--flat-skills", "--no-lock"]), 0)

        res_flat = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-w4-flat-revert", "cwd": str(self.ws), "prompt": "run /ui-refinery and check color contrast ratio"}
        )
        txt_flat = _extract_pre_invocation_messages(res_flat)
        self.assertIn("ui-refinery", txt_flat)
        self.assertIn("ui-refinery-contrast", txt_flat)

        # Workspace .agents/plugins/ui-refinery/plugin.json disabled=true must NOT silence global flat skills
        ws_plug = self.ws / ".agents" / "plugins" / "ui-refinery"
        ws_plug.mkdir(parents=True, exist_ok=True)
        (ws_plug / "plugin.json").write_text(json.dumps({"name": "ui-refinery", "disabled": True}), encoding="utf-8")
        res_no_shadow = agy_hooks.handle_pre_invocation(
            {"conversationId": "conv-w4-no-ws-shadow", "cwd": str(self.ws), "prompt": "use /ui-refinery on my page"}
        )
        self.assertIn("ui-refinery", _extract_pre_invocation_messages(res_no_shadow))

        # 2. Deeply nested JSON / RecursionError guard -> fail-safe enabled + stderr warning
        cfg_json.write_text("{" + '"a":' * 100 + "1" + "}" * 100, encoding="utf-8")
        err_buf = io.StringIO()
        with mock.patch("guard.hooks.pre_invocation.json.loads", side_effect=RecursionError("maximum recursion depth")), contextlib.redirect_stderr(err_buf):
            active = agy_hooks._is_harness_plugin_active("ui-refinery", self.cfg, (self.ws,), _turn_cache={})
        self.assertTrue(active)
        self.assertIn("corrupt/deep JSON", err_buf.getvalue())

        # 3. Standalone workspace .agents/plugins/ui-refinery/mcp_config.json switches MCP hint to ui-refinery_contrast
        empty_cfg = self.tmp / "empty_cfg"
        empty_cfg.mkdir()
        (ws_plug / "plugin.json").write_text(json.dumps({"name": "ui-refinery", "disabled": False}), encoding="utf-8")
        (ws_plug / "mcp_config.json").write_text(json.dumps({"mcpServers": {"contrast": {}}}), encoding="utf-8")
        with mock.patch.dict(os.environ, {"ANTIGRAVITY_CONFIG_DIR": str(empty_cfg)}):
            res_ws_mcp = agy_hooks.handle_pre_invocation(
                {"conversationId": "conv-w4-ws-mcp", "cwd": str(self.ws), "prompt": "check color contrast ratio"}
            )
        self.assertIn("ui-refinery_contrast", _extract_pre_invocation_messages(res_ws_mcp))

        # 4. Synthetic _GlobalsProxy facade override is respected in _collect_invocation_skill_hints
        import guard.hooks.pre_invocation as pre_inv_mod

        class _FakeGlobalsProxy:
            _globals = {
                "SKILL_HINTS": (
                    ("custom-w4-skill", "skills/custom-w4-skill/SKILL.md", re.compile(r"w4-synthetic-token"), "custom"),
                ),
            }

        with mock.patch.object(pre_inv_mod, "_facade", return_value=_FakeGlobalsProxy()):
            matched_sk, _ = pre_inv_mod._collect_invocation_skill_hints(
                "w4-synthetic-token",
                is_short_or_continuation=False,
                has_explicit_cmd=False,
                is_readonly_meta_question=False,
                seen_turns={},
                is_new_user_turn=True,
                active_turn=1,
                workspaces=(self.ws,),
            )
        self.assertTrue(any(s == "custom-w4-skill" for s, _r, _d in matched_sk), matched_sk)

    def test_validate_plugin_dir_mcp_binding_logo_escape_repo_leaks_and_zip_bomb_hardening(self) -> None:
        out_root = self.tmp / "val_packs"
        ui_refinery_dir = build_plugin_pack("ui-refinery", REPO_ROOT, out_root / "ui-refinery")
        rust_dir = build_plugin_pack("rust-suite", REPO_ROOT, out_root / "rust-suite")

        # 1. MCP catalog binding: unexpected mcp_config.json in rust-suite rejected; rogue server in ui-refinery rejected
        (rust_dir / "mcp_config.json").write_text(
            json.dumps({"mcpServers": {"rogue": {"command": "python3", "args": []}}}), encoding="utf-8"
        )
        res_rust_mcp = validate_plugin_dir(rust_dir, expected_pack="rust-suite")
        self.assertFalse(res_rust_mcp.ok)
        self.assertTrue(any("Unexpected mcp_config.json" in e for e in res_rust_mcp.errors), res_rust_mcp.errors)
        (rust_dir / "mcp_config.json").unlink()

        orig_mcp = (ui_refinery_dir / "mcp_config.json").read_text(encoding="utf-8")
        # Double-prefixed key (would expose ui-refinery_ui-refinery_contrast in Antigravity) must be rejected
        (ui_refinery_dir / "mcp_config.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "ui-refinery_contrast": {
                            "command": "python3",
                            "args": ["${PLUGIN_ROOT}/skills/ui-refinery/scripts/contrast-mcp.py"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        res_double_prefix = validate_plugin_dir(ui_refinery_dir, expected_pack="ui-refinery")
        self.assertFalse(res_double_prefix.ok)
        self.assertTrue(any("must be exactly {'contrast'}" in e for e in res_double_prefix.errors), res_double_prefix.errors)

        (ui_refinery_dir / "mcp_config.json").write_text(
            json.dumps({"mcpServers": {"contrast": {"command": "python3", "args": []}}}), encoding="utf-8"
        )
        res_bad_args = validate_plugin_dir(ui_refinery_dir, expected_pack="ui-refinery")
        self.assertFalse(res_bad_args.ok)
        self.assertTrue(any("missing expected arg" in e for e in res_bad_args.errors), res_bad_args.errors)
        (ui_refinery_dir / "mcp_config.json").write_text(orig_mcp, encoding="utf-8")

        # 2. Windows drive-letter logo escape rejected
        orig_pj = (rust_dir / "plugin.json").read_text(encoding="utf-8")
        pj_bad = json.loads(orig_pj)
        pj_bad["logo"] = "C:/outside/logo.svg"
        (rust_dir / "plugin.json").write_text(json.dumps(pj_bad), encoding="utf-8")
        res_win_logo = validate_plugin_dir(rust_dir, expected_pack="rust-suite")
        self.assertFalse(res_win_logo.ok)
        self.assertTrue(any("safe plugin-relative path" in e for e in res_win_logo.errors), res_win_logo.errors)
        (rust_dir / "plugin.json").write_text(orig_pj, encoding="utf-8")

        # 3. Non-dir file under skills/ and leaked repo-relative path in Markdown rejected
        stray_file = rust_dir / "skills" / "stray.txt"
        stray_file.write_text("stray", encoding="utf-8")
        rust_md = rust_dir / "skills" / "rustify" / "SKILL.md"
        orig_rust_md = rust_md.read_text(encoding="utf-8")
        rust_md.write_text(orig_rust_md + "\nSee templates/HANDOFF.template.md for details.\n", encoding="utf-8")
        res_leak = validate_plugin_dir(rust_dir, expected_pack="rust-suite")
        self.assertFalse(res_leak.ok)
        self.assertTrue(any("Unexpected non-directory" in e for e in res_leak.errors), res_leak.errors)
        self.assertTrue(any("leaked repo-relative" in e for e in res_leak.errors), res_leak.errors)
        stray_file.unlink()
        rust_md.write_text(orig_rust_md, encoding="utf-8")

        # 4. Mocked run_agy_validate timeout reports structured error cleanly
        with mock.patch("guard.plugins.shutil.which", return_value="/usr/bin/agy"), mock.patch(
            "guard.plugins.subprocess.run", side_effect=subprocess.TimeoutExpired(["agy"], 30)
        ):
            res_to = validate_plugin_dir(rust_dir, expected_pack="rust-suite", run_agy_validate=True)
        self.assertFalse(res_to.ok)
        self.assertEqual(res_to.agy_validate_status, "failed")

        # 5. Zip validation: symlinked sibling .sha256 rejected even when sha256_path=None; CRC error caught cleanly
        zpath, spath = archive_plugin_pack(rust_dir, self.tmp / "rust-suite-v3.0.0.zip")
        if os.name != "nt":
            spath.unlink()
            os.symlink("/etc/hostname", str(spath))
            res_sym_sha = validate_plugin_zip(zpath, expected_pack="rust-suite")
            self.assertFalse(res_sym_sha.ok)
            self.assertTrue(any("symlinked SHA-256" in e for e in res_sym_sha.errors), res_sym_sha.errors)
            spath.unlink()

        bad_crc_zip = self.tmp / "bad_crc.zip"
        raw_z = bytearray(zpath.read_bytes())
        # Flip a byte inside the first compressed payload to trigger BadZipFile CRC error during extraction
        raw_z[80] ^= 0xFF
        bad_crc_zip.write_bytes(bytes(raw_z))
        res_crc = validate_plugin_zip(bad_crc_zip, expected_pack="rust-suite")
        self.assertFalse(res_crc.ok)

        # 6. Frozen interpreter resolution refuses sys.executable passthrough and untrusted CWD/world-writable PATH
        with mock.patch.object(sys, "frozen", True, create=True), mock.patch.dict(
            os.environ, {"PATH": f".{os.pathsep}{os.getcwd()}"}
        ):
            cmd_frozen = resolve_local_python_command(sys.executable)
            self.assertEqual(cmd_frozen, "python" if os.name == "nt" else "python3")

    def test_state_snapshot_oserror_corrupt_receipt_preservation_link_mcp_restore_and_runtime_release(self) -> None:
        from guard.environment import is_harness_plugin_dir, restore_state_files, snapshot_state_files

        # 1. snapshot_state_files() OSError on existing file -> captured=False -> restore_state_files() preserves file
        existing_state = self.state / "protected_state.json"
        existing_state.write_text('{"keep": true}\n', encoding="utf-8")
        with mock.patch.object(Path, "read_bytes", side_effect=OSError("EACCES")), contextlib.redirect_stderr(io.StringIO()):
            snaps = snapshot_state_files([existing_state])
        self.assertEqual(len(snaps), 1)
        self.assertTrue(snaps[0].existed)
        self.assertFalse(snaps[0].captured)
        with contextlib.redirect_stderr(io.StringIO()):
            restore_state_files(snaps)
        self.assertTrue(existing_state.is_file())
        self.assertEqual(existing_state.read_text(encoding="utf-8"), '{"keep": true}\n')

        # 2. Corrupt install_receipt.json on bare re-run over existing Hybrid profile preserves Hybrid (no shadowing)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(harness_install.main(["--plugins", "--no-lock"]), 0)
        (self.state / "install_receipt.json").write_text("{corrupt", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(harness_install.main(["--no-lock"]), 0)
        rec_after = json.loads((self.state / "install_receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(rec_after["layout"], "hybrid")
        self.assertFalse((self.cfg / "skills" / "ui-refinery").exists())

        # 3. Receiptless --flat-skills revert removes canonical harness packs via is_harness_plugin_dir()
        #    while preserving a non-harness plugins/rust-suite directory
        self.assertTrue(is_harness_plugin_dir(self.cfg / "plugins" / "ui-refinery", expected_pack="ui-refinery"))
        (self.state / "install_receipt.json").unlink()
        shutil.rmtree(self.cfg / "plugins" / "rust-suite")
        (self.cfg / "plugins" / "rust-suite").mkdir(parents=True)
        (self.cfg / "plugins" / "rust-suite" / "plugin.json").write_text(
            json.dumps({"name": "rust-suite", "homepage": "https://third-party.example/rust"}), encoding="utf-8"
        )
        self.assertFalse(is_harness_plugin_dir(self.cfg / "plugins" / "rust-suite", expected_pack="rust-suite"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(harness_install.main(["--flat-skills", "--no-lock"]), 0)
        self.assertFalse((self.cfg / "plugins" / "ui-refinery").exists())
        self.assertTrue((self.cfg / "plugins" / "rust-suite" / "plugin.json").is_file())

        # 4. --link --flat-skills restores retired MCP entry via verified repo symlink; failed restore retains retired key
        mcp_path = self.cfg / "mcp_config.json"
        mcp_path.write_text(
            json.dumps({"mcpServers": {"ui-refinery-contrast": {"command": "python3", "args": [str(self.cfg / "skills" / "ui-refinery" / "scripts" / "contrast-mcp.py")]}}}),
            encoding="utf-8",
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(harness_install.main(["--plugins", "--no-lock"]), 0)
        self.assertEqual(json.loads(mcp_path.read_text(encoding="utf-8")), {"mcpServers": {}})
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(harness_install.main(["--link", "--flat-skills", "--no-lock"]), 0)
        self.assertIn("ui-refinery-contrast", json.loads(mcp_path.read_text(encoding="utf-8"))["mcpServers"])

        # 5. release_runtime_state() unlocks plugins/ and plugins/rea while keeping plugins/ui-refinery write-protected
        if os.name != "nt":
            rt_cfg = self.tmp / "rt_cfg"
            (rt_cfg / "plugins" / "ui-refinery").mkdir(parents=True)
            (rt_cfg / "plugins" / "rea").mkdir(parents=True)
            (rt_cfg / "plugins" / "ui-refinery" / "plugin.json").write_text("{}", encoding="utf-8")
            (rt_cfg / "plugins" / "rea" / "plugin.json").write_text("{}", encoding="utf-8")
            adapter = EnvironmentRegistry().os_adapter
            adapter.lock(rt_cfg / "plugins" / "ui-refinery", recursive=True)
            adapter.lock(rt_cfg / "plugins" / "rea", recursive=True)
            adapter.lock(rt_cfg / "plugins", recursive=False)
            harness_install.release_runtime_state(adapter, rt_cfg, dry_run=False)
            self.assertTrue(os.access(rt_cfg / "plugins", os.W_OK))
            self.assertTrue(os.access(rt_cfg / "plugins" / "rea" / "plugin.json", os.W_OK))
            self.assertFalse(os.access(rt_cfg / "plugins" / "ui-refinery" / "plugin.json", os.W_OK))
            adapter.unlock(rt_cfg / "plugins" / "ui-refinery", recursive=True)

        # 6. Dangling symlink config.json is never followed during bootstrap
        if os.name != "nt":
            ext_target = self.tmp / "should_not_create.json"
            cfg_sym = self.cfg / "config.json"
            if os.path.lexists(cfg_sym):
                cfg_sym.unlink()
            os.symlink(str(ext_target), str(cfg_sym))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(harness_install.main(["--flat-skills", "--no-lock"]), 0)
            self.assertFalse(ext_target.exists())

    def test_porter_cmd_manifest_hybrid_guard_extra_files_meta_audit_negatives_and_ci_contract(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(harness_install.main(["--plugins", "--no-lock"]), 0)

        # 1. porter.py manifest without --check fails closed on installed hybrid root
        runtime_porter = self.data / "runtime" / "porter.py"
        res_gen = subprocess.run(
            [sys.executable, str(runtime_porter), "manifest"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res_gen.returncode, 1, res_gen.stdout + res_gen.stderr)
        self.assertIn("refusing to regenerate", res_gen.stderr.lower())
        with self.assertRaises(ValueError):
            ManifestEngine(self.cfg).save_manifest()

        # 2. _is_hybrid_up_to_date() rejects mutated extra_files and injected stray files inside a pack
        engine = ManifestEngine(self.cfg)
        self.assertTrue(engine.is_up_to_date())
        extra_design = self.cfg / "plugins" / "ui-refinery" / "skills" / "ui-refinery" / "references" / "DESIGN.md"
        orig_design = extra_design.read_bytes()
        extra_design.write_text("# Tampered\n", encoding="utf-8")
        self.assertFalse(engine.is_up_to_date())
        extra_design.write_bytes(orig_design)

        stray_pack_file = self.cfg / "plugins" / "ui-refinery" / "injected.txt"
        stray_pack_file.write_text("rogue\n", encoding="utf-8")
        self.assertFalse(engine.is_up_to_date())
        stray_pack_file.unlink()
        self.assertTrue(engine.is_up_to_date())

        # 3. meta_audit Pass 4 reports BOTH pack error AND core divergence simultaneously
        (self.cfg / "plugins" / "rust-suite" / "mcp_config.json").write_text("{}", encoding="utf-8")
        core_design = self.cfg / "DESIGN.md"
        orig_core_design = core_design.read_bytes()
        core_design.write_text("# Drifted core\n", encoding="utf-8")
        p4_both = MetaAuditEngine(repo_root=self.cfg).run_pass(4)
        self.assertTrue(any("failed validation" in f.message for f in p4_both), p4_both)
        self.assertTrue(any("diverge from canonical" in f.message for f in p4_both), p4_both)
        (self.cfg / "plugins" / "rust-suite" / "mcp_config.json").unlink()
        core_design.write_bytes(orig_core_design)

        # 4. Pass 5 catches guard/hooks/common.py mirror drift
        import guard.hooks.common as hooks_common

        with mock.patch.object(hooks_common, "_HARNESS_PLUGIN_NAMES", frozenset({"ui-refinery"})):
            p5_drift = MetaAuditEngine(repo_root=REPO_ROOT).run_pass(5)
        self.assertTrue(any("Hot-path plugin constants" in f.message for f in p5_drift), p5_drift)

        # 5. scripts/build_plugins.py is Rule-17 gated in pre_tool_use.py
        import guard.hooks.pre_tool_use as ptu_mod

        self.assertTrue(ptu_mod._targets_customization_structure("scripts/build_plugins.py", workspace=REPO_ROOT))

        # 6. .github/workflows/ci.yml contract invariants (3-OS plugin validation, package-plugins, release.needs)
        ci_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('python scripts/build_plugins.py --out "${{ runner.temp }}/plugins" --validate --zip', ci_text)
        self.assertIn("package-plugins:", ci_text)
        self.assertIn("dist/plugins/*.zip", ci_text)
        self.assertIn("dist/plugins/*.zip.sha256", ci_text)
        self.assertIn("sha256sum -c", ci_text)
        self.assertIn("needs: [build-binaries, package-linux, package-plugins]", ci_text)

    def test_f2_f3_plugin_schema_string_repository_mit_license_and_pack_scoped_notices(self) -> None:
        from guard.environment import is_harness_plugin_dir
        from guard.plugins import ALLOWED_PLUGIN_MANIFEST_KEYS, PLUGIN_REPOSITORY

        # F2: PLUGIN_REPOSITORY is a plain https:// URL string and ALLOWED_PLUGIN_MANIFEST_KEYS matches live v1/plugin.json
        self.assertEqual(PLUGIN_REPOSITORY, "https://github.com/hadbilen/plumbwork")
        for official_key in ("license", "keywords", "skills", "extensions", "repository", "homepage", "author"):
            self.assertIn(official_key, ALLOWED_PLUGIN_MANIFEST_KEYS)

        out_root = self.tmp / "f2_f3_packs"
        summary = build_all_plugin_packs(REPO_ROOT, out_root, create_zip=True, validate=True)
        root_license_lf = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8").replace("\r\n", "\n")

        for pack_name in PLUGIN_CATALOG:
            self.assertTrue(summary[pack_name]["ok"], summary[pack_name])
            pdir = out_root / pack_name
            manifest = json.loads((pdir / "plugin.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["repository"], "https://github.com/hadbilen/plumbwork")
            self.assertEqual(manifest["license"], "MIT")

            # F3: LICENSE present in all 4 packs and README states MIT License
            lic_file = pdir / "LICENSE"
            self.assertTrue(lic_file.is_file(), f"Missing LICENSE in {pack_name}")
            self.assertEqual(lic_file.read_text(encoding="utf-8"), root_license_lf)
            readme_txt = (pdir / "README.md").read_text(encoding="utf-8")
            self.assertIn("MIT License", readme_txt)
            self.assertIn("[LICENSE](./LICENSE)", readme_txt)

            # Verify zip archive carries LICENSE (and pack-scoped THIRD_PARTY_NOTICES.md where required)
            zpath = Path(summary[pack_name]["zip"])
            with zipfile.ZipFile(zpath, "r") as zf:
                znames = set(zf.namelist())
            self.assertIn(f"{pack_name}/LICENSE", znames)
            if pack_name in ("ui-refinery", "rust-suite"):
                self.assertIn(f"{pack_name}/THIRD_PARTY_NOTICES.md", znames)
                self.assertIn("[THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)", readme_txt)
            else:
                self.assertNotIn(f"{pack_name}/THIRD_PARTY_NOTICES.md", znames)
                self.assertFalse((pdir / "THIRD_PARTY_NOTICES.md").exists())

        # Verify pack-scoped THIRD_PARTY_NOTICES.md contents (zero cross-pack or Apache-2.0 leakage)
        anti_notices = (out_root / "ui-refinery" / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        self.assertIn("miqdadbadjuber/anti-slop", anti_notices)
        self.assertIn("Miqdad Badjuber", anti_notices)
        self.assertIn("bendrape1-byte/silk-design", anti_notices)
        self.assertIn("Ben Drape", anti_notices)
        self.assertNotIn("erkamyaman/rust-anything", anti_notices)
        self.assertNotIn("Apache-2.0", anti_notices)

        rust_notices = (out_root / "rust-suite" / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        self.assertIn("erkamyaman/rust-anything", rust_notices)
        self.assertIn("Erkam Yaman", rust_notices)
        self.assertNotIn("miqdadbadjuber/anti-slop", rust_notices)
        self.assertNotIn("bendrape1-byte/silk-design", rust_notices)
        self.assertNotIn("Apache-2.0", rust_notices)

        # F2: is_harness_plugin_dir recognizes plain string repository (even without homepage) and rejects third-party
        probe_pack = self.tmp / "probe_repo_only"
        probe_pack.mkdir()
        (probe_pack / "plugin.json").write_text(
            json.dumps({"name": "ui-refinery", "repository": "https://github.com/hadbilen/plumbwork"}),
            encoding="utf-8",
        )
        self.assertTrue(is_harness_plugin_dir(probe_pack, expected_pack="ui-refinery"))
        (probe_pack / "plugin.json").write_text(
            json.dumps({"name": "ui-refinery", "repository": "https://example.invalid/other"}),
            encoding="utf-8",
        )
        self.assertFalse(is_harness_plugin_dir(probe_pack, expected_pack="ui-refinery"))

        # F2 negative: validate_plugin_dir rejects dict repository and validates official schema optional fields
        ge_dir = out_root / "game-engineering"
        pj_path = ge_dir / "plugin.json"
        orig_pj = json.loads(pj_path.read_text(encoding="utf-8"))

        pj_dict_repo = dict(orig_pj, repository={"type": "git", "url": "https://github.com/hadbilen/plumbwork"})
        pj_path.write_text(json.dumps(pj_dict_repo), encoding="utf-8")
        res_obj_repo = validate_plugin_dir(ge_dir, expected_pack="game-engineering")
        self.assertFalse(res_obj_repo.ok)
        self.assertTrue(any("repository" in e and "string" in e for e in res_obj_repo.errors), res_obj_repo.errors)

        # Official schema optional keys accepted when well-typed, rejected when mistyped
        pj_valid_ext = dict(
            orig_pj,
            keywords=["game", "canvas"],
            skills=["extra-skills"],
            extensions={"antigravity": {"tier": "domain"}},
        )
        pj_path.write_text(json.dumps(pj_valid_ext), encoding="utf-8")
        self.assertTrue(validate_plugin_dir(ge_dir, expected_pack="game-engineering").ok)

        pj_bad_ext = dict(orig_pj, keywords="not-a-list", skills=123, extensions={"ns": "not-an-object"})
        pj_path.write_text(json.dumps(pj_bad_ext), encoding="utf-8")
        res_bad_ext = validate_plugin_dir(ge_dir, expected_pack="game-engineering")
        self.assertFalse(res_bad_ext.ok)
        joined_ext_err = "\n".join(res_bad_ext.errors)
        self.assertIn("keywords", joined_ext_err)
        self.assertIn("skills", joined_ext_err)
        self.assertIn("extensions", joined_ext_err)

        # Missing or wrong license in harness pack manifest rejected
        pj_no_lic = {k: v for k, v in orig_pj.items() if k != "license"}
        pj_path.write_text(json.dumps(pj_no_lic), encoding="utf-8")
        res_no_lic = validate_plugin_dir(ge_dir, expected_pack="game-engineering")
        self.assertFalse(res_no_lic.ok)
        self.assertTrue(any("license" in e for e in res_no_lic.errors), res_no_lic.errors)
        pj_path.write_text(json.dumps(orig_pj), encoding="utf-8")

        # F3 negative: missing LICENSE, missing/incomplete THIRD_PARTY_NOTICES.md, unexpected notices in clean pack,
        # and tampered zip missing LICENSE / THIRD_PARTY_NOTICES.md are all rejected
        (ge_dir / "LICENSE").unlink()
        res_no_lic_file = validate_plugin_dir(ge_dir, expected_pack="game-engineering")
        self.assertFalse(res_no_lic_file.ok)
        self.assertTrue(any("LICENSE" in e for e in res_no_lic_file.errors), res_no_lic_file.errors)
        (ge_dir / "LICENSE").write_text(root_license_lf, encoding="utf-8")

        (ge_dir / "THIRD_PARTY_NOTICES.md").write_text("# Stray\n", encoding="utf-8")
        res_stray_notice = validate_plugin_dir(ge_dir, expected_pack="game-engineering")
        self.assertFalse(res_stray_notice.ok)
        self.assertTrue(any("Unexpected THIRD_PARTY_NOTICES.md" in e for e in res_stray_notice.errors), res_stray_notice.errors)
        (ge_dir / "THIRD_PARTY_NOTICES.md").unlink()

        anti_dir = out_root / "ui-refinery"
        orig_anti_notices = (anti_dir / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        (anti_dir / "THIRD_PARTY_NOTICES.md").unlink()
        res_missing_notice = validate_plugin_dir(anti_dir, expected_pack="ui-refinery")
        self.assertFalse(res_missing_notice.ok)
        self.assertTrue(any("THIRD_PARTY_NOTICES.md" in e for e in res_missing_notice.errors), res_missing_notice.errors)

        (anti_dir / "THIRD_PARTY_NOTICES.md").write_text("# Third-Party Notices\n\n## miqdadbadjuber/anti-slop (MIT)\n", encoding="utf-8")
        res_incomplete_notice = validate_plugin_dir(anti_dir, expected_pack="ui-refinery")
        self.assertFalse(res_incomplete_notice.ok)
        self.assertTrue(any("bendrape1-byte/silk-design" in e for e in res_incomplete_notice.errors), res_incomplete_notice.errors)
        (anti_dir / "THIRD_PARTY_NOTICES.md").write_text(orig_anti_notices, encoding="utf-8")

        # Zip validator explicitly rejects archives missing LICENSE or required THIRD_PARTY_NOTICES.md
        anti_zip = Path(summary["ui-refinery"]["zip"])
        stripped_zip = self.tmp / "ui_refinery_missing_legal.zip"
        with zipfile.ZipFile(anti_zip, "r") as src_z, zipfile.ZipFile(stripped_zip, "w") as dst_z:
            for info in src_z.infolist():
                if info.filename in ("ui-refinery/LICENSE", "ui-refinery/THIRD_PARTY_NOTICES.md"):
                    continue
                dst_z.writestr(info, src_z.read(info))
        res_zip_legal = validate_plugin_zip(stripped_zip, expected_pack="ui-refinery")
        self.assertFalse(res_zip_legal.ok)
        joined_zerr = "\n".join(res_zip_legal.errors)
        self.assertIn("LICENSE", joined_zerr)
        self.assertIn("THIRD_PARTY_NOTICES.md", joined_zerr)

        # README missing MIT License link rejected
        ge_readme = ge_dir / "README.md"
        orig_ge_readme = ge_readme.read_text(encoding="utf-8")
        ge_readme.write_text("# Game Engineering\n\nNo license statement.\n", encoding="utf-8")
        res_readme_lic = validate_plugin_dir(ge_dir, expected_pack="game-engineering")
        self.assertFalse(res_readme_lic.ok)
        self.assertTrue(any("MIT License" in e for e in res_readme_lic.errors), res_readme_lic.errors)
        ge_readme.write_text(orig_ge_readme, encoding="utf-8")

    @unittest.skipUnless(os.name != "nt", "POSIX shell directory-drop tests")
    def test_f4_plugin_directory_drop_and_unscoped_agy_plugin_install_import_gate(self) -> None:
        cfg_s = str(self.cfg)
        evil_dir = self.cfg / "plugins" / "evil-drop"
        evil_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg / "plugins" / "rea").mkdir(parents=True, exist_ok=True)

        # 1. Directory copies, clones, moves, and cwd-relative extractions into plugins/<any> trigger 3-sentence force_ask
        force_ask_cases = [
            (f"cp -r /tmp/src {cfg_s}/plugins/evil-drop", self.ws),
            (f"cp -R /tmp/src {cfg_s}/plugins/evil-drop", self.ws),
            (f"cp -a /tmp/src {cfg_s}/plugins/evil-drop", self.ws),
            (f"cp -rf /tmp/src {cfg_s}/plugins/evil-drop", self.ws),
            (f"cp --recursive /tmp/src {cfg_s}/plugins/evil-drop", self.ws),
            (f"cp --archive /tmp/src {cfg_s}/plugins/evil-drop", self.ws),
            (f"cp -r -t {cfg_s}/plugins/evil-drop /tmp/src", self.ws),
            (f"rsync -a /tmp/src/ {cfg_s}/plugins/evil-drop/", self.ws),
            (f"rsync -av --exclude .git ./src/ {cfg_s}/plugins/evil-drop/", self.ws),
            (f"git clone https://example.com/evil.git {cfg_s}/plugins/evil-drop", self.ws),
            (f"git -C {cfg_s}/plugins/evil-drop clone https://example.com/evil.git", self.ws),
            (f"mv ./staged_pack {cfg_s}/plugins/evil-drop", self.ws),
            (f"mv -t {cfg_s}/plugins/evil-drop ./staged_pack", self.ws),
            (f'sh -c "cp -r /tmp/src {cfg_s}/plugins/evil-drop"', self.ws),
            (f'echo "rsync -a /tmp/src/ {cfg_s}/plugins/evil-drop/" | sh', self.ws),
            (f"P=evil-drop; cp -r /tmp/src {cfg_s}/plugins/$P", self.ws),
            ("tar -xf /tmp/evil.tar", evil_dir),
            ("tar xzf /tmp/evil.tar.gz", evil_dir),
            ("tar --extract -f /tmp/evil.tar -C plugins/evil-drop", self.cfg),
            ("unzip /tmp/evil.zip", evil_dir),
            ("unzip -q /tmp/evil.zip -d plugins/evil-drop", self.cfg),
            # Unscoped agy plugin install / import (regardless of target name)
            ("agy plugin install /tmp/random-pack", self.ws),
            ("agy plugin import ./dist/custom-bundle.zip", self.ws),
            ("agy plugin install rea", self.ws),
            ("agy plugin import ./rea", self.ws),
            ("env FOO=1 agy --profile dev plugin install third-party-pack", self.ws),
        ]
        for cmd, run_cwd in force_ask_cases:
            with self.subTest(force_ask_cmd=cmd, cwd=str(run_cwd)):
                res = agy_hooks.handle_pre_tool_use(
                    {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}, "cwd": str(run_cwd)}
                )
                self.assertEqual(res.get("decision"), "force_ask", f"Expected force_ask for `{cmd}`, got {res}")
                reason = str(res.get("reason") or "")
                self.assertTrue(reason.startswith("What changes:"), reason)
                self.assertIn("If approved:", reason)
                self.assertIn("If denied:", reason)

        # Symlink target pointing into plugins/<any> is strictly denied by Governance Shield
        sym_drop = self.ws / "plug_link"
        os.symlink(str(evil_dir), str(sym_drop))
        res_sym_drop = agy_hooks.handle_pre_tool_use(
            {"toolCall": {"name": "run_command", "args": {"CommandLine": f"cp -r ./src {sym_drop}"}}, "cwd": str(self.ws)}
        )
        self.assertEqual(res_sym_drop.get("decision"), "deny", res_sym_drop)

        # Workspace script dropping a directory into plugins/<any> or calling agy plugin install triggers 3-sentence force_ask
        drop_script = self.ws / "drop_plugin.sh"
        drop_script.write_text(f"#!/bin/sh\ncp -r /tmp/src {cfg_s}/plugins/evil-drop\n", encoding="utf-8")
        res_ws_drop = agy_hooks.handle_pre_tool_use(
            {"toolCall": {"name": "run_command", "args": {"CommandLine": "sh ./drop_plugin.sh"}}, "cwd": str(self.ws)}
        )
        self.assertEqual(res_ws_drop.get("decision"), "force_ask", res_ws_drop)
        self.assertTrue(str(res_ws_drop.get("reason") or "").startswith("What changes:"), res_ws_drop)

        inst_script = self.ws / "install_custom.sh"
        inst_script.write_text("#!/bin/sh\nagy plugin install /tmp/custom-pack\n", encoding="utf-8")
        res_ws_inst = agy_hooks.handle_pre_tool_use(
            {"toolCall": {"name": "run_command", "args": {"CommandLine": "sh ./install_custom.sh"}}, "cwd": str(self.ws)}
        )
        self.assertEqual(res_ws_inst.get("decision"), "force_ask", res_ws_inst)

        # 2. Harness packs, plugins/ root, and explicit archive extraction into config tree remain strict deny
        for deny_cmd in (
            f"cp -r /tmp/src {cfg_s}/plugins/ui-refinery",
            f"rsync -a /tmp/src/ {cfg_s}/plugins/rust-suite/",
            f"git clone https://example.com/evil.git {cfg_s}/plugins/ui-refinery",
            f"git clone https://example.com/evil.git {cfg_s}/plugins/",
            f"mv ./staged_pack {cfg_s}/plugins/media-studio",
            f"tar -xf /tmp/evil.tar -C {cfg_s}/plugins/evil-drop",
            f"unzip /tmp/evil.zip -d {cfg_s}/plugins/evil-drop",
            f"tar -xf /tmp/evil.tar -C {cfg_s}/plugins/ui-refinery",
        ):
            with self.subTest(deny_cmd=deny_cmd):
                res_d = agy_hooks.handle_pre_tool_use(
                    {"toolCall": {"name": "run_command", "args": {"CommandLine": deny_cmd}}, "cwd": str(self.ws)}
                )
                self.assertEqual(res_d.get("decision"), "deny", f"Expected deny for `{deny_cmd}`, got {res_d}")

        # 3. Existing third-party allow contracts & read-only backups remain allow
        for allow_cmd, run_cwd in (
            (f"mkdir -p {cfg_s}/plugins/rea", self.ws),
            (f"echo '{{}}' > {cfg_s}/plugins/rea/plugin.json", self.ws),
            (f"cp /tmp/x.json {cfg_s}/plugins/rea/plugin.json", self.ws),
            (f"cp -r {cfg_s}/plugins/rea /tmp/backup_rea", self.ws),
            (f"rsync -a {cfg_s}/plugins/rea/ /tmp/backup_rea/", self.ws),
            ("tar -tf /tmp/archive.tar", evil_dir),
            ("unzip -l /tmp/archive.zip", evil_dir),
            ("git clone https://example.com/repo.git ./local-checkout", self.ws),
            ("agy plugin disable rea", self.ws),
            ("agy plugin uninstall rea", self.ws),
            ("agy plugin install --help", self.ws),
            ("agy plugin import --help", self.ws),
        ):
            with self.subTest(allow_cmd=allow_cmd, cwd=str(run_cwd)):
                res_a = agy_hooks.handle_pre_tool_use(
                    {"toolCall": {"name": "run_command", "args": {"CommandLine": allow_cmd}}, "cwd": str(run_cwd)}
                )
                self.assertEqual(res_a, {"decision": "allow"}, f"Expected allow for `{allow_cmd}`, got {res_a}")

        for safe_write in (
            str(self.cfg / "plugins" / "rea" / "plugin.json"),
            str(self.cfg / "plugins" / "demo" / "plugin.json"),
        ):
            res_w = agy_hooks.handle_pre_tool_use(
                {"toolCall": {"name": "write_to_file", "args": {"TargetFile": safe_write}}, "cwd": str(self.ws)}
            )
            self.assertEqual(res_w, {"decision": "allow"}, res_w)

    def test_cross_os_symlink_ancestor_staging_bootcheck_and_str_root_seams(self) -> None:
        from guard.environment import EnvironmentRegistry
        from guard.integrity import FileIntegrityMonitor
        from guard.paths import is_within
        from guard.startup import StartupManager

        # 1. is_within accepts custom str-only non-PathLike root objects (Windows _FakeDriveRoot parity)
        FakeStrRoot = type("_FakeStrRoot", (), {"__str__": lambda self: str(self.tmp_root)})
        fake_root = FakeStrRoot()
        fake_root.tmp_root = self.tmp / "fake_root"
        self.assertTrue(is_within(self.tmp / "fake_root" / "sub" / "a.txt", fake_root))
        self.assertFalse(is_within(self.tmp / "other" / "a.txt", fake_root))

        # 2. Symlinked ancestor (macOS /var -> /private/var equivalent): staging writes allowed, escapes denied,
        #    and StartupManager matches the resolved global antigravity environment and its FIM baseline.
        if os.name != "nt":
            real_base = self.tmp / "private_var"
            link_base = self.tmp / "var_link"
            real_base.mkdir()
            link_base.symlink_to(real_base)

            home_link = link_base / "home"
            cfg_link = home_link / ".gemini" / "config"
            state_link = link_base / "state" / "plumbwork"
            staging_link = state_link / "staging"
            home_staging = home_link / ".local" / "state" / "plumbwork" / "staging"
            for d in (cfg_link, staging_link, home_staging):
                d.mkdir(parents=True, exist_ok=True)
            (cfg_link / "DESIGN.md").write_text("# Design\n", encoding="utf-8")

            with mock.patch.dict(
                os.environ,
                {
                    "HOME": str(home_link),
                    "ANTIGRAVITY_CONFIG_DIR": str(cfg_link),
                    "PLUMB_GUARD_STATE_DIR": str(state_link),
                },
            ):
                r_write = agy_hooks.handle_pre_tool_use(
                    {
                        "tool_name": "write_to_file",
                        "tool_input": {"TargetFile": str(staging_link / "model-calibration-sync.md")},
                    }
                )
                self.assertEqual(r_write.get("decision"), "allow", r_write)

                esc = staging_link / "esc_state"
                esc.symlink_to(state_link)
                r_esc = agy_hooks.handle_pre_tool_use(
                    {
                        "tool_name": "write_to_file",
                        "tool_input": {"TargetFile": str(esc / "upstream_state.json")},
                    }
                )
                self.assertEqual(r_esc.get("decision"), "deny", r_esc)

                r_cp = agy_hooks.handle_pre_tool_use(
                    {
                        "modelName": "Gemini 4 Neon (XHigh)",
                        "effort": "high",
                        "toolCall": {
                            "name": "run_command",
                            "args": {"CommandLine": "cp /tmp/rfc.md ~/.local/state/plumbwork/staging/rfc.md"},
                        },
                    }
                )
                self.assertEqual(r_cp.get("decision"), "allow", r_cp)

                reg = EnvironmentRegistry()
                ag_env = reg.get_environment("antigravity")
                assert ag_env is not None
                FileIntegrityMonitor.for_environment(ag_env, os_adapter=reg.os_adapter).save_baseline()
                mgr = StartupManager(target_dir=cfg_link, registry=reg)
                self.assertEqual(mgr.environment.id, "antigravity")
                self.assertTrue(mgr.integrity_monitor.state_file.is_file())


class TestDoctorPluginNameCollisions(_IsolatedHybridEnvMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._setup_sandbox("agy_hyb_col_")

    def tearDown(self) -> None:
        self._teardown_sandbox()

    def _seed_healthy_global_env(self) -> tuple[EnvironmentRegistry, object]:
        adapter = mock.MagicMock(spec=OSProtectionAdapter)
        adapter.protection_issues.return_value = []
        adapter.is_locked.return_value = True

        (self.cfg / "rules").mkdir(parents=True, exist_ok=True)
        (self.cfg / "rules" / "plumbwork-constitution.md").write_text("---\ntrigger: always_on\n---\n# C\n", encoding="utf-8")
        valid_hook = self.cfg / "valid_hook.py"
        valid_hook.write_text("# ok\n", encoding="utf-8")
        (self.cfg / "hooks.json").write_text(
            json.dumps(
                {
                    "upstream-watchdog": {"SessionStart": [{"type": "command", "command": f'"{sys.executable}" "{valid_hook}"'}]},
                    "harness-gate": {
                        "PreInvocation": [{"type": "command", "command": f'"{sys.executable}" "{valid_hook}"'}],
                        "PreToolUse": [{"type": "command", "command": f'"{sys.executable}" "{valid_hook}"'}],
                        "Stop": [{"type": "command", "command": f'"{sys.executable}" "{valid_hook}"'}],
                    },
                }
            ),
            encoding="utf-8",
        )
        (self.cfg / "config.json").write_text(
            json.dumps(
                {
                    "userSettings": {
                        "globalPermissionGrants": {
                            "deny": ["command(plumb-guard unlock)", "command(regex:.*--no-verify.*)"]
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        reg = EnvironmentRegistry(config_path=self.state / "environments.json", os_adapter=adapter)
        env = reg.get_environment("antigravity")
        assert env is not None
        FileIntegrityMonitor.for_environment(env, os_adapter=adapter).save_baseline()
        return reg, env

    def test_doctor_duplicate_plugin_name_positive_negative_and_no_skills_dir(self) -> None:
        # Deliberately omit <root>/skills/ to ensure duplicate plugin.json check still runs
        self.assertFalse((self.cfg / "skills").exists())
        (self.cfg / "plugins" / "rea").mkdir(parents=True)
        (self.cfg / "plugins" / "rea" / "plugin.json").write_text('{"name": "rea"}\n', encoding="utf-8")
        (self.cfg / "plugins" / "custom-a").mkdir(parents=True)
        (self.cfg / "plugins" / "custom-a" / "plugin.json").write_text('{"name": "custom-a"}\n', encoding="utf-8")
        (self.cfg / "plugins" / "no-manifest").mkdir(parents=True)

        reg, env = self._seed_healthy_global_env()
        rep_clean = diagnose(env, reg, sentinel_active=True)
        self.assertTrue(rep_clean.healthy, rep_clean.warnings)

        # Add colliding plugin directory with identical name
        (self.cfg / "plugins" / "custom-b").mkdir(parents=True)
        (self.cfg / "plugins" / "custom-b" / "plugin.json").write_text('{"name": "custom-a"}\n', encoding="utf-8")
        rep_dup = diagnose(env, reg, sentinel_active=True)
        self.assertFalse(rep_dup.healthy)
        joined = "\n".join(rep_dup.warnings)
        self.assertIn("custom-a", joined)
        self.assertIn("plugins/custom-a", joined)
        self.assertIn("plugins/custom-b", joined)
        self.assertIn("Remove or rename", joined)
        # Strictly read-only: both plugin directories remain untouched on disk
        self.assertTrue((self.cfg / "plugins" / "custom-a" / "plugin.json").is_file())
        self.assertTrue((self.cfg / "plugins" / "custom-b" / "plugin.json").is_file())

    def test_doctor_plugin_name_jsonc_case_folding_and_omitted_or_blank_defaults(self) -> None:
        # Distinct JSONC manifests with // comments, /* */ comments, trailing commas, and comment-like strings stay healthy
        jsonc_alpha = (
            "\ufeff// Leading line comment\n"
            "{\n"
            "  /* Block comment\n"
            "     spanning lines */\n"
            '  "name": "My-Kit", // inline comment\n'
            '  "homepage": "https://example.com/a/*not-a-comment*/,}",\n'
            '  "note": "escaped quote \\" // still string and trailing slash \\\\", // real comment\n'
            '  "tags": ["a", "b",],\n'
            "}\n"
        )
        jsonc_other = (
            "{\n"
            '  "name": "Other-Kit", /* inline block */\n'
            "}\n"
        )
        (self.cfg / "plugins" / "kit-one").mkdir(parents=True)
        (self.cfg / "plugins" / "kit-one" / "plugin.json").write_text(jsonc_alpha, encoding="utf-8")
        (self.cfg / "plugins" / "kit-other").mkdir(parents=True)
        (self.cfg / "plugins" / "kit-other" / "plugin.json").write_text(jsonc_other, encoding="utf-8")

        reg, env = self._seed_healthy_global_env()
        rep_ok = diagnose(env, reg, sentinel_active=True)
        self.assertTrue(rep_ok.healthy, rep_ok.warnings)

        # Case-insensitive JSONC collision (My-Kit vs my-kit)
        (self.cfg / "plugins" / "kit-two").mkdir(parents=True)
        (self.cfg / "plugins" / "kit-two" / "plugin.json").write_text(
            '{\n  // case collision\n  "name": "  my-kit  ",\n}\n',
            encoding="utf-8",
        )
        # Omitted `name` defaults to dir.name ("gamma") and collides with explicit "GAMMA"
        (self.cfg / "plugins" / "gamma").mkdir(parents=True)
        (self.cfg / "plugins" / "gamma" / "plugin.json").write_text("{ /* omitted name */ }\n", encoding="utf-8")
        (self.cfg / "plugins" / "gamma-copy").mkdir(parents=True)
        (self.cfg / "plugins" / "gamma-copy" / "plugin.json").write_text('{"name": "GAMMA"}\n', encoding="utf-8")
        # Blank `name` defaults to dir.name ("delta") and collides with explicit "delta"
        (self.cfg / "plugins" / "delta").mkdir(parents=True)
        (self.cfg / "plugins" / "delta" / "plugin.json").write_text('{"name": "   "}\n', encoding="utf-8")
        (self.cfg / "plugins" / "delta-copy").mkdir(parents=True)
        (self.cfg / "plugins" / "delta-copy" / "plugin.json").write_text('{"name": "delta"}\n', encoding="utf-8")

        rep_col = diagnose(env, reg, sentinel_active=True)
        self.assertFalse(rep_col.healthy)
        joined = "\n".join(rep_col.warnings)
        self.assertIn("plugins/kit-one", joined)
        self.assertIn("plugins/kit-two", joined)
        self.assertIn("my-kit", joined)
        self.assertIn("plugins/gamma", joined)
        self.assertIn("plugins/gamma-copy", joined)
        self.assertIn("plugins/delta", joined)
        self.assertIn("plugins/delta-copy", joined)

    def test_doctor_plugin_name_type_corrupt_invalid_jsonc_oversized_and_non_regular(self) -> None:
        cases = {
            "bad-int": '{"name": 123}\n',
            "bad-bool": '{"name": true}\n',
            "bad-null": '{"name": null}\n',
            "bad-list": '{"name": ["x"]}\n',
            "bad-root": '["not-an-object"]\n',
            "bad-corrupt": "{not valid json\n",
            "bad-unterminated": '{"name": "ok"} /* unclosed\n',
            "bad-slash-star-slash": '{"name": "ok"} /*/\n',
            "bad-double-comma": '{"name": "ok", ,}\n',
            "bad-leading-comma": '{"tags": [,]}\n',
        }
        for dirname, payload in cases.items():
            d = self.cfg / "plugins" / dirname
            d.mkdir(parents=True)
            (d / "plugin.json").write_text(payload, encoding="utf-8")

        # Non-UTF8 bytes handled cleanly without unhandled exception
        (self.cfg / "plugins" / "bad-utf8").mkdir(parents=True)
        (self.cfg / "plugins" / "bad-utf8" / "plugin.json").write_bytes(b"\xff\xfe\x00not-utf8")

        # Exact 256 KiB manifest is accepted (<= 256 KiB boundary); 256 KiB + 1 is rejected
        (self.cfg / "plugins" / "exact-limit").mkdir(parents=True)
        prefix = '{"name": "exact-limit", "pad": "'
        suffix = '"}'
        exact_payload = (prefix + ("a" * (256 * 1024 - len(prefix) - len(suffix))) + suffix).encode("utf-8")
        self.assertEqual(len(exact_payload), 256 * 1024)
        (self.cfg / "plugins" / "exact-limit" / "plugin.json").write_bytes(exact_payload)

        # Oversized (> 256 KiB) manifest even starting with a colliding name is rejected without parsing
        (self.cfg / "plugins" / "rea").mkdir(parents=True)
        (self.cfg / "plugins" / "rea" / "plugin.json").write_text('{"name": "rea"}\n', encoding="utf-8")
        (self.cfg / "plugins" / "huge-pack").mkdir(parents=True)
        pad = " " * (256 * 1024 + 64)
        (self.cfg / "plugins" / "huge-pack" / "plugin.json").write_text(
            '{"name": "rea", "pad": "' + pad + '"}\n',
            encoding="utf-8",
        )
        # Non-regular manifest (directory named plugin.json)
        (self.cfg / "plugins" / "dir-manifest" / "plugin.json").mkdir(parents=True)

        reg, env = self._seed_healthy_global_env()
        rep = diagnose(env, reg, sentinel_active=True)
        self.assertFalse(rep.healthy)
        for dirname in ("bad-int", "bad-bool", "bad-null", "bad-list"):
            self.assertTrue(
                any(dirname in w and "non-string" in w.lower() for w in rep.warnings),
                f"Expected non-string warning for {dirname}, got {rep.warnings}",
            )
        self.assertTrue(any("bad-root" in w and "json object" in w.lower() for w in rep.warnings), rep.warnings)
        for dirname in (
            "bad-corrupt",
            "bad-unterminated",
            "bad-slash-star-slash",
            "bad-double-comma",
            "bad-leading-comma",
            "bad-utf8",
        ):
            self.assertTrue(
                any(dirname in w and ("valid json" in w.lower() or "jsonc" in w.lower()) for w in rep.warnings),
                f"Expected invalid JSON/JSONC warning for {dirname}, got {rep.warnings}",
            )
        self.assertFalse(any("exact-limit" in w for w in rep.warnings), rep.warnings)
        self.assertTrue(any("huge-pack" in w and "256 KiB" in w for w in rep.warnings), rep.warnings)
        self.assertTrue(any("dir-manifest" in w and "regular file" in w.lower() for w in rep.warnings), rep.warnings)
        # Oversized huge-pack must NOT have been parsed into a collision with rea
        self.assertFalse(any("collision" in w.lower() and "rea" in w.lower() for w in rep.warnings), rep.warnings)

    def test_doctor_plugin_name_symlink_refusal_and_chmod_000_safety(self) -> None:
        (self.cfg / "plugins" / "rea").mkdir(parents=True)
        (self.cfg / "plugins" / "rea" / "plugin.json").write_text('{"name": "rea"}\n', encoding="utf-8")

        if hasattr(os, "symlink"):
            outside = self.tmp / "outside_plugin"
            outside.mkdir()
            ext_manifest = outside / "plugin.json"
            ext_manifest.write_text('{"name": "rea"}\n', encoding="utf-8")

            # Symlinked plugin.json inside real subdir must NOT be followed
            (self.cfg / "plugins" / "sym-manifest").mkdir(parents=True)
            (self.cfg / "plugins" / "sym-manifest" / "plugin.json").symlink_to(ext_manifest)

            # Symlinked plugin subdir must NOT be traversed
            (self.cfg / "plugins" / "sym-dir").symlink_to(outside, target_is_directory=True)

        # Unreadable manifest (chmod 000 on non-root POSIX; mocked PermissionError fallback on root/Windows)
        locked_dir = self.cfg / "plugins" / "locked-pack"
        locked_dir.mkdir(parents=True)
        locked_manifest = locked_dir / "plugin.json"
        locked_manifest.write_text('{"name": "rea"}\n', encoding="utf-8")

        reg, env = self._seed_healthy_global_env()
        use_real_chmod = os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0
        if use_real_chmod:
            os.chmod(locked_manifest, 0o000)
            try:
                rep = diagnose(env, reg, sentinel_active=True)
            finally:
                os.chmod(locked_manifest, 0o600)
        else:
            orig_open = os.open
            locked_manifest_resolved = locked_manifest.resolve()

            def _deny_locked(path: object, flags: int, *args: object, **kwargs: object) -> int:
                cand = Path(os.fspath(path))
                if cand == locked_manifest or (
                    "dir_fd" not in kwargs and cand.is_absolute() and cand.resolve() == locked_manifest_resolved
                ):
                    raise PermissionError(13, "Permission denied", str(path))
                return orig_open(path, flags, *args, **kwargs)

            with mock.patch("guard.doctor.os.open", side_effect=_deny_locked):
                rep = diagnose(env, reg, sentinel_active=True)

        self.assertFalse(rep.healthy)
        # Neither symlinked manifest, symlinked dir, nor unreadable file produced a false 'rea' collision
        self.assertFalse(any("collision" in w.lower() and "rea" in w.lower() for w in rep.warnings), rep.warnings)
        self.assertTrue(any("locked-pack" in w for w in rep.warnings), rep.warnings)
        if hasattr(os, "symlink"):
            self.assertTrue(any("sym-manifest" in w and "symlink" in w.lower() for w in rep.warnings), rep.warnings)


class TestW2UiRefineryThirdPartyPreservationAndCredits(_IsolatedHybridEnvMixin, unittest.TestCase):
    """AC-3 seam tests: 4-case fail-closed third-party preservation (plugins/antislop & skills/antislop) + prominent README credits."""

    def setUp(self) -> None:
        self._setup_sandbox("agy_w2_pres_")

    def tearDown(self) -> None:
        self._teardown_sandbox()

    def test_antislop_and_silk_design_excluded_from_consolidated_skill_slugs(self) -> None:
        from guard.environment import CONSOLIDATED_SKILL_SLUGS

        for third_party_slug in (
            "antislop",
            "antislop-ui",
            "antislop-copywriting",
            "antislop-human",
            "antislop-layoutmobile",
            "antislop-code",
            "silk-design",
        ):
            self.assertNotIn(third_party_slug, CONSOLIDATED_SKILL_SLUGS)

    def test_four_case_fail_closed_preservation_for_third_party_plugins_antislop(self) -> None:
        from guard.environment import can_retire_harness_plugin_dir, is_harness_plugin_dir

        parser = guard_cli.build_parser()
        sentinel_bytes = b"# third-party upstream anti-slop payload -- must never be touched\n"
        stale_receipt = {
            "schema_version": 1,
            "target": str(self.cfg),
            "layout": "hybrid",
            "installed": [
                "plugins/antislop",
                "plugins/rust-suite",
                "plugins/media-studio",
                "plugins/game-engineering",
            ],
            "installed_plugins": ["antislop", "rust-suite", "media-studio", "game-engineering"],
            "retired_mcp_servers": [],
            "backup_dir": None,
        }

        cases = [
            (
                "non_harness_url",
                json.dumps(
                    {
                        "name": "antislop",
                        "version": "1.2.0",
                        "repository": "https://github.com/miqdadbadjuber/anti-slop",
                        "homepage": "https://github.com/miqdadbadjuber/anti-slop",
                    }
                ),
            ),
            (
                "omitted_urls",
                json.dumps({"name": "antislop", "version": "1.0.0"}),
            ),
            (
                "jsonc_manifest",
                '// third-party JSONC manifest\n{"name": "antislop", "repository": "https://github.com/hadbilen/antigravity-harness",}\n',
            ),
        ]
        if hasattr(os, "symlink") and os.name != "nt":
            cases.append(("symlink_dir", ""))
            cases.append(("symlink_manifest", ""))

        for case_name, manifest_body in cases:
            for tool_name in ("installer", "guard_init"):
                for op in ("plugins", "flat-skills", "uninstall"):
                    with self.subTest(case=case_name, tool=tool_name, op=op):
                        hermetic.force_rmtree(self.cfg)
                        self.cfg.mkdir(parents=True)
                        hermetic.force_rmtree(self.state)
                        self.state.mkdir(parents=True)

                        receipt_path = self.state / "install_receipt.json"
                        receipt_path.write_text(json.dumps(stale_receipt), encoding="utf-8")

                        plug_dir = self.cfg / "plugins" / "antislop"
                        outside_dir = self.tmp / f"ext_plug_{case_name}_{tool_name}_{op}"
                        hermetic.force_rmtree(outside_dir)
                        if case_name == "symlink_dir":
                            outside_dir.mkdir(parents=True)
                            (outside_dir / "plugin.json").write_text(
                                json.dumps({"name": "antislop", "repository": "https://github.com/hadbilen/antigravity-harness"}),
                                encoding="utf-8",
                            )
                            (outside_dir / "sentinel.txt").write_bytes(sentinel_bytes)
                            plug_dir.parent.mkdir(parents=True, exist_ok=True)
                            plug_dir.symlink_to(outside_dir, target_is_directory=True)
                            manifest_bytes_before = (outside_dir / "plugin.json").read_bytes()
                        elif case_name == "symlink_manifest":
                            outside_dir.mkdir(parents=True)
                            ext_pj = outside_dir / "plugin.json"
                            ext_pj.write_text(
                                json.dumps({"name": "antislop", "repository": "https://github.com/hadbilen/antigravity-harness"}),
                                encoding="utf-8",
                            )
                            plug_dir.mkdir(parents=True)
                            (plug_dir / "plugin.json").symlink_to(ext_pj)
                            (plug_dir / "sentinel.txt").write_bytes(sentinel_bytes)
                            manifest_bytes_before = ext_pj.read_bytes()
                        else:
                            plug_dir.mkdir(parents=True)
                            (plug_dir / "plugin.json").write_text(manifest_body, encoding="utf-8")
                            (plug_dir / "sentinel.txt").write_bytes(sentinel_bytes)
                            manifest_bytes_before = (plug_dir / "plugin.json").read_bytes()

                        self.assertFalse(is_harness_plugin_dir(plug_dir, expected_pack="antislop", allow_legacy_names=True))
                        self.assertFalse(
                            can_retire_harness_plugin_dir(
                                plug_dir,
                                expected_pack="antislop",
                                in_receipt=True,
                                allow_legacy_names=True,
                            )
                        )

                        with mock.patch.object(harness_install, "request_approval", return_value=True), mock.patch.object(
                            guard_cli, "request_approval", return_value=True
                        ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                            if tool_name == "installer":
                                if op == "plugins":
                                    rc = harness_install.main(["--plugins", "--no-lock"])
                                elif op == "flat-skills":
                                    rc = harness_install.main(["--flat-skills", "--no-lock"])
                                else:
                                    rc = harness_install.uninstall_harness(self.cfg, dry_run=False)
                            else:
                                if op == "plugins":
                                    rc = guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--plugins", "--no-lock"]))
                                elif op == "flat-skills":
                                    rc = guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--flat-skills", "--no-lock"]))
                                else:
                                    rc = guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--uninstall"]))
                        self.assertEqual(rc, 0)

                        # Third-party plugins/antislop MUST survive byte-for-byte
                        if case_name == "symlink_dir":
                            self.assertTrue(os.path.islink(plug_dir))
                            self.assertEqual((outside_dir / "sentinel.txt").read_bytes(), sentinel_bytes)
                            self.assertEqual((outside_dir / "plugin.json").read_bytes(), manifest_bytes_before)
                        elif case_name == "symlink_manifest":
                            self.assertTrue(os.path.islink(plug_dir / "plugin.json"))
                            self.assertEqual((plug_dir / "sentinel.txt").read_bytes(), sentinel_bytes)
                            self.assertEqual((outside_dir / "plugin.json").read_bytes(), manifest_bytes_before)
                        else:
                            self.assertTrue(plug_dir.is_dir())
                            self.assertEqual((plug_dir / "sentinel.txt").read_bytes(), sentinel_bytes)
                            self.assertEqual((plug_dir / "plugin.json").read_bytes(), manifest_bytes_before)

        # Positive contrast: genuine receipted legacy harness plugins/antislop IS retired to backup,
        # while unreceipted legacy harness plugins/antislop is NOT retired automatically.
        hermetic.force_rmtree(self.cfg)
        self.cfg.mkdir(parents=True)
        hermetic.force_rmtree(self.state)
        self.state.mkdir(parents=True)
        leg_plug = self.cfg / "plugins" / "antislop"
        leg_plug.mkdir(parents=True)
        (leg_plug / "plugin.json").write_text(
            json.dumps({"name": "antislop", "version": "2.4.0", "repository": "https://github.com/hadbilen/antigravity-harness"}),
            encoding="utf-8",
        )
        self.assertTrue(is_harness_plugin_dir(leg_plug, expected_pack="antislop", allow_legacy_names=True))
        # Unreceipted legacy harness plugins/antislop must NOT be auto-retired (CC-01)
        self.assertFalse(
            can_retire_harness_plugin_dir(
                leg_plug,
                expected_pack="antislop",
                in_receipt=False,
                allow_legacy_names=True,
            )
        )
        self.assertTrue(
            can_retire_harness_plugin_dir(
                leg_plug,
                expected_pack="antislop",
                in_receipt=True,
                allow_legacy_names=True,
            )
        )
        # Missing plugin.json on legacy pack name fails closed even when listed in receipt
        leg_no_manifest = self.tmp / "leg_no_manifest"
        leg_no_manifest.mkdir(parents=True)
        self.assertFalse(
            can_retire_harness_plugin_dir(
                leg_no_manifest,
                expected_pack="antislop",
                in_receipt=True,
                allow_legacy_names=True,
            )
        )
        (self.state / "install_receipt.json").write_text(json.dumps(stale_receipt), encoding="utf-8")
        with mock.patch.object(harness_install, "request_approval", return_value=True), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(harness_install.main(["--plugins", "--no-lock"]), 0)
        self.assertFalse(leg_plug.exists())
        self.assertTrue((self.cfg / "plugins" / "ui-refinery" / "plugin.json").is_file())
        rec_upgraded = json.loads((self.state / "install_receipt.json").read_text(encoding="utf-8"))
        self.assertIsNotNone(rec_upgraded.get("backup_dir"))
        self.assertTrue((Path(rec_upgraded["backup_dir"]) / "plugins" / "antislop" / "plugin.json").is_file())

    def test_four_case_fail_closed_preservation_for_global_skills_antislop_and_mcp(self) -> None:
        from guard.environment import (
            can_retire_legacy_harness_skill_dir,
            is_legacy_harness_skill_dir,
            migrate_harness_mcp_config,
        )

        parser = guard_cli.build_parser()
        third_party_md = b"---\nname: antislop\ndescription: Upstream anti-slop skill from miqdadbadjuber/anti-slop.\n---\n# Anti-Slop\n"
        legacy_harness_md = (
            b"---\nname: antislop\ndescription: Legacy harness skill.\n---\n"
            b"Run `agy-guard ui-slop` or `skills/antislop/scripts/check_ui_slop.py`.\n"
        )
        silk_third_party_md = b"---\nname: silk-design\ndescription: Upstream silk-design skill.\n---\n# Silk Design\n"
        stale_flat_receipt = {
            "schema_version": 1,
            "target": str(self.cfg),
            "layout": "flat",
            "installed": ["skills/antislop", "skills/silk-design"],
            "installed_plugins": [],
            "retired_mcp_servers": [],
            "backup_dir": None,
        }

        preserved_cases = [
            ("unreceipted_third_party", False, third_party_md),
            ("receipted_third_party", True, third_party_md),
            ("unreceipted_legacy_harness", False, legacy_harness_md),
        ]
        if hasattr(os, "symlink") and os.name != "nt":
            preserved_cases.append(("receipted_symlink_dir", True, legacy_harness_md))
            preserved_cases.append(("receipted_symlink_skill_md", True, legacy_harness_md))

        for case_name, with_receipt, skill_bytes in preserved_cases:
            for tool_name in ("installer", "guard_init"):
                for op in ("plugins", "flat-skills", "uninstall"):
                    with self.subTest(case=case_name, tool=tool_name, op=op):
                        hermetic.force_rmtree(self.cfg)
                        self.cfg.mkdir(parents=True)
                        hermetic.force_rmtree(self.state)
                        self.state.mkdir(parents=True)

                        if with_receipt:
                            (self.state / "install_receipt.json").write_text(
                                json.dumps(stale_flat_receipt), encoding="utf-8"
                            )

                        skill_dir = self.cfg / "skills" / "antislop"
                        silk_dir = self.cfg / "skills" / "silk-design"
                        silk_dir.mkdir(parents=True)
                        (silk_dir / "SKILL.md").write_bytes(silk_third_party_md)

                        outside_dir = self.tmp / f"ext_skill_{case_name}_{tool_name}_{op}"
                        hermetic.force_rmtree(outside_dir)
                        if case_name == "receipted_symlink_dir":
                            outside_dir.mkdir(parents=True)
                            (outside_dir / "SKILL.md").write_bytes(skill_bytes)
                            skill_dir.parent.mkdir(parents=True, exist_ok=True)
                            skill_dir.symlink_to(outside_dir, target_is_directory=True)
                        elif case_name == "receipted_symlink_skill_md":
                            outside_dir.mkdir(parents=True)
                            ext_md = outside_dir / "SKILL.md"
                            ext_md.write_bytes(skill_bytes)
                            skill_dir.mkdir(parents=True)
                            (skill_dir / "SKILL.md").symlink_to(ext_md)
                        else:
                            skill_dir.mkdir(parents=True)
                            (skill_dir / "SKILL.md").write_bytes(skill_bytes)

                        self.assertFalse(
                            can_retire_legacy_harness_skill_dir(
                                skill_dir,
                                slug="antislop",
                                in_receipt=with_receipt,
                            )
                        )

                        with mock.patch.object(harness_install, "request_approval", return_value=True), mock.patch.object(
                            guard_cli, "request_approval", return_value=True
                        ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                            if tool_name == "installer":
                                if op == "plugins":
                                    rc = harness_install.main(["--plugins", "--no-lock"])
                                elif op == "flat-skills":
                                    rc = harness_install.main(["--flat-skills", "--no-lock"])
                                else:
                                    rc = harness_install.uninstall_harness(self.cfg, dry_run=False)
                            else:
                                if op == "plugins":
                                    rc = guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--plugins", "--no-lock"]))
                                elif op == "flat-skills":
                                    rc = guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--flat-skills", "--no-lock"]))
                                else:
                                    rc = guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--uninstall"]))
                        self.assertEqual(rc, 0)

                        # Global skills/antislop and skills/silk-design MUST survive byte-for-byte
                        self.assertEqual((silk_dir / "SKILL.md").read_bytes(), silk_third_party_md)
                        if case_name == "receipted_symlink_dir":
                            self.assertTrue(os.path.islink(skill_dir))
                            self.assertEqual((outside_dir / "SKILL.md").read_bytes(), skill_bytes)
                        elif case_name == "receipted_symlink_skill_md":
                            self.assertTrue(os.path.islink(skill_dir / "SKILL.md"))
                            self.assertEqual((outside_dir / "SKILL.md").read_bytes(), skill_bytes)
                        else:
                            self.assertEqual((skill_dir / "SKILL.md").read_bytes(), skill_bytes)

        # Third-party skills/antislop MCP config entry MUST be preserved untouched by migrate_harness_mcp_config
        hermetic.force_rmtree(self.cfg)
        self.cfg.mkdir(parents=True)
        tp_skill = self.cfg / "skills" / "antislop"
        (tp_skill / "scripts").mkdir(parents=True)
        (tp_skill / "SKILL.md").write_bytes(third_party_md)
        tp_mcp_script = tp_skill / "scripts" / "contrast-mcp.py"
        tp_mcp_script.write_text("# third-party contrast\n", encoding="utf-8")
        mcp_path = self.cfg / "mcp_config.json"
        tp_mcp_cfg = {"mcpServers": {"my-antislop": {"command": "python3", "args": [str(tp_mcp_script)]}}}
        mcp_path.write_text(json.dumps(tp_mcp_cfg), encoding="utf-8")
        changed_tp = migrate_harness_mcp_config(
            self.cfg, REPO_ROOT, dry_run=False, retire_plugin_mcp=HARNESS_PLUGIN_NAMES
        )
        self.assertFalse(changed_tp)
        self.assertEqual(json.loads(mcp_path.read_text(encoding="utf-8")), tp_mcp_cfg)

        # Positive contrast: receipted legacy harness skills/antislop IS cleanly retired to backup
        for tool_name in ("installer", "guard_init"):
            with self.subTest(positive_retire_tool=tool_name):
                hermetic.force_rmtree(self.cfg)
                self.cfg.mkdir(parents=True)
                hermetic.force_rmtree(self.state)
                self.state.mkdir(parents=True)
                (self.state / "install_receipt.json").write_text(json.dumps(stale_flat_receipt), encoding="utf-8")
                leg_skill = self.cfg / "skills" / "antislop"
                leg_skill.mkdir(parents=True)
                (leg_skill / "SKILL.md").write_bytes(legacy_harness_md)
                self.assertTrue(is_legacy_harness_skill_dir(leg_skill))
                self.assertTrue(can_retire_legacy_harness_skill_dir(leg_skill, slug="antislop", in_receipt=True))
                with mock.patch.object(harness_install, "request_approval", return_value=True), mock.patch.object(
                    guard_cli, "request_approval", return_value=True
                ), contextlib.redirect_stdout(io.StringIO()):
                    if tool_name == "installer":
                        rc = harness_install.main(["--plugins", "--no-lock"])
                    else:
                        rc = guard_cli.cmd_init(parser.parse_args(["init", "--source", str(REPO_ROOT), "--plugins", "--no-lock"]))
                self.assertEqual(rc, 0)
                self.assertFalse(leg_skill.exists())
                rec_after = json.loads((self.state / "install_receipt.json").read_text(encoding="utf-8"))
                self.assertIsNotNone(rec_after.get("backup_dir"))
                self.assertTrue((Path(rec_after["backup_dir"]) / "skills" / "antislop" / "SKILL.md").is_file())

    def test_generated_plugin_readme_prominent_upstream_credits_and_validator_gate(self) -> None:
        out_root = self.tmp / "credits_packs"
        build_all_plugin_packs(REPO_ROOT, out_root, validate=True)

        # 1. Source SKILL.md and motion-physics.md carry prominent MIT upstream credit notes near top
        skill_head = "\n".join((REPO_ROOT / "skills" / "ui-refinery" / "SKILL.md").read_text(encoding="utf-8").splitlines()[:20])
        self.assertIn("Upstream Attribution (MIT)", skill_head)
        self.assertIn("miqdadbadjuber/anti-slop", skill_head)
        self.assertIn("bendrape1-byte/silk-design", skill_head)

        motion_head = "\n".join(
            (REPO_ROOT / "skills" / "ui-refinery" / "references" / "motion-physics.md").read_text(encoding="utf-8").splitlines()[:10]
        )
        self.assertIn("Upstream Attribution (MIT)", motion_head)
        self.assertIn("bendrape1-byte/silk-design", motion_head)

        # 2. ui-refinery and rust-suite READMEs place ## Upstream Credits & Attribution between Included components & Standalone installation
        expected_credits = {
            "ui-refinery": ("miqdadbadjuber/anti-slop", "bendrape1-byte/silk-design"),
            "rust-suite": ("erkamyaman/rust-anything",),
        }
        for pack_name, upstreams in expected_credits.items():
            pdir = out_root / pack_name
            readme_path = pdir / "README.md"
            readme = readme_path.read_text(encoding="utf-8")
            idx_inc = readme.index("## Included components")
            idx_cred = readme.index("## Upstream Credits & Attribution")
            idx_inst = readme.index("## Standalone installation")
            self.assertLess(idx_inc, idx_cred, f"{pack_name} credits must follow Included components")
            self.assertLess(idx_cred, idx_inst, f"{pack_name} credits must precede Standalone installation")
            for upstream in upstreams:
                self.assertIn(upstream, readme[idx_cred:idx_inst])

            # Negative 1: removing ## Upstream Credits & Attribution fails validation
            orig_readme = readme
            readme_path.write_text(readme.replace("## Upstream Credits & Attribution", "## Credits"), encoding="utf-8")
            res_missing = validate_plugin_dir(pdir, expected_pack=pack_name)
            self.assertFalse(res_missing.ok)
            self.assertTrue(any("Upstream Credits & Attribution" in e for e in res_missing.errors), res_missing.errors)

            # Negative 2: demoting ## Upstream Credits & Attribution below ## Standalone installation fails validation
            reordered = (
                orig_readme[:idx_cred]
                + orig_readme[idx_inst:]
                + "\n"
                + orig_readme[idx_cred:idx_inst]
            )
            readme_path.write_text(reordered, encoding="utf-8")
            res_order = validate_plugin_dir(pdir, expected_pack=pack_name)
            self.assertFalse(res_order.ok)
            self.assertTrue(any("before `## Standalone installation`" in e for e in res_order.errors), res_order.errors)
            readme_path.write_text(orig_readme, encoding="utf-8")

        # 3. Clean packs without third-party upstreams omit ## Upstream Credits & Attribution
        for clean_pack in ("media-studio", "game-engineering"):
            clean_readme = (out_root / clean_pack / "README.md").read_text(encoding="utf-8")
            self.assertNotIn("## Upstream Credits & Attribution", clean_readme)

    def test_w2_audit_remediations_security_and_contract_seams(self) -> None:
        from guard.doctor import _is_harness_contrast_mcp_arg
        from guard.environment import (
            antigravity_plugin_governance_seams,
            is_harness_plugin_dir,
            is_legacy_harness_skill_dir,
            migrate_harness_mcp_config,
        )

        # SEC-03: generic ~/.gemini/config/skills/antislop/ path in third-party SKILL.md must NOT spoof harness provenance
        tp_doc_skill = self.cfg / "skills" / "antislop"
        tp_doc_skill.mkdir(parents=True)
        (tp_doc_skill / "SKILL.md").write_text(
            "---\nname: antislop\ndescription: Third-party install docs.\n---\n"
            "Installed at `~/.gemini/config/skills/antislop/`.\n",
            encoding="utf-8",
        )
        self.assertFalse(is_legacy_harness_skill_dir(tp_doc_skill))

        # SEC-04: deeply nested JSON in plugin.json fails closed cleanly (no unhandled RecursionError)
        deep_plug = self.tmp / "deep_json_plug"
        deep_plug.mkdir(parents=True)
        (deep_plug / "plugin.json").write_text("[" * 5000 + "]" * 5000, encoding="utf-8")
        self.assertFalse(is_harness_plugin_dir(deep_plug, expected_pack="antislop", allow_legacy_names=True))

        # SEC-06: non-harness plugin at plugins/ui-refinery is excluded from antigravity_plugin_governance_seams
        tp_ui_plug = self.cfg / "plugins" / "ui-refinery"
        tp_ui_plug.mkdir(parents=True)
        (tp_ui_plug / "plugin.json").write_text(
            json.dumps({"name": "ui-refinery", "repository": "https://example.invalid/third-party"}),
            encoding="utf-8",
        )
        self.assertNotIn("plugins/ui-refinery", antigravity_plugin_governance_seams(self.cfg, include_receipt=False))
        shutil.rmtree(tp_ui_plug)

        # CC-03: doctor detects stale v2.4.0 skills/antislop and plugins/antislop MCP args while preserving third-party
        self.assertFalse(
            _is_harness_contrast_mcp_arg(str(self.cfg / "skills" / "antislop" / "scripts" / "contrast-mcp.py"), root=self.cfg)
        )
        shutil.rmtree(tp_doc_skill)
        self.assertTrue(
            _is_harness_contrast_mcp_arg(str(self.cfg / "skills" / "antislop" / "scripts" / "contrast-mcp.py"), root=self.cfg)
        )
        self.assertTrue(
            _is_harness_contrast_mcp_arg(
                str(self.cfg / "plugins" / "antislop" / "skills" / "antislop" / "scripts" / "contrast-mcp.py"),
                root=self.cfg,
            )
        )

        # CC-02 & CC-04: --link flat MCP repointing succeeds via verified repo symlink & repoints legacy plugins/antislop entry
        if hasattr(os, "symlink") and os.name != "nt":
            link_cfg = self.tmp / "cc02_link_cfg"
            (link_cfg / "skills").mkdir(parents=True)
            (link_cfg / "skills" / "ui-refinery").symlink_to(REPO_ROOT / "skills" / "ui-refinery", target_is_directory=True)
            link_mcp = link_cfg / "mcp_config.json"
            link_mcp.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "legacy-flat": {
                                "command": "python3",
                                "args": [str(link_cfg / "skills" / "antislop" / "scripts" / "contrast-mcp.py")],
                            },
                            "legacy-plug": {
                                "command": "python3",
                                "args": [str(link_cfg / "plugins" / "antislop" / "skills" / "antislop" / "scripts" / "contrast-mcp.py")],
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            self.assertTrue(migrate_harness_mcp_config(link_cfg, REPO_ROOT, dry_run=False))
            migrated = json.loads(link_mcp.read_text(encoding="utf-8"))["mcpServers"]
            expected_link_script = str(link_cfg / "skills" / "ui-refinery" / "scripts" / "contrast-mcp.py")
            self.assertEqual(migrated["legacy-flat"]["args"], [expected_link_script])
            self.assertEqual(migrated["legacy-plug"]["args"], [expected_link_script])

        # SEC-02: uninstall receipt empty target, .. traversal, and subpath entries cannot bypass third-party preservation
        sec2_cfg = self.tmp / "sec02_cfg"
        sec2_plug = sec2_cfg / "plugins" / "antislop"
        sec2_plug.mkdir(parents=True)
        (sec2_plug / "plugin.json").write_text(json.dumps({"name": "antislop", "version": "1.0.0"}), encoding="utf-8")
        sec2_skill = sec2_cfg / "skills" / "antislop"
        sec2_skill.mkdir(parents=True)
        (sec2_skill / "SKILL.md").write_text("---\nname: antislop\n---\n# Third-party\n", encoding="utf-8")
        (sec2_cfg / "rules").mkdir(parents=True)
        (self.state / "install_receipt.json").write_text(
            json.dumps(
                {
                    "target": str(sec2_cfg),
                    "installed": [
                        "rules/../plugins/antislop",
                        "skills/antislop/SKILL.md",
                        "rules/..",
                    ],
                }
            ),
            encoding="utf-8",
        )
        with mock.patch.object(harness_install, "request_approval", return_value=True), contextlib.redirect_stdout(
            io.StringIO()
        ), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(harness_install.uninstall_harness(sec2_cfg, dry_run=False), 0)
        self.assertTrue((sec2_plug / "plugin.json").is_file())
        self.assertTrue((sec2_skill / "SKILL.md").is_file())

        # CC-06: fenced ## Upstream Credits & Attribution or upstream slug outside credits section is rejected
        cc6_root = self.tmp / "cc06_packs"
        ui_dir = build_plugin_pack("ui-refinery", REPO_ROOT, cc6_root / "ui-refinery")
        orig_readme = (ui_dir / "README.md").read_text(encoding="utf-8")
        fenced_readme = orig_readme.replace(
            "## Upstream Credits & Attribution",
            "```markdown\n## Upstream Credits & Attribution\n```",
        )
        (ui_dir / "README.md").write_text(fenced_readme, encoding="utf-8")
        res_fenced = validate_plugin_dir(ui_dir, expected_pack="ui-refinery")
        self.assertFalse(res_fenced.ok)
        self.assertTrue(any("Upstream Credits & Attribution" in e for e in res_fenced.errors), res_fenced.errors)
        (ui_dir / "README.md").write_text(orig_readme, encoding="utf-8")


class TestW3PlumbworkCutoverSeams(unittest.TestCase):
    """AC-4 / AC-5 seam tests: v3.0.0 Plumbwork cutover, doctor legacy-residue, dual-token leaks, concrete fnmatchcase probes."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-w3-plumbwork-")
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / "home"
        self.cfg = self.home / ".gemini" / "config"
        self.state = self.tmp / "state" / "plumbwork"
        self.data = self.tmp / "data" / "plumbwork"
        for d in (self.home, self.cfg, self.state, self.data):
            d.mkdir(parents=True, exist_ok=True)
        self._env = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "XDG_STATE_HOME": str(self.tmp / "state"),
                "XDG_DATA_HOME": str(self.tmp / "data"),
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg),
                "PLUMB_GUARD_STATE_DIR": str(self.state),
                "PLUMB_GUARD_DATA_DIR": str(self.data),
                "PLUMB_GUARD_NOTIFY": "off",
            },
            clear=False,
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        self._tmp.cleanup()

    def test_version_sync_and_plumbwork_catalog_metadata(self) -> None:
        from guard import __version__ as guard_version
        from guard.environment import CONSTITUTION_RULE_REL
        from guard.paths import APP_NAME
        from guard.plugins import PLUGIN_AUTHOR, PLUGIN_HOMEPAGE, PLUGIN_REPOSITORY
        from porter import __version__ as porter_version

        self.assertEqual(guard_version, "3.0.0")
        self.assertEqual(porter_version, "3.0.0")
        self.assertEqual(APP_NAME, "plumbwork")
        self.assertEqual(CONSTITUTION_RULE_REL, "rules/plumbwork-constitution.md")
        self.assertEqual(PLUGIN_REPOSITORY, "https://github.com/hadbilen/plumbwork")
        self.assertEqual(PLUGIN_HOMEPAGE, "https://github.com/hadbilen/plumbwork")
        self.assertEqual(PLUGIN_AUTHOR["url"], "https://github.com/hadbilen/plumbwork")

    def test_doctor_read_only_legacy_residue_warnings_and_third_party_preservation(self) -> None:
        from guard.doctor import diagnose
        from guard.environment import EnvironmentRegistry

        # Seed current v3.0.0 constitution + config.json with plumb-guard unlock deny rule
        (self.cfg / "rules").mkdir(parents=True, exist_ok=True)
        (self.cfg / "rules" / "plumbwork-constitution.md").write_text(
            "---\ntrigger: always_on\n---\n# Plumbwork Global Engineering & Behavioral Constitution\n",
            encoding="utf-8",
        )
        (self.cfg / "config.json").write_text(
            json.dumps(
                {
                    "userSettings": {
                        "globalPermissionGrants": {
                            "deny": ["command(plumb-guard unlock)", "command(regex:.*--no-verify.*)"]
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        # Seed ALL pre-v3.0 legacy residue artifacts
        legacy_state = self.tmp / "state" / "antigravity-harness"
        legacy_data = self.tmp / "data" / "antigravity-harness"
        legacy_rule = self.cfg / "rules" / "antigravity-constitution.md"
        legacy_systemd = self.home / ".config" / "systemd" / "user" / "agy-guard-boot.service"
        legacy_launchd = self.home / "Library" / "LaunchAgents" / "com.antigravity.guard.plist"
        legacy_plug = self.cfg / "plugins" / "antislop"
        legacy_skill = self.cfg / "skills" / "antislop"

        legacy_state.mkdir(parents=True)
        (legacy_state / "marker.txt").write_text("legacy-state\n", encoding="utf-8")
        legacy_data.mkdir(parents=True)
        (legacy_data / "marker.txt").write_text("legacy-data\n", encoding="utf-8")
        legacy_rule.write_text("# legacy\n", encoding="utf-8")
        legacy_systemd.parent.mkdir(parents=True, exist_ok=True)
        legacy_systemd.write_text("[Unit]\nDescription=legacy\n", encoding="utf-8")
        legacy_launchd.parent.mkdir(parents=True, exist_ok=True)
        legacy_launchd.write_text("<plist/>\n", encoding="utf-8")
        legacy_plug.mkdir(parents=True)
        (legacy_plug / "plugin.json").write_text(
            json.dumps({"name": "antislop", "version": "2.4.0", "repository": "https://github.com/hadbilen/antigravity-harness"}),
            encoding="utf-8",
        )
        legacy_skill.mkdir(parents=True)
        (legacy_skill / "SKILL.md").write_text(
            "---\nname: antislop\ndescription: Legacy\n---\nRun `agy-guard ui-slop`.\n",
            encoding="utf-8",
        )

        reg = EnvironmentRegistry(config_path=self.state / "environments.json")
        env = reg.get_environment("antigravity")
        self.assertIsNotNone(env)
        rep = diagnose(env, reg, sentinel_active=True)
        warns = "\n".join(rep.warnings)

        # Native deny rule recognizes plumb-guard unlock + --no-verify
        self.assertIn("Native Antigravity deny rules cover 'plumb-guard unlock' and '--no-verify'.", rep.infos)

        # All legacy residue warnings emitted
        self.assertIn("legacy v2.x state directory", warns)
        self.assertIn("legacy v2.x data directory", warns)
        self.assertIn("Legacy pre-v3.0 constitution rule", warns)
        self.assertIn("Legacy pre-v3.0 systemd boot sentinel", warns)
        self.assertIn("Legacy pre-v3.0 launchd boot sentinel", warns)
        self.assertIn("Unreceipted legacy harness plugin", warns)
        self.assertIn("Unreceipted legacy harness skill", warns)

        # Strictly read-only: NONE of the seeded legacy artifacts were deleted or altered
        self.assertTrue((legacy_state / "marker.txt").is_file())
        self.assertTrue((legacy_data / "marker.txt").is_file())
        self.assertTrue(legacy_rule.is_file())
        self.assertTrue(legacy_systemd.is_file())
        self.assertTrue(legacy_launchd.is_file())
        self.assertTrue((legacy_plug / "plugin.json").is_file())
        self.assertTrue((legacy_skill / "SKILL.md").is_file())

        # Replace legacy artifacts with third-party upstream antislop installs -> ZERO legacy-residue warnings
        shutil.rmtree(legacy_state)
        shutil.rmtree(legacy_data)
        legacy_rule.unlink()
        legacy_systemd.unlink()
        legacy_launchd.unlink()
        shutil.rmtree(legacy_plug)
        shutil.rmtree(legacy_skill)
        legacy_plug.mkdir(parents=True)
        (legacy_plug / "plugin.json").write_text(
            json.dumps({"name": "antislop", "version": "1.2.0", "repository": "https://github.com/miqdadbadjuber/anti-slop"}),
            encoding="utf-8",
        )
        legacy_skill.mkdir(parents=True)
        (legacy_skill / "SKILL.md").write_text(
            "---\nname: antislop\ndescription: Upstream third-party anti-slop\n---\n# Third-party skill\n",
            encoding="utf-8",
        )
        # Also remove plumb-guard unlock deny rule and confirm doctor warns about it
        (self.cfg / "config.json").write_text(json.dumps({"userSettings": {"globalPermissionGrants": {"deny": []}}}), encoding="utf-8")

        rep_tp = diagnose(env, reg, sentinel_active=True)
        warns_tp = "\n".join(rep_tp.warnings)
        self.assertNotIn("Legacy pre-v3.0", warns_tp)
        self.assertNotIn("Unreceipted legacy harness", warns_tp)
        self.assertIn("plumb-guard unlock", "\n".join(rep_tp.infos + rep_tp.warnings))

    def test_dual_token_standalone_markdown_leak_rejection(self) -> None:
        out = self.tmp / "dual_packs"
        ui_dir = build_plugin_pack("ui-refinery", REPO_ROOT, out / "ui-refinery")
        skill_md = ui_dir / "skills" / "ui-refinery" / "SKILL.md"
        orig = skill_md.read_text(encoding="utf-8")

        # 1. Both new plumb-guard/plumbwork AND legacy agy-guard/antigravity-harness inline/path leaks are rejected
        for label, snippet in (
            ("new-inline-cmd", "\nRun `plumb-guard verify` before shipping.\n"),
            ("legacy-inline-cmd", "\nRun `agy-guard verify` before shipping.\n"),
            ("new-fenced-cmd", "\n```bash\nplumb-guard status\n```\n"),
            ("legacy-fenced-cmd", "\n```bash\nagy-guard status\n```\n"),
            ("new-runtime-path", "\nInspect `~/.local/share/plumbwork/runtime/guard/cli.py`.\n"),
            ("legacy-runtime-path", "\nInspect `~/.local/share/antigravity-harness/runtime/guard/cli.py`.\n"),
        ):
            skill_md.write_text(orig + snippet, encoding="utf-8")
            res = validate_plugin_dir(ui_dir, expected_pack="ui-refinery")
            self.assertFalse(res.ok, f"Expected validation failure for dual-token leak case {label}")
            self.assertTrue(len(res.errors) >= 1, f"Expected concrete error for {label}")

        skill_md.write_text(orig, encoding="utf-8")
        self.assertTrue(validate_plugin_dir(ui_dir, expected_pack="ui-refinery").ok)

    def test_shell_guard_concrete_fnmatchcase_archive_probes_and_facade_budget(self) -> None:
        from guard import agy_hooks

        # 1. Concrete fnmatchcase probes catch both v3.0.0 and v0.0.0 globs for harness packs
        for cmd in (
            "agy plugin install ./dist/ui-refinery-v*.zip",
            "agy plugin import ./dist/rust-suite-v[0-9].0.0.zip",
            "agy plugin disable ui-ref*",
            "agy plugin uninstall media-st*",
        ):
            res = agy_hooks.handle_pre_tool_use({"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}})
            self.assertEqual(res.get("decision"), "force_ask", f"Expected force_ask for {cmd!r}, got {res}")

        # Explicit archive extraction into ~/.gemini/config/plugins with harness pack glob is denied
        res_extract = agy_hooks.handle_pre_tool_use(
            {"toolCall": {"name": "run_command", "args": {"CommandLine": "unzip ./dist/ui-refinery-v*.zip -d ~/.gemini/config/plugins"}}}
        )
        self.assertEqual(res_extract.get("decision"), "deny", res_extract)

        # Third-party literal plugin disable remains exempt
        res_tp = agy_hooks.handle_pre_tool_use(
            {"toolCall": {"name": "run_command", "args": {"CommandLine": "agy plugin disable rea"}}}
        )
        self.assertEqual(res_tp.get("decision"), "allow", res_tp)

        # 2. guard/agy_hooks.py stays strictly within the 32,768 UTF-8 byte ceiling (ADR-0015/0017)
        facade_bytes = (REPO_ROOT / "guard" / "agy_hooks.py").stat().st_size
        self.assertLessEqual(facade_bytes, 32768, f"guard/agy_hooks.py exceeded 32,768 B budget: {facade_bytes}")

    def test_w3_auditor_remediations_doctor_null_receipt_and_hook_glob_bypass(self) -> None:
        from guard import agy_hooks
        from guard.doctor import diagnose
        from guard.environment import EnvironmentRegistry
        from guard.hooks import pre_tool_use as ptu
        from guard.tray import DummyAdapter, create_tray_adapter

        # 1. Doctor handles missing/null/non-list receipt fields without TypeError
        reg = EnvironmentRegistry(config_path=self.state / "environments.json")
        env = reg.get_environment("antigravity")
        self.assertIsNotNone(env)
        for bad_receipt in (
            {"target": str(self.cfg)},
            {"target": str(self.cfg), "installed_plugins": None, "installed": "not-a-list"},
        ):
            (self.state / "install_receipt.json").write_text(json.dumps(bad_receipt), encoding="utf-8")
            rep = diagnose(env, reg, sentinel_active=True)
            self.assertIsInstance(rep.warnings, list)
        self.assertTrue(any("not a list" in w for w in rep.warnings), rep.warnings)
        (self.state / "install_receipt.json").unlink()

        # 2. Glob & shell-var obfuscated admin commands + ${HOME}/early-wildcard/FHS governance mutations are denied
        for cmd in (
            "~/.local/bin/plumb-g* unlock",
            "/usr/bin/plumb-g* unlock",
            "~/.local/bin/plumb-p* stage /tmp/a.md",
            "G=plumb-guard; $G unlock",
            "chmod 777 ${HOME}/.local/state/plumb*/environments.json",
            "truncate -s 0 ~/.local/bin/p?umb-guard",
            "chmod 777 /usr/share/plumb*/GEMINI.md",
            "chmod 777 /usr/lib/plumb*/guard.py",
        ):
            res = agy_hooks.handle_pre_tool_use({"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}})
            self.assertEqual(res.get("decision"), "deny", f"Expected deny for {cmd!r}, got {res}")

        # 3. Inline Python writing directly to plumbwork/staging is allowed; non-Python targeting /usr/bin/plumb-guard is denied
        res_stage = agy_hooks.handle_pre_tool_use(
            {
                "toolCall": {
                    "name": "run_command",
                    "args": {
                        "CommandLine": (
                            'python3 -c "from pathlib import Path; '
                            "Path('~/.local/state/plumbwork/staging/rfc.md').expanduser().write_text('ok')\""
                        )
                    },
                }
            }
        )
        self.assertEqual(res_stage.get("decision"), "allow", res_stage)
        res_node_bin = agy_hooks.handle_pre_tool_use(
            {
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "node -e \"require('path').join('/usr', 'bin', 'plumb-guard')\""},
                }
            }
        )
        self.assertEqual(res_node_bin.get("decision"), "deny", res_node_bin)

        # 4. Leading-wildcard versioned .zip/.tar.gz agy plugin disable/uninstall targets trigger force_ask
        for cmd in (
            "agy plugin uninstall ?i-refinery-v2.4.0.zip",
            "agy plugin disable ?i-refinery-v3.0.0.tar.gz",
            "agy plugin uninstall *refinery-v3.0.1.zip",
            "agy plugin uninstall ui-refiner?-3.0.0.zip",
        ):
            res = agy_hooks.handle_pre_tool_use({"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}})
            self.assertEqual(res.get("decision"), "force_ask", f"Expected force_ask for {cmd!r}, got {res}")

        # 5. PLUMBWORK_SHARE_DIR whitespace & relative values stay protected in _targets_governance_dir
        for raw_val in ("   ", " /opt/plumbwork ", "custom_share"):
            with mock.patch.dict(os.environ, {"PLUMBWORK_SHARE_DIR": raw_val}, clear=False):
                self.assertTrue(
                    ptu._targets_governance_dir("$PLUMBWORK_SHARE_DIR/GEMINI.md"),
                    f"Failed for PLUMBWORK_SHARE_DIR={raw_val!r}",
                )

        # 6. Optional qualifier never waives legacy agy-guard; fenced env-prefix & ${HOME} runtime path rejected
        out = self.tmp / "remed_packs"
        ui_dir = build_plugin_pack("ui-refinery", REPO_ROOT, out / "ui-refinery")
        skill_md = ui_dir / "skills" / "ui-refinery" / "SKILL.md"
        orig = skill_md.read_text(encoding="utf-8")
        for label, bad in (
            ("opt-legacy", "\nOptional helper when installed: `agy-guard ui-slop index.html`.\n"),
            ("fenced-env", "\n```bash\nFOO=1 plumb-guard status\n```\n"),
            ("braced-home", "\nInspect `${HOME}/.local/share/plumbwork/runtime/guard/cli.py`.\n"),
        ):
            skill_md.write_text(orig + bad, encoding="utf-8")
            vres = validate_plugin_dir(ui_dir, expected_pack="ui-refinery")
            self.assertFalse(vres.ok, f"Expected validation error for {label}")
        skill_md.write_text(orig, encoding="utf-8")

        # 7. PLUMB_GUARD_NO_TRAY=1 disables tray across macOS/Windows too
        for plat in ("Darwin", "Windows"):
            with mock.patch("guard.tray.platform.system", return_value=plat), mock.patch.dict(
                os.environ, {"PLUMB_GUARD_NO_TRAY": "1"}, clear=False
            ):
                ad = create_tray_adapter(lambda: None, lambda: None, lambda: None)
                self.assertIsInstance(ad, DummyAdapter)
                self.assertIn("PLUMB_GUARD_NO_TRAY=1", ad.fallback_reason)


if __name__ == "__main__":
    unittest.main()
