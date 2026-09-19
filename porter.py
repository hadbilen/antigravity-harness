#!/usr/bin/env python3
"""
porter.py — Universal Bidirectional AI Agent Bridge & Suitability Transpiler
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

# Ensure repository root is in python path
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from porter import __version__ as PORTER_VERSION
from porter.analyzer import SuitabilityAnalyzer
from porter.emitters.aider import AiderEmitter
from porter.emitters.claude import ClaudeEmitter
from porter.emitters.cursor import CursorEmitter
from porter.emitters.generic import GenericEmitter
from porter.emitters.universal import UniversalEmitter
from porter.manifest import ManifestEngine
from porter.net import safe_fetch_url, validate_safe_url
from porter.parsers.generic_parser import GenericParser
from porter.sanitizer import ConstitutionalSanitizer


def fetch_target_content(target: str) -> str:
    """Reads content from local filesystem path or remote HTTP(S) URL with SSRF protection."""
    if target.startswith("http://") or target.startswith("https://"):
        return safe_fetch_url(target, user_agent=f"Antigravity-Porter/{PORTER_VERSION}")
    path = Path(target).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")
    return path.read_text(encoding="utf-8", errors="ignore")


def cmd_inspect(args: argparse.Namespace) -> int:
    """Performs pre-flight suitability and adaptability analysis without mutating any files."""
    try:
        content = fetch_target_content(args.target)
    except Exception as e:
        print(f"Error reading target '{args.target}': {e}", file=sys.stderr)
        return 1

    analyzer = SuitabilityAnalyzer(harness_root=SCRIPT_DIR)
    report = analyzer.analyze(content, source_identifier=args.target)

    if args.json:
        # Output clean JSON
        output_data = {
            "source_target": report.source_target,
            "detected_format": report.detected_format,
            "recommended_type": report.recommended_type,
            "recommended_name": report.recommended_name,
            "constitutional_score": report.constitutional_score,
            "adaptability_score": report.adaptability_score,
            "is_safe_to_import": report.is_safe_to_import,
            "issues": [
                {"severity": i.severity, "category": i.category, "message": i.message, "suggested_fix": i.suggested_fix}
                for i in report.issues
            ],
            "redundancies": report.redundancies
        }
        print(json.dumps(output_data, indent=2))
    else:
        print(report.to_markdown())

    return 0 if report.is_safe_to_import else 2


def cmd_import(args: argparse.Namespace) -> int:
    """Imports and converts an external rule into a standardized harness skill or agent."""
    try:
        content = fetch_target_content(args.target)
    except Exception as e:
        print(f"Error reading target '{args.target}': {e}", file=sys.stderr)
        return 1

    analyzer = SuitabilityAnalyzer(harness_root=SCRIPT_DIR)
    report = analyzer.analyze(content, source_identifier=args.target)

    if not report.is_safe_to_import and not args.force:
        print(report.to_markdown(), file=sys.stderr)
        print("\n[BLOCKED] Critical constitutional issues detected. Use --force to override.", file=sys.stderr)
        return 1

    target_type = "agent" if args.as_agent else "skill"
    raw_name = args.as_agent or args.as_skill or report.recommended_name
    clean_name = re.sub(r"[^a-zA-Z0-9_-]", "-", Path(raw_name).name).strip("-").lower()
    if not clean_name:
        clean_name = "imported-custom"
    name = clean_name

    # Build clean sanitized content
    sanitized_body = report.sanitized_content

    if target_type == "skill":
        base_dir = (SCRIPT_DIR / "skills").resolve()
        dest_dir = (base_dir / name).resolve()
        try:
            dest_dir.relative_to(base_dir)
        except ValueError:
            print(f"Error: Invalid skill destination path '{dest_dir}'", file=sys.stderr)
            return 1
        dest_file = dest_dir / "SKILL.md"
        output_content = f"""---
name: {name}
description: {report.source_target} adapted via Porter.
---

{sanitized_body}
"""
    else:
        base_dir = (SCRIPT_DIR / "agents").resolve()
        dest_dir = base_dir
        dest_file = (dest_dir / f"{name}.md").resolve()
        try:
            dest_file.relative_to(base_dir)
        except ValueError:
            print(f"Error: Invalid agent destination path '{dest_file}'", file=sys.stderr)
            return 1
        output_content = f"""---
name: {name}
description: {name} autonomous agent definition adapted via Porter.
---

{sanitized_body}
"""

    if args.dry_run:
        print(f"[DRY-RUN] Target destination: {dest_file}")
        print("-" * 50)
        print(output_content[:500] + ("\n... [truncated]" if len(output_content) > 500 else ""))
        return 0

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file.write_text(output_content, encoding="utf-8")
    print(f"[IMPORTED] Successfully created: {dest_file}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Exports the canonical harness into native target agent configurations."""
    manifest_engine = ManifestEngine(harness_root=SCRIPT_DIR)
    manifest = manifest_engine.build_manifest()

    out_base = Path(args.out).resolve() if args.out else SCRIPT_DIR / "export"
    targets = [args.target] if args.target != "all" else ["claude", "cursor", "universal", "aider", "generic"]

    print(f"Antigravity Porter Export — Version {manifest.version}")
    print(f"Source: {SCRIPT_DIR}")
    print(f"Output: {out_base}")
    print("-" * 50)

    for target in targets:
        target_dir = out_base if len(targets) == 1 and args.out else out_base / target
        emitted = []

        if target == "claude":
            emitted = ClaudeEmitter.emit(manifest, target_dir)
        elif target == "cursor":
            emitted = CursorEmitter.emit(manifest, target_dir)
        elif target == "universal":
            emitted = UniversalEmitter.emit(manifest, target_dir)
        elif target == "aider":
            emitted = AiderEmitter.emit(manifest, target_dir)
        elif target == "generic":
            emitted = GenericEmitter.emit(manifest, target_dir)

        print(f"[{target.upper()}] Generated {len(emitted)} files in {target_dir}")
        for p in emitted:
            print(f"  - {p.relative_to(target_dir)}")

    return 0


def cmd_manifest(args: argparse.Namespace) -> int:
    """Generates the lossless Universal Canonical Manifest (.harness/manifest.json)."""
    manifest_engine = ManifestEngine(harness_root=SCRIPT_DIR)
    out_path = Path(args.out).resolve() if args.out else SCRIPT_DIR / ".harness" / "manifest.json"
    saved = manifest_engine.save_manifest(out_path)
    print(f"[MANIFEST] Lossless manifest generated at: {saved}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="porter",
        description="Universal Bidirectional AI Agent Bridge, Suitability Analyzer, and Transpiler."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {PORTER_VERSION}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # inspect
    p_inspect = subparsers.add_parser("inspect", help="Run pre-flight suitability and adaptability analysis.")
    p_inspect.add_argument("target", help="File path or URL to inspect.")
    p_inspect.add_argument("--json", action="store_true", help="Output machine-readable JSON.")

    # import
    p_import = subparsers.add_parser("import", help="Import and sanitize an external rule into the harness.")
    p_import.add_argument("target", help="File path or URL to import.")
    p_import.add_argument("--as-skill", help="Import as a modular skill with given name.")
    p_import.add_argument("--as-agent", help="Import as an autonomous subagent with given name.")
    p_import.add_argument("--force", action="store_true", help="Override critical constitutional warnings.")
    p_import.add_argument("--dry-run", action="store_true", help="Preview output without writing files.")

    # export
    p_export = subparsers.add_parser("export", help="Export harness to target agent platform.")
    p_export.add_argument(
        "--target",
        choices=["claude", "cursor", "universal", "aider", "generic", "all"],
        default="all",
        help="Target platform format (default: all)"
    )
    p_export.add_argument("--out", help="Output directory path (defaults to ./export/<target>).")

    # manifest
    p_manifest = subparsers.add_parser("manifest", help="Generate lossless .harness/manifest.json.")
    p_manifest.add_argument("--out", help="Output file path (default: .harness/manifest.json).")

    args = parser.parse_args()

    if args.command == "inspect":
        return cmd_inspect(args)
    elif args.command == "import":
        return cmd_import(args)
    elif args.command == "export":
        return cmd_export(args)
    elif args.command == "manifest":
        return cmd_manifest(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
