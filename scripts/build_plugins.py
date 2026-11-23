#!/usr/bin/env python3
"""
scripts/build_plugins.py — Standalone Antigravity Plugin Pack Builder & Validator CLI
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Usage:
  python3 scripts/build_plugins.py [--out DIR] [--pack NAME ...] [--validate] [--zip] [--json] [--run-agy-validate]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guard.plugins import PLUGIN_CATALOG, build_all_plugin_packs  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_plugins.py",
        description="Build, archive, and validate standalone Antigravity domain plugin packs.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "dist" / "plugins",
        help="Output directory for built plugin packs and optional .zip/.sha256 archives (default: dist/plugins).",
    )
    parser.add_argument(
        "--pack",
        action="append",
        choices=sorted(PLUGIN_CATALOG.keys()),
        help="Plugin pack name to build (repeatable; defaults to all 4 canonical packs).",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Run strict offline validation on built plugin directories (and .zip archives when --zip is set).",
    )
    parser.add_argument(
        "--zip",
        action="store_true",
        dest="create_zip",
        help="Create deterministic cross-OS .zip archives and 2-space .sha256 sidecars.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit machine-readable JSON summary to stdout.",
    )
    parser.add_argument(
        "--run-agy-validate",
        action="store_true",
        help="Also invoke `agy plugin validate --strict` when the `agy` CLI is available on PATH.",
    )
    parser.add_argument(
        "--version",
        default=None,
        help="Override plugin version string (defaults to guard.__version__).",
    )
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        default=None,
        help="Override deterministic ZIP timestamp as Unix epoch seconds.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    do_validate = bool(args.validate or args.run_agy_validate)

    try:
        summary = build_all_plugin_packs(
            repo_root=REPO_ROOT,
            out_dir=args.out,
            packs=args.pack,
            version=args.version,
            create_zip=args.create_zip,
            validate=do_validate,
            run_agy_validate=args.run_agy_validate,
            source_date_epoch=args.source_date_epoch,
        )
    except (OSError, ValueError) as exc:
        if args.as_json:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(f"[ERROR] Plugin build failed: {exc}", file=sys.stderr)
        return 2

    all_ok = all(entry["ok"] for entry in summary.values())
    if args.as_json:
        print(json.dumps({"ok": all_ok, "out_dir": str(args.out), "packs": summary}, indent=2))
        return 0 if all_ok else 1

    for pack_name, entry in summary.items():
        status = "PASS" if entry["ok"] else "FAIL"
        line = f"[{status}] {pack_name} (v{entry['version']}) -> {entry['dir']}"
        if "zip" in entry:
            line += f" | zip={Path(entry['zip']).name} sha256={entry['sha256'][:12]}..."
        print(line)
        for key in ("dir_validation", "zip_validation"):
            val = entry.get(key)
            if not val:
                continue
            if val.get("agy_validate_status") == "unavailable":
                print(f"  [INFO] {pack_name} ({key}): `agy` CLI not on PATH (offline validator ran)")
            for err in val.get("errors", []):
                print(f"  [ERROR] {pack_name} ({key}): {err}", file=sys.stderr)
            for warn in val.get("warnings", []):
                print(f"  [WARN] {pack_name} ({key}): {warn}", file=sys.stderr)

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
