#!/usr/bin/env python3
"""
porter.py — Universal AI Agent Bridge & Suitability Transpiler
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

`porter import` writes into this SOURCE repository (reviewable via git diff). It never
writes into the live, Guard-protected configuration: use `agy-guard porter stage` for that.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
from pathlib import Path

# Ensure repository root is in python path
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from porter import __version__ as PORTER_VERSION
from porter.analyzer import SuitabilityAnalyzer
from porter.archive import inspect_zip
from porter.emitters import EMITTERS, EmitterConflictError
from porter.frontmatter import FrontmatterError, dump_frontmatter, parse_frontmatter_block, split_frontmatter
from porter.manifest import ManifestEngine, default_harness_root
from porter.net import safe_fetch_url


def _harness_root() -> Path:
    return default_harness_root(SCRIPT_DIR)


def fetch_target_content(target: str) -> str:
    """Reads content from a local path or a remote HTTP(S) URL with SSRF protection."""
    if target.startswith(("http://", "https://")):
        return safe_fetch_url(target, user_agent=f"Antigravity-Porter/{PORTER_VERSION}")
    path = Path(target).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")
    return path.read_text(encoding="utf-8", errors="ignore")


def _is_live_config(path: Path) -> bool:
    live = Path(os.environ.get("ANTIGRAVITY_CONFIG_DIR", Path.home() / ".gemini" / "config")).expanduser().resolve()
    try:
        path.resolve().relative_to(live)
        return True
    except ValueError:
        return False


def _confirm(prompt: str) -> bool:
    if not (sys.stdin and sys.stdin.isatty()):
        return False
    try:
        return input(f"{prompt} Type 'yes' to confirm: ").strip().lower() == "yes"
    except (EOFError, KeyboardInterrupt):
        return False


def _is_zip_target(target: str) -> bool:
    if target.startswith(("http://", "https://")):
        return urllib.parse.urlparse(target).path.lower().endswith(".zip")
    return target.lower().endswith(".zip")


def cmd_inspect_archive(args: argparse.Namespace) -> int:
    """Inspects a local ZIP archive without extracting it (Porter never unpacks archives)."""
    if args.target.startswith(("http://", "https://")):
        print(f"Error: '{args.target}' is a remote ZIP archive. Porter does not fetch archives: "
              "download and inspect locally ('porter.py inspect <file.zip>').", file=sys.stderr)
        return 1
    path = Path(args.target)
    if not path.is_file():
        print(f"Error reading target '{args.target}': not a file", file=sys.stderr)
        return 1
    report = inspect_zip(path, harness_root=_harness_root())
    print(json.dumps(report.to_dict(), indent=2) if args.json else report.to_markdown())
    return 0 if report.is_safe else 2


def cmd_inspect(args: argparse.Namespace) -> int:
    """Performs pre-flight suitability and adaptability analysis without mutating any files."""
    if _is_zip_target(args.target):
        return cmd_inspect_archive(args)
    try:
        content = fetch_target_content(args.target)
    except Exception as e:
        print(f"Error reading target '{args.target}': {e}", file=sys.stderr)
        return 1

    report = SuitabilityAnalyzer(harness_root=_harness_root()).analyze(content, source_identifier=args.target)
    if args.json:
        print(json.dumps({
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
            "redundancies": report.redundancies,
        }, indent=2))
    else:
        print(report.to_markdown())
    return 0 if report.is_safe_to_import else 2


def cmd_import(args: argparse.Namespace) -> int:
    """Imports and converts an external rule into a harness skill or agent in this repository."""
    if getattr(args, "as_skill", None) and getattr(args, "as_agent", None):
        print("Error: --as-skill and --as-agent cannot be used together.", file=sys.stderr)
        return 2
    harness_root = _harness_root()
    if _is_live_config(harness_root):
        print("Error: porter.py is running from the live configuration directory. "
              "Use 'agy-guard porter stage' to ingest into a protected environment.", file=sys.stderr)
        return 1
    if _is_zip_target(args.target):
        print(f"Error: '{args.target}' is a ZIP archive. Porter never extracts archives; "
              "review it with 'porter.py inspect <file.zip>'.", file=sys.stderr)
        return 1
    try:
        content = fetch_target_content(args.target)
    except Exception as e:
        print(f"Error reading target '{args.target}': {e}", file=sys.stderr)
        return 1

    report = SuitabilityAnalyzer(harness_root=harness_root).analyze(content, source_identifier=args.target)
    if not report.is_safe_to_import:
        print(report.to_markdown(), file=sys.stderr)
        if not args.force:
            print("\n[BLOCKED] Critical constitutional issues detected. Use --force to override.", file=sys.stderr)
            return 1
        if not args.dry_run and not _confirm("Import content that FAILED the constitutional gate?"):
            print("[BLOCKED] --force requires interactive human confirmation.", file=sys.stderr)
            return 3
    review = [i for i in report.issues if i.category == "NEEDS_REVIEW"]
    if review and report.is_safe_to_import:
        print("[REVIEW] Ambiguous directives were kept unchanged and need a human decision:", file=sys.stderr)
        for issue in review:
            print(f"  - {issue.message}", file=sys.stderr)

    if args.as_agent:
        target_type = "agent"
    elif args.as_skill:
        target_type = "skill"
    elif report.recommended_type in ("agent", "subagent"):
        target_type = "agent"
    else:
        target_type = "skill"
    raw_name = args.as_agent or args.as_skill or report.recommended_name
    name = re.sub(r"[^a-zA-Z0-9_-]", "-", Path(raw_name).name).strip("-").lower() or "imported-custom"

    if target_type == "skill":
        base_dir = harness_root / "skills"
        dest_dir = base_dir / name
        dest_file = dest_dir / "SKILL.md"
        segments = (harness_root, base_dir, dest_dir, dest_file)
        description = f"{Path(str(report.source_target)).name} adapted via Porter."
    else:
        base_dir = harness_root / "agents"
        dest_dir = base_dir
        dest_file = dest_dir / f"{name}.md"
        segments = (harness_root, base_dir, dest_file)
        description = f"{name} agent definition adapted via Porter."

    for seg in segments:
        if os.path.islink(seg):
            print(f"Error: refusing to write through symlink {seg}.", file=sys.stderr)
            return 1
    try:
        dest_file.resolve().relative_to(base_dir.resolve())
    except ValueError:
        print(f"Error: Invalid destination path '{dest_file}'", file=sys.stderr)
        return 1

    try:
        fm, body = split_frontmatter(report.sanitized_content)
    except FrontmatterError:
        fm, body = None, report.sanitized_content
    parsed_meta = {}
    if isinstance(fm, str):
        try:
            parsed_meta = dict(parse_frontmatter_block(fm))
        except FrontmatterError:
            parsed_meta = {}
    elif isinstance(fm, dict):
        parsed_meta = dict(fm)
    raw_desc = parsed_meta.get("description")
    clean_desc = raw_desc.strip() if isinstance(raw_desc, str) and raw_desc.strip() else description
    if target_type == "agent":
        meta = {
            "name": name,
            "description": clean_desc,
            "access": "read-only",
        }
    else:
        meta = {"name": name}
        for k, v in parsed_meta.items():
            if k not in ("name", "description", "access", "tools", "EnableWriteTools", "EnableSubagentTools"):
                meta[k] = v
        meta["description"] = clean_desc
    output_content = dump_frontmatter(meta) + "\n" + body.lstrip() + "\n"

    if args.dry_run:
        print(f"[DRY-RUN] Target destination: {dest_file}")
        print("-" * 50)
        print(output_content[:500] + ("\n... [truncated]" if len(output_content) > 500 else ""))
        return 0

    if dest_file.exists() and not args.overwrite:
        print(f"Error: {dest_file} already exists. Use --overwrite to replace it.", file=sys.stderr)
        return 1
    for seg in segments:
        if os.path.islink(seg):
            print(f"Error: refusing to write through symlink {seg}.", file=sys.stderr)
            return 1
    dest_dir.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(dest_file), flags, 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(output_content.encode("utf-8"))  # LF on every OS
    print(f"[IMPORTED] Successfully created: {dest_file} (review with 'git diff' before deploying)")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Exports the canonical harness into native target agent configurations."""
    harness_root = _harness_root()
    manifest = ManifestEngine(harness_root=harness_root).build_manifest()
    default_out = (Path.cwd() / "export") if harness_root != SCRIPT_DIR else (SCRIPT_DIR / "export")
    out_base = Path(args.out).resolve() if args.out else default_out
    targets = [args.target] if args.target != "all" else list(EMITTERS)

    print(f"Antigravity Porter Export — Version {manifest.version}")
    print(f"Source: {harness_root}")
    print(f"Output: {out_base}")
    print("-" * 50)
    for target in targets:
        target_dir = out_base if len(targets) == 1 and args.out else out_base / target
        try:
            emitted = EMITTERS[target].emit(manifest, target_dir, force=args.force)
        except (EmitterConflictError, ValueError, OSError) as e:
            print(f"[{target.upper()}] {e}", file=sys.stderr)
            return 1
        print(f"[{target.upper()}] Generated {len(emitted)} files in {target_dir}")
    return 0


def cmd_manifest(args: argparse.Namespace) -> int:
    """Generates the Universal Canonical Manifest (.harness/manifest.json) or checks it."""
    harness_root = _harness_root()
    engine = ManifestEngine(harness_root=harness_root)
    out_path = Path(args.out).resolve() if args.out else harness_root / ".harness" / "manifest.json"
    if args.check:
        if engine.is_up_to_date(out_path):
            print(f"[MANIFEST] Up to date: {out_path}")
            return 0
        print(f"[MANIFEST] STALE: {out_path} does not match the repository. Run 'python3 porter.py manifest'.", file=sys.stderr)
        return 1
    saved = engine.save_manifest(out_path, deterministic=args.deterministic)
    print(f"[MANIFEST] Manifest generated at: {saved}")
    return 0



def _robust_console() -> None:
    """Never crash on a console that cannot encode a character (Windows cp1252 pipes): replace it."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass

def main() -> int:
    _robust_console()
    parser = argparse.ArgumentParser(
        prog="porter",
        description="Universal AI Agent Bridge, Suitability Analyzer, and Transpiler.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {PORTER_VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_inspect = subparsers.add_parser("inspect", help="Run pre-flight suitability and adaptability analysis.")
    p_inspect.add_argument("target", help="File path or URL to inspect (a local .zip is inspected without extraction).")
    p_inspect.add_argument("--json", action="store_true", help="Output machine-readable JSON.")

    p_import = subparsers.add_parser("import", help="Import and sanitize an external rule into this repository.")
    p_import.add_argument("target", help="File path or URL to import.")
    p_import_kind = p_import.add_mutually_exclusive_group()
    p_import_kind.add_argument("--as-skill", help="Import as a modular skill with given name.")
    p_import_kind.add_argument("--as-agent", help="Import as a subagent with given name.")
    p_import.add_argument("--force", action="store_true", help="Import despite critical findings (interactive confirmation).")
    p_import.add_argument("--overwrite", action="store_true", help="Replace an existing skill/agent file.")
    p_import.add_argument("--dry-run", action="store_true", help="Preview output without writing files.")

    p_export = subparsers.add_parser("export", help="Export harness to target agent platform(s).")
    p_export.add_argument("--target", choices=list(EMITTERS) + ["all"], default="all", help="Target platform (default: all)")
    p_export.add_argument("--out", help="Output directory path (defaults to ./export/<target>).")
    p_export.add_argument("--force", action="store_true", help="Overwrite existing files that differ.")

    p_manifest = subparsers.add_parser("manifest", help="Generate or check .harness/manifest.json.")
    p_manifest.add_argument("--out", help="Output file path (default: .harness/manifest.json).")
    p_manifest.add_argument("--check", action="store_true", help="Exit 1 if the manifest is stale.")
    p_manifest.add_argument("--deterministic", action="store_true", help="Omit the generation timestamp.")

    args = parser.parse_args()
    handlers = {"inspect": cmd_inspect, "import": cmd_import, "export": cmd_export, "manifest": cmd_manifest}
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
