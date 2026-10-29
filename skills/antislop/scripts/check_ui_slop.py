#!/usr/bin/env python3
"""
skills/antislop/scripts/check_ui_slop.py — Deterministic scanner for structural UI/CSS/JSX/HTML slop
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Python standard library only; runs on Python 3.10 and later.

Rule families:
  UI-1  Cloned sibling card grid      (3+ consecutive sibling containers with identical card/box class signature)
  UI-2  Nested card-in-card           (bordered/shadowed card container nested inside another card container)
  UI-3  Unearned AI visual tells      (purple/pink gradients, >2 backdrop-blur layers, continuous bounce/ping)
  UI-4  Programmer-art game primaries (raw #FF0000/#00FF00/#0000FF/#FFFF00/#FF00FF/#00FFFF in game/canvas files)
  UI-5  Dead interactive stubs        (href="#", href="javascript:void(0)", empty onClick={() => {}} handlers)

Usage:
  python3 skills/antislop/scripts/check_ui_slop.py PATH [PATH ...]
  cat index.html | python3 skills/antislop/scripts/check_ui_slop.py - --mode game
  python3 skills/antislop/scripts/check_ui_slop.py src/ --mode utility --summary
  python3 skills/antislop/scripts/check_ui_slop.py src/ --json

Exit codes: 0 clean, 1 findings, 2 read or argument error.
"""

from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SCAN_EXTENSIONS = {".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".css"}
SKIP_DIRS = frozenset({
    "node_modules", ".git", "dist", "build", ".next", "coverage",
    "__pycache__", ".venv", "venv", "target", "vendor",
})
MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024
MODES = ("auto", "utility", "editorial", "game")


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    category: str
    severity: str
    description: str
    fix_hint: str


RULES: Dict[str, RuleSpec] = {
    "UI-1": RuleSpec(
        "UI-1",
        "layout-symmetry",
        "high",
        "Cloned sibling card grid (3+ consecutive sibling containers with identical card/box class signature)",
        "Sibling Symmetry Cap (R-05 / R-14): break 3+ identical card clones into an asymmetric split, open table, or hairlined list.",
    ),
    "UI-2": RuleSpec(
        "UI-2",
        "boxification",
        "high",
        "Nested card-in-card boxification (bordered/shadowed card container inside another card container)",
        "Anti-Boxification (R-05 / R-14): remove the inner or outer card border/shadow and separate sub-groups with spacing or a 1px hairline.",
    ),
    "UI-3": RuleSpec(
        "UI-3",
        "visual-tells",
        "medium",
        "Unearned AI visual tell (purple/pink gradient, >2 backdrop-blur layers, or continuous bounce/ping animation)",
        "R-01 / R-10 / R-13 / R-19: remove decorative purple/pink gradients, cap backdrop-blur at 2 per view, and restrict bounce/ping to live status.",
    ),
    "UI-4": RuleSpec(
        "UI-4",
        "game-vitality",
        "high",
        "Uncalibrated programmer-art RGB/CMY primary hex literal in game or canvas code",
        "R-29 / Game & Interactive Canvas Vitality: replace raw #FF0000/#00FF00/#0000FF/#FFFF00/#FF00FF/#00FFFF with cohesive palette tokens.",
    ),
    "UI-5": RuleSpec(
        "UI-5",
        "dead-interaction",
        "high",
        "Dead interactive stub (href=\"#\", javascript:void(0), or no-op click handler)",
        "R-24 / R-26 / R-35: wire the control to real state/navigation or remove the unimplemented interactive element.",
    ),
}

RULE_ORDER = {rid: idx for idx, rid in enumerate(RULES)}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    line_number: int
    excerpt: str
    matched_span: str
    fix_hint: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "line_number": self.line_number,
            "excerpt": self.excerpt,
            "matched_span": self.matched_span,
            "fix_hint": self.fix_hint,
        }


@dataclass(frozen=True)
class FileReport:
    path: str
    mode: str
    lines: int
    findings: List[Finding]

    def to_dict(self) -> Dict[str, object]:
        return {
            "path": self.path,
            "mode": self.mode,
            "lines": self.lines,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Tag & token helpers
# ---------------------------------------------------------------------------

CONTAINER_TAGS = {"div", "article", "section", "li", "aside"}
EXEMPT_BOUNDARY_TAGS = {"table", "thead", "tbody", "tr", "td", "th", "dialog", "form"}
SELF_CLOSING_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}

TAG_TOKEN_RE = re.compile(
    r"<!--[\s\S]*?-->|"
    r"<(?P<close>/)?(?P<tag>[a-zA-Z][a-zA-Z0-9_-]*)"
    r"(?P<attrs>(?:[^<>\"'{}]|\"[^\"]*\"|'[^']*'|\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})*?)"
    r"(?P<self>/)?>",
    re.DOTALL,
)

CLASS_ATTR_RE = re.compile(
    r"\b(?:class|className)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|\{\s*[\"']([^\"']*)[\"']\s*\})",
    re.DOTALL,
)
ROLE_ATTR_RE = re.compile(r"\brole\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
STYLE_ATTR_RE = re.compile(r"\bstyle\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
DRAGGABLE_ATTR_RE = re.compile(
    r"\bdraggable(?:\s*=\s*(?:[\"']true[\"']|\{\s*true\s*\}))?(?=\s|/|>|$)",
    re.IGNORECASE,
)

CARD_CLASS_TOKEN_RE = re.compile(
    r"^(?:"
    r"card|panel|tile|box|bento(?:-card|-item)?|metric-card|stat-card|feature-card|"
    r"rounded(?:-[a-z0-9]+)?|border(?:-[a-z0-9/]+)?|shadow(?:-[a-z0-9]+)?|"
    r"ring(?:-[0-9]+)?|bg-[a-z0-9/_-]+|p-[0-9]+|px-[0-9]+|py-[0-9]+"
    r")$",
    re.IGNORECASE,
)

BOX_BORDER_SHADE_RE = re.compile(
    r"^(?:"
    r"card|panel|tile|bento(?:-card|-item)?|metric-card|stat-card|feature-card|"
    r"border|border-[248]|border-[a-z]+-[0-9]{2,3}(?:/[0-9]+)?|"
    r"shadow|shadow-(?:sm|md|lg|xl|2xl|inner)|ring-1|ring-2"
    r")$",
    re.IGNORECASE,
)

BOX_SURFACE_RE = re.compile(
    r"^(?:"
    r"card|panel|tile|bento(?:-card|-item)?|metric-card|stat-card|feature-card|"
    r"rounded(?:-(?:md|lg|xl|2xl|3xl))?|bg-[a-z0-9/_-]+"
    r")$",
    re.IGNORECASE,
)

INLINE_BOX_STYLE_RE = re.compile(
    r"(?:border\s*:\s*(?!none\b|0\b)[^;]+|box-shadow\s*:\s*(?!none\b)[^;]+)",
    re.IGNORECASE,
)

# UI-3 patterns
AI_GRADIENT_RE = re.compile(
    r"\b(?:from|via|to)-(?:purple|violet|indigo|pink|fuchsia)-[0-9]{2,3}\b|"
    r"linear-gradient\([^)]*(?:#8b5cf6|#a855f7|#ec4899|#6366f1|#d946ef|purple|violet|magenta|fuchsia)[^)]*\)",
    re.IGNORECASE,
)

BACKDROP_BLUR_RE = re.compile(
    r"\bbackdrop-blur(?:-[a-z0-9]+)?\b|backdrop-filter\s*:\s*blur\(",
    re.IGNORECASE,
)

CONTINUOUS_BOUNCE_RE = re.compile(
    r"\banimate-(?:bounce|ping|spin-slow)\b",
    re.IGNORECASE,
)

STATUS_EXEMPT_RE = re.compile(
    r"\b(?:aria-busy|role\s*=\s*[\"']status[\"']|loading|spinner|skeleton)\b",
    re.IGNORECASE,
)

# UI-4 patterns (raw programmer-art RGB/CMY primaries)
RAW_PRIMARY_HEX_RE = re.compile(
    r"(?<![0-9a-fA-F])#(?:ff0000|00ff00|0000ff|ffff00|ff00ff|00ffff)\b",
    re.IGNORECASE,
)

CANVAS_SIGNAL_RE = re.compile(
    r"<canvas\b|\.getContext\s*\(\s*[\"'](?:2d|webgl|webgl2)[\"']|\brequestAnimationFrame\s*\(",
    re.IGNORECASE,
)

# UI-5 patterns (dead interactive stubs)
DEAD_HREF_RE = re.compile(
    r"\bhref\s*=\s*(?:[\"'](?:#|javascript:\s*void\(0\)?;?|javascript:\s*;?)[\"']|[\"']\s*[\"'])",
    re.IGNORECASE,
)

EMPTY_ONCLICK_RE = re.compile(
    r"\bon[Cc]lick\s*=\s*(?:"
    r"\{\s*\([^)]*\)\s*=>\s*\{\s*(?:/\*.*?\*/\s*)?\}\s*\}|"
    r"\{\s*\(\)\s*=>\s*(?:null|undefined|false)\s*\}|"
    r"[\"']\s*(?:return\s+false\s*;?|void\(0\)\s*;?)?\s*[\"']"
    r")",
    re.DOTALL,
)


def _extract_classes(attrs: str) -> List[str]:
    tokens: List[str] = []
    for m in CLASS_ATTR_RE.finditer(attrs):
        raw = m.group(1) or m.group(2) or m.group(3) or ""
        tokens.extend(t for t in raw.split() if t)
    return tokens


def _card_signature(tag: str, classes: Sequence[str], style: str) -> Optional[str]:
    """Returns a normalized structural signature if the element is styled like a card/tile box."""
    has_border_or_shade = any(BOX_BORDER_SHADE_RE.match(c) for c in classes)
    has_surface = any(BOX_SURFACE_RE.match(c) for c in classes)
    has_explicit_card = any(
        c.lower() in {"card", "panel", "tile", "bento-card", "bento-item", "metric-card", "stat-card", "feature-card"}
        for c in classes
    )
    has_inline_box = bool(style and INLINE_BOX_STYLE_RE.search(style))

    if not (has_explicit_card or (has_border_or_shade and has_surface) or has_inline_box):
        return None

    relevant = sorted(c.lower() for c in classes if CARD_CLASS_TOKEN_RE.match(c))
    if not relevant and has_inline_box:
        relevant = ["inline-box"]
    return f"{tag.lower()}:{' '.join(relevant)}"


def _is_exempt_boundary(tag: str, attrs: str, classes: Sequence[str]) -> bool:
    if tag.lower() in EXEMPT_BOUNDARY_TAGS:
        return True
    role_m = ROLE_ATTR_RE.search(attrs)
    if role_m and role_m.group(1).lower() in {"dialog", "alertdialog", "grid", "table", "treegrid"}:
        return True
    if any(c.lower() in {"modal", "dialog", "drawer", "popover"} for c in classes):
        return True
    if DRAGGABLE_ATTR_RE.search(attrs):
        return True
    return False


@dataclass
class _Node:
    tag: str
    offset: int
    span: str
    card_sig: Optional[str]
    exempt_boundary: bool
    child_runs: List[Tuple[Optional[str], int, str]]


def _line_lookup_table(text: str) -> List[int]:
    starts = [0]
    for idx, ch in enumerate(text):
        if ch == "\n":
            starts.append(idx + 1)
    return starts


def _line_and_excerpt(text: str, line_starts: Sequence[int], offset: int) -> Tuple[int, str]:
    line_idx = bisect.bisect_right(line_starts, offset) - 1
    line_num = max(1, line_idx + 1)
    start = line_starts[line_idx]
    end = text.find("\n", start)
    if end == -1:
        end = len(text)
    excerpt = text[start:end].strip()
    if len(excerpt) > 120:
        excerpt = excerpt[:117] + "..."
    return line_num, excerpt


def scan_text(text: str, *, path: str = "<stdin>", mode: str = "auto") -> FileReport:
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    if mode == "auto":
        effective_mode = "game" if CANVAS_SIGNAL_RE.search(text) else "utility"
    else:
        effective_mode = mode

    line_starts = _line_lookup_table(text)
    raw_hits: List[Tuple[str, int, str]] = []

    # 1. Structural HTML / JSX pass for UI-1 (sibling card clones) & UI-2 (nested cards)
    stack: List[_Node] = [
        _Node(tag="__root__", offset=0, span="", card_sig=None, exempt_boundary=False, child_runs=[])
    ]
    reported_ui1_offsets: set[int] = set()
    reported_ui2_offsets: set[int] = set()

    def _flush_sibling_runs(children: List[Tuple[Optional[str], int, str]]) -> None:
        idx = 0
        while idx < len(children):
            sig, first_offset, first_span = children[idx]
            if not sig:
                idx += 1
                continue
            end = idx + 1
            while end < len(children) and children[end][0] == sig:
                end += 1
            if end - idx >= 3 and first_offset not in reported_ui1_offsets:
                reported_ui1_offsets.add(first_offset)
                raw_hits.append(("UI-1", first_offset, first_span))
            idx = end

    for m in TAG_TOKEN_RE.finditer(text):
        whole = m.group(0)
        if whole.startswith("<!--"):
            continue
        is_close = bool(m.group("close"))
        tag = (m.group("tag") or "").lower()
        attrs = m.group("attrs") or ""
        is_self = bool(m.group("self")) or tag in SELF_CLOSING_TAGS

        if not is_close:
            classes = _extract_classes(attrs)
            style_m = STYLE_ATTR_RE.search(attrs)
            style = style_m.group(1) if style_m else ""
            card_sig = _card_signature(tag, classes, style) if tag in CONTAINER_TAGS else None
            exempt = _is_exempt_boundary(tag, attrs, classes)

            # Check UI-2: card inside a card (depth delta 1 or 2) without an exempt boundary
            if card_sig and not exempt:
                for ancestor in reversed(stack[1:]):
                    if ancestor.exempt_boundary:
                        break
                    if ancestor.card_sig is not None:
                        if m.start() not in reported_ui2_offsets:
                            reported_ui2_offsets.add(m.start())
                            raw_hits.append(("UI-2", m.start(), whole))
                        break

            # Record on parent's child list for UI-1 sibling symmetry check
            stack[-1].child_runs.append((card_sig, m.start(), whole))

            if not is_self:
                stack.append(
                    _Node(
                        tag=tag,
                        offset=m.start(),
                        span=whole,
                        card_sig=card_sig,
                        exempt_boundary=exempt,
                        child_runs=[],
                    )
                )
        else:
            # Closing tag: pop matching tag if present on stack
            match_idx = None
            for idx in range(len(stack) - 1, 0, -1):
                if stack[idx].tag == tag:
                    match_idx = idx
                    break
            if match_idx is not None:
                while len(stack) > match_idx:
                    popped = stack.pop()
                    _flush_sibling_runs(popped.child_runs)

    while stack:
        popped = stack.pop()
        _flush_sibling_runs(popped.child_runs)

    # 2. UI-3: Unearned AI visual tells (purple/pink gradients, >2 backdrop-blur, continuous bounce/ping)
    for m in AI_GRADIENT_RE.finditer(text):
        raw_hits.append(("UI-3", m.start(), m.group(0)))

    blur_matches = list(BACKDROP_BLUR_RE.finditer(text))
    if len(blur_matches) > 2:
        for m in blur_matches[2:]:
            raw_hits.append(("UI-3", m.start(), m.group(0)))

    if effective_mode != "game":
        for m in CONTINUOUS_BOUNCE_RE.finditer(text):
            line_num, excerpt = _line_and_excerpt(text, line_starts, m.start())
            if not STATUS_EXEMPT_RE.search(excerpt):
                raw_hits.append(("UI-3", m.start(), m.group(0)))

    # 3. UI-4: Uncalibrated programmer-art primaries in game or canvas mode
    if effective_mode == "game":
        for m in RAW_PRIMARY_HEX_RE.finditer(text):
            raw_hits.append(("UI-4", m.start(), m.group(0)))

    # 4. UI-5: Dead interactive stubs
    for m in DEAD_HREF_RE.finditer(text):
        raw_hits.append(("UI-5", m.start(), m.group(0)))
    for m in EMPTY_ONCLICK_RE.finditer(text):
        raw_hits.append(("UI-5", m.start(), m.group(0)))

    raw_hits.sort(key=lambda h: (h[1], RULE_ORDER[h[0]]))
    findings: List[Finding] = []
    for rule_id, offset, span in raw_hits:
        spec = RULES[rule_id]
        line_num, excerpt = _line_and_excerpt(text, line_starts, offset)
        clean_span = " ".join(span.split())
        if len(clean_span) > 80:
            clean_span = clean_span[:77] + "..."
        findings.append(
            Finding(
                rule_id=rule_id,
                category=spec.category,
                severity=spec.severity,
                line_number=line_num,
                excerpt=excerpt,
                matched_span=clean_span,
                fix_hint=spec.fix_hint,
            )
        )

    total_lines = max(1, len(line_starts))
    return FileReport(path=path, mode=effective_mode, lines=total_lines, findings=findings)


def _iter_paths(inputs: Sequence[str]) -> Iterable[Path]:
    for raw in inputs:
        p = Path(raw)
        if p.is_symlink():
            raise ValueError(f"Refusing to scan symlink path: {raw}")
        if not p.exists():
            raise FileNotFoundError(f"Path not found: {raw}")
        if p.is_file():
            st = p.stat()
            if st.st_size > MAX_SCAN_FILE_BYTES:
                raise ValueError(
                    f"File exceeds {MAX_SCAN_FILE_BYTES} byte scan limit ({st.st_size} bytes): {raw}"
                )
            yield p
        elif p.is_dir():
            for root, dirs, files in os.walk(p, followlinks=False):
                root_path = Path(root)
                dirs[:] = sorted(
                    d for d in dirs if d not in SKIP_DIRS and not (root_path / d).is_symlink()
                )
                for fname in sorted(files):
                    child = root_path / fname
                    if child.is_symlink() or child.suffix.lower() not in SCAN_EXTENSIONS:
                        continue
                    try:
                        st = child.stat()
                    except OSError:
                        continue
                    if st.st_size <= MAX_SCAN_FILE_BYTES and child.is_file():
                        yield child


def _format_human(reports: Sequence[FileReport]) -> str:
    total = sum(len(r.findings) for r in reports)
    if total == 0:
        return "No structural UI slop findings."
    out: List[str] = []
    for report in reports:
        if not report.findings:
            continue
        out.append(f"=== {report.path} (mode={report.mode}, {len(report.findings)} findings) ===")
        for f in report.findings:
            out.append(f"  L{f.line_number} [{f.rule_id}] ({f.severity}) {RULES[f.rule_id].description}")
            out.append(f"    Matched: \"{f.matched_span}\"")
            out.append(f"    Fix:     {f.fix_hint}")
    return "\n".join(out)


def _format_summary(reports: Sequence[FileReport]) -> str:
    counts: Dict[str, int] = {rid: 0 for rid in RULES}
    total_lines = 0
    for r in reports:
        total_lines += r.lines
        for f in r.findings:
            counts[f.rule_id] += 1
    total_findings = sum(counts.values())
    status = "PASS" if total_findings == 0 else "FAIL (Action Required)"
    lines = [
        f"UI Slop Structural Summary — Files: {len(reports)} | Lines: {total_lines} | Findings: {total_findings}",
        f"Status: {status}",
        "-" * 72,
    ]
    for rid, spec in RULES.items():
        if counts[rid] > 0:
            lines.append(f"  {rid:<6} {counts[rid]:>4}  ({spec.severity:<6}) {spec.description}")
    if total_findings == 0:
        lines.append("  All structural UI checks passed (0 findings).")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic structural UI/CSS/JSX/HTML slop scanner for Antigravity Harness."
    )
    parser.add_argument("paths", nargs="+", help="Files or directories to scan, or '-' for stdin.")
    parser.add_argument(
        "--mode",
        choices=MODES,
        default="auto",
        help="Domain archetype mode from DESIGN.md (auto, utility, editorial, game). Default: auto.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--summary", action="store_true", help="Emit a per-rule summary table.")

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code != 0 else 0

    if args.json and args.summary:
        sys.stderr.write("error: --json and --summary cannot be used together.\n")
        return 2

    reports: List[FileReport] = []
    try:
        if list(args.paths) == ["-"]:
            content = sys.stdin.read()
            reports.append(scan_text(content, path="<stdin>", mode=args.mode))
        else:
            for file_path in _iter_paths(args.paths):
                text = file_path.read_text(encoding="utf-8-sig")
                reports.append(scan_text(text, path=str(file_path), mode=args.mode))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    total_findings = sum(len(r.findings) for r in reports)
    if args.json:
        payload = {
            "files": [r.to_dict() for r in reports],
            "total_findings": total_findings,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif args.summary:
        print(_format_summary(reports))
    else:
        print(_format_human(reports))

    return 1 if total_findings > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
