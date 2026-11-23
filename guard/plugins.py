"""
guard/plugins.py — Canonical Antigravity Plugin Catalog, Standalone Builder, Hybrid Core Rewriter & Validator.
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library (Python 3.10+).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

from guard import __version__ as HARNESS_VERSION
from guard.paths import atomic_write_text
from porter.frontmatter import FrontmatterError, parse_frontmatter_block, split_frontmatter

PLUGIN_SCHEMA_URL = "https://antigravity.google/schemas/v1/plugin.json"

ALLOWED_PLUGIN_MANIFEST_KEYS: FrozenSet[str] = frozenset({
    "$schema",
    "name",
    "displayName",
    "description",
    "version",
    "logo",
    "suggestedPrompts",
    "author",
    "homepage",
    "repository",
    "license",
    "keywords",
    "skills",
    "extensions",
    "disabled",
})

BANNED_BRAND_PREFIXES: Tuple[str, ...] = (
    "antigravity",
    "gemini",
    "claude",
    "cursor",
)

PLUGIN_AUTHOR: Dict[str, str] = {
    "name": "hadbilen",
    "url": "https://github.com/hadbilen/antigravity-harness",
}
PLUGIN_HOMEPAGE = "https://github.com/hadbilen/antigravity-harness"
PLUGIN_REPOSITORY = "https://github.com/hadbilen/antigravity-harness"
PLUGIN_LICENSE = "MIT"

# Fixed UTC epoch (2026-11-23T00:00:00Z) used for bit-identical archives when SOURCE_DATE_EPOCH is unset.
PLUGIN_DEFAULT_SOURCE_DATE_EPOCH = 1795392000

MAX_SVG_LOGO_BYTES = 16 * 1024
SVG_VIEWBOX_SIZE = 128.0
SVG_MIN_BOUND = 12.0
SVG_MAX_BOUND = 116.0
SVG_MIN_CONTRAST = 3.0
SVG_LIGHT_BG = "#FFFFFF"
SVG_DARK_BG = "#09090B"

MAX_ZIP_ENTRIES = 500
MAX_ZIP_UNCOMPRESSED_BYTES = 32 * 1024 * 1024

_EXCLUDED_DIR_NAMES: FrozenSet[str] = frozenset({
    "__pycache__",
    ".git",
    "node_modules",
    "tests",
})
_EXCLUDED_FILE_NAMES: FrozenSet[str] = frozenset({
    ".DS_Store",
    "Thumbs.db",
    "upstream_state.json",
    "MISTAKES.md",
})
_EXCLUDED_FILE_SUFFIXES: Tuple[str, ...] = (".pyc", ".pyo")

_TEXT_LF_SUFFIXES: FrozenSet[str] = frozenset({
    ".md",
    ".json",
    ".svg",
    ".py",
    ".sh",
    ".css",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".txt",
    ".yml",
    ".yaml",
})

HYBRID_CORE_REWRITE_EXCLUDES: FrozenSet[str] = frozenset({
    "skills/upstream-auditor/upstream_state.seed.json",
})


@dataclass(frozen=True)
class PluginSpec:
    """Immutable specification of a canonical Antigravity Harness domain plugin pack."""

    name: str
    display_name: str
    description: str
    skills: Tuple[str, ...]
    logo_asset: str
    suggested_prompts: Tuple[str, ...]
    extra_files: Tuple[Tuple[str, str], ...] = ()
    mcp_server_name: Optional[str] = None
    mcp_script_rel: Optional[str] = None
    third_party_upstreams: Tuple[str, ...] = ()


PLUGIN_CATALOG: Dict[str, PluginSpec] = {
    "antislop": PluginSpec(
        name="antislop",
        display_name="AntiSlop UI",
        description=(
            "UI design quality filter, WCAG AA contrast MCP and CLI checkers, de-AI prose scanner, "
            "kinetic showcase patterns, and single-file HTML rapid prototyping."
        ),
        skills=("antislop", "vibecoder"),
        logo_asset="antislop.svg",
        suggested_prompts=(
            "Audit this UI component and CSS for visual slop, mobile overflow, and WCAG AA contrast",
            "Scan this draft documentation or landing copy for synthetic AI markers and rewrite cleanly",
            "Prototype a self-contained single-file HTML interactive tool or game using /vibecoder",
        ),
        extra_files=(("DESIGN.md", "skills/antislop/references/DESIGN.md"),),
        mcp_server_name="contrast",
        mcp_script_rel="skills/antislop/scripts/contrast-mcp.py",
        third_party_upstreams=("miqdadbadjuber/anti-slop", "bendrape1-byte/silk-design"),
    ),
    "rust-suite": PluginSpec(
        name="rust-suite",
        display_name="Rust Suite",
        description=(
            "Cross-language porting and FFI bridging into Rust (C, C++, Go, Python, TS/JS, Ruby, Java), "
            "intra-Rust ownership and panic hardening, greenfield Cargo architecture, and an opt-in Vulkan template."
        ),
        skills=("rustify", "rust-harden"),
        logo_asset="rust-suite.svg",
        suggested_prompts=(
            "Port this C/C++ or Python module into safe Rust with golden-vector differential tests",
            "Harden this Rust crate to eliminate production panics, clone debt, and async cancellation bugs",
            "Scaffold a new Rust 2024 Cargo workspace with strict lints and clean domain/bin boundaries",
        ),
        extra_files=(("templates/vulkan.SKILL.template.md", "skills/rust-harden/assets/vulkan.SKILL.template.md"),),
        third_party_upstreams=("erkamyaman/rust-anything",),
    ),
    "media-studio": PluginSpec(
        name="media-studio",
        display_name="Media Studio",
        description=(
            "Deterministic audio, video, and still-image synthesis, timeline editing, damaged-container salvage, "
            "photo restoration, fidelity-bounded upscaling, and two-pass EBU R128 mastering."
        ),
        skills=("media-studio",),
        logo_asset="media-studio.svg",
        suggested_prompts=(
            "Probe and master this audio file to -14 LUFS and -1.0 dBTP with two-pass EBU R128",
            "Salvage a damaged WAV or MP4 container losslessly and verify recovered duration",
            "Restore and upscale this scanned photo or video clip without altering original identity",
        ),
    ),
    "game-engineering": PluginSpec(
        name="game-engineering",
        display_name="Game Engineering",
        description=(
            "Deterministic fixed-timestep game loops, entity state machines, zero per-frame allocation discipline, "
            "seeded procedural generation, and diegetic HUD craft for web and native engines."
        ),
        skills=("game-engineering",),
        logo_asset="game-engineering.svg",
        suggested_prompts=(
            "Build a deterministic fixed-timestep Canvas game loop with a seeded headless stepTick test",
            "Audit this game simulation for per-frame heap allocations, delta-time drift, and state bugs",
            "Design a diegetic HUD and Input Feedback Triad for a 2D action or strategy game",
        ),
    ),
}

HARNESS_PLUGIN_NAMES: FrozenSet[str] = frozenset(PLUGIN_CATALOG.keys())

PLUGIN_SKILL_TO_PACK: Dict[str, str] = {
    skill_slug: pack_name
    for pack_name, spec in PLUGIN_CATALOG.items()
    for skill_slug in spec.skills
}

PLUGIN_OWNED_SKILL_SLUGS: FrozenSet[str] = frozenset(PLUGIN_SKILL_TO_PACK.keys())

PLUGIN_ASSET_FILENAMES: Tuple[str, ...] = tuple(spec.logo_asset for spec in PLUGIN_CATALOG.values())


@dataclass(frozen=True)
class PluginValidationResult:
    """Structured result from offline plugin directory or zip validation."""

    target: str
    pack_name: str
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]
    agy_validate_status: str = "skipped"

    @property
    def ok(self) -> bool:
        return not self.errors and not self.warnings

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "pack_name": self.pack_name,
            "ok": self.ok,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "agy_validate_status": self.agy_validate_status,
        }


# ---------------------------------------------------------------------------
# Asset & Interpreter Resolution Helpers
# ---------------------------------------------------------------------------


def _plugin_assets_dir(repo_root: Optional[Path] = None) -> Path:
    """Resolves bundled SVG logo assets across frozen PyInstaller (_MEIPASS) and source checkouts."""
    candidates: List[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "guard" / "plugin_assets")
    candidates.append(Path(__file__).resolve().parent / "plugin_assets")
    if repo_root is not None:
        candidates.append(Path(repo_root) / "guard" / "plugin_assets")

    for cand in candidates:
        if cand.is_dir() and not os.path.islink(cand):
            return cand
    searched = ", ".join(str(c) for c in candidates)
    raise FileNotFoundError(f"Plugin SVG asset directory not found (searched: {searched})")


def _find_trusted_python_on_path(binary_names: Tuple[str, ...]) -> Optional[str]:
    """Searches filtered PATH entries via shutil.which, rejecting empty, relative, CWD, and world-writable dirs."""
    raw_path = os.environ.get("PATH", "")
    if not raw_path:
        return None
    try:
        cwd_real = os.path.realpath(os.getcwd())
    except OSError:
        cwd_real = ""
    safe_dirs: List[str] = []
    for entry in raw_path.split(os.pathsep):
        cleaned = entry.strip().strip('"')
        if not cleaned or not os.path.isabs(cleaned):
            continue
        try:
            if not os.path.isdir(cleaned):
                continue
            dir_real = os.path.realpath(cleaned)
            if cwd_real and dir_real == cwd_real:
                continue
            if os.name != "nt" and sys.platform != "win32":
                st = os.stat(dir_real)
                if st.st_mode & stat.S_IWOTH:
                    continue
            safe_dirs.append(dir_real)
        except OSError:
            continue
    if not safe_dirs:
        return None
    trusted_path = os.pathsep.join(safe_dirs)
    for name in binary_names:
        cand = shutil.which(name, path=trusted_path)
        if not cand:
            continue
        try:
            cand_dir_real = os.path.realpath(os.path.dirname(cand))
            if cwd_real and cand_dir_real == cwd_real:
                continue
        except OSError:
            continue
        return cand
    return None


def resolve_local_python_command(python_executable: Optional[str] = None) -> str:
    """Resolves a safe local Python command for installed plugin mcp_config.json (frozen-aware)."""
    is_frozen = bool(getattr(sys, "frozen", False))
    if python_executable:
        same_as_frozen = False
        if is_frozen:
            try:
                same_as_frozen = (
                    python_executable == sys.executable
                    or os.path.realpath(python_executable) == os.path.realpath(sys.executable)
                )
            except OSError:
                same_as_frozen = python_executable == sys.executable
        if not same_as_frozen:
            return python_executable
    if is_frozen:
        if os.name == "nt":
            return _find_trusted_python_on_path(("python", "python3")) or "python"
        return _find_trusted_python_on_path(("python3", "python")) or "python3"
    return sys.executable


def _is_plugin_script_path(rel_posix: str) -> bool:
    parts = PurePosixPath(rel_posix).parts
    return "scripts" in parts and rel_posix.endswith((".py", ".sh", ".mjs"))


def _normalize_lf(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _validate_safe_rel_path(rel_posix: str) -> str:
    if not rel_posix or rel_posix.startswith("/") or "\\" in rel_posix:
        raise ValueError(f"Unsafe plugin relative path: {rel_posix!r}")
    parts = PurePosixPath(rel_posix).parts
    if any(p in ("", ".", "..") for p in parts) or ":" in parts[0]:
        raise ValueError(f"Path traversal or drive component rejected: {rel_posix!r}")
    return "/".join(parts)


def _rel_within_plugin(from_plugin_rel: str, to_plugin_rel: str) -> str:
    """Computes a depth-aware POSIX relative path with an explicit ./ or ../ prefix."""
    trailing_slash = to_plugin_rel.endswith("/")
    clean_target = to_plugin_rel.rstrip("/")
    from_dir = posixpath.dirname(from_plugin_rel) or "."
    rel = posixpath.relpath(clean_target, from_dir)
    if not rel.startswith((".", "/")):
        rel = "./" + rel
    if trailing_slash and not rel.endswith("/"):
        rel += "/"
    return rel


# ---------------------------------------------------------------------------
# Standalone-Clean Plugin Markdown Rewriter (D4)
# ---------------------------------------------------------------------------

_ANTISLOP_BUNDLE_NOTE_MARKER = "> **Plugin Bundle Note:**"
_ANTISLOP_BUNDLE_NOTE = (
    "> **Plugin Bundle Note:** When no project-local `DESIGN.md` exists, default visual tokens ship "
    "inside this plugin at [references/DESIGN.md](./references/DESIGN.md). Deterministic WCAG AA "
    "contrast checks are available via the bundled `antislop_contrast` MCP server (`check_contrast`) "
    "or `python3 ./scripts/contrast-check.py`."
)

_MEDIA_QC_BLOCK_RE = re.compile(
    r'^(?P<indent>[ \t]*)MEDIA_QC="skills/media-studio/scripts/media_qc\.py"\n'
    r'(?P=indent)for _p in \.claude \.cursor \.agents \.aider; do \[ -f "\$MEDIA_QC" \] \|\| '
    r'MEDIA_QC="\$_p/skills/media-studio/scripts/media_qc\.py"; done\n'
    r'(?P=indent)\[ -f "\$MEDIA_QC" \] \|\| MEDIA_QC="\$HOME/\.gemini/config/skills/media-studio/scripts/media_qc\.py"\n'
    r'(?P=indent)\[ -f "\$MEDIA_QC" \] \|\| MEDIA_QC="/usr/share/antigravity-harness/skills/media-studio/scripts/media_qc\.py"',
    re.MULTILINE,
)

_SKILL_OR_TEMPLATE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./~$-])"
    r"(?P<prefix>~/\.gemini/config/|\$HOME/\.gemini/config/)?"
    r"(?P<kind>skills|templates)/"
    r"(?P<rest>[A-Za-z0-9_./{}-]+)"
)


def _strip_trailing_sentence_punct(path_str: str) -> Tuple[str, str]:
    trailing = ""
    while path_str and path_str[-1] in ".,;:":
        trailing = path_str[-1] + trailing
        path_str = path_str[:-1]
    return path_str, trailing


def _concept_name_for_external_path(kind: str, rest: str) -> str:
    """Converts a non-bundled core or cross-plugin skill/template path into a clean path-free name."""
    clean = rest.rstrip("/")
    if kind == "templates":
        stem = clean
        if stem.endswith(".SKILL.template.md"):
            stem = stem[: -len(".SKILL.template.md")]
        elif stem.endswith(".template.md"):
            stem = stem[: -len(".template.md")]
        elif stem.endswith(".md"):
            stem = stem[: -len(".md")]
        return stem
    parts = clean.split("/")
    slug = parts[0]
    if len(parts) == 1 or parts[1] == "SKILL.md":
        return slug
    if len(parts) >= 3 and parts[1] == "references" and parts[-1].endswith(".md"):
        ref_stem = parts[-1][:-3]
        if slug == "harness":
            return ref_stem
        return f"{slug} ({ref_stem})"
    return slug


def _rewrite_antislop_agy_guard(text: str, plugin_rel_path: str) -> str:
    ui_rel = _rel_within_plugin(plugin_rel_path, "skills/antislop/scripts/check_ui_slop.py")
    synth_rel = _rel_within_plugin(plugin_rel_path, "skills/antislop/scripts/check_synthetic_markers.py")
    contrast_rel = _rel_within_plugin(plugin_rel_path, "skills/antislop/scripts/contrast-check.py")

    # 1. Fenced bash fallback blocks in antislop/SKILL.md and references/copywriting.md
    text = re.sub(
        r"^agy-guard ui-slop ([^\n]+)$",
        rf"python3 {ui_rel} \1",
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r"^# Canonical installed fallback \(when agy-guard is not on PATH\):\n"
        r"python3 ~/\.gemini/config/skills/antislop/scripts/check_ui_slop\.py ([^\n]+)$",
        r"# Optional (when agy-guard is installed): agy-guard ui-slop \1",
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r"^agy-guard synthetic-markers ([^\n]+)$",
        rf"python3 {synth_rel} \1",
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r"^# Canonical installed fallback \(when agy-guard is not on PATH\):\n"
        r"python3 ~/\.gemini/config/skills/antislop/scripts/check_synthetic_markers\.py ([^\n]+)$",
        r"# Optional (when agy-guard is installed): agy-guard synthetic-markers \1",
        text,
        flags=re.MULTILINE,
    )

    # 2. Inline dual invocations (`agy-guard ...` or `python3 ~/.gemini/config/skills/antislop/scripts/...`)
    text = re.sub(
        r"`agy-guard synthetic-markers`\s+or\s+`python3 ~/\.gemini/config/skills/antislop/scripts/check_synthetic_markers\.py`",
        f"`python3 {synth_rel}` (or optional `agy-guard synthetic-markers`)",
        text,
    )
    text = re.sub(
        r"\(`agy-guard ui-slop`\s+or\s+`python3 ~/\.gemini/config/skills/antislop/scripts/check_ui_slop\.py`\)",
        f"(`python3 {ui_rel}`, or optional `agy-guard ui-slop`)",
        text,
    )
    text = re.sub(
        r"`agy-guard ui-slop`\s*\(or\s+`python3 ~/\.gemini/config/skills/antislop/scripts/check_ui_slop\.py`\)",
        f"`python3 {ui_rel}` (or optional `agy-guard ui-slop`)",
        text,
    )
    text = re.sub(
        r"`agy-guard ui-slop ([^`]+)`\s*\(or\s+`python3 ~/\.gemini/config/skills/antislop/scripts/check_ui_slop\.py \1`\)",
        rf"`python3 {ui_rel} \1` (or optional `agy-guard ui-slop`)",
        text,
    )
    text = re.sub(
        r"`agy-guard ui-slop ([^`]+)`\s*\(([^;)]+);\s*fallback\s+`python3 ~/\.gemini/config/skills/antislop/scripts/check_ui_slop\.py`\)",
        rf"`python3 {ui_rel} \1` (\2; optional `agy-guard ui-slop`)",
        text,
    )

    # 3. human-a11y.md repo-checkout duplicate contrast-check line
    text = re.sub(
        r"^# Or from the repository checkout:\npython3 skills/antislop/scripts/contrast-check\.py \"#FFFFFF\" \"#777777\"\n",
        "",
        text,
        flags=re.MULTILINE,
    )
    text = text.replace(
        "alongside `references/human-a11y.md`",
        "alongside `human-a11y.md`",
    )

    # 4. DESIGN.md bare `scripts/meta_audit.py` reference
    text = text.replace(
        "The harness self-audit (`scripts/meta_audit.py`, Pass 6) recomputes every row",
        f"The bundled contrast self-test (`python3 {contrast_rel} --selftest`) recomputes every row",
    )

    # 5. silk-design/references/templates.md internal template path relative to templates.md
    if plugin_rel_path == "skills/antislop/references/silk-design/references/templates.md":
        text = text.replace(
            "`references/silk-design/templates/Reference<N>/theme.css`",
            "`../templates/Reference<N>/theme.css`",
        )
    if plugin_rel_path == "skills/antislop/SKILL.md":
        text = text.replace(
            "(`references/silk-design/assets/`, `references/silk-design/references/`, `references/silk-design/templates/`)",
            "(`./references/silk-design/assets/`, `./references/silk-design/references/`, `./references/silk-design/templates/`)",
        )
    return text


def _rewrite_rust_suite_agy_guard(text: str) -> str:
    text = text.replace(
        "mapping blast radius first via `agy-guard code-map callers <symbol>` and `agy-guard code-map blast-radius <symbol>`",
        "mapping blast radius first via `cargo check --workspace`, `rust-analyzer`, `rg`, or optional `agy-guard code-map`",
    )
    text = text.replace(
        "Map symbol dependencies via `agy-guard code-map profile <symbol>` / `blast-radius <symbol>`",
        "Map symbol dependencies via native tooling (`compile_commands.json`, `clangd`, `rust-analyzer`, `rg`, or optional `agy-guard code-map`)",
    )
    text = text.replace(
        "and the human operator seals a fresh `agy-guard test-boundary snapshot`.",
        "and record the approved test transition before retiring legacy tests (or seal a snapshot when optional `agy-guard` is installed).",
    )
    text = text.replace(
        "## 5. Static Analysis Limits: `~/.local/share/antigravity-harness/runtime/scripts/code_map.py` on C/C++",
        "## 5. Static Analysis Limits: Lightweight Regex/AST Call-Graph Tools on C/C++",
    )
    text = text.replace(
        "Treat `agy-guard code-map` (`~/.local/share/antigravity-harness/runtime/scripts/code_map.py`) output on C and C++ sources",
        "Treat lightweight static call-graph output (such as optional `agy-guard code-map` / `code_map.py`) on C and C++ sources",
    )
    return text


def _rewrite_game_engineering_agy_guard(text: str) -> str:
    text = re.sub(
        r"^(?P<indent>[ \t]*)agy-guard ui-slop <paths> --mode game\n"
        r"(?P=indent)# Or from installed global config:\n"
        r"(?P=indent)python3 ~/\.gemini/config/skills/antislop/scripts/check_ui_slop\.py <paths> --mode game",
        r"\g<indent># When the optional antislop plugin is installed:\n"
        r"\g<indent>python3 <path/to/antislop/scripts/check_ui_slop.py> <paths> --mode game\n"
        r"\g<indent># Optional (when agy-guard is installed): agy-guard ui-slop <paths> --mode game",
        text,
        flags=re.MULTILINE,
    )
    return text


def _rewrite_media_studio_paths(text: str, plugin_rel_path: str) -> str:
    rel_media_qc = _rel_within_plugin(plugin_rel_path, "skills/media-studio/scripts/media_qc.py")

    def _replace_block(m: re.Match[str]) -> str:
        ind = m.group("indent")
        return (
            f'{ind}MEDIA_QC="{rel_media_qc}"\n'
            f'{ind}for _p in . .claude .cursor .agents .aider; do [ -f "$MEDIA_QC" ] || '
            f'MEDIA_QC="$_p/skills/media-studio/scripts/media_qc.py"; done\n'
            f'{ind}[ -f "$MEDIA_QC" ] || MEDIA_QC="$HOME/.gemini/config/plugins/media-studio/skills/media-studio/scripts/media_qc.py"\n'
            f'{ind}[ -f "$MEDIA_QC" ] || MEDIA_QC="/usr/share/antigravity-harness/skills/media-studio/scripts/media_qc.py"'
        )

    text = _MEDIA_QC_BLOCK_RE.sub(_replace_block, text)
    text = text.replace(
        "$HOME/.gemini/config/skills/media-studio/scripts/media_qc.py",
        "$HOME/.gemini/config/plugins/media-studio/skills/media-studio/scripts/media_qc.py",
    )
    text = text.replace(
        "installed global `~/.gemini/config/skills/media-studio/scripts/media_qc.py`",
        f"plugin-local `{rel_media_qc}` or installed plugin `$HOME/.gemini/config/plugins/media-studio/skills/media-studio/scripts/media_qc.py`",
    )
    return text


def _inject_antislop_bundle_note(text: str) -> str:
    if _ANTISLOP_BUNDLE_NOTE_MARKER in text:
        return text
    lines = text.split("\n")
    in_fm = False
    for idx, line in enumerate(lines):
        if idx == 0 and line.strip() == "---":
            in_fm = True
            continue
        if in_fm:
            if line.strip() == "---":
                in_fm = False
            continue
        if line.startswith("# "):
            lines.insert(idx + 1, "")
            lines.insert(idx + 2, _ANTISLOP_BUNDLE_NOTE)
            return "\n".join(lines)
    return _ANTISLOP_BUNDLE_NOTE + "\n\n" + text


def rewrite_plugin_markdown(text: str, pack_name: str, plugin_rel_path: str) -> str:
    """Rewrites canonical skill/reference Markdown into a 100% standalone-clean plugin file."""
    if pack_name not in PLUGIN_CATALOG:
        raise ValueError(f"Unknown plugin pack: {pack_name!r}")
    spec = PLUGIN_CATALOG[pack_name]
    rel_norm = _validate_safe_rel_path(plugin_rel_path.replace("\\", "/"))
    out = _normalize_lf(text)

    if pack_name == "media-studio":
        out = _rewrite_media_studio_paths(out, rel_norm)
    elif pack_name == "antislop":
        out = _rewrite_antislop_agy_guard(out, rel_norm)
    elif pack_name == "rust-suite":
        out = _rewrite_rust_suite_agy_guard(out)
    elif pack_name == "game-engineering":
        out = _rewrite_game_engineering_agy_guard(out)

    extra_map: Dict[str, str] = {src: dst for src, dst in spec.extra_files}
    bundled_skills: FrozenSet[str] = frozenset(spec.skills)

    def _replace_path(match: re.Match[str]) -> str:
        kind = match.group("kind")
        raw_rest = match.group("rest")
        rest, trailing = _strip_trailing_sentence_punct(raw_rest)
        candidate = f"{kind}/{rest}"
        if candidate in extra_map:
            return _rel_within_plugin(rel_norm, extra_map[candidate]) + trailing
        if kind == "skills":
            slug = rest.split("/", 1)[0]
            if slug in bundled_skills:
                return _rel_within_plugin(rel_norm, candidate) + trailing
        return _concept_name_for_external_path(kind, rest) + trailing

    out = _SKILL_OR_TEMPLATE_PATH_RE.sub(_replace_path, out)

    # Collapse redundant self-parentheticals created by path-free rewrites (e.g. "`procoder` (`procoder`)").
    out = re.sub(r"`([a-z][a-z0-9-]*)`\s*\(`\1`\)", r"`\1`", out)
    out = re.sub(r"(/marathon)\s*\(`marathon`\)", r"\1", out)

    if pack_name == "antislop" and rel_norm == "skills/antislop/SKILL.md":
        out = _inject_antislop_bundle_note(out)

    return out


# ---------------------------------------------------------------------------
# Install-Time Core Hybrid Path Rewriter (D3)
# ---------------------------------------------------------------------------

_HYBRID_CORE_PLUGIN_SKILL_RE = re.compile(
    r"(?P<prefix>~/\.gemini/config/|\$HOME/\.gemini/config/|(?<![A-Za-z0-9_./~$-]))"
    r"skills/(?P<slug>" + "|".join(re.escape(s) for s in sorted(PLUGIN_SKILL_TO_PACK)) + r")/"
)
_HYBRID_CORE_PLUGIN_SKILL_DIR_RE = re.compile(
    r"(?P<prefix>~/\.gemini/config/|\$HOME/\.gemini/config/)"
    r"skills/(?P<slug>" + "|".join(re.escape(s) for s in sorted(PLUGIN_SKILL_TO_PACK)) + r")(?![A-Za-z0-9_/-])"
)


def rewrite_core_for_hybrid(text: str, rel_path: str) -> str:
    """Rewrites installed core Markdown paths pointing to the 6 plugin-owned skills into plugins/<pack>/..."""
    norm = rel_path.replace("\\", "/").lstrip("./")
    if norm in HYBRID_CORE_REWRITE_EXCLUDES or not norm.endswith(".md"):
        return text

    def _sub(match: re.Match[str]) -> str:
        prefix = match.group("prefix") or ""
        slug = match.group("slug")
        pack = PLUGIN_SKILL_TO_PACK[slug]
        return f"{prefix}plugins/{pack}/skills/{slug}/"

    def _sub_dir(match: re.Match[str]) -> str:
        prefix = match.group("prefix") or ""
        slug = match.group("slug")
        pack = PLUGIN_SKILL_TO_PACK[slug]
        return f"{prefix}plugins/{pack}/skills/{slug}"

    out = _HYBRID_CORE_PLUGIN_SKILL_RE.sub(_sub, text)
    return _HYBRID_CORE_PLUGIN_SKILL_DIR_RE.sub(_sub_dir, out)


# ---------------------------------------------------------------------------
# Plugin Pack Builder & Deterministic Cross-OS Archiver (AC-1)
# ---------------------------------------------------------------------------


def render_plugin_readme(spec: PluginSpec, version: str) -> str:
    """Generates a concise, factual per-plugin README.md with zero dead paths."""
    lines: List[str] = [
        f"# {spec.display_name}",
        "",
        spec.description,
        "",
        "## Included components",
        "",
    ]
    for skill_slug in spec.skills:
        lines.append(f"- Skill `{skill_slug}`: [./skills/{skill_slug}/SKILL.md](./skills/{skill_slug}/SKILL.md)")
    for _src_rel, dst_rel in spec.extra_files:
        lines.append(f"- Bundled asset: [./{dst_rel}](./{dst_rel})")
    if spec.mcp_server_name and spec.mcp_script_rel:
        runtime_mcp_name = f"{spec.name}_{spec.mcp_server_name}"
        lines.append(
            f"- MCP server `{spec.mcp_server_name}` (exposed by Antigravity as `{runtime_mcp_name}`): "
            f"[mcp_config.json](./mcp_config.json) (stdio entry `./{spec.mcp_script_rel}`)"
        )
    lines.extend([
        "",
        "## Standalone installation",
        "",
        f"1. Extract `{spec.name}-v{version}.zip` into your Antigravity `plugins/` directory "
        f"(user global `plugins/` or project `.agents/plugins/`) so the manifest sits at "
        f"`plugins/{spec.name}/plugin.json`.",
        "2. Open Antigravity Customizations to verify the plugin appears and toggle it on or off at any time.",
    ])
    if spec.mcp_server_name or spec.name in ("antislop", "media-studio"):
        lines.append(
            "3. Bundled scripts and stdio MCP servers require Python `3.10+` on `PATH` "
            "(on Windows, ensure `python3` or a local `python` executable is configured in `mcp_config.json`)."
        )
    if spec.name == "media-studio":
        lines.append("4. Media probing, salvage, and mastering require `ffmpeg` and `ffprobe` on `PATH`.")
    license_clause = (
        f"Licensed under the MIT License (see [LICENSE](./LICENSE) and "
        f"[THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)). "
        f"Built from [antigravity-harness]({PLUGIN_HOMEPAGE}) (`v{version}`)."
        if spec.third_party_upstreams
        else f"Licensed under the MIT License (see [LICENSE](./LICENSE)). "
        f"Built from [antigravity-harness]({PLUGIN_HOMEPAGE}) (`v{version}`)."
    )
    lines.extend([
        "",
        "## License and source",
        "",
        license_clause,
        "",
    ])
    return "\n".join(lines)


def _resolve_repo_legal_file(repo_root: Path, filename: str) -> Path:
    """Resolves root LICENSE or THIRD_PARTY_NOTICES.md from repo_root (with Linux FHS licenses fallback)."""
    candidates = [repo_root / filename]
    if repo_root == Path("/usr/share/antigravity-harness"):
        candidates.append(Path("/usr/share/licenses/antigravity-guard") / filename)
    for cand in candidates:
        if os.path.islink(cand):
            raise FileNotFoundError(f"Refusing symlinked legal notice file: {cand}")
        if cand.is_file():
            return cand
    raise FileNotFoundError(f"Required legal file '{filename}' missing under {repo_root}")


def render_plugin_third_party_notices(spec: PluginSpec, root_notices_text: str) -> str:
    """Extracts pack-scoped third-party MIT attribution rows and license blocks from root THIRD_PARTY_NOTICES.md."""
    if not spec.third_party_upstreams:
        return ""
    norm_text = _normalize_lf(root_notices_text)
    lines = norm_text.split("\n")

    matched_rows: List[str] = []
    for upstream in spec.third_party_upstreams:
        row_prefix = f"| [{upstream}]("
        found_row = next((ln for ln in lines if ln.startswith(row_prefix)), None)
        if found_row is None:
            raise ValueError(f"Root THIRD_PARTY_NOTICES.md missing attribution table row for {upstream!r}")
        matched_rows.append(rewrite_plugin_markdown(found_row, spec.name, "THIRD_PARTY_NOTICES.md"))

    sections_by_upstream: Dict[str, str] = {}
    idx = 0
    while idx < len(lines):
        ln = lines[idx]
        if ln.startswith("## "):
            end = idx + 1
            while end < len(lines) and not lines[end].startswith("## "):
                end += 1
            heading_body = ln[3:].strip()
            for upstream in spec.third_party_upstreams:
                if heading_body == upstream or heading_body.startswith(f"{upstream} "):
                    sections_by_upstream[upstream] = "\n".join(lines[idx:end]).strip()
            idx = end
        else:
            idx += 1

    matched_sections: List[str] = []
    for upstream in spec.third_party_upstreams:
        sec = sections_by_upstream.get(upstream)
        if not sec:
            raise ValueError(f"Root THIRD_PARTY_NOTICES.md missing license section for {upstream!r}")
        if "MIT License" not in sec or "Copyright" not in sec:
            raise ValueError(f"Third-party section for {upstream!r} is missing MIT License or Copyright notice")
        matched_sections.append(sec)

    out_lines: List[str] = [
        "# Third-Party Notices",
        "",
        f"{spec.display_name} is MIT-licensed (see [LICENSE](./LICENSE)). Portions of the bundled skills are",
        "adapted from the third-party open-source projects listed below. Their original copyright and",
        "license notices are reproduced as required. Adapted files may have been modified for this plugin.",
        "",
        "| Upstream | License | Adapted components in this plugin |",
        "|---|---|---|",
        *matched_rows,
        "",
        "\n\n".join(matched_sections),
        "",
    ]
    return "\n".join(out_lines)


def _copy_safe_tree_into_plugin(
    src_root: Path,
    stage_dir: Path,
    dst_prefix: str,
    pack_name: str,
) -> None:
    if os.path.islink(src_root) or not src_root.is_dir():
        raise ValueError(f"Plugin skill source must be a real directory (not symlink): {src_root}")
    for dirpath, dirnames, filenames in os.walk(src_root, followlinks=False):
        cur_dir = Path(dirpath)
        kept_dirs: List[str] = []
        for dname in sorted(dirnames):
            if dname in _EXCLUDED_DIR_NAMES:
                continue
            cand_dir = cur_dir / dname
            if os.path.islink(cand_dir):
                raise ValueError(f"Symlink directory forbidden in plugin source: {cand_dir}")
            kept_dirs.append(dname)
        dirnames[:] = kept_dirs

        for fname in sorted(filenames):
            if fname in _EXCLUDED_FILE_NAMES or fname.endswith(_EXCLUDED_FILE_SUFFIXES):
                continue
            src_file = cur_dir / fname
            if os.path.islink(src_file) or not src_file.is_file():
                raise ValueError(f"Symlink or non-regular file forbidden in plugin source: {src_file}")
            rel_inside = src_file.relative_to(src_root).as_posix()
            plugin_rel = _validate_safe_rel_path(f"{dst_prefix}/{rel_inside}")
            dst_file = stage_dir / plugin_rel
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            if src_file.suffix.lower() == ".md":
                rewritten = rewrite_plugin_markdown(src_file.read_text(encoding="utf-8"), pack_name, plugin_rel)
                dst_file.write_bytes(rewritten.encode("utf-8"))
            elif src_file.suffix.lower() in _TEXT_LF_SUFFIXES:
                norm_text = _normalize_lf(src_file.read_text(encoding="utf-8"))
                dst_file.write_bytes(norm_text.encode("utf-8"))
            else:
                shutil.copyfile(src_file, dst_file)


def build_plugin_pack(
    pack_name: str,
    repo_root: Path,
    dest_dir: Path,
    *,
    version: Optional[str] = None,
    python_executable: Optional[str] = None,
    portable_mcp: bool = True,
) -> Path:
    """Atomically builds one standalone-clean plugin pack directory from canonical monorepo sources."""
    if pack_name not in PLUGIN_CATALOG:
        raise ValueError(f"Unknown plugin pack: {pack_name!r}")
    spec = PLUGIN_CATALOG[pack_name]
    repo_root = Path(repo_root).resolve()
    dest_dir = Path(dest_dir)
    if os.path.islink(dest_dir):
        raise ValueError(f"Refusing to build plugin pack into symlink target: {dest_dir}")
    if dest_dir.exists() and not dest_dir.is_dir():
        raise ValueError(f"Refusing to overwrite non-directory target: {dest_dir}")

    resolved_version = version or HARNESS_VERSION
    dest_dir.parent.mkdir(parents=True, exist_ok=True)
    stage_dir = Path(tempfile.mkdtemp(prefix=f".{pack_name}-stage-", dir=str(dest_dir.parent)))
    backup_dir: Optional[Path] = None
    try:
        # 1. plugin.json (strict v1/plugin.json)
        manifest = {
            "name": spec.name,
            "displayName": spec.display_name,
            "version": resolved_version,
            "description": spec.description,
            "logo": "assets/logo.svg",
            "suggestedPrompts": list(spec.suggested_prompts),
            "author": dict(PLUGIN_AUTHOR),
            "homepage": PLUGIN_HOMEPAGE,
            "repository": PLUGIN_REPOSITORY,
            "license": PLUGIN_LICENSE,
        }
        (stage_dir / "plugin.json").write_bytes((json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))

        # 2. SVG Logo
        assets_dir = _plugin_assets_dir(repo_root)
        src_logo = assets_dir / spec.logo_asset
        if os.path.islink(src_logo) or not src_logo.is_file():
            raise FileNotFoundError(f"Plugin SVG logo missing or symlink: {src_logo}")
        dst_logo = stage_dir / "assets" / "logo.svg"
        dst_logo.parent.mkdir(parents=True, exist_ok=True)
        dst_logo.write_bytes(_normalize_lf(src_logo.read_text(encoding="utf-8")).encode("utf-8"))

        # 3. Skills trees
        for skill_slug in spec.skills:
            src_skill = repo_root / "skills" / skill_slug
            _copy_safe_tree_into_plugin(src_skill, stage_dir, f"skills/{skill_slug}", pack_name)

        # 4. Extra bundled files
        for src_rel, dst_rel in spec.extra_files:
            safe_src = _validate_safe_rel_path(src_rel)
            safe_dst = _validate_safe_rel_path(dst_rel)
            src_path = repo_root / safe_src
            if os.path.islink(src_path) or not src_path.is_file():
                raise FileNotFoundError(f"Plugin extra asset missing or symlink: {src_path}")
            dst_path = stage_dir / safe_dst
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            if src_path.suffix.lower() == ".md":
                rewritten = rewrite_plugin_markdown(src_path.read_text(encoding="utf-8"), pack_name, safe_dst)
                dst_path.write_bytes(rewritten.encode("utf-8"))
            else:
                shutil.copyfile(src_path, dst_path)

        # 5. Optional mcp_config.json
        if spec.mcp_server_name and spec.mcp_script_rel:
            safe_mcp_rel = _validate_safe_rel_path(spec.mcp_script_rel)
            if not (stage_dir / safe_mcp_rel).is_file():
                raise FileNotFoundError(f"Bundled MCP script missing in staged plugin: {safe_mcp_rel}")
            if portable_mcp and python_executable is None:
                mcp_cmd = "python3"
            else:
                mcp_cmd = resolve_local_python_command(python_executable)
            mcp_payload = {
                "mcpServers": {
                    spec.mcp_server_name: {
                        "command": mcp_cmd,
                        "args": [f"${{PLUGIN_ROOT}}/{safe_mcp_rel}"],
                    }
                }
            }
            (stage_dir / "mcp_config.json").write_bytes(
                (json.dumps(mcp_payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
            )

        # 6. LICENSE & pack-scoped THIRD_PARTY_NOTICES.md
        src_license = _resolve_repo_legal_file(repo_root, "LICENSE")
        (stage_dir / "LICENSE").write_bytes(_normalize_lf(src_license.read_text(encoding="utf-8")).encode("utf-8"))
        if spec.third_party_upstreams:
            src_notices = _resolve_repo_legal_file(repo_root, "THIRD_PARTY_NOTICES.md")
            pack_notices = render_plugin_third_party_notices(spec, src_notices.read_text(encoding="utf-8"))
            (stage_dir / "THIRD_PARTY_NOTICES.md").write_bytes(pack_notices.encode("utf-8"))

        # 7. Generated README.md
        (stage_dir / "README.md").write_bytes(render_plugin_readme(spec, resolved_version).encode("utf-8"))

        if os.name != "nt":
            os.chmod(stage_dir, 0o755)
            for root_p, dirs, files in os.walk(stage_dir, followlinks=False):
                for d in dirs:
                    os.chmod(Path(root_p) / d, 0o755)
                for f in files:
                    fp = Path(root_p) / f
                    rel_f = fp.relative_to(stage_dir).as_posix()
                    os.chmod(fp, 0o755 if _is_plugin_script_path(rel_f) else 0o644)

        # 7. Atomic swap into dest_dir
        if dest_dir.exists():
            backup_dir = dest_dir.parent / f".{dest_dir.name}-old-{os.getpid()}-{id(stage_dir)}"
            os.replace(dest_dir, backup_dir)
            try:
                os.replace(stage_dir, dest_dir)
            except OSError as swap_exc:
                try:
                    os.replace(backup_dir, dest_dir)
                    backup_dir = None
                except OSError as rb_exc:
                    print(
                        f"[WARN] Failed rolling back plugin pack swap for {dest_dir} from {backup_dir}: {rb_exc}",
                        file=sys.stderr,
                    )
                raise swap_exc
            try:
                shutil.rmtree(backup_dir)
            except OSError as clean_exc:
                print(
                    f"[WARN] Failed removing replaced plugin backup directory {backup_dir}: {clean_exc}",
                    file=sys.stderr,
                )
            backup_dir = None
        else:
            os.replace(stage_dir, dest_dir)
        return dest_dir
    except Exception:
        if stage_dir.exists():
            try:
                shutil.rmtree(stage_dir)
            except OSError as clean_exc:
                print(f"[WARN] Failed cleaning staged plugin directory {stage_dir}: {clean_exc}", file=sys.stderr)
        if backup_dir is not None and backup_dir.exists() and not dest_dir.exists():
            try:
                os.replace(backup_dir, dest_dir)
            except OSError as rb_exc:
                print(
                    f"[WARN] Failed restoring plugin pack backup {backup_dir} -> {dest_dir}: {rb_exc}",
                    file=sys.stderr,
                )
        raise


def _resolve_zip_date_time(source_date_epoch: Optional[int] = None) -> Tuple[int, int, int, int, int, int]:
    epoch = source_date_epoch
    if epoch is None:
        raw_env = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
        if raw_env:
            try:
                epoch = int(raw_env)
            except ValueError as exc:
                raise ValueError(f"Invalid SOURCE_DATE_EPOCH value: {raw_env!r}") from exc
        else:
            epoch = PLUGIN_DEFAULT_SOURCE_DATE_EPOCH
    dt = datetime.fromtimestamp(max(epoch, 315532800), tz=timezone.utc)
    return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)


def archive_plugin_pack(
    plugin_dir: Path,
    zip_path: Path,
    *,
    source_date_epoch: Optional[int] = None,
) -> Tuple[Path, Path]:
    """Creates a bit-deterministic cross-OS .zip archive and 2-space .sha256 sidecar."""
    plugin_dir = Path(plugin_dir)
    zip_path = Path(zip_path)
    if os.path.islink(plugin_dir) or not plugin_dir.is_dir():
        raise ValueError(f"Plugin directory does not exist or is a symlink: {plugin_dir}")

    date_time = _resolve_zip_date_time(source_date_epoch)
    top_name = _validate_safe_rel_path(plugin_dir.name)
    entries: List[Tuple[str, Path]] = []

    for dirpath, dirnames, filenames in os.walk(plugin_dir, followlinks=False):
        cur = Path(dirpath)
        dirnames[:] = sorted(dirnames)
        for d in dirnames:
            cand = cur / d
            if os.path.islink(cand):
                raise ValueError(f"Refusing to archive symlink directory: {cand}")
            if d in _EXCLUDED_DIR_NAMES:
                raise ValueError(f"Forbidden directory present in plugin pack: {cand}")
        for f in sorted(filenames):
            fp = cur / f
            if os.path.islink(fp) or not fp.is_file():
                raise ValueError(f"Refusing to archive symlink or non-regular file: {fp}")
            if f in _EXCLUDED_FILE_NAMES or f.endswith(_EXCLUDED_FILE_SUFFIXES):
                raise ValueError(f"Forbidden file present in plugin pack: {fp}")
            rel = _validate_safe_rel_path(fp.relative_to(plugin_dir).as_posix())
            entries.append((rel, fp))

    entries.sort(key=lambda item: item[0])
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{zip_path.name}.", suffix=".tmp", dir=str(zip_path.parent))
    os.close(fd)
    tmp_zip = Path(tmp_name)
    try:
        with zipfile.ZipFile(tmp_zip, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for rel, fp in entries:
                arcname = f"{top_name}/{rel}"
                info = zipfile.ZipInfo(filename=arcname, date_time=date_time)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3  # Unix (portable across Linux, macOS, Windows)
                is_exec = _is_plugin_script_path(rel)
                info.external_attr = (0o100755 if is_exec else 0o100644) << 16
                raw_bytes = fp.read_bytes()
                if fp.suffix.lower() in _TEXT_LF_SUFFIXES or fp.name == "LICENSE":
                    raw_bytes = raw_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                zf.writestr(info, raw_bytes, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        if os.name != "nt":
            os.chmod(tmp_zip, 0o644)
        hasher = hashlib.sha256()
        with open(tmp_zip, "rb") as zfh:
            while True:
                chunk = zfh.read(65536)
                if not chunk:
                    break
                hasher.update(chunk)
        digest = hasher.hexdigest()
        sha_path = zip_path.with_name(f"{zip_path.name}.sha256")
        sha_fd, sha_tmp_name = tempfile.mkstemp(prefix=f".{sha_path.name}.", suffix=".tmp", dir=str(sha_path.parent))
        os.close(sha_fd)
        sha_tmp = Path(sha_tmp_name)
        try:
            atomic_write_text(sha_tmp, f"{digest}  {zip_path.name}\n", mode=0o644)
            os.replace(tmp_zip, zip_path)
            os.replace(sha_tmp, sha_path)
        except Exception:
            if sha_tmp.exists():
                sha_tmp.unlink(missing_ok=True)
            raise
    except Exception:
        if tmp_zip.exists():
            tmp_zip.unlink(missing_ok=True)
        raise

    return zip_path, sha_path


# ---------------------------------------------------------------------------
# SVG Security, Geometry ([12, 116]) & WCAG Contrast (>= 3.0:1) Validator
# ---------------------------------------------------------------------------

_ALLOWED_SVG_TAGS: FrozenSet[str] = frozenset({
    "svg",
    "g",
    "path",
    "rect",
    "circle",
    "ellipse",
    "line",
    "polyline",
    "polygon",
    "title",
    "desc",
})
_HEX_COLOR_RE = re.compile(r"^#(?:[0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$")
_PATH_TOKEN_RE = re.compile(r"[MmZzLlHhVvCcSsQqTtAa]|[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")
_NUMBER_RE = re.compile(r"[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")
_SVG_PI_RE = re.compile(r"<\?(?!xml(?:\s|\?>))[^?]*\?>", re.IGNORECASE)
_SVG_EXTERNAL_URL_RE = re.compile(r"url\(\s*['\"]?(?:https?:|//|data:|javascript:|vbscript:)", re.IGNORECASE)
_REPO_REL_LEAK_RE = re.compile(
    r"(?<![A-Za-z0-9_./~$-])(?:skills|templates|agents|guard|porter)/[A-Za-z0-9_.-]+"
)


def _parse_hex_rgb(hex_color: str) -> Tuple[int, int, int]:
    h = hex_color.strip().lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    if not re.fullmatch(r"[0-9A-Fa-f]{6}", h):
        raise ValueError(f"Invalid hex color: {hex_color!r}")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _wcag_luminance(rgb: Tuple[int, int, int]) -> float:
    channels = []
    for ch in rgb:
        c = ch / 255.0
        channels.append(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def wcag_contrast_ratio(hex_a: str, hex_b: str) -> float:
    """Computes the exact WCAG 2.x contrast ratio between two hex colors."""
    la = _wcag_luminance(_parse_hex_rgb(hex_a))
    lb = _wcag_luminance(_parse_hex_rgb(hex_b))
    lighter, darker = (la, lb) if la >= lb else (lb, la)
    return (lighter + 0.05) / (darker + 0.05)


def _parse_svg_number(raw: Optional[str], default: float = 0.0) -> float:
    if raw is None:
        return default
    cleaned = raw.strip()
    if cleaned.endswith("px"):
        cleaned = cleaned[:-2].strip()
    val = float(cleaned)
    if not math.isfinite(val):
        raise ValueError(f"non-finite SVG number: {raw!r}")
    return val


def _extract_path_points(d_attr: str) -> List[Tuple[float, float]]:
    """Extracts conservative vertex and control-point coordinates from an SVG path `d` attribute."""
    if not d_attr or not d_attr.strip():
        raise ValueError("SVG path 'd' attribute must be non-empty")
    remainder = _PATH_TOKEN_RE.sub("", d_attr)
    if re.search(r"[^\s,]", remainder):
        raise ValueError(f"SVG path contains unexpected token(s): {remainder.strip()!r}")
    tokens = _PATH_TOKEN_RE.findall(d_attr)
    points: List[Tuple[float, float]] = []
    idx = 0
    cmd = ""
    cx, cy = 0.0, 0.0
    sx, sy = 0.0, 0.0

    def _next_float() -> float:
        nonlocal idx
        if idx >= len(tokens):
            raise ValueError(f"truncated SVG path command {cmd!r}: {d_attr!r}")
        val = float(tokens[idx])
        if not math.isfinite(val):
            raise ValueError(f"non-finite SVG path coordinate: {tokens[idx]!r}")
        idx += 1
        return val

    while idx < len(tokens):
        tok = tokens[idx]
        if tok.isalpha():
            cmd = tok
            idx += 1
            if cmd in ("Z", "z"):
                cx, cy = sx, sy
                continue
        if not cmd:
            raise ValueError(f"SVG path missing initial command: {d_attr!r}")

        if cmd in ("M", "m"):
            x, y = _next_float(), _next_float()
            if cmd == "m":
                x, y = cx + x, cy + y
            cx, cy = x, y
            sx, sy = x, y
            points.append((cx, cy))
            cmd = "L" if cmd == "M" else "l"
        elif cmd in ("L", "l", "T", "t"):
            x, y = _next_float(), _next_float()
            if cmd in ("l", "t"):
                x, y = cx + x, cy + y
            cx, cy = x, y
            points.append((cx, cy))
        elif cmd in ("H", "h"):
            x = _next_float()
            cx = cx + x if cmd == "h" else x
            points.append((cx, cy))
        elif cmd in ("V", "v"):
            y = _next_float()
            cy = cy + y if cmd == "v" else y
            points.append((cx, cy))
        elif cmd in ("C", "c"):
            x1, y1, x2, y2, x, y = (_next_float() for _ in range(6))
            if cmd == "c":
                x1, y1 = cx + x1, cy + y1
                x2, y2 = cx + x2, cy + y2
                x, y = cx + x, cy + y
            points.extend([(x1, y1), (x2, y2), (x, y)])
            cx, cy = x, y
        elif cmd in ("S", "s", "Q", "q"):
            x1, y1, x, y = (_next_float() for _ in range(4))
            if cmd in ("s", "q"):
                x1, y1 = cx + x1, cy + y1
                x, y = cx + x, cy + y
            points.extend([(x1, y1), (x, y)])
            cx, cy = x, y
        elif cmd in ("A", "a"):
            rx, ry, _rot, _large, _sweep, x, y = (_next_float() for _ in range(7))
            if cmd == "a":
                x, y = cx + x, cy + y
            points.extend([(cx, cy), (x, y), (min(cx, x) - abs(rx), min(cy, y) - abs(ry)), (max(cx, x) + abs(rx), max(cy, y) + abs(ry))])
            cx, cy = x, y
        else:
            raise ValueError(f"Unsupported SVG path command {cmd!r}")
    return points


def _local_tag(tag: str) -> str:
    return tag.split("}", 1)[-1].lower() if "}" in tag else tag.lower()


def validate_svg_logo(svg_path: Path) -> List[str]:
    """Validates an SVG logo for XML safety, <= 16 KiB size, [12, 116] bounds, and >= 3.0:1 dual-theme WCAG contrast."""
    errors: List[str] = []
    if os.path.islink(svg_path) or not svg_path.is_file():
        return [f"SVG logo missing or symlink: {svg_path}"]

    raw_bytes = svg_path.read_bytes()
    if len(raw_bytes) > MAX_SVG_LOGO_BYTES:
        errors.append(f"SVG logo exceeds {MAX_SVG_LOGO_BYTES} bytes: {len(raw_bytes)} bytes")

    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [f"SVG logo is not valid UTF-8: {exc}"]

    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", content, re.IGNORECASE):
        errors.append("Unsafe XML DOCTYPE/ENTITY declaration found in SVG logo")
        return errors
    if _SVG_PI_RE.search(content):
        errors.append("Unsafe XML processing instruction found in SVG logo")
        return errors

    try:
        root = ET.fromstring(content)
    except (ET.ParseError, RecursionError) as exc:
        errors.append(f"Malformed SVG XML: {exc}")
        return errors

    if _local_tag(root.tag) != "svg":
        errors.append(f"Invalid SVG root element <{_local_tag(root.tag)}>; expected <svg>")
        return errors

    viewbox = root.attrib.get("viewBox", "").strip()
    vb_rem = _NUMBER_RE.sub("", viewbox)
    vb_nums = [float(x) for x in _NUMBER_RE.findall(viewbox)]
    if re.search(r"[^\s,]", vb_rem) or len(vb_nums) != 4 or vb_nums != [0.0, 0.0, SVG_VIEWBOX_SIZE, SVG_VIEWBOX_SIZE]:
        errors.append(f'SVG viewBox must be "0 0 128 128" (got {viewbox!r})')

    for dim_attr in ("width", "height"):
        if dim_attr not in root.attrib:
            errors.append(f'SVG root element must declare explicit {dim_attr}="128"')
        else:
            try:
                if _parse_svg_number(root.attrib[dim_attr]) != SVG_VIEWBOX_SIZE:
                    errors.append(f"SVG {dim_attr} must be 128 (got {root.attrib[dim_attr]!r})")
            except ValueError:
                errors.append(f"SVG {dim_attr} is not numeric: {root.attrib[dim_attr]!r}")

    min_x, min_y = float("inf"), float("inf")
    max_x, max_y = float("-inf"), float("-inf")
    colors_found: List[str] = []
    shape_count = 0

    def _expand(x0: float, y0: float, x1: float, y1: float, pad: float) -> None:
        nonlocal min_x, min_y, max_x, max_y, shape_count
        shape_count += 1
        min_x = min(min_x, x0 - pad)
        min_y = min(min_y, y0 - pad)
        max_x = max(max_x, x1 + pad)
        max_y = max(max_y, y1 + pad)

    _FILLABLE_SVG_TAGS = frozenset({"rect", "circle", "ellipse", "polygon", "polyline", "path"})

    def _walk(elem: ET.Element, inh_fill: str, inh_stroke: str, inh_sw: float) -> None:
        tag = _local_tag(elem.tag)
        if tag not in _ALLOWED_SVG_TAGS:
            errors.append(f"Disallowed SVG element <{tag}> found in logo")
            return
        if "transform" in elem.attrib:
            errors.append(f"SVG transform attribute on <{tag}> is disallowed for deterministic bounds checking")

        for raw_attr, val in elem.attrib.items():
            attr = raw_attr.split("}", 1)[-1].lower()
            val_compact = re.sub(r"[\x00-\x20]+", "", val).lower()
            if attr == "style":
                errors.append(f"Inline style attribute on <{tag}> is disallowed in SVG logo")
            if attr.startswith("on"):
                errors.append(f"Unsafe SVG event handler attribute `{attr}` on <{tag}>")
            if attr == "href" and not val_compact.startswith("#"):
                errors.append(f"External or unsafe SVG href `{val}` on <{tag}>")
            if (
                "javascript:" in val_compact
                or "vbscript:" in val_compact
                or "data:" in val_compact
                or _SVG_EXTERNAL_URL_RE.search(val_compact)
            ):
                errors.append(f"Unsafe external/data URI in `{attr}` on <{tag}>")
            if attr in ("opacity", "fill-opacity", "stroke-opacity"):
                try:
                    op_val = _parse_svg_number(val)
                    if op_val < 1.0:
                        errors.append(f"Translucent {attr}={val!r} on <{tag}> breaks deterministic WCAG contrast")
                except ValueError:
                    errors.append(f"Invalid {attr}={val!r} on <{tag}>")

        cur_fill = elem.attrib.get("fill", inh_fill).strip()
        cur_stroke = elem.attrib.get("stroke", inh_stroke).strip()
        try:
            cur_sw = _parse_svg_number(elem.attrib.get("stroke-width"), inh_sw)
        except ValueError:
            errors.append(f"Invalid stroke-width {elem.attrib.get('stroke-width')!r} on <{tag}>")
            cur_sw = inh_sw
        if cur_sw < 0:
            errors.append(f"Negative stroke-width {cur_sw} on <{tag}>")

        for color_attr in ("fill", "stroke", "stop-color"):
            cval = elem.attrib.get(color_attr)
            if cval is None:
                continue
            cstrip = cval.strip()
            if cstrip.lower() in ("none", "transparent"):
                continue
            if not _HEX_COLOR_RE.fullmatch(cstrip):
                errors.append(f"Non-hex SVG color `{cstrip}` on <{tag} {color_attr}=...>; use explicit #RRGGBB hex")
            else:
                colors_found.append(cstrip.upper())

        if tag in _FILLABLE_SVG_TAGS and cur_fill.lower() not in ("", "none", "transparent"):
            if _HEX_COLOR_RE.fullmatch(cur_fill):
                colors_found.append(cur_fill.upper())

        pad = (cur_sw / 2.0) if cur_stroke.lower() not in ("", "none", "transparent") and cur_sw > 0 else 0.0

        try:
            if tag == "rect":
                x = _parse_svg_number(elem.attrib.get("x"), 0.0)
                y = _parse_svg_number(elem.attrib.get("y"), 0.0)
                w = _parse_svg_number(elem.attrib.get("width"), 0.0)
                h = _parse_svg_number(elem.attrib.get("height"), 0.0)
                if w < 0 or h < 0:
                    raise ValueError(f"negative rect dimensions ({w}, {h})")
                _expand(x, y, x + w, y + h, pad)
            elif tag == "circle":
                cx = _parse_svg_number(elem.attrib.get("cx"), 0.0)
                cy = _parse_svg_number(elem.attrib.get("cy"), 0.0)
                r = _parse_svg_number(elem.attrib.get("r"), 0.0)
                if r < 0:
                    raise ValueError(f"negative circle radius ({r})")
                _expand(cx - r, cy - r, cx + r, cy + r, pad)
            elif tag == "ellipse":
                cx = _parse_svg_number(elem.attrib.get("cx"), 0.0)
                cy = _parse_svg_number(elem.attrib.get("cy"), 0.0)
                rx = _parse_svg_number(elem.attrib.get("rx"), 0.0)
                ry = _parse_svg_number(elem.attrib.get("ry"), 0.0)
                if rx < 0 or ry < 0:
                    raise ValueError(f"negative ellipse radii ({rx}, {ry})")
                _expand(cx - rx, cy - ry, cx + rx, cy + ry, pad)
            elif tag == "line":
                x1 = _parse_svg_number(elem.attrib.get("x1"), 0.0)
                y1 = _parse_svg_number(elem.attrib.get("y1"), 0.0)
                x2 = _parse_svg_number(elem.attrib.get("x2"), 0.0)
                y2 = _parse_svg_number(elem.attrib.get("y2"), 0.0)
                _expand(min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2), pad)
            elif tag in ("polygon", "polyline"):
                pts_raw = elem.attrib.get("points", "")
                pts_rem = _NUMBER_RE.sub("", pts_raw)
                nums = [float(n) for n in _NUMBER_RE.findall(pts_raw)]
                if not re.search(r"[^\s,]", pts_rem) and len(nums) >= 2 and len(nums) % 2 == 0 and all(math.isfinite(n) for n in nums):
                    xs = nums[0::2]
                    ys = nums[1::2]
                    _expand(min(xs), min(ys), max(xs), max(ys), pad)
                else:
                    errors.append(f"Invalid points attribute on <{tag}>")
            elif tag == "path":
                pts = _extract_path_points(elem.attrib.get("d", ""))
                if pts:
                    xs = [p[0] for p in pts]
                    ys = [p[1] for p in pts]
                    _expand(min(xs), min(ys), max(xs), max(ys), pad)
                else:
                    errors.append("SVG <path> contains zero drawable coordinates")
        except (ValueError, IndexError) as exc:
            errors.append(f"Invalid geometry on <{tag}>: {exc}")

        for child in elem:
            _walk(child, cur_fill, cur_stroke, cur_sw)

    _walk(root, "#000000", "none", 1.0)

    if shape_count == 0:
        errors.append("SVG logo contains zero visible geometric primitives")
    else:
        if min_x < SVG_MIN_BOUND or min_y < SVG_MIN_BOUND or max_x > SVG_MAX_BOUND or max_y > SVG_MAX_BOUND:
            errors.append(
                f"SVG logo bounds ({min_x:.1f}, {min_y:.1f}, {max_x:.1f}, {max_y:.1f}) "
                f"exceed required safe box [{SVG_MIN_BOUND:.0f}, {SVG_MAX_BOUND:.0f}]"
            )

    if not colors_found:
        errors.append("SVG logo declares no explicit hex fill/stroke colors")
    else:
        for hx in sorted(set(colors_found)):
            light_ratio = wcag_contrast_ratio(hx, SVG_LIGHT_BG)
            dark_ratio = wcag_contrast_ratio(hx, SVG_DARK_BG)
            if light_ratio < SVG_MIN_CONTRAST:
                errors.append(f"SVG color {hx} fails contrast on {SVG_LIGHT_BG}: {light_ratio:.2f}:1 < {SVG_MIN_CONTRAST:.1f}:1")
            if dark_ratio < SVG_MIN_CONTRAST:
                errors.append(f"SVG color {hx} fails contrast on {SVG_DARK_BG}: {dark_ratio:.2f}:1 < {SVG_MIN_CONTRAST:.1f}:1")

    return errors


# ---------------------------------------------------------------------------
# Strict Offline Plugin Directory & Zip Validators (AC-1)
# ---------------------------------------------------------------------------

_KEBAB_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_LOGO_SUFFIXES = (".svg", ".png", ".jpg", ".jpeg", ".webp")
_MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
_BARE_SCRIPTS_RE = re.compile(r"(?<![A-Za-z0-9_./~$-])scripts/[A-Za-z0-9_./-]+")
_TILDE_CONFIG_RE = re.compile(r"~/\.gemini/config/")
_FLAT_HOME_SKILLS_RE = re.compile(r"\$HOME/\.gemini/config/skills/")
_RUNTIME_PATH_RE = re.compile(r"~/\.local/share/antigravity-harness/")
_INLINE_AGY_GUARD_RE = re.compile(r"`agy-guard\b[^`]*`")
_OPTIONAL_QUALIFIER_RE = re.compile(r"(?i)\b(?:optional|when\s+[^\n`]*installed|if\s+available)\b")
_BACKTICK_REL_PATH_RE = re.compile(r"`(\.\.?/[A-Za-z0-9_./-]+\.(?:md|py|sh|css|json|svg))`")


def _has_banned_brand_prefix(value: str) -> bool:
    low = value.strip().lower()
    return any(low.startswith(prefix) for prefix in BANNED_BRAND_PREFIXES)


def _validate_manifest_dict(
    data: Any,
    plugin_dir: Path,
    expected_pack: Optional[str],
    errors: List[str],
) -> str:
    if not isinstance(data, dict):
        errors.append("plugin.json root must be a JSON object")
        return expected_pack or plugin_dir.name

    extra_keys = sorted(set(data.keys()) - ALLOWED_PLUGIN_MANIFEST_KEYS)
    if extra_keys:
        errors.append(f"plugin.json contains disallowed additionalProperties: {', '.join(extra_keys)}")

    if "$schema" in data and data["$schema"] != PLUGIN_SCHEMA_URL:
        errors.append(f"plugin.json $schema must equal {PLUGIN_SCHEMA_URL!r}")

    name = data.get("name")
    if not isinstance(name, str) or not _KEBAB_NAME_RE.fullmatch(name):
        errors.append(f"plugin.json 'name' must be lowercase kebab-case (got {name!r})")
        resolved_name = expected_pack or plugin_dir.name
    else:
        resolved_name = name
        if _has_banned_brand_prefix(name):
            errors.append(f"plugin.json 'name' uses a banned brand prefix: {name!r}")
        if expected_pack is not None and name != expected_pack:
            errors.append(f"plugin.json 'name' ({name!r}) does not match expected pack ({expected_pack!r})")

    display_name = data.get("displayName")
    if display_name is not None:
        if not isinstance(display_name, str) or not display_name.strip() or len(display_name) > 64:
            errors.append(f"plugin.json 'displayName' must be a non-empty string <= 64 chars (got {display_name!r})")
        elif _has_banned_brand_prefix(display_name):
            errors.append(f"plugin.json 'displayName' uses a banned brand prefix: {display_name!r}")
    elif resolved_name in PLUGIN_CATALOG:
        errors.append("plugin.json 'displayName' is required for harness plugin packs")

    description = data.get("description")
    if not isinstance(description, str) or not (10 <= len(description.strip()) <= 500):
        errors.append("plugin.json 'description' must be a string between 10 and 500 characters")

    version = data.get("version")
    if version is not None and (not isinstance(version, str) or not _SEMVER_RE.fullmatch(version)):
        errors.append(f"plugin.json 'version' must be valid SemVer (got {version!r})")

    logo = data.get("logo")
    if not isinstance(logo, str) or not logo.strip():
        errors.append("plugin.json 'logo' is required")
    else:
        safe_logo: Optional[str] = None
        if logo.startswith(("http://", "https://")):
            errors.append(f"plugin.json 'logo' must be a safe plugin-relative path (got {logo!r})")
        else:
            try:
                safe_logo = _validate_safe_rel_path(logo)
            except ValueError:
                errors.append(f"plugin.json 'logo' must be a safe plugin-relative path (got {logo!r})")
        if safe_logo is not None:
            if not safe_logo.lower().endswith(_LOGO_SUFFIXES):
                errors.append(f"plugin.json 'logo' has unsupported extension: {logo!r}")
            else:
                logo_path = plugin_dir / safe_logo
                has_sym_anc = False
                cur_chk = plugin_dir
                for seg in PurePosixPath(safe_logo).parts:
                    cur_chk = cur_chk / seg
                    if os.path.islink(cur_chk):
                        has_sym_anc = True
                        break
                try:
                    logo_res = logo_path.resolve()
                    logo_res.relative_to(plugin_dir.resolve())
                    inside_root = True
                except (OSError, RuntimeError, ValueError):
                    inside_root = False
                if has_sym_anc or not inside_root or not logo_path.is_file():
                    errors.append(f"plugin.json 'logo' file missing, symlink, or outside plugin root: {logo}")
                elif safe_logo.lower().endswith(".svg"):
                    errors.extend(validate_svg_logo(logo_path))

    prompts = data.get("suggestedPrompts")
    if prompts is not None:
        if (
            not isinstance(prompts, list)
            or not (1 <= len(prompts) <= 3)
            or any(not isinstance(p, str) or not p.strip() for p in prompts)
        ):
            errors.append("plugin.json 'suggestedPrompts' must be a list of 1..3 non-empty strings")
        elif resolved_name in PLUGIN_CATALOG and len(prompts) != 3:
            errors.append(f"Harness plugin pack '{resolved_name}' must declare exactly 3 suggestedPrompts")
    elif resolved_name in PLUGIN_CATALOG:
        errors.append("plugin.json 'suggestedPrompts' is required for harness plugin packs")

    if "author" in data:
        author = data["author"]
        if isinstance(author, str):
            if not author.strip():
                errors.append("plugin.json 'author' string must be non-empty")
        elif isinstance(author, dict):
            bad_author_keys = set(author.keys()) - {"name", "email", "url"}
            if bad_author_keys or not isinstance(author.get("name"), str) or not author["name"].strip():
                errors.append(f"plugin.json 'author' object invalid: {author!r}")
            if "email" in author and (not isinstance(author["email"], str) or not author["email"].strip()):
                errors.append(f"plugin.json 'author.email' must be a non-empty string: {author.get('email')!r}")
            if "url" in author and (not isinstance(author["url"], str) or not author["url"].startswith("https://")):
                errors.append(f"plugin.json 'author.url' must be an https:// URL: {author.get('url')!r}")
        else:
            errors.append("plugin.json 'author' must be a string or object")

    if "homepage" in data:
        hp = data["homepage"]
        if not isinstance(hp, str) or not hp.startswith("https://"):
            errors.append(f"plugin.json 'homepage' must be an https:// URL (got {hp!r})")

    if "repository" in data:
        repo = data["repository"]
        if not isinstance(repo, str) or not repo.startswith("https://"):
            errors.append(f"plugin.json 'repository' must be an https:// URL string (got {repo!r})")

    if "license" in data:
        lic = data["license"]
        if not isinstance(lic, str) or not lic.strip():
            errors.append(f"plugin.json 'license' must be a non-empty string (got {lic!r})")
        elif resolved_name in PLUGIN_CATALOG and lic != PLUGIN_LICENSE:
            errors.append(
                f"Harness plugin pack '{resolved_name}' must declare license {PLUGIN_LICENSE!r} (got {lic!r})"
            )
    elif resolved_name in PLUGIN_CATALOG:
        errors.append("plugin.json 'license' is required for harness plugin packs")

    if "keywords" in data:
        kws = data["keywords"]
        if not isinstance(kws, list) or any(not isinstance(k, str) or not k.strip() for k in kws):
            errors.append("plugin.json 'keywords' must be a list of non-empty strings")

    if "skills" in data:
        sk = data["skills"]
        if isinstance(sk, str):
            if not sk.strip():
                errors.append("plugin.json 'skills' string must be non-empty")
        elif isinstance(sk, list):
            if any(not isinstance(item, str) or not item.strip() for item in sk):
                errors.append("plugin.json 'skills' array items must be non-empty strings")
        else:
            errors.append("plugin.json 'skills' must be a string or list of strings")

    if "extensions" in data:
        ext = data["extensions"]
        if not isinstance(ext, dict) or any(
            not isinstance(k, str) or not k.strip() or not isinstance(v, dict) for k, v in ext.items()
        ):
            errors.append("plugin.json 'extensions' must be an object mapping namespaces to objects")

    if "disabled" in data and not isinstance(data["disabled"], bool):
        errors.append("plugin.json 'disabled' must be a boolean")

    return resolved_name


def _validate_markdown_standalone(md_path: Path, plugin_dir: Path, errors: List[str]) -> None:
    rel = md_path.relative_to(plugin_dir).as_posix()
    try:
        text = md_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"{rel}: unreadable or non-UTF-8 Markdown ({exc})")
        return
    lines = text.splitlines()
    plugin_root_res = plugin_dir.resolve()

    in_fence = False
    for lineno, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            in_fence = not in_fence
            continue

        if _TILDE_CONFIG_RE.search(line):
            errors.append(f"{rel}:{lineno}: forbidden ~/.gemini/config/ path inside standalone plugin")
        if _FLAT_HOME_SKILLS_RE.search(line):
            errors.append(f"{rel}:{lineno}: forbidden flat $HOME/.gemini/config/skills/ path inside standalone plugin")
        if _RUNTIME_PATH_RE.search(line):
            errors.append(f"{rel}:{lineno}: forbidden ~/.local/share/antigravity-harness/ path inside standalone plugin")
        if _BARE_SCRIPTS_RE.search(line):
            errors.append(f"{rel}:{lineno}: bare scripts/... path without explicit ./ or ../ prefix")
        if rel != "README.md":
            for m_leak in _REPO_REL_LEAK_RE.finditer(line):
                errors.append(
                    f"{rel}:{lineno}: leaked repo-relative harness path `{m_leak.group(0)}` inside standalone plugin"
                )

        if in_fence:
            if stripped.startswith("agy-guard ") or stripped == "agy-guard":
                errors.append(f"{rel}:{lineno}: mandatory uncommented `agy-guard` command inside code fence")
            continue

        for m in _INLINE_AGY_GUARD_RE.finditer(line):
            if not _OPTIONAL_QUALIFIER_RE.search(line):
                errors.append(f"{rel}:{lineno}: unqualified mandatory {m.group(0)} invocation")

        for m in _MD_LINK_RE.finditer(line):
            href = m.group(1).strip()
            if href.startswith(("http://", "https://", "mailto:", "#", "customization://")):
                continue
            target_part = href.split("#", 1)[0]
            if not target_part:
                continue
            resolved = (md_path.parent / target_part).resolve()
            try:
                resolved.relative_to(plugin_root_res)
            except ValueError:
                errors.append(f"{rel}:{lineno}: markdown link escapes plugin root: {href}")
                continue
            if not resolved.exists():
                errors.append(f"{rel}:{lineno}: broken relative markdown link: {href}")

        for m in _BACKTICK_REL_PATH_RE.finditer(line):
            rel_tok = m.group(1)
            if any(ch in rel_tok for ch in "<>*{}"):
                continue
            resolved = (md_path.parent / rel_tok).resolve()
            try:
                resolved.relative_to(plugin_root_res)
            except ValueError:
                errors.append(f"{rel}:{lineno}: relative path escapes plugin root: {rel_tok}")
                continue
            if not resolved.exists():
                errors.append(f"{rel}:{lineno}: broken plugin-relative path: {rel_tok}")


def validate_plugin_dir(
    plugin_dir: Path,
    *,
    expected_pack: Optional[str] = None,
    run_agy_validate: bool = False,
) -> PluginValidationResult:
    """Strictly validates a built or installed plugin directory against v1/plugin.json and standalone invariants."""
    plugin_dir = Path(plugin_dir)
    errors: List[str] = []
    pack_name = expected_pack or plugin_dir.name

    if os.path.islink(plugin_dir) or not plugin_dir.is_dir():
        return PluginValidationResult(
            target=str(plugin_dir),
            pack_name=pack_name,
            errors=(f"Plugin directory missing or symlink: {plugin_dir}",),
            warnings=(),
        )

    # 1. Tree hygiene (symlinks, forbidden files/dirs, POSIX script permissions)
    md_files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(plugin_dir, followlinks=False):
        cur = Path(dirpath)
        for d in sorted(dirnames):
            dp = cur / d
            if os.path.islink(dp):
                errors.append(f"Symlink directory forbidden in plugin: {dp.relative_to(plugin_dir).as_posix()}")
            if d in _EXCLUDED_DIR_NAMES:
                errors.append(f"Forbidden directory inside plugin: {dp.relative_to(plugin_dir).as_posix()}")
        for f in sorted(filenames):
            fp = cur / f
            rel = fp.relative_to(plugin_dir).as_posix()
            if os.path.islink(fp) or not fp.is_file():
                errors.append(f"Symlink or non-regular file forbidden in plugin: {rel}")
                continue
            if f in _EXCLUDED_FILE_NAMES or f.endswith(_EXCLUDED_FILE_SUFFIXES):
                errors.append(f"Forbidden artifact inside plugin: {rel}")
            if os.name != "nt" and _is_plugin_script_path(rel):
                if not (os.lstat(fp).st_mode & stat.S_IXUSR):
                    errors.append(f"Bundled script lacks POSIX executable bit (0755): {rel}")
            if fp.suffix.lower() == ".md":
                md_files.append(fp)

    # 2. Strict plugin.json validation
    manifest_path = plugin_dir / "plugin.json"
    if os.path.islink(manifest_path) or not manifest_path.is_file():
        errors.append("Missing required plugin.json manifest")
    else:
        try:
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"Invalid JSON in plugin.json: {exc}")
        else:
            pack_name = _validate_manifest_dict(manifest_data, plugin_dir, expected_pack, errors)

    # 3. Required README.md, LICENSE & pack-scoped THIRD_PARTY_NOTICES.md
    spec = PLUGIN_CATALOG.get(pack_name)
    readme_path = plugin_dir / "README.md"
    if os.path.islink(readme_path) or not readme_path.is_file():
        errors.append("Missing or empty README.md at plugin root")
    else:
        try:
            readme_text = readme_path.read_text(encoding="utf-8")
            if not readme_text.strip():
                errors.append("Missing or empty README.md at plugin root")
            elif spec is not None:
                if "MIT License" not in readme_text or "./LICENSE" not in readme_text:
                    errors.append("README.md for harness plugin pack must state MIT License and link ./LICENSE")
                if spec.third_party_upstreams and "./THIRD_PARTY_NOTICES.md" not in readme_text:
                    errors.append(
                        f"README.md for '{pack_name}' must link ./THIRD_PARTY_NOTICES.md for bundled third-party works"
                    )
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"Unreadable README.md at plugin root: {exc}")

    license_path = plugin_dir / "LICENSE"
    if os.path.islink(license_path) or not license_path.is_file():
        errors.append("Missing required LICENSE at plugin root")
    else:
        try:
            lic_text = license_path.read_text(encoding="utf-8")
            if not lic_text.strip():
                errors.append("Empty LICENSE at plugin root")
            elif spec is not None and (
                "MIT License" not in lic_text or "Permission is hereby granted, free of charge" not in lic_text
            ):
                errors.append(f"LICENSE in '{pack_name}' must contain the full MIT License text")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"Unreadable LICENSE at plugin root: {exc}")

    notices_path = plugin_dir / "THIRD_PARTY_NOTICES.md"
    if spec is not None:
        if spec.third_party_upstreams:
            if os.path.islink(notices_path) or not notices_path.is_file():
                errors.append(f"Missing required THIRD_PARTY_NOTICES.md for '{pack_name}'")
            else:
                try:
                    notices_text = notices_path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError) as exc:
                    errors.append(f"Unreadable THIRD_PARTY_NOTICES.md at plugin root: {exc}")
                else:
                    if not notices_text.strip():
                        errors.append(f"Empty THIRD_PARTY_NOTICES.md for '{pack_name}'")
                    if "Apache-2.0" in notices_text:
                        errors.append(f"Unexpected Apache-2.0 notice leaked into MIT pack '{pack_name}'")
                    other_upstreams = {
                        u
                        for p_other, sp_other in PLUGIN_CATALOG.items()
                        if p_other != pack_name
                        for u in sp_other.third_party_upstreams
                    }
                    for foreign in sorted(other_upstreams):
                        if foreign in notices_text:
                            errors.append(f"Cross-pack upstream notice {foreign!r} leaked into '{pack_name}'")
                    for upstream in spec.third_party_upstreams:
                        if f"## {upstream}" not in notices_text:
                            errors.append(
                                f"THIRD_PARTY_NOTICES.md for '{pack_name}' missing notice section for {upstream!r}"
                            )
                    if "MIT License" not in notices_text or "Copyright" not in notices_text:
                        errors.append(
                            f"THIRD_PARTY_NOTICES.md for '{pack_name}' missing MIT License or Copyright text"
                        )
        elif os.path.lexists(notices_path):
            errors.append(f"Unexpected THIRD_PARTY_NOTICES.md in '{pack_name}' (pack contains no third-party works)")

    # 4. Skills structure & YAML frontmatter
    skills_dir = plugin_dir / "skills"
    found_skills: List[str] = []
    if not skills_dir.is_dir():
        errors.append("Missing skills/ directory")
    else:
        for child in sorted(skills_dir.iterdir()):
            if os.path.islink(child) or not child.is_dir():
                errors.append(f"Unexpected non-directory or symlink entry under skills/: {child.name}")
                continue
            found_skills.append(child.name)
            skill_md = child / "SKILL.md"
            if os.path.islink(skill_md) or not skill_md.is_file():
                errors.append(f"Missing SKILL.md for bundled skill '{child.name}'")
                continue
            try:
                fm_raw, _body = split_frontmatter(skill_md.read_text(encoding="utf-8"))
                if fm_raw is None:
                    raise FrontmatterError("missing YAML frontmatter")
                fm = parse_frontmatter_block(fm_raw)
            except (FrontmatterError, OSError, UnicodeDecodeError) as exc:
                errors.append(f"skills/{child.name}/SKILL.md invalid frontmatter: {exc}")
            else:
                if fm.get("name") != child.name:
                    errors.append(f"skills/{child.name}/SKILL.md frontmatter name ({fm.get('name')!r}) != dir '{child.name}'")
                if not isinstance(fm.get("description"), str) or not fm["description"].strip():
                    errors.append(f"skills/{child.name}/SKILL.md missing non-empty description")

    if spec is not None:
        if tuple(sorted(found_skills)) != tuple(sorted(spec.skills)):
            errors.append(
                f"Bundled skills mismatch for '{pack_name}': expected {sorted(spec.skills)}, got {sorted(found_skills)}"
            )
        for _src_rel, dst_rel in spec.extra_files:
            if not (plugin_dir / dst_rel).is_file():
                errors.append(f"Missing required bundled asset for '{pack_name}': {dst_rel}")

    # 5. MCP config validation
    mcp_path = plugin_dir / "mcp_config.json"
    if spec is not None:
        if spec.mcp_server_name and not mcp_path.is_file():
            errors.append(f"Missing required mcp_config.json for '{pack_name}'")
        elif not spec.mcp_server_name and os.path.lexists(mcp_path):
            errors.append(f"Unexpected mcp_config.json in '{pack_name}' (pack defines no MCP server)")
    if mcp_path.is_file() and not os.path.islink(mcp_path):
        try:
            mcp_data = json.loads(mcp_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"Invalid JSON in mcp_config.json: {exc}")
        else:
            servers = mcp_data.get("mcpServers") if isinstance(mcp_data, dict) else None
            if not isinstance(servers, dict) or not servers:
                errors.append("mcp_config.json must define a non-empty 'mcpServers' object")
            else:
                if spec is not None and spec.mcp_server_name:
                    if set(servers.keys()) != {spec.mcp_server_name}:
                        errors.append(
                            f"mcp_config.json servers for '{pack_name}' must be exactly "
                            f"{{{spec.mcp_server_name!r}}}, got {sorted(servers.keys())}"
                        )
                plugin_root_res = plugin_dir.resolve()
                for srv_name, srv_cfg in servers.items():
                    if not isinstance(srv_cfg, dict):
                        errors.append(f"mcp_config.json server '{srv_name}' must be an object")
                        continue
                    cmd = srv_cfg.get("command")
                    args = srv_cfg.get("args", [])
                    if not isinstance(cmd, str) or not cmd.strip():
                        errors.append(f"mcp_config.json server '{srv_name}' missing non-empty 'command'")
                    if not isinstance(args, list) or any(not isinstance(a, str) for a in args):
                        errors.append(f"mcp_config.json server '{srv_name}' 'args' must be a list of strings")
                    else:
                        if (
                            spec is not None
                            and spec.mcp_server_name == srv_name
                            and spec.mcp_script_rel
                            and f"${{PLUGIN_ROOT}}/{spec.mcp_script_rel}" not in args
                        ):
                            errors.append(
                                f"mcp_config.json server '{srv_name}' missing expected arg "
                                f"'${{PLUGIN_ROOT}}/{spec.mcp_script_rel}'"
                            )
                        for arg in args:
                            if arg.startswith("${PLUGIN_ROOT}/"):
                                rel_arg = arg[len("${PLUGIN_ROOT}/") :]
                                try:
                                    safe_arg = _validate_safe_rel_path(rel_arg)
                                except ValueError as exc:
                                    errors.append(f"mcp_config.json server '{srv_name}' unsafe path: {exc}")
                                    continue
                                target_file = (plugin_dir / safe_arg).resolve()
                                try:
                                    target_file.relative_to(plugin_root_res)
                                except ValueError:
                                    errors.append(f"mcp_config.json server '{srv_name}' arg escapes plugin root: {arg}")
                                    continue
                                if not target_file.is_file():
                                    errors.append(f"mcp_config.json server '{srv_name}' target missing: {arg}")

    # 6. Standalone-clean Markdown audit across every .md file
    for md in sorted(md_files):
        _validate_markdown_standalone(md, plugin_dir, errors)

    # 7. Optional official `agy plugin validate` hook
    agy_status = "skipped"
    if run_agy_validate:
        agy_bin = shutil.which("agy")
        if not agy_bin:
            agy_status = "unavailable"
        else:
            try:
                res = subprocess.run(
                    [agy_bin, "plugin", "validate", "--strict", str(plugin_dir)],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                agy_status = "failed"
                errors.append(f"agy plugin validate failed to execute: {exc}")
            else:
                if res.returncode == 0:
                    agy_status = "passed"
                else:
                    agy_status = "failed"
                    detail = (res.stderr or res.stdout or "").strip().splitlines()
                    errors.append(f"agy plugin validate failed (rc={res.returncode}): {detail[0] if detail else 'error'}")

    return PluginValidationResult(
        target=str(plugin_dir),
        pack_name=pack_name,
        errors=tuple(errors),
        warnings=(),
        agy_validate_status=agy_status,
    )


def validate_plugin_zip(
    zip_path: Path,
    *,
    expected_pack: Optional[str] = None,
    sha256_path: Optional[Path] = None,
    run_agy_validate: bool = False,
) -> PluginValidationResult:
    """Validates a deterministic plugin .zip archive (permissions, POSIX paths, checksum, and extracted contents)."""
    zip_path = Path(zip_path)
    errors: List[str] = []
    pack_name = expected_pack or zip_path.stem

    if os.path.islink(zip_path) or not zip_path.is_file():
        return PluginValidationResult(
            target=str(zip_path),
            pack_name=pack_name,
            errors=(f"Zip archive missing or symlink: {zip_path}",),
            warnings=(),
        )

    # Optional or sibling .sha256 sidecar verification (fail closed on symlinked/corrupt sidecars)
    sidecar = Path(sha256_path) if sha256_path is not None else zip_path.with_name(f"{zip_path.name}.sha256")
    if os.path.islink(sidecar):
        errors.append(f"Refusing symlinked SHA-256 sidecar: {sidecar.name}")
    elif sidecar.is_file():
        try:
            sha_text = sidecar.read_text(encoding="utf-8")
            hasher = hashlib.sha256()
            with open(zip_path, "rb") as zfh:
                while True:
                    chunk = zfh.read(65536)
                    if not chunk:
                        break
                    hasher.update(chunk)
            expected_digest = hasher.hexdigest()
        except (OSError, ValueError) as exc:
            errors.append(f"Failed verifying SHA-256 sidecar {sidecar.name}: {exc}")
        else:
            expected_line = f"{expected_digest}  {zip_path.name}\n"
            if sha_text != expected_line:
                errors.append(f"SHA-256 sidecar mismatch or bad 2-space format in {sidecar.name}")
    elif sha256_path is not None:
        errors.append(f"Declared SHA-256 sidecar missing: {sidecar}")

    try:
        zf = zipfile.ZipFile(zip_path, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        return PluginValidationResult(
            target=str(zip_path),
            pack_name=pack_name,
            errors=(f"Invalid zip archive: {exc}",),
            warnings=(),
        )

    with zf:
        infos = zf.infolist()
        if not infos:
            errors.append("Zip archive is empty")
            return PluginValidationResult(target=str(zip_path), pack_name=pack_name, errors=tuple(errors), warnings=())
        if len(infos) > MAX_ZIP_ENTRIES:
            errors.append(f"Zip entry count ({len(infos)}) exceeds ceiling ({MAX_ZIP_ENTRIES})")

        names = [i.filename for i in infos]
        if len(names) != len(set(names)):
            errors.append("Zip archive contains duplicate entry paths")
        if names != sorted(names):
            errors.append("Zip archive entries are not sorted in deterministic POSIX order")

        total_size = 0
        top_dirs = set()
        for info in infos:
            fname = info.filename
            if fname.endswith("/"):
                errors.append(f"Unexpected directory entry in deterministic archive: {fname}")
                continue
            try:
                safe_name = _validate_safe_rel_path(fname)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            parts = PurePosixPath(safe_name).parts
            if len(parts) < 2:
                errors.append(f"Zip entry must sit under a top-level <pack>/ root directory: {fname}")
                continue
            top_dirs.add(parts[0])
            inner_rel = "/".join(parts[1:])
            if any(p in _EXCLUDED_DIR_NAMES for p in parts[1:-1]):
                errors.append(f"Forbidden directory in zip entry: {fname}")
            if parts[-1] in _EXCLUDED_FILE_NAMES or parts[-1].endswith(_EXCLUDED_FILE_SUFFIXES):
                errors.append(f"Forbidden file in zip entry: {fname}")

            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                errors.append(f"Symlink entry forbidden in zip archive: {fname}")
            if info.create_system != 3:
                errors.append(f"Zip entry {fname} has create_system={info.create_system}; expected 3 (Unix)")
            perm = mode & 0o777
            expected_perm = 0o755 if _is_plugin_script_path(inner_rel) else 0o644
            if perm != expected_perm:
                errors.append(f"Zip entry {fname} has mode {oct(perm)}; expected {oct(expected_perm)}")

            total_size += info.file_size
            if total_size > MAX_ZIP_UNCOMPRESSED_BYTES:
                errors.append("Zip uncompressed payload exceeds safety limit")
                break

        if len(top_dirs) != 1:
            errors.append(f"Zip archive must contain exactly one top-level plugin root (found: {sorted(top_dirs)})")
        else:
            sole_top = next(iter(top_dirs))
            if expected_pack is not None and sole_top != expected_pack:
                errors.append(f"Zip top-level directory ({sole_top!r}) does not match expected pack ({expected_pack!r})")
            pack_name = expected_pack or sole_top
            name_set = set(names)
            if f"{sole_top}/LICENSE" not in name_set:
                errors.append(f"Zip archive missing required {sole_top}/LICENSE")
            z_spec = PLUGIN_CATALOG.get(pack_name)
            if z_spec is not None:
                notices_entry = f"{sole_top}/THIRD_PARTY_NOTICES.md"
                if z_spec.third_party_upstreams and notices_entry not in name_set:
                    errors.append(f"Zip archive missing required {notices_entry}")
                elif not z_spec.third_party_upstreams and notices_entry in name_set:
                    errors.append(f"Zip archive contains unexpected {notices_entry}")

        if errors:
            return PluginValidationResult(
                target=str(zip_path),
                pack_name=pack_name,
                errors=tuple(errors),
                warnings=(),
            )

        with tempfile.TemporaryDirectory(prefix="agy-plugin-zip-check-") as tmp_root:
            extract_root = Path(tmp_root)
            extracted_bytes = 0
            for info in infos:
                out_file = extract_root / info.filename
                out_file.parent.mkdir(parents=True, exist_ok=True)
                entry_bytes = 0
                try:
                    with zf.open(info, "r") as src_fh, open(out_file, "wb") as dst_fh:
                        while True:
                            chunk = src_fh.read(65536)
                            if not chunk:
                                break
                            entry_bytes += len(chunk)
                            extracted_bytes += len(chunk)
                            if extracted_bytes > MAX_ZIP_UNCOMPRESSED_BYTES:
                                errors.append("Zip decompressed stream exceeds safety limit")
                                break
                            dst_fh.write(chunk)
                except (zipfile.BadZipFile, zlib.error, RuntimeError, OSError) as exc:
                    errors.append(f"Failed extracting zip entry {info.filename}: {exc}")
                    break
                if errors:
                    break
                if entry_bytes != info.file_size:
                    errors.append(
                        f"Zip entry {info.filename} header size ({info.file_size}) != decompressed size ({entry_bytes})"
                    )
                    break
                if os.name != "nt":
                    os.chmod(out_file, (info.external_attr >> 16) & 0o777)
            if errors:
                return PluginValidationResult(
                    target=str(zip_path),
                    pack_name=pack_name,
                    errors=tuple(errors),
                    warnings=(),
                )
            extracted_dir = extract_root / next(iter(top_dirs))
            dir_res = validate_plugin_dir(
                extracted_dir,
                expected_pack=expected_pack,
                run_agy_validate=run_agy_validate,
            )
            return PluginValidationResult(
                target=str(zip_path),
                pack_name=dir_res.pack_name,
                errors=tuple(errors) + dir_res.errors,
                warnings=dir_res.warnings,
                agy_validate_status=dir_res.agy_validate_status,
            )


def build_all_plugin_packs(
    repo_root: Path,
    out_dir: Path,
    *,
    packs: Optional[Sequence[str]] = None,
    version: Optional[str] = None,
    create_zip: bool = False,
    validate: bool = False,
    run_agy_validate: bool = False,
    source_date_epoch: Optional[int] = None,
) -> Dict[str, Dict[str, Any]]:
    """Builds, optionally zips, and optionally validates selected (or all) canonical plugin packs."""
    selected = list(packs) if packs else list(PLUGIN_CATALOG.keys())
    unknown = [p for p in selected if p not in PLUGIN_CATALOG]
    if unknown:
        raise ValueError(f"Unknown plugin pack(s): {', '.join(unknown)}")

    resolved_version = version or HARNESS_VERSION
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary: Dict[str, Dict[str, Any]] = {}

    for pack_name in selected:
        pack_dir = build_plugin_pack(
            pack_name,
            repo_root=repo_root,
            dest_dir=out_dir / pack_name,
            version=resolved_version,
            portable_mcp=True,
        )
        entry: Dict[str, Any] = {
            "pack": pack_name,
            "version": resolved_version,
            "dir": str(pack_dir),
            "ok": True,
        }
        if validate:
            dir_res = validate_plugin_dir(
                pack_dir,
                expected_pack=pack_name,
                run_agy_validate=run_agy_validate,
            )
            entry["dir_validation"] = dir_res.to_dict()
            entry["ok"] = entry["ok"] and dir_res.ok

        if create_zip:
            zip_target = out_dir / f"{pack_name}-v{resolved_version}.zip"
            zip_path, sha_path = archive_plugin_pack(
                pack_dir,
                zip_target,
                source_date_epoch=source_date_epoch,
            )
            entry["zip"] = str(zip_path)
            entry["sha256_file"] = str(sha_path)
            entry["sha256"] = sha_path.read_text(encoding="utf-8").split()[0]
            if validate:
                zip_res = validate_plugin_zip(
                    zip_path,
                    expected_pack=pack_name,
                    sha256_path=sha_path,
                    run_agy_validate=run_agy_validate,
                )
                entry["zip_validation"] = zip_res.to_dict()
                entry["ok"] = entry["ok"] and zip_res.ok

        summary[pack_name] = entry

    return summary
