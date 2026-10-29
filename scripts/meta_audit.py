#!/usr/bin/env python3
"""
scripts/meta_audit.py — Meta-Consistency & Self-Audit Engine (GEMINI.md Rule 17)
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Uses the Python standard library; uses PyYAML for frontmatter when it is installed.

Passes:
  1  Frontmatter schema: every skill/agent parses as YAML (what Antigravity needs to load it);
     an agent's optional `access` key is one of AGENT_ACCESS_LEVELS
  2  Cross-references: agents/templates named in GEMINI.md, relative Markdown links,
     backticked repository paths and bare *.md references resolve
  3  Mode isolation: mode skills declare an explicit mutual-exclusion section; tier
     thresholds agree across GEMINI.md and skills
  4  Porter parity: every emitter reproduces every skill, support file, link and agent
     verbatim (plus executable bits on POSIX and the portable templates); emitted frontmatter is valid YAML; committed manifest is current; the
     harness passes its own constitutional sanitizer
  5  CLI & documentation sync: README commands exist, README examples parse, numeric
     claims (subcommands, tests, skills, subagents) and policy names match the code
  6  Design contract: DESIGN.md "Measured Contrast Pairs" are recomputed (WCAG 2.x)
  7  Trigger specificity: every skill frontmatter description declares an explicit negative boundary

Usage:
  python3 scripts/meta_audit.py [--all] [--pass N ...] [--strict] [--json]
Exit status: 1 if any CRITICAL finding (or any WARNING with --strict), else 0.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shlex
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

MODE_SKILLS = ("chisle", "marathon", "procoder", "unlazy", "vibecoder")
KNOWN_EXTERNAL_MD = {
    "AGENTS.md", "CLAUDE.md", "CODEX.md", "CONVENTIONS.md", "RULES.md", "GATES.md", "HANDOFF.md",
    "tasks.md", "plan.md", "PLAN.md", "implementation_plan.md", "walkthrough.md", "SKILL.md",
    "MISTAKES.md", "GEMINI.md", "DESIGN.md", "README.md", "CHANGELOG.md", "SECURITY.md",
    "CONTRIBUTING.md", "task.md", "spec.md", "todo.md", "backlog.md", "sprint.md", "ADR.md",
    "RELEASE.md", "template.md", "GLOSSARY.md", "PRODUCT.md",  # files the skills create inside the user's project
}
# `.claude` holds local agent worktrees (full repository copies) and is never harness content.
SKIP_DIRS = {".git", "node_modules", "export", "__pycache__", "dist", "build", ".harness", ".claude"}
# Custom subagents in Antigravity 2.0 are read-only (no shell execution tool in custom agent profiles).
AGENT_ACCESS_LEVELS = ("read-only",)
DEPRECATED_V1_TOOLS = {
    "view_file": "read_file",
    "grep_search": "run_command (ripgrep / grep / code_map.py)",
    "read_url_content": "search_web or python3 porter/net.py safe_fetch_url",
    "list_dir": "run_command or glob",
    "find_by_name": "run_command or glob",
    "replace_file_content": "edit_file",
    "multi_replace_file_content": "edit_file",
    "write_to_file": "write_file",
}
_DEPRECATED_V1_TOOL_RE = re.compile(r"\b(" + "|".join(re.escape(k) for k in DEPRECATED_V1_TOOLS) + r")\b")
_STALE_XDG_GUARD_RE = re.compile(r"~/\.(?:local/(?:share|state)|gemini)/antigravity-guard\b")
_HISTORICAL_LEDGER_NAMES = {"HANDOFF.md", "tasks.md", "MISTAKES.md", "CHANGELOG.md"}
_BUILTIN_OR_IGNORED_SUBAGENTS = {
    "self",
    "image-generator",
    "subagent",
    "build",
    "fast-path",
    "rea-agents",
    "read-only",
    "write-enabled",
}
_LINE_ANCHOR_RE = re.compile(r"^L\d+(?:-L?\d+)?$", re.IGNORECASE)


def _extract_pre_tool_use_matcher_tools(py_text: str) -> Optional[Tuple[str, ...]]:
    """Extracts PRE_TOOL_USE_MATCHER_TOOLS string tuple from guard/agy_hooks.py via AST."""
    try:
        tree = ast.parse(py_text)
    except SyntaxError:
        return None
    for node in tree.body:
        val_node = None
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "PRE_TOOL_USE_MATCHER_TOOLS":
                    val_node = node.value
                    break
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == "PRE_TOOL_USE_MATCHER_TOOLS":
                val_node = node.value
        if isinstance(val_node, (ast.Tuple, ast.List)):
            items: List[str] = []
            for elt in val_node.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    items.append(elt.value)
                else:
                    return None
            return tuple(items) if items else None
    return None


@dataclass
class AuditFinding:
    severity: str  # "CRITICAL", "WARNING", "INFO"
    pass_name: str
    target: str
    message: str
    suggested_fix: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


def _load_yaml_frontmatter(text: str):
    """Returns (dict, error). Validates with both porter.frontmatter and PyYAML (when installed)."""
    if text.startswith("﻿"):
        text = text[1:]
    m = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", text, re.DOTALL)
    if not m:
        return None, "missing YAML frontmatter markers (---)"
    block = m.group(1)
    from porter.frontmatter import FrontmatterError, parse_frontmatter_block

    try:
        data = parse_frontmatter_block(block)
    except FrontmatterError as e:
        return None, f"invalid YAML frontmatter: {e}"
    try:
        import yaml  # type: ignore

        try:
            yaml_data = yaml.safe_load(block)
        except yaml.YAMLError as e:
            return None, f"invalid YAML frontmatter: {str(e).splitlines()[0]}"
        if not isinstance(yaml_data, dict):
            return None, "frontmatter is not a mapping"
    except ImportError:
        pass
    if not isinstance(data, dict):
        return None, "frontmatter is not a mapping"
    return data, None


def _luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    channels = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast_ratio(fg: str, bg: str) -> float:
    a, b = sorted((_luminance(fg), _luminance(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


class MetaAuditEngine:
    """Deterministic meta-auditor verifying the harness's own integrity and consistency."""

    def __init__(self, repo_root: Optional[Path] = None):
        self.repo_root = Path(repo_root or REPO_ROOT).resolve()
        self.findings: List[AuditFinding] = []
        self._text_cache: Dict[Tuple[Path, int, int], str] = {}
        self._heading_cache: Dict[Path, Tuple[Set[str], Set[str]]] = {}

    def _add(self, severity: str, pass_name: str, target: str, message: str, fix: str) -> None:
        self.findings.append(AuditFinding(severity, pass_name, target, message, fix))

    def _rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.repo_root).as_posix()
        except ValueError:
            return str(path)

    def _read_text(self, path: Path) -> str:
        try:
            st = path.stat()
            key = (path, st.st_mtime_ns, st.st_size)
            cached = self._text_cache.get(key)
            if cached is not None:
                return cached
            text = path.read_text(encoding="utf-8", errors="ignore")
            self._text_cache[key] = text
            return text
        except OSError:
            return path.read_text(encoding="utf-8", errors="ignore")

    def _heading_slugs_and_sections(self, md_path: Path) -> Tuple[Set[str], Set[str]]:
        """Returns (github_anchor_slugs, section_numbers) extracted from ATX headings in md_path."""
        resolved = md_path.resolve()
        cached = self._heading_cache.get(resolved)
        if cached is not None:
            return cached
        raw = self._read_text(resolved)
        if raw.startswith("\ufeff"):
            raw = raw[1:]
        raw = re.sub(r"^---\r?\n.*?\r?\n---\r?\n", "", raw, count=1, flags=re.DOTALL)
        slugs: Set[str] = set()
        slug_counts: Dict[str, int] = {}
        sections: Set[str] = set()
        parent_num: Optional[str] = None
        in_fence = False
        for line in raw.splitlines():
            if line.lstrip().startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            m = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*$", line)
            if not m:
                continue
            lvl = len(m.group(1))
            title = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", m.group(2))
            clean_for_slug = title.replace("`", "").replace("*", "").replace("_", "").replace("~", "")
            base_slug = re.sub(r"[^\w\s-]", "", clean_for_slug.lower(), flags=re.UNICODE)
            base_slug = re.sub(r"\s+", "-", base_slug.strip())
            if base_slug:
                count = slug_counts.get(base_slug, 0)
                slug_counts[base_slug] = count + 1
                slugs.add(base_slug if count == 0 else f"{base_slug}-{count}")

            clean_sec = clean_for_slug.strip()
            m_num = re.match(
                r"^(?:Section\s+|Mode\s+|Pass\s+|Stage\s+|Phase\s+|Step\s+)?(\d+(?:\.[A-Za-z0-9]+)*)\b",
                clean_sec,
                re.IGNORECASE,
            )
            if m_num:
                sec_id = m_num.group(1).upper()
                sections.add(sec_id)
                sections.add(sec_id.replace(".", ""))
                if lvl <= 2:
                    parent_num = sec_id.split(".", 1)[0]
            elif lvl >= 3 and parent_num:
                m_sub = re.match(r"^([A-Za-z0-9])\.", clean_sec)
                if m_sub:
                    sub = m_sub.group(1).upper()
                    sections.add(f"{parent_num}.{sub}")
                    sections.add(f"{parent_num}{sub}")
            elif lvl <= 2:
                parent_num = None
        res = (slugs, sections)
        self._heading_cache[resolved] = res
        return res

    @staticmethod
    def _collect_basenames(root: Path) -> Set[str]:
        names: Set[str] = set()
        for _dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            names.update(dirnames)
            names.update(filenames)
        return names

    def _markdown_files(self) -> List[Path]:
        files = []
        for dirpath, dirnames, filenames in os.walk(self.repo_root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            files.extend(Path(dirpath) / f for f in sorted(filenames) if f.endswith(".md"))
        return files

    def run_pass(self, number: int) -> List[AuditFinding]:
        {
            1: self.pass1_schema_validation,
            2: self.pass2_cross_references,
            3: self.pass3_directive_collision_and_mutex,
            4: self.pass4_porter_parity,
            5: self.pass5_cli_doc_sync,
            6: self.pass6_design_contract,
            7: self.pass7_trigger_specificity,
        }[number]()
        return self.findings

    def run_all_passes(self) -> List[AuditFinding]:
        self.findings = []
        for n in range(1, 8):
            self.run_pass(n)
        return self.findings

    # ------------------------------------------------------------------
    # Pass 1
    # ------------------------------------------------------------------
    def pass1_schema_validation(self) -> None:
        name = "Pass 1 (Schema Validation)"
        entries = []
        ref_md_files: List[Path] = []
        skills_dir = self.repo_root / "skills"
        if skills_dir.is_dir():
            for p in sorted(skills_dir.iterdir()):
                if not p.is_dir():
                    self._add(
                        "CRITICAL",
                        name,
                        f"skills/{p.name}",
                        f"Stray non-directory file '{p.name}' directly under skills/",
                        f"Move 'skills/{p.name}' into a skill directory or remove it.",
                    )
                    continue
                skill_file = p / "SKILL.md"
                if not skill_file.is_file():
                    self._add(
                        "CRITICAL",
                        name,
                        f"skills/{p.name}",
                        f"Missing SKILL.md in skill directory '{p.name}'",
                        f"Create skills/{p.name}/SKILL.md with valid YAML frontmatter.",
                    )
                    continue
                entries.append((skill_file, p.name))
                refs_dir = p / "references"
                if refs_dir.is_dir():
                    ref_md_files.extend(
                        sorted(
                            rf
                            for rf in refs_dir.rglob("*.md")
                            if rf.is_file() and not SKIP_DIRS.intersection(rf.relative_to(self.repo_root).parts)
                        )
                    )
        agents_dir = self.repo_root / "agents"
        if agents_dir.is_dir():
            for p in sorted(agents_dir.iterdir()):
                if p.is_dir():
                    self._add(
                        "CRITICAL",
                        name,
                        f"agents/{p.name}",
                        f"Unexpected subdirectory '{p.name}' under agents/",
                        f"Flatten or remove 'agents/{p.name}' (agents/ only holds *.md profiles).",
                    )
                    continue
                if p.suffix.lower() != ".md":
                    self._add(
                        "CRITICAL",
                        name,
                        f"agents/{p.name}",
                        f"Stray non-Markdown file '{p.name}' under agents/",
                        f"Convert 'agents/{p.name}' to a valid .md agent profile or remove it.",
                    )
                    continue
                entries.append((p, p.stem))

        for path, expected in entries:
            data, err = _load_yaml_frontmatter(path.read_text(encoding="utf-8", errors="replace"))
            target = self._rel(path)
            if err:
                self._add("CRITICAL", name, target, f"Frontmatter error: {err} (the platform will not load this file)",
                          "Fix the YAML frontmatter (quote values containing ': ' or use a '>-' block).")
                continue
            if not data.get("name"):
                self._add("CRITICAL", name, target, "Frontmatter is missing required 'name' field", f"Add 'name: {expected}'.")
            elif str(data["name"]).strip() != expected:
                self._add("WARNING", name, target, f"name '{data['name']}' mismatches '{expected}'", f"Use name: {expected}")
            desc = data.get("description")
            if not isinstance(desc, str) or not desc.strip():
                self._add("WARNING", name, target, "Frontmatter has missing or empty 'description' field",
                          "Provide a descriptive summary of when to use it.")
            if path.parent.name == "agents" and "access" not in data:
                self._add("WARNING", name, target, "Agent frontmatter is missing 'access' field",
                          f"Add 'access' ({', '.join(AGENT_ACCESS_LEVELS)}).")
            elif "access" in data and str(data["access"]).strip() not in AGENT_ACCESS_LEVELS:
                self._add("WARNING", name, target, f"Unsupported 'access' value '{data['access']}' (Antigravity 2.0 custom subagents must be read-only)",
                          f"Use one of: {', '.join(AGENT_ACCESS_LEVELS)}.")

            is_readonly_agent = (
                path.parent.name == "agents" and str(data.get("access", "")).strip() == "read-only"
            )
            full_text = path.read_text(encoding="utf-8", errors="replace")
            for lineno, line in enumerate(full_text.splitlines(), 1):
                for m_tool in _DEPRECATED_V1_TOOL_RE.finditer(line):
                    old_tool = m_tool.group(1)
                    if old_tool == "view_file" and is_readonly_agent:
                        continue
                    self._add(
                        "CRITICAL",
                        name,
                        f"{target}:{lineno}",
                        f"Deprecated Antigravity 1.x tool `{old_tool}` referenced in active instruction file",
                        f"Replace `{old_tool}` with `{DEPRECATED_V1_TOOLS[old_tool]}`.",
                    )

        for ref_md in ref_md_files:
            ref_target = self._rel(ref_md)
            ref_text = ref_md.read_text(encoding="utf-8", errors="replace")
            for lineno, line in enumerate(ref_text.splitlines(), 1):
                for m_tool in _DEPRECATED_V1_TOOL_RE.finditer(line):
                    old_tool = m_tool.group(1)
                    self._add(
                        "CRITICAL",
                        name,
                        f"{ref_target}:{lineno}",
                        f"Deprecated Antigravity 1.x tool `{old_tool}` referenced in skill reference file",
                        f"Replace `{old_tool}` with `{DEPRECATED_V1_TOOLS[old_tool]}`.",
                    )

    # ------------------------------------------------------------------
    # Pass 2
    # ------------------------------------------------------------------
    @staticmethod
    def _is_within(path: Path, root: Path) -> bool:
        try:
            path.resolve().relative_to(root.resolve())
            return True
        except ValueError:
            return False

    def pass2_cross_references(self) -> None:
        name = "Pass 2 (Cross-Reference Integrity)"
        agents_dir = self.repo_root / "agents"
        available_agents = {f.stem for f in agents_dir.glob("*.md")} if agents_dir.is_dir() else set()
        skills_dir = self.repo_root / "skills"
        available_skills = (
            {p.name for p in skills_dir.iterdir() if p.is_dir() and (p / "SKILL.md").is_file()}
            if skills_dir.is_dir()
            else set()
        )

        def _extract_subagents(text_without_fences: str) -> Set[str]:
            explicit = set(re.findall(r"`([a-z0-9-]+)`\s+(?:subagent|auditor|agent)", text_without_fences))
            suffixed = (
                set(re.findall(r"`([a-z0-9-]+-(?:auditor|verifier|hunter|resolver))`", text_without_fences))
                - available_skills
            )
            return (explicit | suffixed) - _BUILTIN_OR_IGNORED_SUBAGENTS

        gemini_md = self.repo_root / "GEMINI.md"
        if gemini_md.is_file():
            content = gemini_md.read_text(encoding="utf-8", errors="ignore")
            g_no_code = re.sub(r"```.*?```", "", content, flags=re.DOTALL)
            for agent in sorted(_extract_subagents(g_no_code)):
                if agent not in available_agents:
                    self._add("CRITICAL", name, "GEMINI.md",
                              f"GEMINI.md mandates dispatch of `{agent}` subagent, but agents/{agent}.md is missing.",
                              f"Create agents/{agent}.md or update the reference.")
            for tmpl in re.findall(r"templates/([a-zA-Z0-9_.-]+)", content):
                if not (self.repo_root / "templates" / tmpl).exists():
                    self._add("CRITICAL", name, "GEMINI.md", f"GEMINI.md references 'templates/{tmpl}', which does not exist.",
                              f"Create templates/{tmpl} or update the path.")

        if available_agents or agents_dir.is_dir():
            subagent_scan_files: List[Path] = []
            if skills_dir.is_dir():
                subagent_scan_files.extend(
                    sorted(
                        p
                        for p in skills_dir.rglob("*.md")
                        if not SKIP_DIRS.intersection(p.relative_to(self.repo_root).parts)
                    )
                )
            if agents_dir.is_dir():
                subagent_scan_files.extend(sorted(agents_dir.glob("*.md")))
            for doc_md in subagent_scan_files:
                s_text = re.sub(r"```.*?```", "", self._read_text(doc_md), flags=re.DOTALL)
                s_target = self._rel(doc_md)
                for agent in sorted(_extract_subagents(s_text)):
                    if doc_md.parent == agents_dir and agent == doc_md.stem:
                        continue
                    if agent not in available_agents:
                        self._add("WARNING", name, s_target,
                                  f"{s_target} references `{agent}` subagent, but agents/{agent}.md is missing.",
                                  f"Create agents/{agent}.md or update the reference.")

        top_dirs = {"skills", "agents", "scripts", "guard", "porter", "templates", "installers", "tests", "bin"}
        config_mapped_heads = {"GEMINI.md", "DESIGN.md", "MISTAKES.md", "skills", "agents", "templates", "scripts", "guard", "porter"}
        code_dirs = {"scripts", "guard", "porter", "tests"}
        is_split_layout = not (self.repo_root / "scripts").is_dir() and (self.repo_root / "GEMINI.md").is_file()
        runtime_roots: List[Path] = []
        if is_split_layout:
            try:
                from guard.paths import data_dir
                rt = data_dir() / "runtime"
                if rt.is_dir():
                    runtime_roots.append(rt)
            except ImportError:
                pass
            for sys_lib in (
                self.repo_root.parent.parent / "lib" / "antigravity-guard",
                Path("/usr/lib/antigravity-guard"),
            ):
                if sys_lib.is_dir() and sys_lib not in runtime_roots and sys_lib != self.repo_root:
                    runtime_roots.append(sys_lib)
            if REPO_ROOT.is_dir() and REPO_ROOT not in runtime_roots and REPO_ROOT != self.repo_root:
                runtime_roots.append(REPO_ROOT)

        is_split_p2, _, managed_agents_p2, _ = self._split_layout_managed_sets()
        hooks_py = self._resolve_hooks_py_for_audit(
            allow_split_fallback=bool(is_split_p2 and managed_agents_p2)
        )
        h_text = hooks_py.read_text(encoding="utf-8", errors="ignore") if hooks_py.is_file() else ""
        if available_agents and hooks_py.is_file():
            for m in re.finditer(r"(?<!Built-in\s)Subagents?\s+((?:`[a-z0-9-]+`(?:\s*(?:&|,|and)\s*)?)+)", h_text):
                for agent in re.findall(r"`([a-z0-9-]+)`", m.group(1)):
                    if agent in ("self",):
                        continue
                    if agent not in available_agents:
                        self._add("WARNING", name, "guard/agy_hooks.py",
                                  f"guard/agy_hooks.py routes to repo Subagent `{agent}`, but agents/{agent}.md is missing (prefix with 'Built-in Subagent' if platform-provided).",
                                  f"Create agents/{agent}.md or label as 'Built-in Subagent `{agent}`'.")

        hooks_json = self.repo_root / "hooks.json"
        if hooks_json.is_file():
            try:
                hj_data = json.loads(hooks_json.read_text(encoding="utf-8"))
                if not isinstance(hj_data, dict):
                    self._add(
                        "CRITICAL",
                        name,
                        "hooks.json",
                        "hooks.json root must be a JSON object",
                        "Fix hooks.json top-level structure.",
                    )
                else:
                    uw_block = hj_data.get("upstream-watchdog")
                    if not isinstance(uw_block, dict) or not isinstance(uw_block.get("PreInvocation"), list) or not uw_block.get("PreInvocation"):
                        self._add(
                            "CRITICAL",
                            name,
                            "hooks.json",
                            "hooks.json is missing upstream-watchdog.PreInvocation registration",
                            "Register PreInvocation under upstream-watchdog in hooks.json.",
                        )

                    gate_block = hj_data.get("harness-gate")
                    if not isinstance(gate_block, dict):
                        self._add(
                            "CRITICAL",
                            name,
                            "hooks.json",
                            "hooks.json is missing harness-gate block",
                            "Restore harness-gate block in hooks.json.",
                        )
                    else:
                        for ev_req in ("PreInvocation", "PreToolUse", "Stop"):
                            ev_val = gate_block.get(ev_req)
                            if not isinstance(ev_val, list) or not ev_val:
                                self._add(
                                    "CRITICAL",
                                    name,
                                    "hooks.json",
                                    f"hooks.json is missing harness-gate.{ev_req} registration",
                                    f"Restore {ev_req} under harness-gate in hooks.json.",
                                )

                    expected_tools: Optional[Tuple[str, ...]] = None
                    if hooks_py.is_file():
                        expected_tools = _extract_pre_tool_use_matcher_tools(h_text)
                        if expected_tools is None:
                            self._add(
                                "CRITICAL",
                                name,
                                "guard/agy_hooks.py",
                                "Could not extract PRE_TOOL_USE_MATCHER_TOOLS from guard/agy_hooks.py",
                                "Define PRE_TOOL_USE_MATCHER_TOOLS as a non-empty string tuple in guard/agy_hooks.py.",
                            )

                    ptu_list = gate_block.get("PreToolUse") if isinstance(gate_block, dict) else None
                    if isinstance(ptu_list, list) and ptu_list:
                        for ptu_idx, ptu_entry in enumerate(ptu_list):
                            hj_matcher = ptu_entry.get("matcher") if isinstance(ptu_entry, dict) else None
                            if not isinstance(hj_matcher, str) or not hj_matcher.strip():
                                self._add(
                                    "CRITICAL",
                                    name,
                                    "hooks.json",
                                    f"hooks.json is missing harness-gate.PreToolUse[{ptu_idx}].matcher",
                                    "Restore PreToolUse matcher in hooks.json.",
                                )
                            elif expected_tools is not None:
                                expected_matcher = "|".join(expected_tools)
                                if hj_matcher != expected_matcher:
                                    self._add(
                                        "CRITICAL",
                                        name,
                                        "hooks.json",
                                        f"hooks.json PreToolUse[{ptu_idx}] matcher differs from PRE_TOOL_USE_MATCHER_TOOLS in guard/agy_hooks.py (`{hj_matcher}` != `{expected_matcher}`)",
                                        "Synchronize hooks.json PreToolUse matcher with PRE_TOOL_USE_MATCHER_TOOLS in guard/agy_hooks.py.",
                                    )

                    for grp_name, grp_events in (
                        ("upstream-watchdog", ("PreInvocation",)),
                        ("harness-gate", ("PreInvocation", "PreToolUse", "Stop")),
                    ):
                        grp_obj = hj_data.get(grp_name)
                        if not isinstance(grp_obj, dict):
                            continue
                        for ev_name in grp_events:
                            ev_entries = grp_obj.get(ev_name)
                            if not isinstance(ev_entries, list):
                                continue
                            for e_idx, ev_item in enumerate(ev_entries):
                                if not isinstance(ev_item, dict):
                                    self._add(
                                        "CRITICAL",
                                        name,
                                        "hooks.json",
                                        f"hooks.json {grp_name}.{ev_name}[{e_idx}] must be an object",
                                        f"Provide a valid hook entry under {grp_name}.{ev_name}[{e_idx}].",
                                    )
                                    continue
                                if ev_name == "PreToolUse" or "hooks" in ev_item:
                                    hooks_sub = ev_item.get("hooks")
                                    if not isinstance(hooks_sub, list) or not hooks_sub:
                                        self._add(
                                            "CRITICAL",
                                            name,
                                            "hooks.json",
                                            f"hooks.json {grp_name}.{ev_name}[{e_idx}] has missing or empty hooks list",
                                            f"Add at least one command hook entry under {grp_name}.{ev_name}[{e_idx}].",
                                        )
                                        continue
                                else:
                                    hooks_sub = [ev_item]
                                for h_idx, hook_item in enumerate(hooks_sub):
                                    cmd_str = hook_item.get("command") if isinstance(hook_item, dict) else None
                                    if not isinstance(cmd_str, str) or not cmd_str.strip():
                                        self._add(
                                            "CRITICAL",
                                            name,
                                            "hooks.json",
                                            f"hooks.json {grp_name}.{ev_name}[{e_idx}].hooks[{h_idx}] is missing a command string",
                                            f"Provide a valid command string under {grp_name}.{ev_name}[{e_idx}].hooks[{h_idx}].",
                                        )
                                        continue
                                    try:
                                        cmd_tokens = shlex.split(cmd_str)
                                    except ValueError:
                                        cmd_tokens = cmd_str.split()
                                    for tok in cmd_tokens:
                                        if tok.startswith("-") or not tok.endswith((".py", ".sh", ".mjs")):
                                            continue
                                        script_p = Path(tok).expanduser()
                                        if not script_p.is_absolute():
                                            script_cands = [self.repo_root / script_p] + [rt / script_p for rt in runtime_roots]
                                            if not any(c.is_file() for c in script_cands):
                                                self._add(
                                                    "CRITICAL",
                                                    name,
                                                    "hooks.json",
                                                    f"hooks.json references missing hook script `{tok}` in {grp_name}.{ev_name}",
                                                    f"Restore `{tok}` or update the hook command in hooks.json.",
                                                )
                                        elif (
                                            not is_split_layout
                                            or self._is_within(script_p, self.repo_root)
                                            or any(self._is_within(script_p, rt) for rt in runtime_roots)
                                        ):
                                            if not script_p.is_file():
                                                self._add(
                                                    "CRITICAL",
                                                    name,
                                                    "hooks.json",
                                                    f"hooks.json references missing hook script `{tok}` in {grp_name}.{ev_name}",
                                                    f"Restore `{tok}` or update the hook command in hooks.json.",
                                                )
            except (OSError, ValueError) as exc:
                self._add(
                    "CRITICAL",
                    name,
                    "hooks.json",
                    f"hooks.json is not valid JSON: {exc}",
                    "Fix JSON syntax in hooks.json.",
                )

        basenames = self._collect_basenames(self.repo_root)
        for rt in runtime_roots:
            basenames |= self._collect_basenames(rt)
        for md in self._markdown_files():
            text = self._read_text(md)
            target = self._rel(md)
            is_historical = md.name in _HISTORICAL_LEDGER_NAMES or target.startswith("docs/adr/")
            if not is_historical:
                for lineno, line in enumerate(text.splitlines(), 1):
                    m_stale = _STALE_XDG_GUARD_RE.search(line)
                    if m_stale:
                        self._add(
                            "WARNING",
                            name,
                            f"{target}:{lineno}",
                            f"Stale 1.x XDG path `{m_stale.group(0)}` referenced (v2.0 uses `antigravity-harness`)",
                            "Update XDG path from `antigravity-guard` to `antigravity-harness`.",
                        )
                    for m_rt in re.finditer(r"~/\.local/share/antigravity-harness/runtime/([A-Za-z0-9_./-]+)", line):
                        rel_rt = m_rt.group(1).rstrip(".,:;)`'\"")
                        if rel_rt and "." in rel_rt.rsplit("/", 1)[-1]:
                            rt_candidates = [self.repo_root / rel_rt] + [rt / rel_rt for rt in runtime_roots]
                            if not any(c.exists() for c in rt_candidates):
                                self._add(
                                    "WARNING",
                                    name,
                                    f"{target}:{lineno}",
                                    f"Referenced runtime path `~/.local/share/antigravity-harness/runtime/{rel_rt}` does not exist",
                                    f"Update the runtime path or restore `{rel_rt}`.",
                                )
                    for m_cfg in re.finditer(r"~/\.gemini/config/([A-Za-z0-9_./-]+)", line):
                        rel_cfg_line = m_cfg.group(1).rstrip(".,:;)`'\"")
                        cfg_head_line = rel_cfg_line.split("/", 1)[0]
                        if rel_cfg_line and cfg_head_line in config_mapped_heads and "." in rel_cfg_line.rsplit("/", 1)[-1]:
                            cfg_candidates = [self.repo_root / rel_cfg_line] + [rt / rel_cfg_line for rt in runtime_roots]
                            if not any(c.exists() for c in cfg_candidates):
                                self._add(
                                    "WARNING",
                                    name,
                                    f"{target}:{lineno}",
                                    f"Referenced config path `~/.gemini/config/{rel_cfg_line}` does not exist in repository",
                                    f"Update the config path or restore `{rel_cfg_line}`.",
                                )
            text_no_code = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
            for link in re.findall(r'\]\(([^)\s]+)(?:\s+"[^"]*"|\s+\'[^\']*\')?\)', text_no_code):
                if re.match(r"^(https?:|mailto:|<|conversation:)", link) or "{" in link:
                    continue
                if link.startswith("#"):
                    frag = link[1:]
                    if not is_historical and frag and not _LINE_ANCHOR_RE.fullmatch(frag):
                        own_slugs, _ = self._heading_slugs_and_sections(md)
                        if frag.lower() not in own_slugs:
                            self._add(
                                "CRITICAL",
                                name,
                                target,
                                f"Broken Markdown heading anchor '{link}' in {target}",
                                "Update the #anchor fragment to match an actual ATX heading.",
                            )
                    continue
                if link.startswith("file://"):
                    path_and_frag = link[len("file://"):].split("#", 1)
                    parsed_path = path_and_frag[0]
                    frag = path_and_frag[1] if len(path_and_frag) > 1 else ""
                    if any(p in parsed_path for p in ("/path/to/", "/absolute/path", "<", ">")):
                        continue
                    resolved_file = Path(parsed_path) if parsed_path else None
                    if resolved_file and not resolved_file.exists():
                        self._add("WARNING", name, target, f"Broken file:// link '{link}'", "Fix the link target or use a relative link.")
                    elif (
                        not is_historical
                        and resolved_file
                        and resolved_file.is_file()
                        and resolved_file.suffix.lower() == ".md"
                        and frag
                        and not _LINE_ANCHOR_RE.fullmatch(frag)
                    ):
                        t_slugs, _ = self._heading_slugs_and_sections(resolved_file)
                        if frag.lower() not in t_slugs:
                            self._add(
                                "CRITICAL",
                                name,
                                target,
                                f"Broken Markdown heading anchor '#{frag}' in link '{link}'",
                                "Update the #anchor fragment to match an actual heading in the target file.",
                            )
                    continue
                rel_parts = link.split("#", 1)
                path_part = rel_parts[0]
                frag = rel_parts[1] if len(rel_parts) > 1 else ""
                resolved_rel = (md.parent / path_part) if path_part else md
                if path_part and not resolved_rel.exists():
                    self._add("WARNING", name, target, f"Broken relative link '{link}'", "Fix the link target or remove the link.")
                elif (
                    not is_historical
                    and resolved_rel.is_file()
                    and resolved_rel.suffix.lower() == ".md"
                    and frag
                    and not _LINE_ANCHOR_RE.fullmatch(frag)
                ):
                    t_slugs, _ = self._heading_slugs_and_sections(resolved_rel)
                    if frag.lower() not in t_slugs:
                        self._add(
                            "CRITICAL",
                            name,
                            target,
                            f"Broken Markdown heading anchor '#{frag}' in link '{link}'",
                            f"Update '#{frag}' to match an actual heading in {self._rel(resolved_rel)}.",
                        )

            if not is_historical and "§" in text_no_code:
                sec_atom = r"§\d+(?:\.[A-Za-z0-9]+)?(?:`?\s*\([^§)\n]{1,60}\))?"
                sec_chain_pat = rf"{sec_atom}(?:\s*(?:,|&|and|/|[–-])\s*`?{sec_atom})*"
                doc_sec_re = re.compile(
                    rf"(?:`([A-Za-z0-9_./-]+\.md)`|(?<![/\w.-])([A-Za-z0-9_./-]+\.md)|\[[^\]]+\]\((?:\./)?([A-Za-z0-9_./-]+\.md)(?:#[^)\s]*)?(?:\s+\"[^\"]*\"|\s+'[^']*')?\)|`([a-z][a-z0-9-]*)`)(?:\]\([^)]+\))?\s*(?:\(\s*)?`?({sec_chain_pat})"
                )
                in_fence_sec = False
                for lineno_s, line_s in enumerate(text.splitlines(), 1):
                    if line_s.lstrip().startswith("```"):
                        in_fence_sec = not in_fence_sec
                        continue
                    if in_fence_sec or "§" not in line_s:
                        continue
                    covered_spans: List[Tuple[int, int]] = []
                    for m_ds in doc_sec_re.finditer(line_s):
                        covered_spans.append(m_ds.span())
                        ref_md = m_ds.group(1) or m_ds.group(2) or m_ds.group(3)
                        ref_skill = m_ds.group(4)
                        sec_chain = m_ds.group(5)
                        cand_docs: List[Path] = []
                        ref_label = ref_md or ref_skill or ""
                        if ref_md:
                            cand_docs = [self.repo_root / ref_md, md.parent / ref_md] + [rt / ref_md for rt in runtime_roots]
                        elif ref_skill and ref_skill in available_skills:
                            cand_docs = [self.repo_root / "skills" / ref_skill / "SKILL.md"]
                        else:
                            continue
                        target_doc = next((c for c in cand_docs if c.is_file()), None)
                        if target_doc is None:
                            continue
                        _, doc_sections = self._heading_slugs_and_sections(target_doc)
                        for sec_tok in re.findall(r"§(\d+(?:\.[A-Za-z0-9]+)?)\b", sec_chain):
                            norm_sec = sec_tok.upper()
                            if norm_sec not in doc_sections and norm_sec.replace(".", "") not in doc_sections:
                                self._add(
                                    "CRITICAL",
                                    name,
                                    f"{target}:{lineno_s}",
                                    f"Broken section reference `{ref_label} §{sec_tok}` (section `{sec_tok}` not found in `{self._rel(target_doc)}`)",
                                    f"Update `§{sec_tok}` to match an actual numbered heading in `{self._rel(target_doc)}`.",
                                )
                    for m_own in re.finditer(r"§(\d+(?:\.[A-Za-z0-9]+)?)\b", line_s):
                        pos = m_own.start()
                        if any(s <= pos < e for s, e in covered_spans):
                            continue
                        prefix_tail = line_s[:pos][-40:]
                        if re.search(r"(?:\.md`?(?:\]\([^)]+\))?\s*\(?\s*|Rule\s+\d+\s*\(?\s*)$", prefix_tail):
                            continue
                        _, own_sections = self._heading_slugs_and_sections(md)
                        if own_sections:
                            norm_own = m_own.group(1).upper()
                            if norm_own not in own_sections and norm_own.replace(".", "") not in own_sections:
                                self._add(
                                    "CRITICAL",
                                    name,
                                    f"{target}:{lineno_s}",
                                    f"Broken internal section reference `§{m_own.group(1)}` in `{target}`",
                                    f"Update `§{m_own.group(1)}` to match an actual numbered heading in `{target}`.",
                                )
            for token in set(re.findall(r"`([^`\s]+)`", text_no_code)):
                clean = token.rstrip(".,:;)")
                if clean.startswith("~/.gemini/config/") and not any(c in clean for c in "<>*{}$"):
                    rel_cfg = clean[len("~/.gemini/config/"):].rstrip("/")
                    cfg_head = rel_cfg.split("/", 1)[0]
                    if rel_cfg and cfg_head in config_mapped_heads and "." in rel_cfg.rsplit("/", 1)[-1]:
                        candidates = [self.repo_root / rel_cfg] + [rt / rel_cfg for rt in runtime_roots]
                        if not any(c.exists() for c in candidates):
                            self._add("WARNING", name, target,
                                      f"Referenced config path `{clean}` does not exist in repository (`{rel_cfg}`)",
                                      "Update the config path or restore the file in the repository.")
                    continue
                if any(c in clean for c in "<>*{}$~") or clean.startswith(("/", "http")):
                    continue
                head = clean.split("/", 1)[0]
                if "/" in clean and head in top_dirs and "." in clean.rsplit("/", 1)[-1]:
                    parts = md.relative_to(self.repo_root).parts
                    skill_root = self.repo_root / parts[0] / parts[1] if len(parts) > 2 and parts[0] == "skills" else md.parent
                    candidates = [self.repo_root / clean, md.parent / clean, skill_root / clean]
                    if is_split_layout and head in code_dirs:
                        candidates.extend(rt / clean for rt in runtime_roots)
                        if head == "tests" and not any((r / "tests").is_dir() for r in [self.repo_root] + runtime_roots):
                            continue
                    if not any(c.exists() for c in candidates):
                        self._add("WARNING", name, target, f"Referenced repository path `{clean}` does not exist",
                                  "Update the path or restore the file.")
                elif re.fullmatch(r"[\w.-]+\.md", clean) and clean not in KNOWN_EXTERNAL_MD and clean not in basenames:
                    self._add("WARNING", name, target, f"Referenced file `{clean}` does not exist anywhere in the repository",
                              "Reference the real file path (e.g. skills/<name>/SKILL.md).")

        self._check_slash_commands(name)

    _SECTION_DECLARES = re.compile(r"(?i)invocation|trigger|slash|command")
    _LINE_DECLARES = re.compile(r"(?i)slash commands?|triggers?:|invoke with")

    @staticmethod
    def _code_spans(line: str) -> List[str]:
        """Inline code spans, paired left to right (so text between two spans is never taken as code)."""
        return re.findall(r"`([^`\n]*)`", line)

    @staticmethod
    def _frontmatter_slash_commands(text: str) -> Set[str]:
        if not text.startswith("---"):
            return set()
        parts = text.split("---", 2)
        return set(re.findall(r"(?<![\w/.])(/[a-z][a-z0-9-]*)", parts[1])) if len(parts) >= 3 else set()

    def _declared_slash_commands(self) -> Set[str]:
        """Commands a skill declares in its YAML frontmatter description."""
        declared: Set[str] = set()
        for skill_md in sorted((self.repo_root / "skills").glob("*/SKILL.md")):
            text = self._read_text(skill_md)
            declared |= self._frontmatter_slash_commands(text)
        return declared

    def _check_slash_commands(self, name: str) -> None:
        """Instructions must not point the agent or the user at slash commands no skill provides in frontmatter."""
        declared = self._declared_slash_commands()
        sources = [self.repo_root / "GEMINI.md"] + sorted((self.repo_root / "agents").glob("*.md")) \
            + sorted((self.repo_root / "templates").glob("*.md")) + sorted((self.repo_root / "skills").rglob("*.md"))
        for md in sources:
            if not md.is_file() or SKIP_DIRS.intersection(md.relative_to(self.repo_root).parts):
                continue
            text = self._read_text(md)
            is_skill_root = md.name == "SKILL.md" and md.parent.parent == (self.repo_root / "skills")
            own_fm_cmds = self._frontmatter_slash_commands(text) if is_skill_root else set()
            in_fence = False
            in_section = False
            for number, line in enumerate(text.splitlines(), 1):
                if line.lstrip().startswith("```"):
                    in_fence = not in_fence
                    continue
                if in_fence:
                    continue
                if line.startswith("#"):
                    in_section = bool(self._SECTION_DECLARES.search(line))
                declares_line = is_skill_root and (in_section or bool(self._LINE_DECLARES.search(line)))
                for span in self._code_spans(line):
                    m = re.match(r"(/[a-z][a-z0-9-]*)(?![/\w.])", span)
                    if not m:
                        continue
                    cmd = m.group(1)
                    if cmd not in declared:
                        self._add("WARNING", name, f"{self._rel(md)}:{number}",
                                  f"Slash command `{cmd}` is not provided by any skill's YAML frontmatter description",
                                  "Add the command to the skill's YAML frontmatter description or point to an existing skill.")
                    elif declares_line and cmd not in own_fm_cmds:
                        self._add("WARNING", name, f"{self._rel(md)}:{number}",
                                  f"Slash command `{cmd}` is declared in skill body but absent from YAML frontmatter description",
                                  "Add the command to this skill's YAML frontmatter description.")

    # ------------------------------------------------------------------
    # Pass 3
    # ------------------------------------------------------------------
    def pass3_directive_collision_and_mutex(self) -> None:
        name = "Pass 3 (Directive Collision & Mutex)"
        skills_dir = self.repo_root / "skills"
        for skill in MODE_SKILLS:
            f = skills_dir / skill / "SKILL.md"
            if not f.is_file():
                continue
            content = self._read_text(f)
            section = re.search(r"(?ims)^#+\s*mutual exclusion[^\n]*\n(.*?)(?=^#+\s|\Z)", content)
            body = section.group(1) if section else ""
            missing = []
            if not section:
                missing.append("a '## Mutual Exclusion' section")
            else:
                if "harness" not in body:
                    missing.append("the partner skill 'harness'")
                if not re.search(r"(?i)\b(activat|trigger|exclusively|only when)", body):
                    missing.append("an activation condition")
                deact_re = rf"(?i)(?:\*\*deactivation[^*]*\*\*|\bdeactivation\s*:|\boff\s+only\s+when\b|\bends\s+when\b|(?<!do\snot\s)\bstop\s+{re.escape(skill)}\b)"
                if not re.search(deact_re, body):
                    missing.append("a deactivation condition")
            if missing:
                self._add("WARNING", name, f"skills/{skill}/SKILL.md",
                          f"Skill '{skill}' lacks an explicit mutual exclusion barrier with 'harness' (missing {', '.join(missing)}).",
                          "Add a '## Mutual Exclusion' section naming the trigger, the deactivation and 'harness'.")

        thresholds = {}
        for rel in ("GEMINI.md", "skills/harness/SKILL.md", "skills/unlazy/SKILL.md"):
            p = self.repo_root / rel
            if p.is_file():
                m = re.search(r"(?is)tier\s*3[^\n]*?\n?.{0,300}?(?:>\s*(\d+)\s*files|\b(\d+)\+\s*files)", self._read_text(p))
                if m:
                    thresholds[rel] = int(m.group(1) or m.group(2)) + (0 if m.group(1) else -1)
        for md in self._markdown_files():
            rel = self._rel(md)
            if rel in thresholds:
                continue
            for m in re.finditer(r"(?i)\btier\s*3\b[^\n]{0,120}?(?:>\s*(\d+)\s*files|\b(\d+)\+\s*files)", self._read_text(md)):
                thresholds[rel] = int(m.group(1) or m.group(2)) + (0 if m.group(1) else -1)
        if len(set(thresholds.values())) > 1:
            self._add("WARNING", name, ", ".join(thresholds),
                      f"Tier 3 file thresholds disagree: {thresholds} (as 'more than N files')",
                      "Use one threshold everywhere (GEMINI.md is the source of truth).")

    # ------------------------------------------------------------------
    # Pass 4
    # ------------------------------------------------------------------
    def pass4_porter_parity(self) -> None:
        name = "Pass 4 (Porter Parity)"
        try:
            from porter.emitters import EMITTERS
            from porter.manifest import ManifestEngine
            from porter.sanitizer import find_directives
        except Exception as e:
            self._add("CRITICAL", name, "porter", f"Porter could not be imported: {e}", "Resolve the import error.")
            return

        engine = ManifestEngine(harness_root=self.repo_root)
        manifest = engine.build_manifest(deterministic=True)
        if not manifest.constitution.get("raw"):
            self._add("CRITICAL", name, "porter/manifest.py", "Manifest failed to ingest GEMINI.md.", "Ensure GEMINI.md exists.")

        committed = self.repo_root / ".harness" / "manifest.json"
        if committed.is_file():
            is_split, m_skills, m_agents, m_templates = self._split_layout_managed_sets(committed)
            check_manifest = manifest
            if is_split and m_skills is not None and m_agents is not None and m_templates is not None:
                import copy

                check_manifest = copy.copy(manifest)
                check_manifest.skills = [s for s in manifest.skills if s.get("name") in m_skills]
                check_manifest.agents = [a for a in manifest.agents if a.get("name") in m_agents]
                check_manifest.templates = {k: v for k, v in manifest.templates.items() if k in m_templates}
            if not engine.is_up_to_date(committed, manifest=check_manifest):
                sys_share = Path(os.environ.get("ANTIGRAVITY_SHARE_DIR", "/usr/share/antigravity-harness"))
                if not (self.repo_root / "install.py").is_file() and (
                    "share/antigravity-harness" in self.repo_root.as_posix()
                    or sys_share.is_dir()
                    or not (REPO_ROOT / "install.py").is_file()
                ):
                    fix_msg = "Run 'agy-guard init' to refresh installed governance assets from /usr/share/antigravity-harness."
                elif is_split:
                    fix_msg = "Re-run 'python3 install.py' from the source checkout to refresh installed governance assets."
                else:
                    fix_msg = "Run 'python3 porter.py manifest' and commit the result."
                self._add(
                    "CRITICAL",
                    name,
                    ".harness/manifest.json",
                    "Committed manifest is stale (content differs from a fresh build).",
                    fix_msg,
                )

        readonly_agents: Set[str] = set()
        for agent in manifest.agents:
            a_fm, _ = _load_yaml_frontmatter(agent.get("raw", ""))
            if isinstance(a_fm, dict) and str(a_fm.get("access", "")).strip() == "read-only":
                readonly_agents.add(str(agent["name"]))

        leak_re = re.compile(r"<RULE\[|<appDataDir>|\binvoke_subagent\b|\bmanage_task\b")
        for target, emitter in EMITTERS.items():
            with tempfile.TemporaryDirectory(prefix=f"agy-parity-{target}-") as tmp:
                out = Path(tmp)
                try:
                    emitter.emit(manifest, out, force=True)
                except Exception as e:
                    self._add("CRITICAL", name, f"porter/emitters/{target}.py", f"Emitter crashed: {e}", "Fix the emitter.")
                    continue
                losses = []
                for skill in manifest.skills:
                    base = out / emitter.SKILLS_DIR / skill["name"]
                    try:
                        if (base / "SKILL.md").read_text(encoding="utf-8") != skill["raw"]:
                            losses.append(f"{skill['name']}/SKILL.md altered")
                    except OSError:
                        losses.append(f"{skill['name']}/SKILL.md missing")
                    for rel in skill.get("subfiles", {}):
                        if not (base / rel).is_file():
                            losses.append(f"{skill['name']}/{rel}")
                    for rel in skill.get("links", {}):
                        if not os.path.lexists(base / rel):
                            losses.append(f"{skill['name']}/{rel} (link)")
                    for rel in skill.get("executables", []) if os.name != "nt" else []:
                        if (base / rel).is_file() and not os.access(base / rel, os.X_OK):
                            losses.append(f"{skill['name']}/{rel} (executable bit)")
                for tmpl in getattr(manifest, "templates", {}) or {}:
                    if not (out / "templates" / tmpl).is_file():
                        losses.append(f"templates/{tmpl}")
                for agent in manifest.agents:
                    p = out / emitter.AGENTS_DIR / f"{agent['name']}.md"
                    if not p.is_file() or p.read_text(encoding="utf-8") != agent["raw"]:
                        losses.append(f"agent {agent['name']}")
                if losses:
                    self._add("CRITICAL", name, f"porter/emitters/{target}.py",
                              f"Export to '{target}' lost {len(losses)} item(s): {', '.join(losses[:5])}",
                              "Emit every skill, support file, link and agent verbatim.")
                for f in sorted(out.rglob("*.mdc")):
                    _, err = _load_yaml_frontmatter(f.read_text(encoding="utf-8"))
                    if err:
                        self._add("CRITICAL", name, f"porter/emitters/{target}.py", f"{f.name}: {err}", "Emit frontmatter via dump_frontmatter().")
                if target == "claude":
                    claude_agents_dir = out / ".claude" / "agents"
                    for a_name in sorted(readonly_agents):
                        ca_file = claude_agents_dir / f"{a_name}.md"
                        if not ca_file.is_file():
                            self._add(
                                "CRITICAL",
                                name,
                                f"porter/emitters/{target}.py",
                                f".claude/agents/{a_name}.md missing for read-only agent",
                                "Emit native .claude/agents/<name>.md files for all agents.",
                            )
                    if claude_agents_dir.is_dir():
                        for ca_file in sorted(claude_agents_dir.glob("*.md")):
                            ca_data, ca_err = _load_yaml_frontmatter(ca_file.read_text(encoding="utf-8"))
                            if ca_err:
                                self._add(
                                    "CRITICAL",
                                    name,
                                    f"porter/emitters/{target}.py",
                                    f".claude/agents/{ca_file.name}: {ca_err}",
                                    "Emit valid frontmatter in .claude/agents/*.md.",
                                )
                            elif ca_file.stem in readonly_agents:
                                tools_val = ca_data.get("tools") if isinstance(ca_data, dict) else None
                                if not tools_val or (isinstance(tools_val, str) and not tools_val.strip()):
                                    self._add(
                                        "CRITICAL",
                                        name,
                                        f"porter/emitters/{target}.py",
                                        f".claude/agents/{ca_file.name}: missing 'tools' frontmatter allow-list for read-only agent",
                                        "Emit a read-only 'tools:' allow-list in Claude native subagent frontmatter.",
                                    )
                for top_rule in ("CLAUDE.md", "AGENTS.md", "CONVENTIONS.md", "RULES.md"):
                    top_path = out / top_rule
                    if top_path.is_file():
                        top_text = top_path.read_text(encoding="utf-8", errors="replace")
                        m_leak = leak_re.search(top_text)
                        if m_leak:
                            self._add(
                                "CRITICAL",
                                name,
                                f"porter/emitters/{target}.py",
                                f"{top_rule} contains leaked Antigravity runtime token `{m_leak.group(0)}`",
                                "Sanitize Antigravity-only tags and tool names before emitting portable rule files.",
                            )

        sources = [("GEMINI.md", manifest.constitution.get("raw", "")), ("DESIGN.md", manifest.design_contract.get("raw", ""))]
        sources += [(f"skills/{s['name']}/SKILL.md", s["raw"]) for s in manifest.skills]
        sources += [(f"agents/{a['name']}.md", a["raw"]) for a in manifest.agents]
        for rel, text in sources:
            hits = find_directives(text)
            if hits:
                self._add("CRITICAL", name, rel,
                          f"Harness content trips its own sanitizer at line {hits[0].line_start + 1}: \"{hits[0].text[:70]}\"",
                          "Rephrase as an explicit prohibition or fix the sanitizer false positive.")

    # ------------------------------------------------------------------
    # Pass 5
    # ------------------------------------------------------------------
    def pass5_cli_doc_sync(self) -> None:
        name = "Pass 5 (CLI & Doc Sync)"
        readme = self.repo_root / "README.md"
        cli = self.repo_root / "guard" / "cli.py"
        if not readme.is_file() or not cli.is_file():
            return
        text = readme.read_text(encoding="utf-8", errors="ignore")
        try:
            from guard.cli import build_parser
            from guard.environment import VALID_POLICIES
        except Exception as e:
            self._add("CRITICAL", name, "guard/cli.py", f"CLI parser could not be imported: {e}", "Fix guard/cli.py.")
            return
        parser = build_parser()
        sub_action = next(a for a in parser._actions if a.__class__.__name__ == "_SubParsersAction")
        commands = set(sub_action.choices)
        public = commands - {"lease-tick"}

        for cmd in sorted(public):
            if f"agy-guard {cmd}" not in text and f"`{cmd}`" not in text:
                self._add("WARNING", name, "README.md", f"CLI subcommand '{cmd}' is not documented in README.md",
                          f"Document 'agy-guard {cmd}'.")
        workflow_line = next((l for l in text.splitlines() if "Full CLI Workflow" in l), "")
        for m in re.finditer(r"`([a-z][a-z-]+)`", workflow_line.split(":", 1)[-1]):
            if m.group(1) not in commands:
                self._add("CRITICAL", name, "README.md", f"README lists CLI command '{m.group(1)}' which does not exist",
                          "Remove it or implement it.")

        valid_porter_cmds = {"inspect", "import", "export", "manifest", "--help", "-h", "--version"}
        for block in re.findall(r"```(?:bash|sh|shell)?\n(.*?)```", text, re.DOTALL):
            for line in block.splitlines():
                line = line.split(" #", 1)[0].strip()
                if line.startswith("agy-guard "):
                    argv = shlex.split(line)[1:]
                    try:
                        parser.parse_args(argv)
                    except SystemExit:
                        self._add("CRITICAL", name, "README.md", f"README example does not parse: `{line}`",
                                  "Fix the example to match the CLI.")
                elif line.startswith(("python3 porter.py ", "porter.py ", "agy-porter ")):
                    tokens = shlex.split(line)
                    porter_argv = tokens[2:] if tokens[0] == "python3" else tokens[1:]
                    if porter_argv and porter_argv[0] not in valid_porter_cmds:
                        self._add("CRITICAL", name, "README.md",
                                  f"README porter example uses unknown subcommand '{porter_argv[0]}': `{line}`",
                                  f"Use one of: {', '.join(sorted(valid_porter_cmds))}.")

        claims = {
            "subcommands": (r"\((\d+)\s+subcommands\)", len(public)),
            "tests": (r"\((\d+)\s+(?:passing\s+)?tests\)", self._count_tests()),
            "skills": (r"\b(\d+)\s+(?:modular\s+)?skills\b", self._count_dirs("skills")),
            "subagents": (r"\b(\d+)\s+(?:autonomous\s+|read-only\s+|auditor\s+)?subagents?\b", self._count_agents()),
        }
        for label, (pattern, actual) in claims.items():
            for m in re.finditer(pattern, text):
                if int(m.group(1)) != actual:
                    self._add("WARNING", name, "README.md", f"README claims {m.group(1)} {label}; actual is {actual}",
                              f"Update the {label} count.")

        for m in re.finditer(r"(?i)policies\s*\(([^)]*)\)", text):
            names = re.findall(r"`([a-z_]+)`", m.group(1))
            unknown = [n for n in names if n not in VALID_POLICIES]
            if unknown:
                self._add("CRITICAL", name, "README.md", f"README names policies {unknown} that the code does not accept",
                          f"Use {', '.join(VALID_POLICIES)}.")

        guard_py = self.repo_root / "guard.py"
        if guard_py.is_file():
            doc = guard_py.read_text(encoding="utf-8", errors="ignore")
            for cmd in sorted(public):
                if cmd not in doc:
                    self._add("INFO", name, "guard.py", f"Subcommand '{cmd}' is not listed in the guard.py docstring",
                              f"Document 'python3 guard.py {cmd}'.")

        pkgbuild = self.repo_root / "installers" / "packaging" / "PKGBUILD"
        pkg_linux = self.repo_root / "installers" / "packaging" / "package_linux.py"
        if pkgbuild.is_file():
            pb_text = pkgbuild.read_text(encoding="utf-8", errors="ignore")
            for req_tok in ("porter.py", "agy-porter", "hooks.json", ".harness/manifest.json", "bash-completion/completions/agy-guard"):
                if req_tok not in pb_text:
                    self._add(
                        "WARNING",
                        name,
                        "installers/packaging/PKGBUILD",
                        f"PKGBUILD is missing required packaging artifact `{req_tok}`",
                        f"Install `{req_tok}` inside PKGBUILD package() to maintain parity with package_linux.py.",
                    )
        if pkg_linux.is_file():
            pl_text = pkg_linux.read_text(encoding="utf-8", errors="ignore")
            for req_tok in ("porter.py", "agy-porter", "hooks.json", "manifest.json", "bash-completion"):
                if req_tok not in pl_text:
                    self._add(
                        "WARNING",
                        name,
                        "installers/packaging/package_linux.py",
                        f"package_linux.py is missing required packaging artifact `{req_tok}`",
                        f"Stage `{req_tok}` in LinuxPackager._prepare_payload.",
                    )

    def _count_tests(self) -> int:
        tests = self.repo_root / "tests"
        if not tests.is_dir():
            return 0
        return sum(len(re.findall(r"^\s+def (test_\w+)\(", f.read_text(encoding="utf-8", errors="ignore"), re.M))
                   for f in tests.glob("test_*.py"))

    def _count_dirs(self, rel: str) -> int:
        d = self.repo_root / rel
        return sum(1 for p in d.iterdir() if p.is_dir() and (p / "SKILL.md").is_file()) if d.is_dir() else 0

    def _count_agents(self) -> int:
        d = self.repo_root / "agents"
        return len(list(d.glob("*.md"))) if d.is_dir() else 0

    # ------------------------------------------------------------------
    # Pass 6
    # ------------------------------------------------------------------
    def pass6_design_contract(self) -> None:
        name = "Pass 6 (Design Contract Measurements)"
        design = self.repo_root / "DESIGN.md"
        if not design.is_file():
            return
        text = design.read_text(encoding="utf-8", errors="ignore")
        section = re.search(r"(?is)#+\s*measured contrast pairs\s*\n(.*?)(?=\n#+\s|\Z)", text)
        if not section:
            if re.search(r"\d+\.\d+:1", text):
                self._add("WARNING", name, "DESIGN.md", "Contrast ratios are stated without a machine-checkable 'Measured Contrast Pairs' table.",
                          "Add the table (Pair | Foreground | Background | Ratio | Minimum).")
            return
        for row in section.group(1).splitlines():
            cells = [c.strip().strip("`") for c in row.strip().strip("|").split("|")]
            if len(cells) < 5 or not re.fullmatch(r"#[0-9A-Fa-f]{6}", cells[1] or ""):
                continue
            pair, fg, bg, stated, minimum = cells[:5]
            try:
                stated_v = float(stated.split(":")[0])
                minimum_v = float(minimum.split(":")[0])
            except ValueError:
                continue
            actual = contrast_ratio(fg, bg)
            if abs(actual - stated_v) > 0.05:
                self._add("CRITICAL", name, "DESIGN.md", f"{pair}: stated {stated_v:.2f}:1 but {fg}/{bg} measures {actual:.2f}:1",
                          "Recompute with skills/antislop-human/contrast-check.py.")
            if actual + 1e-9 < minimum_v:
                self._add("CRITICAL", name, "DESIGN.md", f"{pair}: {actual:.2f}:1 is below the required {minimum_v:.1f}:1",
                          "Choose a color pair that meets the minimum.")

    def _split_layout_managed_sets(
        self, committed_manifest: Optional[Path] = None
    ) -> tuple[bool, Optional[set[str]], Optional[set[str]], Optional[set[str]]]:
        """On non-checkout split layouts, scope manifest/hint checks to harness-managed entries."""
        is_split = not (self.repo_root / "porter.py").is_file() and not (self.repo_root / "guard.py").is_file()
        if not is_split:
            return False, None, None, None
        m_path = committed_manifest or (self.repo_root / ".harness" / "manifest.json")
        managed_skills: set[str] = set()
        managed_agents: set[str] = set()
        managed_templates: set[str] = set()
        has_anchor = False
        if m_path.is_file():
            try:
                cdata = json.loads(m_path.read_text(encoding="utf-8"))
                if isinstance(cdata, dict):
                    has_anchor = True
                    for s in cdata.get("skills") or []:
                        if isinstance(s, dict) and s.get("name"):
                            managed_skills.add(str(s["name"]))
                    for a in cdata.get("agents") or []:
                        if isinstance(a, dict) and a.get("name"):
                            managed_agents.add(str(a["name"]))
                    t_map = cdata.get("templates")
                    if isinstance(t_map, dict):
                        managed_templates.update(str(k) for k in t_map)
            except (OSError, ValueError):
                pass
        try:
            from guard.paths import state_dir

            receipt_file = state_dir() / "install_receipt.json"
            if receipt_file.is_file():
                rdata = json.loads(receipt_file.read_text(encoding="utf-8"))
                if isinstance(rdata, dict) and rdata.get("target"):
                    if Path(str(rdata["target"])).expanduser().resolve() == self.repo_root.resolve():
                        has_anchor = True
                        for rel in rdata.get("installed") or []:
                            parts = str(rel).replace("\\", "/").split("/")
                            if len(parts) >= 2 and parts[0] == "skills":
                                managed_skills.add(parts[1])
                            elif len(parts) >= 2 and parts[0] == "agents":
                                managed_agents.add(Path(parts[1]).stem)
                            elif len(parts) >= 2 and parts[0] == "templates":
                                managed_templates.add(parts[1])
        except Exception:
            pass
        if not has_anchor:
            return True, None, None, None
        return True, managed_skills, managed_agents, managed_templates

    # ------------------------------------------------------------------
    # Pass 7
    # ------------------------------------------------------------------
    _NEGATIVE_TRIGGER_RE = re.compile(
        r"(?i)\b(?:not\s+for\b|do\s+not\s+(?:use|co-load|invoke)\b|don't\s+use\s+(?:for|on|to|when)\b|skip\s+[^.;]{1,60}\bfor\b|(?:use|invoke)\s+(?:this\s+skill\s+)?exclusively\s+when\b|never\s+(?:use|invoke)\s+to\b)"
    )
    _HINT_STOP_WORDS = frozenset({
        "and", "the", "for", "with", "from", "into", "this", "our", "dan", "den", "tan", "ten",
        "ing", "ies", "imi", "leri", "sini", "http", "https", "true", "false",
    })

    @classmethod
    def _extract_standalone_literals(cls, pattern: str) -> Set[str]:
        words: Set[str] = set()
        for m in re.finditer(r"(?:(?<!\w)\(\?:|\|)([a-z][a-z0-9_-]{2,})(?:\\b)?(?=\||\))", pattern):
            rest = pattern[m.end():]
            if re.match(r"^(?:\|[a-z0-9_\\-]+)*\)\??(?=\\s)", rest):
                continue
            w = m.group(1)
            if w not in cls._HINT_STOP_WORDS:
                words.add(w)
        return words

    @staticmethod
    def _extract_pre_invocation_text(res: object) -> str:
        if not isinstance(res, dict):
            return ""
        parts: List[str] = []
        hso = res.get("hookSpecificOutput")
        if isinstance(hso, dict) and hso.get("additionalContext"):
            parts.append(str(hso["additionalContext"]))
        if res.get("systemMessage"):
            parts.append(str(res["systemMessage"]))
        inj = res.get("injectSteps")
        if isinstance(inj, list):
            for step in inj:
                if isinstance(step, dict) and step.get("ephemeralMessage"):
                    parts.append(str(step["ephemeralMessage"]))
        return "\n".join(parts)

    def _resolve_hooks_py_for_audit(self, allow_split_fallback: bool = False) -> Path:
        direct = self.repo_root / "guard" / "agy_hooks.py"
        if direct.is_file():
            return direct
        relocated = self.repo_root.parent.parent / "lib" / "antigravity-guard" / "guard" / "agy_hooks.py"
        if relocated.is_file():
            return relocated
        if not allow_split_fallback:
            return direct
        candidates: List[Path] = []
        try:
            from guard.paths import data_dir

            candidates.append(data_dir() / "runtime" / "guard" / "agy_hooks.py")
        except Exception:
            pass
        candidates.extend([
            Path.home() / ".local" / "share" / "antigravity-harness" / "runtime" / "guard" / "agy_hooks.py",
            Path("/usr/lib/antigravity-guard/guard/agy_hooks.py"),
            REPO_ROOT / "guard" / "agy_hooks.py",
        ])
        for cand in candidates:
            if cand.is_file():
                return cand
        return direct

    def pass7_trigger_specificity(self) -> None:
        name = "Pass 7 (Trigger Specificity)"
        skills_dir = self.repo_root / "skills"
        if not skills_dir.is_dir():
            return
        is_split, managed_skills, _, _ = self._split_layout_managed_sets()
        hooks_py = self._resolve_hooks_py_for_audit(allow_split_fallback=bool(is_split and managed_skills is not None))
        hint_map: Dict[str, object] = {}
        eco_hints: List[Tuple[str, object, str]] = []
        hooks_mod = None
        if hooks_py.is_file() and ("SKILL_HINTS" in self._read_text(hooks_py) or "ECOSYSTEM_ROUTING_HINTS" in self._read_text(hooks_py)):
            try:
                import importlib.util

                spec = importlib.util.spec_from_file_location("_meta_audit_agy_hooks", hooks_py)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    hooks_mod = mod
                    for s_name, s_rel, s_rx, _reason in getattr(mod, "SKILL_HINTS", ()):
                        hint_map[s_name] = (s_rel, s_rx)
                        if (
                            not is_split
                            and str(s_rel).startswith("skills/")
                            and not (self.repo_root / s_rel).is_file()
                        ):
                            self._add(
                                "WARNING",
                                name,
                                "guard/agy_hooks.py",
                                f"SKILL_HINTS entry `{s_name}` points to missing file `{s_rel}`",
                                f"Restore `{s_rel}` or update SKILL_HINTS in guard/agy_hooks.py.",
                            )
                    for r_entry in getattr(mod, "ECOSYSTEM_ROUTING_HINTS", ()):
                        if isinstance(r_entry, tuple) and len(r_entry) == 3:
                            eco_hints.append(r_entry)
            except Exception as exc:
                self._add(
                    "CRITICAL",
                    name,
                    "guard/agy_hooks.py",
                    f"Could not load SKILL_HINTS from guard/agy_hooks.py: {exc}",
                    "Ensure guard/agy_hooks.py imports cleanly.",
                )

        if hooks_mod is not None and (hint_map or eco_hints):
            probe_slugs: Set[str] = set()
            for s_name, (_s_rel, s_rx) in hint_map.items():  # type: ignore[misc]
                probe_slugs.add(str(s_name))
                if isinstance(s_rx, re.Pattern):
                    probe_slugs.update(re.findall(r"/([a-z][a-z0-9-]*)", s_rx.pattern))
                    probe_slugs.update(self._extract_standalone_literals(s_rx.pattern))
            for r_key, r_rx, _r_dir in eco_hints:
                tail_slug = str(r_key).rsplit(":", 1)[-1]
                if tail_slug:
                    probe_slugs.add(tail_slug)
                if isinstance(r_rx, re.Pattern):
                    probe_slugs.update(re.findall(r"/([a-z][a-z0-9-]*)", r_rx.pattern))
                    probe_slugs.update(self._extract_standalone_literals(r_rx.pattern))

            sorted_probes = sorted(probe_slugs)
            for r_key, r_rx, _r_dir in eco_hints:
                if isinstance(r_rx, re.Pattern):
                    for p_slug in sorted_probes:
                        eco_probe = f"Inspect src/{p_slug}/worker.py and check the return value."
                        if r_rx.search(eco_probe):
                            self._add(
                                "CRITICAL",
                                name,
                                "guard/agy_hooks.py",
                                f"ECOSYSTEM_ROUTING_HINTS entry `{r_key}` falsely triggers on benign file path `{eco_probe}`",
                                "Guard trigger keywords and slash tokens with `_PATH_WORD_PRE`/`_PATH_WORD_POST` and `_SLASH_PRE`/`_SLASH_POST`.",
                            )
                            break

            pre_inv_fn = getattr(hooks_mod, "handle_pre_invocation", None)
            if callable(pre_inv_fn):
                hint_headers = (
                    "[Harness Skill Hint]",
                    "[Harness Ecosystem Routing]",
                    "[Active Skill Hint]",
                    "[Ecosystem Routing Hint]",
                )
                env_keys = (
                    "HOME",
                    "XDG_STATE_HOME",
                    "AGY_GUARD_STATE_DIR",
                    "ANTIGRAVITY_STATE_DIR",
                    "ANTIGRAVITY_CONFIG_DIR",
                )
                saved_env = {k: os.environ.get(k) for k in env_keys}
                orig_mod_repo = getattr(hooks_mod, "REPO_ROOT", None)
                with tempfile.TemporaryDirectory(prefix="agy-p7-collision-") as tmp_col:
                    tmp_path = Path(tmp_col)
                    fake_home = tmp_path / "home"
                    fake_cfg = fake_home / ".gemini" / "config"
                    fake_state = tmp_path / "state"
                    fake_ws = tmp_path / "ws"
                    fake_cfg.mkdir(parents=True, exist_ok=True)
                    fake_state.mkdir(parents=True, exist_ok=True)
                    fake_ws.mkdir(parents=True, exist_ok=True)
                    (fake_cfg / "GEMINI.md").write_text("# Test Constitution\n", encoding="utf-8")
                    try:
                        os.environ["HOME"] = str(fake_home)
                        os.environ["XDG_STATE_HOME"] = str(fake_state)
                        os.environ["AGY_GUARD_STATE_DIR"] = str(fake_state)
                        os.environ["ANTIGRAVITY_STATE_DIR"] = str(fake_state)
                        os.environ["ANTIGRAVITY_CONFIG_DIR"] = str(fake_cfg)
                        if orig_mod_repo is not None:
                            hooks_mod.REPO_ROOT = self.repo_root  # type: ignore[attr-defined]
                        conv_idx = 0
                        for p_slug in sorted_probes:
                            for tmpl in (
                                f"Inspect src/{p_slug}/worker.py and check the return value.",
                                f"Open app/{p_slug}/runner.py and summarize its exports.",
                            ):
                                conv_idx += 1
                                res = pre_inv_fn(
                                    {"prompt": tmpl, "cwd": str(fake_ws), "conversation_id": f"p7-col-{conv_idx}"}
                                )
                                ctx_msg = self._extract_pre_invocation_text(res)
                                if any(hdr in ctx_msg for hdr in hint_headers):
                                    self._add(
                                        "CRITICAL",
                                        name,
                                        "guard/agy_hooks.py",
                                        f"Benign file-path prompt `{tmpl}` falsely triggered PreInvocation hint",
                                        "Add file-path boundary lookarounds (`_PATH_WORD_PRE`/`_PATH_WORD_POST`, `_SLASH_PRE`/`_SLASH_POST`) in guard/agy_hooks.py.",
                                    )
                                    break
                        res_plug = pre_inv_fn(
                            {
                                "prompt": "/rea inspect sample binary layout",
                                "cwd": str(fake_ws),
                                "conversation_id": "p7-plugin-check",
                            }
                        )
                        plug_msg = self._extract_pre_invocation_text(res_plug)
                        for m_pl in re.finditer(r"(plugins/[A-Za-z0-9_./-]+\.md)", plug_msg):
                            rel_pl = m_pl.group(1)
                            if not (fake_cfg / rel_pl).is_file() and not (self.repo_root / rel_pl).is_file():
                                self._add(
                                    "CRITICAL",
                                    name,
                                    "guard/agy_hooks.py",
                                    f"PreInvocation emitted a hint pointing to non-existent plugin file `{rel_pl}`",
                                    "Gate optional plugin hints with `_optional_plugin_skill_available` in guard/agy_hooks.py.",
                                )
                    finally:
                        if orig_mod_repo is not None:
                            hooks_mod.REPO_ROOT = orig_mod_repo  # type: ignore[attr-defined]
                        for k, v in saved_env.items():
                            if v is None:
                                os.environ.pop(k, None)
                            else:
                                os.environ[k] = v

        pos_clause_split = re.compile(
            r"(?i)\b(?:not\s+for\b|do\s+not\s+(?:use|co-load|invoke)\b|don't\s+use\s+(?:for|on|to|when)\b|skip\s+[^.;]{1,60}\bfor\b|never\s+(?:use|invoke)\s+to\b)"
        )
        for d in sorted(p for p in skills_dir.iterdir() if p.is_dir()):
            skill_file = d / "SKILL.md"
            if not skill_file.is_file():
                continue
            data, err = _load_yaml_frontmatter(skill_file.read_text(encoding="utf-8", errors="replace"))
            if err or not isinstance(data, dict):
                continue
            desc = data.get("description")
            if not isinstance(desc, str) or not desc.strip():
                continue
            if not self._NEGATIVE_TRIGGER_RE.search(desc):
                self._add(
                    "WARNING",
                    name,
                    self._rel(skill_file),
                    f"Skill '{d.name}' frontmatter description lacks an explicit negative trigger boundary ('Not for ...' / 'DO NOT ...' / 'Skip ...' / 'EXCLUSIVELY when ...')",
                    "Add a 'Not for ... (use <adjacent-skill>)' or 'DO NOT co-load/use when ...' clause to the YAML frontmatter description.",
                )
            if hint_map:
                if is_split and managed_skills is not None and d.name not in managed_skills:
                    continue
                if d.name not in hint_map:
                    self._add(
                        "WARNING",
                        name,
                        self._rel(skill_file),
                        f"Skill '{d.name}' is missing from SKILL_HINTS auto-routing table in guard/agy_hooks.py",
                        f"Register '{d.name}' in SKILL_HINTS inside guard/agy_hooks.py.",
                    )
                else:
                    _, s_rx = hint_map[d.name]  # type: ignore[misc]
                    pos_desc = pos_clause_split.split(desc, maxsplit=1)[0]
                    for slash_cmd in sorted(set(re.findall(r"(?<![\w/.])(/[a-z][a-z0-9-]*)", pos_desc))):
                        if not s_rx.search(slash_cmd):  # type: ignore[union-attr]
                            self._add(
                                "WARNING",
                                name,
                                self._rel(skill_file),
                                f"Positive frontmatter slash trigger `{slash_cmd}` in '{d.name}' is not matched by SKILL_HINTS in guard/agy_hooks.py",
                                f"Add `{slash_cmd}` to the `{d.name}` trigger regex in guard/agy_hooks.py.",
                            )
                        path_probe = f"src{slash_cmd}/worker.py"
                        if s_rx.search(path_probe):  # type: ignore[union-attr]
                            self._add(
                                "WARNING",
                                name,
                                self._rel(skill_file),
                                f"Slash trigger `{slash_cmd}` in '{d.name}' lacks a left-side token boundary and false-triggers on file path `{path_probe}`",
                                "Guard slash commands in SKILL_HINTS with `(?:^|(?<=[\\s(\\[\\\"'«“]))` and right-side delimiter boundaries.",
                            )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="meta_audit", description="Meta-Consistency & Self-Audit Engine for Antigravity Harness")
    parser.add_argument("--all", action="store_true", help="Run all passes (default)")
    parser.add_argument("--pass", dest="passes", type=int, action="append", choices=range(1, 8), help="Run only pass N (repeatable)")
    parser.add_argument("--strict", action="store_true", help="Fail on WARNING findings too")
    parser.add_argument("--json", action="store_true", help="Output findings as structured JSON")
    parser.add_argument("--root", help="Harness root to audit (default: this repository)")
    args = parser.parse_args(argv)

    engine = MetaAuditEngine(repo_root=Path(args.root) if args.root else None)
    if args.passes:
        engine.findings = []
        for n in sorted(set(args.passes)):
            engine.run_pass(n)
        findings = engine.findings
    else:
        findings = engine.run_all_passes()

    criticals = [f for f in findings if f.severity == "CRITICAL"]
    warnings = [f for f in findings if f.severity == "WARNING"]
    infos = [f for f in findings if f.severity == "INFO"]
    failed = bool(criticals) or (args.strict and bool(warnings))

    if args.json:
        print(json.dumps({
            "is_valid": not failed,
            "total_findings": len(findings),
            "critical_count": len(criticals),
            "warning_count": len(warnings),
            "info_count": len(infos),
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
        return 1 if failed else 0

    print("=" * 64)
    print("    Antigravity Harness — Meta-Audit & Self-Check    ")
    print("=" * 64)
    print(f"Target Repository: {engine.repo_root}")
    print(f"Results          : {len(criticals)} Critical, {len(warnings)} Warnings, {len(infos)} Info")
    print("-" * 64)
    for f in findings:
        print(f"[{f.severity}] {f.pass_name} -> {f.target}")
        print(f"   Message : {f.message}")
        print(f"   Fix     : {f.suggested_fix}")
        print("-" * 64)
    if failed:
        print("[FAIL] Meta-consistency violations detected. Blocking delivery.")
        return 1
    print("[PASS] Harness meta-consistency checks passed." + (" (with notices)" if findings else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
