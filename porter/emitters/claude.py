"""
porter/emitters/claude.py — Emitter for Claude Code environments.
Generates CLAUDE.md, native skills (.claude/skills/<name>/SKILL.md + support files, verbatim),
native subagents (.claude/agents/<name>.md) and the portable templates (templates/).

A harness agent's `access:` frontmatter key becomes a Claude Code `tools:` allow-list in the
native subagent (read-only -> Read, Grep, Glob; read-exec -> + Bash; web tools are added only
when the agent's own text says it researches the web). Because the native file then differs
from the source by that one line, the verbatim source definitions are kept in the support
tree `.claude/harness/agents/`, which is what the lossless-parity checks compare.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from porter.emitters.common import (
    Plan, commit, index_section, plan_support_tree, plan_templates, support_executables,
)
from porter.frontmatter import FrontmatterError, parse_frontmatter
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer

ACCESS_TOOLS: Dict[str, List[str]] = {
    "read-only": ["Read", "Grep", "Glob"],
    "read-exec": ["Read", "Grep", "Glob", "Bash"],
}
WEB_TOOLS = ["WebFetch", "WebSearch"]
_READONLY_CANONICAL_TOOLS: Dict[str, str] = {
    "read": "Read",
    "grep": "Grep",
    "glob": "Glob",
    "webfetch": "WebFetch",
    "websearch": "WebSearch",
}
_WEB_RESEARCH = re.compile(r"(?i)\bweb\s+resources?\b|\bfetch\s+target\s+urls?\b|\bweb\s+(?:search|research)(?:es)?\b")
_FRONTMATTER = re.compile(r"\A(---\r?\n.*?\r?\n)(---[ \t]*(?:\r?\n|\Z))", re.DOTALL)
_EXISTING_TOOLS_BLOCK = re.compile(r"(?m)^tools\s*:[^\r\n]*(?:\r?\n[ \t]+-[ \t]+[^\r\n]*)*\r?\n?")


def agent_tools(raw: str) -> Optional[List[str]]:
    """The Claude Code tool allow-list for an agent definition, or None (no `access:` key / unknown value)."""
    try:
        meta, body = parse_frontmatter(raw)
    except FrontmatterError:
        return None
    tools = ACCESS_TOOLS.get(str(meta.get("access") or "").strip().lower())
    if tools is None:
        return None
    if _WEB_RESEARCH.search(f"{meta.get('description', '')}\n{body}"):
        tools = tools + WEB_TOOLS
    return list(tools)


def _filter_readonly_tools(raw_fm: str, parsed_tools: object, fallback: List[str]) -> List[str]:
    tokens: List[str] = []
    if isinstance(parsed_tools, list):
        tokens = [str(item).strip() for item in parsed_tools if str(item).strip()]
    elif isinstance(parsed_tools, str):
        tokens = [tok.strip(" []'\"") for tok in re.split(r"[,\s]+", parsed_tools) if tok.strip(" []'\"")]
    else:
        m_line = re.search(r"(?m)^tools\s*:\s*(.*)$", raw_fm)
        if m_line and m_line.group(1).strip():
            tokens = [tok.strip(" []'\"") for tok in re.split(r"[,\s]+", m_line.group(1)) if tok.strip(" []'\"")]
    cleaned: List[str] = []
    for tok in tokens:
        canon = _READONLY_CANONICAL_TOOLS.get(tok.lower())
        if canon and canon not in cleaned:
            cleaned.append(canon)
    return cleaned if cleaned else list(fallback)


def native_agent(raw: str, target: str = "claude") -> str:
    """The agent definition with a `tools:` line derived from `access:` and a sanitized body."""
    tools = agent_tools(raw)
    m = _FRONTMATTER.match(raw)
    if not m:
        san = ConstitutionalSanitizer.sanitize_for_export(raw, target=target)
        return f"{san}\n" if san else ""
    fm_part = m.group(1)
    fence_end = m.group(2)
    newline = "\r\n" if fm_part.endswith("\r\n") else "\n"
    access_val = ""
    parsed_tools: object = None
    try:
        meta, _ = parse_frontmatter(raw)
        access_val = str(meta.get("access") or "").strip().lower()
        parsed_tools = meta.get("tools")
    except FrontmatterError:
        m_acc = re.search(r"(?im)^access\s*:\s*['\"]?([^\s'\"#]+)", fm_part)
        if m_acc:
            access_val = m_acc.group(1).strip().lower()

    has_existing_tools = bool(re.search(r"(?m)^tools\s*:", fm_part))
    if access_val == "read-only" and has_existing_tools:
        clean_tools = _filter_readonly_tools(fm_part, parsed_tools, tools or ACCESS_TOOLS["read-only"])
        stripped_fm = _EXISTING_TOOLS_BLOCK.sub("", fm_part)
        if not stripped_fm.endswith(("\n", "\r\n")):
            stripped_fm += newline
        fm_out = f"{stripped_fm}tools: {', '.join(clean_tools)}{newline}{fence_end}"
    elif tools is not None and not has_existing_tools:
        fm_out = f"{fm_part}tools: {', '.join(tools)}{newline}{fence_end}"
    else:
        fm_out = f"{fm_part}{fence_end}"
    san_body = ConstitutionalSanitizer.sanitize_for_export(raw[m.end():], target=target)
    if not san_body:
        return fm_out
    sep = newline if fm_out.endswith(("\n", "\r\n")) else f"{newline}{newline}"
    return f"{fm_out}{sep}{san_body}{newline}"


class ClaudeEmitter:
    """Exports Antigravity Harness as a native Claude Code workspace."""

    TARGET = "claude"
    SKILLS_DIR = ".claude/skills"
    AGENTS_DIR = ".claude/harness/agents"   # verbatim source definitions (lossless parity)
    NATIVE_AGENTS_DIR = ".claude/agents"    # Claude Code subagents with a tools: allow-list

    @classmethod
    def plan(cls, manifest: UniversalManifest, output_dir: Path) -> Tuple[Plan, Dict[Path, str]]:
        plan, links = plan_support_tree(manifest, output_dir / cls.SKILLS_DIR, output_dir / cls.AGENTS_DIR)
        plan.update(plan_templates(manifest, output_dir))
        for agent in manifest.agents:
            name = agent.get("name")
            if name:
                plan[output_dir / cls.NATIVE_AGENTS_DIR / f"{name}.md"] = native_agent(
                    agent.get("raw", ""), target=cls.TARGET
                )
        const = ConstitutionalSanitizer.sanitize_for_export(manifest.constitution.get("raw", ""), target=cls.TARGET)
        design = ConstitutionalSanitizer.sanitize_for_export(manifest.design_contract.get("raw", ""), target=cls.TARGET)
        plan[output_dir / "CLAUDE.md"] = f"""# Claude Code Engineering Guidelines

> Exported from Antigravity Harness v{manifest.version}. Skills live in `{cls.SKILLS_DIR}/`,
> auditor subagents in `{cls.NATIVE_AGENTS_DIR}/` (invoke them with the Task tool before delivery).

---

## 1. Behavioral & Engineering Constitution

{const}

---

## 2. Baseline Design Contract & Quality Filter

{design}

---

{index_section(manifest, cls.SKILLS_DIR, cls.NATIVE_AGENTS_DIR)}
"""
        return plan, links

    @classmethod
    def emit(cls, manifest: UniversalManifest, output_dir: Path, force: bool = False) -> List[Path]:
        output_dir = Path(output_dir)
        plan, links = cls.plan(manifest, output_dir)
        return commit(
            plan,
            links,
            force=force,
            executables=support_executables(manifest, output_dir / cls.SKILLS_DIR),
            output_dir=output_dir,
            target_name=cls.TARGET,
        )
