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
_WEB_RESEARCH = re.compile(r"(?i)\bweb\s+resources?\b|\bfetch\s+target\s+urls?\b|\bweb\s+(?:search|research)(?:es)?\b")
_FRONTMATTER = re.compile(r"\A(---\r?\n.*?\r?\n)(---[ \t]*(?:\r?\n|\Z))", re.DOTALL)


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


def native_agent(raw: str) -> str:
    """The agent definition with a `tools:` line derived from `access:` (unchanged when not applicable)."""
    tools = agent_tools(raw)
    m = _FRONTMATTER.match(raw)
    if tools is None or not m or re.search(r"(?m)^tools\s*:", m.group(1)):
        return raw
    newline = "\r\n" if m.group(1).endswith("\r\n") else "\n"
    return f"{m.group(1)}tools: {', '.join(tools)}{newline}{m.group(2)}{raw[m.end():]}"


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
                plan[output_dir / cls.NATIVE_AGENTS_DIR / f"{name}.md"] = native_agent(agent.get("raw", ""))
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
        return commit(plan, links, force=force, executables=support_executables(manifest, output_dir / cls.SKILLS_DIR))
