"""
porter/emitters/claude.py — Emitter for Claude Code environments.
Generates CLAUDE.md, native skills (.claude/skills/<name>/SKILL.md + support files) and
native subagents (.claude/agents/<name>.md), all exported verbatim.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

from porter.emitters.common import Plan, commit, index_section, plan_support_tree
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer


class ClaudeEmitter:
    """Exports Antigravity Harness as a native Claude Code workspace."""

    TARGET = "claude"
    SKILLS_DIR = ".claude/skills"
    AGENTS_DIR = ".claude/agents"

    @classmethod
    def plan(cls, manifest: UniversalManifest, output_dir: Path) -> Tuple[Plan, Dict[Path, str]]:
        plan, links = plan_support_tree(manifest, output_dir / cls.SKILLS_DIR, output_dir / cls.AGENTS_DIR)
        const = ConstitutionalSanitizer.sanitize_for_export(manifest.constitution.get("raw", ""), target=cls.TARGET)
        design = ConstitutionalSanitizer.sanitize_for_export(manifest.design_contract.get("raw", ""), target=cls.TARGET)
        plan[output_dir / "CLAUDE.md"] = f"""# Claude Code Engineering Guidelines

> Exported from Antigravity Harness v{manifest.version}. Skills live in `{cls.SKILLS_DIR}/`,
> auditor subagents in `{cls.AGENTS_DIR}/` (invoke them with the Task tool before delivery).

---

## 1. Behavioral & Engineering Constitution

{const}

---

## 2. Baseline Design Contract & Quality Filter

{design}

---

{index_section(manifest, cls.SKILLS_DIR, cls.AGENTS_DIR)}
"""
        return plan, links

    @classmethod
    def emit(cls, manifest: UniversalManifest, output_dir: Path, force: bool = False) -> List[Path]:
        plan, links = cls.plan(manifest, Path(output_dir))
        return commit(plan, links, force=force)
