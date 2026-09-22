"""
porter/emitters/cursor.py — Emitter for Cursor and Windsurf environments.
Generates .cursor/rules/*.mdc files with valid YAML frontmatter, plus a verbatim support
tree (.cursor/skills, .cursor/agents) so skill scripts, references and assets survive.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

from porter.emitters.common import Plan, commit, plan_support_tree, sanitized_body, skill_body
from porter.frontmatter import dump_frontmatter
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer

UI_GLOBS = "**/*.tsx, **/*.jsx, **/*.vue, **/*.svelte, **/*.html, **/*.css"


def _globs_for(name: str) -> str:
    if any(k in name for k in ("ui", "design", "css", "html", "layout")):
        return UI_GLOBS
    if any(k in name for k in ("database", "migration", "sql")):
        return "**/*.sql, **/prisma/**, **/drizzle/**, **/migrations/**"
    if any(k in name for k in ("test", "diagnos")):
        return "**/*.test.*, **/*.spec.*, **/tests/**"
    return ""


class CursorEmitter:
    """Exports Antigravity Harness as native Cursor .mdc rules."""

    TARGET = "cursor"
    SKILLS_DIR = ".cursor/skills"
    AGENTS_DIR = ".cursor/agents"
    RULES_DIR = ".cursor/rules"

    @staticmethod
    def _mdc(meta: Dict, title: str, body: str) -> str:
        return f"{dump_frontmatter(meta)}\n# {title}\n\n{body}\n"

    @classmethod
    def plan(cls, manifest: UniversalManifest, output_dir: Path) -> Tuple[Plan, Dict[Path, str]]:
        plan, links = plan_support_tree(manifest, output_dir / cls.SKILLS_DIR, output_dir / cls.AGENTS_DIR)
        rules = output_dir / cls.RULES_DIR
        const = ConstitutionalSanitizer.sanitize_for_export(manifest.constitution.get("raw", ""), target=cls.TARGET)
        plan[rules / "00-constitution.mdc"] = cls._mdc(
            {"description": "Universal Behavioral & Engineering Constitution", "globs": "", "alwaysApply": True},
            "Global Engineering Constitution", const,
        )
        design = ConstitutionalSanitizer.sanitize_for_export(manifest.design_contract.get("raw", ""), target=cls.TARGET)
        plan[rules / "10-design-antislop.mdc"] = cls._mdc(
            {"description": "Baseline Design Contract & Antislop Filter", "globs": UI_GLOBS, "alwaysApply": False},
            "UI Design Contract & Antislop Filter", design,
        )
        for skill in manifest.skills:
            name = skill.get("name")
            if not name:
                continue
            body = sanitized_body(skill.get("raw", ""), cls.TARGET)
            support = f"\n\n> Support files for this skill: `{cls.SKILLS_DIR}/{name}/`" if skill.get("subfiles") else ""
            plan[rules / f"skill-{name}.mdc"] = cls._mdc(
                {"description": " ".join(str(skill.get("description", "")).split()), "globs": _globs_for(name), "alwaysApply": False},
                f"Skill: {name}", body + support,
            )
        for agent in manifest.agents:
            name = agent.get("name")
            if not name:
                continue
            body = ConstitutionalSanitizer.sanitize_for_export(skill_body(agent.get("raw", "")), target=cls.TARGET)
            plan[rules / f"agent-{name}.mdc"] = cls._mdc(
                {"description": " ".join(str(agent.get("description", "")).split()), "globs": "", "alwaysApply": False},
                f"Auditor Role: {name}", body,
            )
        return plan, links

    @classmethod
    def emit(cls, manifest: UniversalManifest, output_dir: Path, force: bool = False) -> List[Path]:
        plan, links = cls.plan(manifest, Path(output_dir))
        return commit(plan, links, force=force)
