"""
porter/emitters/cursor.py — Emitter for Cursor and Windsurf environments.
Generates .cursor/rules/*.mdc files with valid YAML frontmatter (including an index rule), a
verbatim support tree (.cursor/skills, .cursor/agents) so skill scripts, references and assets
survive, and the portable templates (templates/).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from porter.emitters.common import (
    Plan, commit, index_section, plan_support_tree, plan_templates, sanitized_body, skill_body, support_executables,
)
from porter.frontmatter import dump_frontmatter
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer

UI_GLOBS = "**/*.tsx, **/*.jsx, **/*.vue, **/*.svelte, **/*.html, **/*.css"
_INLINE_CODE_RE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
_REL_SUPPORT_SPAN_RE = re.compile(r"(?:^|(?<=\s))(?:\./)?((?:references|scripts|assets|examples)/[^\s`'\")\]]+)")
_EXPLICIT_SKILL_PATH_RE = re.compile(
    r"(?<![.\w/-])skills/([a-z0-9][a-z0-9_-]*)/((?:(?:references|scripts|assets|examples)/)?[^\s`'\")\]<>]+)"
)


def _globs_for(name: str) -> str:
    if any(k in name for k in ("test", "diagnos")):
        return "**/*.test.*, **/*.spec.*, **/tests/**"
    if any(k in name for k in ("database", "migration", "sql")):
        return "**/*.sql, **/prisma/**, **/drizzle/**, **/migrations/**"
    if re.search(r"(?:^|[-_])rust", name):
        return "**/*.rs, **/Cargo.toml, **/*.c, **/*.h, **/*.cpp, **/*.cc, **/*.cxx, **/*.hpp, **/*.hh, **/*.hxx"
    if any(k in name for k in ("ui", "design", "css", "html", "layout")) or (
        "antislop" in name and name != "antislop-code"
    ):
        return UI_GLOBS
    return ""


def _skill_owned_paths(skill: Dict[str, Any]) -> Set[str]:
    owned: Set[str] = set()
    subfiles = skill.get("subfiles") or {}
    if isinstance(subfiles, dict):
        owned.update(str(k).strip("./") for k in subfiles.keys())
    elif isinstance(subfiles, list):
        for item in subfiles:
            if isinstance(item, dict):
                rel = item.get("relpath") or item.get("path")
                if rel:
                    owned.add(str(rel).strip("./"))
    links = skill.get("links") or {}
    if isinstance(links, dict):
        owned.update(str(k).strip("./") for k in links.keys())
    return owned


def _is_skill_subpath(rel_candidate: str, owned: Set[str]) -> bool:
    clean = rel_candidate.split("#", 1)[0].split("?", 1)[0].strip()
    if clean.startswith("./"):
        clean = clean[2:]
    if not clean:
        return False
    if clean in owned:
        return True
    if clean.endswith("/"):
        prefix = clean.rstrip("/") + "/"
        return any(p.startswith(prefix) for p in owned)
    return False


def _rewrite_cursor_skill_paths(
    body: str,
    skill_name: str,
    owned: Set[str],
    all_skill_paths: Dict[str, Set[str]],
    skills_dir: str,
) -> str:
    def _replace_explicit(m: "re.Match[str]") -> str:
        sname, raw_sub = m.group(1), m.group(2)
        core = raw_sub.rstrip(".,;:")
        trail = raw_sub[len(core):]
        target_owned = all_skill_paths.get(sname)
        if target_owned is not None and (core == "SKILL.md" or _is_skill_subpath(core, target_owned)):
            return f"{skills_dir}/{sname}/{core}{trail}"
        return m.group(0)

    body = _EXPLICIT_SKILL_PATH_RE.sub(_replace_explicit, body)
    body = re.sub(
        r"\]\((?:\./)?((?:references|scripts|assets|examples)/[^)\s]+)\)",
        lambda m: f"]({skills_dir}/{skill_name}/{m.group(1)})" if _is_skill_subpath(m.group(1), owned) else m.group(0),
        body,
    )

    def _replace_inline_code(m: "re.Match[str]") -> str:
        inner = m.group(1)
        rewritten = _REL_SUPPORT_SPAN_RE.sub(
            lambda sm: f"{skills_dir}/{skill_name}/{sm.group(1)}"
            if _is_skill_subpath(sm.group(1), owned)
            else sm.group(0),
            inner,
        )
        return f"`{rewritten}`"

    return _INLINE_CODE_RE.sub(_replace_inline_code, body)


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
        plan.update(plan_templates(manifest, output_dir))
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
        all_skill_paths = {
            str(s["name"]): _skill_owned_paths(s) for s in manifest.skills if s.get("name")
        }
        for skill in manifest.skills:
            name = skill.get("name")
            if not name:
                continue
            owned = all_skill_paths.get(name, set())
            body = sanitized_body(skill.get("raw", ""), cls.TARGET)
            body = _rewrite_cursor_skill_paths(body, name, owned, all_skill_paths, cls.SKILLS_DIR)
            support = f"\n\n> Support files for this skill: `{cls.SKILLS_DIR}/{name}/`" if owned else ""
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
        plan[rules / "99-harness-index.mdc"] = cls._mdc(
            {"description": "Index of the exported harness skills, auditor roles, templates and non-portable files",
             "globs": "", "alwaysApply": False},
            "Harness Export Index", index_section(manifest, cls.SKILLS_DIR, cls.AGENTS_DIR),
        )
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
        )
