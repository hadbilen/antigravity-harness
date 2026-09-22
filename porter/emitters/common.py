"""
porter/emitters/common.py — Shared planning/commit helpers for all Porter emitters.

Every emitter first builds a complete plan {path: content}; nothing is written until the
plan is known to be conflict-free. Existing files with different content are only
replaced with force=True. Skill SKILL.md files, all support files, in-skill symlinks and
agent definitions are exported VERBATIM into a per-target support tree, which is what
makes the export lossless and verifiable by hash.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Dict, List, Tuple, Union

from porter.frontmatter import FrontmatterError, parse_frontmatter
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer

Content = Union[str, bytes]
Plan = Dict[Path, Content]


class EmitterConflictError(FileExistsError):
    def __init__(self, conflicts: List[Path]):
        self.conflicts = conflicts
        shown = ", ".join(str(p) for p in conflicts[:5])
        more = f" (+{len(conflicts) - 5} more)" if len(conflicts) > 5 else ""
        super().__init__(f"Refusing to overwrite {len(conflicts)} existing file(s) with different content: {shown}{more}. Use --force.")


def decode_subfile(value: str) -> Content:
    return base64.b64decode(value[len("base64:"):]) if value.startswith("base64:") else value


def plan_support_tree(manifest: UniversalManifest, skills_root: Path, agents_root: Path) -> Tuple[Plan, Dict[Path, str]]:
    """Returns (file plan, symlink plan) reproducing every skill and agent verbatim."""
    plan: Plan = {}
    links: Dict[Path, str] = {}
    for skill in manifest.skills:
        name = skill.get("name")
        if not name:
            continue
        base = skills_root / name
        plan[base / "SKILL.md"] = skill.get("raw", "")
        for rel, value in (skill.get("subfiles") or {}).items():
            plan[base / rel] = decode_subfile(value)
        for rel, target in (skill.get("links") or {}).items():
            links[base / rel] = target
    for agent in manifest.agents:
        name = agent.get("name")
        if name:
            plan[agents_root / f"{name}.md"] = agent.get("raw", "")
    return plan, links


def skill_body(raw: str) -> str:
    try:
        _, body = parse_frontmatter(raw)
        return body.strip()
    except FrontmatterError:
        return raw.strip()


def sanitized_body(raw: str, target: str) -> str:
    return ConstitutionalSanitizer.sanitize_for_export(skill_body(raw), target=target)


def index_section(manifest: UniversalManifest, skills_rel: str, agents_rel: str) -> str:
    lines = ["## Skills (full definitions and support files are exported verbatim)", ""]
    for skill in manifest.skills:
        desc = " ".join(str(skill.get("description", "")).split())
        lines.append(f"- `{skills_rel}/{skill['name']}/SKILL.md` — {desc[:160]}")
    lines += ["", "## Subagents (independent auditor roles)", ""]
    for agent in manifest.agents:
        desc = " ".join(str(agent.get("description", "")).split())
        lines.append(f"- `{agents_rel}/{agent['name']}.md` — {desc[:160]}")
    return "\n".join(lines)


def _same(path: Path, content: Content) -> bool:
    try:
        existing = path.read_bytes()
    except OSError:
        return False
    data = content.encode("utf-8") if isinstance(content, str) else content
    return existing == data


def commit(plan: Plan, links: Dict[Path, str], force: bool = False) -> List[Path]:
    conflicts = [p for p, c in plan.items() if os.path.lexists(p) and not _same(p, c)]
    conflicts += [p for p, t in links.items() if os.path.lexists(p) and not (os.path.islink(p) and os.readlink(p) == t)]
    if conflicts and not force:
        raise EmitterConflictError(sorted(conflicts))
    written: List[Path] = []
    for path, content in sorted(plan.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.path.islink(path):
            path.unlink()
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        written.append(path)
    for path, target in sorted(links.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.path.islink(path) and os.readlink(path) == target:
            written.append(path)
            continue
        if os.path.lexists(path):
            if path.is_dir() and not path.is_symlink():
                continue  # never delete a real directory to create a link
            path.unlink()
        try:
            os.symlink(target, path, target_is_directory=True)
            written.append(path)
        except (OSError, NotImplementedError):
            pass  # platforms without symlink support: the link target is exported separately
    return written
