"""
porter/emitters/common.py — Shared planning/commit helpers for all Porter emitters.

Every emitter first builds a complete plan {path: content}; nothing is written until the
plan is known to be conflict-free. Existing files with different content are only
replaced with force=True. Skill SKILL.md files, all support files (with their executable
bits), in-skill symlinks, agent definitions and the portable document templates are
exported VERBATIM into a per-target support tree, which is what makes the export lossless
and verifiable by hash. Text is always written as UTF-8 with the manifest's LF newlines on
every OS, so a re-export compares byte-for-byte equal.
"""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple, Union

from porter.frontmatter import FrontmatterError, parse_frontmatter
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer

Content = Union[str, bytes]
Plan = Dict[Path, Content]

TEMPLATES_DIR = "templates"
# Harness files that are deliberately not exported, with the reason shown in every export index.
NOT_PORTABLE = {
    "hooks.json": "Antigravity-specific PreInvocation hook (upstream watchdog); intentionally not portable",
}


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


def plan_templates(manifest: UniversalManifest, output_dir: Path) -> Plan:
    """The portable document templates, verbatim, under <output>/templates/."""
    templates = getattr(manifest, "templates", None) or {}
    return {output_dir / TEMPLATES_DIR / name: decode_subfile(value) for name, value in templates.items()}


def support_executables(manifest: UniversalManifest, skills_root: Path) -> Set[Path]:
    """Exported support files that must carry an executable bit (manifest skills[].executables)."""
    found: Set[Path] = set()
    for skill in manifest.skills:
        name = skill.get("name")
        if name:
            found.update(skills_root / name / rel for rel in (skill.get("executables") or []))
    return found


def skill_body(raw: str) -> str:
    try:
        _, body = parse_frontmatter(raw)
        return body.strip()
    except FrontmatterError:
        return raw.strip()


def sanitized_body(raw: str, target: str) -> str:
    return ConstitutionalSanitizer.sanitize_for_export(skill_body(raw), target=target)


def index_section(manifest: UniversalManifest, skills_rel: str, agents_rel: str, templates_rel: str = TEMPLATES_DIR) -> str:
    lines = ["## Skills (full definitions and support files are exported verbatim)", ""]
    for skill in manifest.skills:
        desc = " ".join(str(skill.get("description", "")).split())
        lines.append(f"- `{skills_rel}/{skill['name']}/SKILL.md` — {desc[:160]}")
    lines += ["", "## Subagents (independent auditor roles)", ""]
    for agent in manifest.agents:
        desc = " ".join(str(agent.get("description", "")).split())
        lines.append(f"- `{agents_rel}/{agent['name']}.md` — {desc[:160]}")
    templates = getattr(manifest, "templates", None) or {}
    if templates:
        lines += ["", "## Templates (exported verbatim)", ""]
        lines += [f"- `{templates_rel}/{name}`" for name in templates]
    lines += ["", "## Not exported", ""]
    lines += [f"- `{name}` — {reason}." for name, reason in NOT_PORTABLE.items()]
    return "\n".join(lines)


def _encode(content: Content) -> bytes:
    return content.encode("utf-8") if isinstance(content, str) else content


def _same(path: Path, content: Content) -> bool:
    try:
        existing = path.read_bytes()
    except OSError:
        return False
    return existing == _encode(content)


def _make_executable(path: Path) -> None:
    if os.name == "nt":
        return  # no POSIX mode bits to restore
    mode = stat.S_IMODE(path.stat().st_mode)
    path.chmod(mode | ((mode & 0o444) >> 2))  # add x wherever r is set (0644 -> 0755)


def commit(plan: Plan, links: Dict[Path, str], force: bool = False, executables: Iterable[Path] = ()) -> List[Path]:
    conflicts = [p for p, c in plan.items() if os.path.lexists(p) and not _same(p, c)]
    conflicts += [p for p, t in links.items()
                  if os.path.lexists(p) and not (os.path.islink(p) and os.readlink(p).replace(os.sep, "/") == t)]
    if conflicts and not force:
        raise EmitterConflictError(sorted(conflicts))
    exec_set = set(executables)
    written: List[Path] = []
    for path, content in sorted(plan.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.path.islink(path):
            path.unlink()
        # Bytes, never write_text(): text mode would turn LF into CRLF on Windows.
        path.write_bytes(_encode(content))
        if path in exec_set:
            _make_executable(path)
        written.append(path)
    for path, target in sorted(links.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.path.islink(path) and os.readlink(path).replace(os.sep, "/") == target:
            written.append(path)
            continue
        if os.path.lexists(path):
            if path.is_dir() and not path.is_symlink():
                continue  # never delete a real directory to create a link
            path.unlink()
        try:
            os.symlink(target.replace("/", os.sep), path, target_is_directory=True)
            written.append(path)
        except (OSError, NotImplementedError):
            pass  # platforms without symlink support: the link target is exported separately
    return written
