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
import errno
import json
import os
import secrets
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

from porter.frontmatter import FrontmatterError, parse_frontmatter
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer

Content = Union[str, bytes]
Plan = Dict[Path, Content]

TEMPLATES_DIR = "templates"
EXPORT_RECEIPT_FILENAME = ".porter-export-receipt.json"
_KNOWN_EXPORT_ROOT_DIRS = frozenset({".cursor", ".claude", ".aider", ".agents"})
_KNOWN_EXPORT_ROOT_FILES = frozenset({"CLAUDE.md", "AGENTS.md", "CONVENTIONS.md", ".aider.conf.yml", "RULES.md"})
# Harness files that are deliberately not exported, with the reason shown in every export index.
NOT_PORTABLE = {
    "hooks.json": "Antigravity-specific lifecycle hooks (PreInvocation, PreToolUse, Stop); intentionally not portable",
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
    if os.path.islink(path):
        return False
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


def _check_no_symlink_ancestors(target: Path, output_dir: Optional[Path] = None) -> None:
    abs_target = Path(os.path.abspath(target))
    stop_roots = {
        Path(os.path.abspath(os.sep)),
        Path("/tmp"),
        Path("/var"),
        Path("/private"),
        Path("/private/tmp"),
        Path("/private/var"),
        Path(os.path.abspath(tempfile.gettempdir())),
    }
    if output_dir is not None:
        abs_out = Path(os.path.abspath(output_dir))
        if os.path.islink(abs_out):
            raise ValueError(f"Refusing to write through symlinked output directory: {abs_out}")
        stop_roots.add(abs_out.parent)
    anc = abs_target.parent
    while anc not in stop_roots and anc.parent != anc:
        if os.path.islink(anc):
            raise ValueError(f"Refusing to write through symlinked ancestor directory: {anc}")
        anc = anc.parent


def _is_within(child: Path, root: Path) -> bool:
    abs_child = Path(os.path.abspath(child))
    abs_root = Path(os.path.abspath(root))
    try:
        abs_child.relative_to(abs_root)
        return abs_child != abs_root
    except ValueError:
        return False


def _infer_output_dir(plan: Plan, links: Dict[Path, str], explicit: Optional[Path]) -> Optional[Path]:
    if explicit is not None:
        return Path(os.path.abspath(explicit))
    all_paths = [Path(os.path.abspath(p)) for p in list(plan) + list(links)]
    if not all_paths:
        return None
    cand: Optional[Path] = None
    for p in all_paths:
        if p.name in _KNOWN_EXPORT_ROOT_FILES:
            cand = p.parent
            break
        for anc in p.parents:
            if anc.name in _KNOWN_EXPORT_ROOT_DIRS:
                cand = anc.parent
                break
        if cand is not None:
            break
    if cand is None:
        try:
            common = Path(os.path.commonpath([str(p) for p in all_paths]))
        except ValueError:
            return None
        cand = common.parent if common in all_paths else common
    if all(_is_within(p, cand) for p in all_paths):
        return cand
    return None


def _safe_rel_posix(rel: str) -> Optional[PurePosixPath]:
    if not isinstance(rel, str) or not rel or "\\" in rel or rel.startswith("/"):
        return None
    pure = PurePosixPath(rel)
    if pure.is_absolute() or not pure.parts or any(part in ("", ".", "..") for part in pure.parts):
        return None
    if len(pure.parts[0]) >= 2 and pure.parts[0][1] == ":":
        return None
    return pure


def _infer_target_name(
    plan: Plan,
    links: Dict[Path, str],
    resolved_out: Optional[Path],
    explicit: Optional[str],
) -> str:
    if explicit:
        return explicit
    rels: List[str] = []
    for p in list(plan) + list(links):
        abs_p = Path(os.path.abspath(p))
        if resolved_out is not None and _is_within(abs_p, resolved_out):
            rels.append(abs_p.relative_to(resolved_out).as_posix())
        else:
            rels.append(abs_p.name)
    rel_set = set(rels)
    if "CLAUDE.md" in rel_set or any(r.startswith(".claude/") for r in rels):
        return "claude"
    if any(r.startswith(".cursor/") or r.endswith(".mdc") for r in rels):
        return "cursor"
    if "CONVENTIONS.md" in rel_set or ".aider.conf.yml" in rel_set or any(r.startswith(".aider/") for r in rels):
        return "aider"
    if "AGENTS.md" in rel_set or any(r.startswith(".agents/") for r in rels):
        return "universal"
    if "RULES.md" in rel_set:
        return "generic"
    return "default"


def _classify_v1_rel_owner(rel: str) -> Optional[str]:
    if rel == "CLAUDE.md" or rel.startswith(".claude/"):
        return "claude"
    if rel.startswith(".cursor/"):
        return "cursor"
    if rel in ("CONVENTIONS.md", ".aider.conf.yml") or rel.startswith(".aider/"):
        return "aider"
    if rel == "AGENTS.md" or rel.startswith(".agents/"):
        return "universal"
    if rel == "RULES.md" or rel.startswith(("skills/", "agents/")):
        return "generic"
    return None


def _validate_str_list(val: object, field_name: str, receipt_path: Path) -> List[str]:
    if not isinstance(val, list) or not all(isinstance(item, str) for item in val):
        raise ValueError(f"Corrupt export receipt '{receipt_path}': '{field_name}' must be a list of strings")
    return list(val)


def _load_export_receipt(receipt_path: Path, default_target: str = "default") -> Dict[str, Dict[str, List[str]]]:
    if os.path.islink(receipt_path):
        raise ValueError(f"Refusing to access symlinked export receipt: {receipt_path}")
    if not os.path.lexists(receipt_path):
        return {}
    if not receipt_path.is_file():
        raise ValueError(f"Corrupt export receipt '{receipt_path}': not a regular file")
    try:
        raw = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"Corrupt or unreadable export receipt '{receipt_path}': {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"Corrupt export receipt '{receipt_path}': root JSON value must be an object")

    version = raw.get("version", 1)
    if version == 1:
        v1_files = _validate_str_list(raw.get("files", []), "files", receipt_path)
        v1_links = _validate_str_list(raw.get("links", []), "links", receipt_path)
        migrated: Dict[str, Dict[str, List[str]]] = {}
        shared_files: List[str] = []
        shared_links: List[str] = []
        for rel in v1_files:
            owner = _classify_v1_rel_owner(rel)
            if owner is None:
                shared_files.append(rel)
            else:
                migrated.setdefault(owner, {"files": [], "links": []})["files"].append(rel)
        for rel in v1_links:
            owner = _classify_v1_rel_owner(rel)
            if owner is None:
                shared_links.append(rel)
            else:
                migrated.setdefault(owner, {"files": [], "links": []})["links"].append(rel)
        if shared_files or shared_links:
            owners = list(migrated.keys()) or [default_target]
            for owner in owners:
                entry = migrated.setdefault(owner, {"files": [], "links": []})
                entry["files"] = sorted(set(entry["files"]) | set(shared_files))
                entry["links"] = sorted(set(entry["links"]) | set(shared_links))
        return migrated

    if version == 2:
        raw_targets = raw.get("targets")
        if not isinstance(raw_targets, dict):
            raise ValueError(f"Corrupt export receipt '{receipt_path}': 'targets' must be an object")
        targets_out: Dict[str, Dict[str, List[str]]] = {}
        for tname, entry in raw_targets.items():
            if not isinstance(tname, str) or not tname or not isinstance(entry, dict):
                raise ValueError(f"Corrupt export receipt '{receipt_path}': invalid target entry {tname!r}")
            t_files = _validate_str_list(entry.get("files", []), f"targets.{tname}.files", receipt_path)
            t_links = _validate_str_list(entry.get("links", []), f"targets.{tname}.links", receipt_path)
            targets_out[tname] = {"files": sorted(set(t_files)), "links": sorted(set(t_links))}
        return targets_out

    raise ValueError(f"Unsupported or corrupt export receipt version in '{receipt_path}': {version!r}")


def _prune_empty_parents(start_dir: Path, root_dir: Path) -> None:
    cur = Path(os.path.abspath(start_dir))
    abs_root = Path(os.path.abspath(root_dir))
    while cur != abs_root and _is_within(cur, abs_root):
        if os.path.islink(cur):
            break
        try:
            cur.rmdir()
        except OSError:
            break
        cur = cur.parent


def _is_windows_symlink_unsupported(exc: BaseException) -> bool:
    if isinstance(exc, NotImplementedError):
        return True
    if not isinstance(exc, OSError) or os.name != "nt":
        return False
    if getattr(exc, "winerror", None) in (1, 50, 1314):
        return True
    return exc.errno in (
        errno.ENOSYS,
        errno.EPERM,
        getattr(errno, "EOPNOTSUPP", -1),
        getattr(errno, "ENOTSUP", -1),
    )


def _write_bytes_atomic_nofollow(path: Path, data: bytes, output_dir: Optional[Path] = None) -> None:
    _check_no_symlink_ancestors(path, output_dir)
    if os.path.islink(path):
        raise ValueError(f"Refusing to write through symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    _check_no_symlink_ancestors(path, output_dir)
    tmp_path = path.parent / f".{path.name}.porter-{os.getpid()}-{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp_path), flags, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        _check_no_symlink_ancestors(path, output_dir)
        if os.path.islink(path):
            raise ValueError(f"Refusing to write through symlink: {path}")
        os.replace(str(tmp_path), str(path))
    except BaseException:
        try:
            if os.path.lexists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass
        raise


def commit(
    plan: Plan,
    links: Dict[Path, str],
    force: bool = False,
    executables: Iterable[Path] = (),
    output_dir: Optional[Path] = None,
    target_name: Optional[str] = None,
) -> List[Path]:
    resolved_out = _infer_output_dir(plan, links, output_dir)
    resolved_target = _infer_target_name(plan, links, resolved_out, target_name)
    for p in list(plan) + list(links):
        _check_no_symlink_ancestors(p, resolved_out)
        if resolved_out is not None and not _is_within(p, resolved_out):
            raise ValueError(f"Planned export path escapes output directory '{resolved_out}': {p}")

    conflicts = [p for p, c in plan.items() if os.path.lexists(p) and not _same(p, c)]
    conflicts += [p for p, t in links.items()
                  if os.path.lexists(p) and not (os.path.islink(p) and os.readlink(p).replace(os.sep, "/") == t)]
    if conflicts and not force:
        raise EmitterConflictError(sorted(conflicts))

    targets_map: Dict[str, Dict[str, List[str]]] = {}
    prev_files: List[str] = []
    prev_links: List[str] = []
    receipt_path: Optional[Path] = None
    plan_rels: Set[str] = set()
    link_rels: Set[str] = set()
    if resolved_out is not None:
        if os.path.islink(resolved_out):
            raise ValueError(f"Refusing to write through symlinked output directory: {resolved_out}")
        receipt_path = resolved_out / EXPORT_RECEIPT_FILENAME
        if os.path.islink(receipt_path):
            raise ValueError(f"Refusing to access symlinked export receipt: {receipt_path}")
        targets_map = _load_export_receipt(receipt_path, default_target=resolved_target)
        prev_entry = targets_map.get(resolved_target, {"files": [], "links": []})
        prev_files = list(prev_entry.get("files", []))
        prev_links = list(prev_entry.get("links", []))
        plan_rels = {Path(os.path.abspath(p)).relative_to(resolved_out).as_posix() for p in plan}
        link_rels = {Path(os.path.abspath(p)).relative_to(resolved_out).as_posix() for p in links}

    prev_links_set = set(prev_links)
    exec_set = set(executables)
    written: List[Path] = []
    for path, content in sorted(plan.items()):
        _check_no_symlink_ancestors(path, resolved_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        _check_no_symlink_ancestors(path, resolved_out)
        if os.path.islink(path):
            rel_cand = (
                Path(os.path.abspath(path)).relative_to(resolved_out).as_posix()
                if resolved_out is not None and _is_within(path, resolved_out)
                else None
            )
            if force and rel_cand is not None and rel_cand in prev_links_set:
                path.unlink()
            else:
                raise ValueError(f"Refusing to write through symlink: {path}")
        # Bytes, never write_text(): text mode would turn LF into CRLF on Windows.
        _write_bytes_atomic_nofollow(path, _encode(content), output_dir=resolved_out)
        if path in exec_set:
            _make_executable(path)
        written.append(path)
    for path, target in sorted(links.items()):
        _check_no_symlink_ancestors(path, resolved_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        _check_no_symlink_ancestors(path, resolved_out)
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
        except (OSError, NotImplementedError) as exc:
            if not _is_windows_symlink_unsupported(exc):
                raise

    if resolved_out is not None and receipt_path is not None:
        current_rels = plan_rels | link_rels
        other_claimed: Set[str] = set()
        for other_target, other_entry in targets_map.items():
            if other_target == resolved_target:
                continue
            other_claimed.update(other_entry.get("files", []))
            other_claimed.update(other_entry.get("links", []))

        if force:
            for orphan_rel in sorted((set(prev_files) | set(prev_links)) - current_rels - other_claimed):
                if orphan_rel == EXPORT_RECEIPT_FILENAME:
                    continue
                pure_rel = _safe_rel_posix(orphan_rel)
                if pure_rel is None:
                    continue
                orphan_path = resolved_out.joinpath(*pure_rel.parts)
                if not _is_within(orphan_path, resolved_out):
                    continue
                _check_no_symlink_ancestors(orphan_path, resolved_out)
                if os.path.islink(orphan_path) or (os.path.lexists(orphan_path) and orphan_path.is_file()):
                    orphan_path.unlink()
                    _prune_empty_parents(orphan_path.parent, resolved_out)

        if plan or links or prev_files or prev_links:
            _check_no_symlink_ancestors(receipt_path, resolved_out)
            resolved_out.mkdir(parents=True, exist_ok=True)
            if os.path.islink(receipt_path):
                raise ValueError(f"Refusing to write through symlinked export receipt: {receipt_path}")
            if not force:
                kept_files = {
                    r for r in prev_files
                    if _safe_rel_posix(r) is not None and os.path.lexists(resolved_out.joinpath(*_safe_rel_posix(r).parts))  # type: ignore[union-attr]
                }
                kept_links = {
                    r for r in prev_links
                    if _safe_rel_posix(r) is not None and os.path.lexists(resolved_out.joinpath(*_safe_rel_posix(r).parts))  # type: ignore[union-attr]
                }
                plan_rels = plan_rels | (kept_files - link_rels)
                link_rels = link_rels | (kept_links - plan_rels)
            targets_map[resolved_target] = {
                "files": sorted(plan_rels),
                "links": sorted(link_rels),
            }
            receipt_payload = {
                "version": 2,
                "targets": {t: targets_map[t] for t in sorted(targets_map)},
            }
            _write_bytes_atomic_nofollow(
                receipt_path,
                (json.dumps(receipt_payload, indent=2) + "\n").encode("utf-8"),
                output_dir=resolved_out,
            )
    return written
