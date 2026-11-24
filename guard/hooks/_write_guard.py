"""
guard/hooks/_write_guard.py — Lazy PreToolUse `tasks.md` Authorized Test Modifications & stale-reset guard (ADR-0013).
Part of Plumbwork (https://github.com/hadbilen/plumbwork)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import os
import re
import stat
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from guard.paths import HOOK_LOCK_TIMEOUT

from . import pre_tool_use as _ptu
from .common import (
    _AUTH_HEADING_RE,
    _FENCE_RE,
    _LazyRegex,
    _extract_normalized_auth_section,
    _extract_ws_flight_conversations,
    _flight_recorder_file,
    _is_git_repo_workspace,
    _normalize_markdown_newlines,
    _read_bounded_markdown_checked,
    _read_ledger_checked,
    _repo_root,
    file_lock,
    subprocess,
)

_HANDOFF_COMPLETE_STATUS_RE = _LazyRegex(
    r"(?im)^[^\S\r\n]*(?:[-*•][^\S\r\n]+)?(?:\*\*Status:\*\*|\*\*Status\*\*:|Status:)[^\S\r\n]*`?\[COMPLETE\]`?[^\S\r\n]*$"
)
_HANDOFF_ANY_STATUS_RE = _LazyRegex(
    r"(?im)^[^\S\r\n]*(?:[-*•][^\S\r\n]+)?(?:\*\*Status:\*\*|\*\*Status\*\*:|Status:)[^\S\r\n]*(\S.*?)[^\S\r\n]*$"
)
_AUTH_HTML_COMMENT_RE = _LazyRegex(r"(?s)<!--.*?-->")
_EDIT_TARGET_KEYS: Tuple[str, ...] = (
    "TargetContent",
    "Target",
    "old_string",
    "old_str",
    "oldText",
    "old_text",
)
_EDIT_REPLACEMENT_KEYS: Tuple[str, ...] = (
    "ReplacementContent",
    "Replacement",
    "new_string",
    "new_str",
    "newText",
    "new_text",
)


def _handoff_file_allows_stale_reset(handoff_path: Path) -> bool:
    if not os.path.lexists(handoff_path):
        return True
    try:
        if handoff_path.is_symlink():
            return False
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(handoff_path, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > 512 * 1024:
                return False
            chunks: List[bytes] = []
            rem = 512 * 1024 + 1
            while rem > 0:
                buf = os.read(fd, min(65536, rem))
                if not buf:
                    break
                chunks.append(buf)
                rem -= len(buf)
            raw_bytes = b"".join(chunks)
            if len(raw_bytes) > 512 * 1024:
                return False
        finally:
            os.close(fd)
    except OSError:
        return False
    raw_handoff = _normalize_markdown_newlines(raw_bytes.decode("utf-8", errors="replace"))
    htext = _FENCE_RE.sub(" ", raw_handoff)
    statuses = _HANDOFF_ANY_STATUS_RE.findall(htext)
    if not statuses or not _HANDOFF_COMPLETE_STATUS_RE.search(htext):
        return False
    return all(bool(_HANDOFF_COMPLETE_STATUS_RE.match(f"Status: {val}")) for val in statuses)


def _old_auth_has_only_parsed_entries(old_text: str, old_auth: set[str], tb_cls: Any) -> bool:
    empty_tokens = ("", "none", "yok", "n/a", "na", "null", "nil", "false", "hayir", "hayır")
    norm_src = _normalize_markdown_newlines(old_text)
    saw_heading = False
    for match in _AUTH_HEADING_RE.finditer(norm_src):
        saw_heading = True
        inline_tail = (match.group(1) or "").strip()
        if inline_tail:
            cleaned_tail = re.sub(r"[-*•\[\]\s.`_:;()]+", "", inline_tail.lower())
            if cleaned_tail not in empty_tokens:
                for part in inline_tail.split(","):
                    seg = part.strip()
                    if seg and tb_cls._extract_authorized_path(seg) not in old_auth:
                        return False
        body = _AUTH_HTML_COMMENT_RE.sub("", match.group(2) or "")
        for raw_line in body.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            cleaned_line = re.sub(r"[-*•\[\]\s.`_:;()]+", "", stripped.lower())
            if cleaned_line in empty_tokens:
                continue
            if not stripped.startswith(("-", "*", "•", "[")):
                return False
            if tb_cls._extract_authorized_path(raw_line) not in old_auth:
                return False
    return saw_heading


def _check_worktree_paths_clean_for_reset(
    wt_root: Path,
    sorted_paths: List[str],
    tb_cls: Any,
    *,
    conv_id: str = "",
) -> bool:
    for rel_p in sorted_paths:
        cur = wt_root
        parts = [seg for seg in rel_p.split("/") if seg]
        for idx, seg in enumerate(parts):
            cur = cur / seg
            try:
                if cur.is_symlink():
                    return False
                if idx < len(parts) - 1 and (cur / ".git").exists():
                    return False
            except OSError:
                return False
    try:
        tbg = tb_cls(workspace_dir=wt_root)
        snap_src = tbg._snapshot_source(None)
        if os.path.lexists(snap_src) and not tbg.verify(mode="tdd", authorized_modifications=set()).is_intact:
            return False
    except Exception:
        return False
    try:
        head_proc = subprocess.run(
            ["git", "--literal-pathspecs", "-C", str(wt_root), "rev-parse", "--verify", "HEAD"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        head_oid = head_proc.stdout.strip().lower()
        if head_proc.returncode != 0 or not head_oid:
            return False
        status_proc = subprocess.run(
            [
                "git",
                "--literal-pathspecs",
                "-C",
                str(wt_root),
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--ignored=matching",
                "--",
                *sorted_paths,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if status_proc.returncode != 0 or status_proc.stdout.strip() != "":
            return False
        ls_proc = subprocess.run(
            [
                "git",
                "--literal-pathspecs",
                "-C",
                str(wt_root),
                "ls-files",
                "-v",
                "-z",
                "--",
                *sorted_paths,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if ls_proc.returncode != 0:
            return False
        for entry in ls_proc.stdout.split("\0"):
            if entry and not entry.startswith("H "):
                return False
        flight_file = _flight_recorder_file()
        if conv_id and flight_file.is_file():
            wt_key = str(wt_root.resolve())
            with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
                ok_fr, ledger = _read_ledger_checked(flight_file, quarantine=False)
            if not ok_fr:
                return False
            ws_entry = ledger.get(wt_key) if isinstance(ledger.get(wt_key), dict) else {}
            convs = _extract_ws_flight_conversations(ws_entry)
            rec = convs.get(conv_id)
            if isinstance(rec, dict):
                rec_touched = {
                    str(x).strip().replace("\\", "/").lstrip("./")
                    for x in (rec.get("touched_files") or [])
                    if isinstance(x, str) and x.strip()
                }
                touched_relevant = (
                    str(ws_entry.get("conversation_id") or "") == conv_id
                    or bool(rec.get("has_shell_write"))
                    or bool(rec.get("touched_overflow"))
                    or any(t.startswith("<") for t in rec_touched)
                    or bool(rec_touched & set(sorted_paths))
                )
                rec_base = str(rec.get("base_head") or "").strip().lower()
                if touched_relevant and rec_base and rec_base != head_oid:
                    diff_proc = subprocess.run(
                        [
                            "git",
                            "--literal-pathspecs",
                            "-C",
                            str(wt_root),
                            "diff",
                            "--diff-filter=MDCR",
                            "--name-only",
                            rec_base,
                            "HEAD",
                            "--",
                            *sorted_paths,
                        ],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if diff_proc.returncode != 0 or diff_proc.stdout.strip() != "":
                        return False
    except (OSError, RuntimeError, TimeoutError, subprocess.SubprocessError):
        return False
    return True


def _is_safe_stale_auth_reset(
    disk_path: Optional[Path],
    old_text: str,
    new_text: str,
    *,
    conv_id: str = "",
) -> bool:
    if disk_path is None or _extract_normalized_auth_section(new_text) != "":
        return False
    try:
        from guard.test_boundary import TestBoundaryGuard
    except Exception:
        return False
    if TestBoundaryGuard.parse_authorized_tasks_text(new_text) != set():
        return False
    old_auth = TestBoundaryGuard.parse_authorized_tasks_text(old_text)
    if not old_auth or not _old_auth_has_only_parsed_entries(old_text, old_auth, TestBoundaryGuard):
        return False
    ws_dir = disk_path.parent
    try:
        if not ws_dir.is_dir() or not (ws_dir / ".git").exists() or not _is_git_repo_workspace(ws_dir):
            return False
        ws_resolved = ws_dir.resolve()
    except (OSError, RuntimeError):
        return False
    if not _handoff_file_allows_stale_reset(ws_dir / "HANDOFF.md"):
        return False
    main_root = TestBoundaryGuard.resolve_linked_worktree_root(ws_dir)
    if main_root is not None and not _handoff_file_allows_stale_reset(main_root / "HANDOFF.md"):
        return False
    sorted_paths = sorted(old_auth)
    for rel_p in sorted_paths:
        if rel_p.startswith(("-", ":")) or any(ord(ch) < 32 for ch in rel_p):
            return False
    if not _check_worktree_paths_clean_for_reset(ws_dir, sorted_paths, TestBoundaryGuard, conv_id=conv_id):
        return False
    try:
        has_worktrees_dir = (ws_dir / ".git" / "worktrees").is_dir()
    except OSError:
        return False
    if has_worktrees_dir:
        try:
            wt_proc = subprocess.run(
                ["git", "-C", str(ws_dir), "worktree", "list", "--porcelain"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if wt_proc.returncode != 0:
                return False
            for raw_wt_line in wt_proc.stdout.splitlines():
                if raw_wt_line.startswith("worktree "):
                    cand_wt = Path(raw_wt_line[len("worktree "):].strip())
                    try:
                        if not cand_wt.is_dir() or cand_wt.resolve() == ws_resolved:
                            continue
                    except (OSError, RuntimeError):
                        return False
                    if not _handoff_file_allows_stale_reset(cand_wt / "HANDOFF.md"):
                        return False
                    if not _check_worktree_paths_clean_for_reset(
                        cand_wt, sorted_paths, TestBoundaryGuard, conv_id=conv_id
                    ):
                        return False
        except (OSError, subprocess.SubprocessError):
            return False
    return True


def _auth_sections_differ(
    old_text: str,
    new_text: str,
    *,
    disk_path: Optional[Path] = None,
    conv_id: str = "",
) -> bool:
    differ = _extract_normalized_auth_section(new_text) != _extract_normalized_auth_section(old_text)
    if not differ:
        try:
            from guard.test_boundary import TestBoundaryGuard

            if TestBoundaryGuard.parse_authorized_tasks_text(new_text) != TestBoundaryGuard.parse_authorized_tasks_text(old_text):
                differ = True
        except Exception:
            differ = True
    if not differ:
        return False
    if _is_safe_stale_auth_reset(disk_path, old_text, new_text, conv_id=conv_id):
        return False
    return True


def _extract_edit_pair(mapping: Dict[str, Any]) -> Tuple[bool, Optional[Tuple[str, str]]]:
    has_t = any(k in mapping for k in _EDIT_TARGET_KEYS)
    has_r = any(k in mapping for k in _EDIT_REPLACEMENT_KEYS)
    if not has_t and not has_r:
        return False, None
    t_val = next((mapping[k] for k in _EDIT_TARGET_KEYS if k in mapping and mapping[k] is not None), None)
    r_val = next((mapping[k] for k in _EDIT_REPLACEMENT_KEYS if k in mapping and mapping[k] is not None), None)
    if not isinstance(t_val, str) or not isinstance(r_val, str) or t_val == "":
        return True, None
    return True, (_normalize_markdown_newlines(t_val), _normalize_markdown_newlines(r_val))


def _resolve_tasks_md_state(
    target: str,
    base_dir: Optional[Path],
) -> Tuple[Optional[str], Optional[Path], bool, bool, str]:
    """
    Resolves `target` and reads existing `tasks.md` with bounded non-symlink checks.
    Returns `(norm_target, disk_path, is_symlink, read_ok, norm_old_text)`.
    When `norm_target is None`, `target` was an unparseable `file:` URI (`is_symlink` signals tasks mention).
    """
    raw_s = target.strip()
    if raw_s.lower().startswith("file:"):
        parsed_uri = _ptu._parse_file_uri(raw_s)
        if parsed_uri is None:
            return None, None, ("tasks" in urllib.parse.unquote(raw_s).lower()), False, ""
        norm_target = _ptu._canonicalize_check_path(parsed_uri)
    else:
        norm_target = _ptu._canonicalize_check_path(raw_s)
    raw_disk_path = Path(os.path.expanduser(norm_target))
    if not raw_disk_path.is_absolute():
        raw_disk_path = (base_dir or _repo_root()) / raw_disk_path
    is_target_symlink = False
    try:
        is_target_symlink = raw_disk_path.is_symlink()
        disk_path = raw_disk_path.resolve()
    except (OSError, RuntimeError):
        is_target_symlink = True
        disk_path = raw_disk_path
    read_ok = True
    old_text = ""
    if is_target_symlink:
        try:
            if disk_path.is_file() and disk_path.stat().st_size <= 524288:
                old_text = disk_path.read_text(encoding="utf-8", errors="replace")
            elif disk_path.is_file():
                read_ok = False
        except OSError as exc:
            read_ok = False
            sys.stderr.write(f"[Harness Write Guard] Failed reading symlinked `{disk_path}`: {exc}\n")
    else:
        read_ok, old_text = _read_bounded_markdown_checked(disk_path)
        if not read_ok:
            sys.stderr.write(f"[Harness Write Guard] Failed reading `{disk_path}` within 512 KiB bound.\n")
    return norm_target, disk_path, is_target_symlink, read_ok, _normalize_markdown_newlines(old_text)


def _simulate_tasks_write_candidates(
    norm_old: str,
    args: Dict[str, Any],
) -> Tuple[List[str], bool]:
    """
    Simulates every content/chunk/edit payload in `args` against `norm_old`.
    Returns `(simulated_texts, ambiguous_or_unsimulatable)`.
    """
    sim_texts: List[str] = []
    ambiguous = False
    evaluated_any = False

    for content_key in ("Content", "FileContent", "CodeContent", "content", "file_text"):
        if content_key in args and args.get(content_key) is not None:
            raw_body = args.get(content_key)
            if not isinstance(raw_body, str):
                return sim_texts, True
            evaluated_any = True
            body = _normalize_markdown_newlines(raw_body)
            is_append = bool(args.get("Append") or args.get("append"))
            sim_texts.append((norm_old + body) if is_append else body)

    pair_groups: List[List[Tuple[str, str]]] = []
    for chunk_key in ("ReplacementChunks", "edits", "chunks"):
        if chunk_key in args and args.get(chunk_key) is not None:
            chunks = args.get(chunk_key)
            if not isinstance(chunks, list) or not chunks:
                return sim_texts, True
            group: List[Tuple[str, str]] = []
            for ch in chunks:
                if not isinstance(ch, dict):
                    return sim_texts, True
                has_keys, extracted_pair = _extract_edit_pair(ch)
                if not has_keys or extracted_pair is None:
                    return sim_texts, True
                group.append(extracted_pair)
            pair_groups.append(group)

    has_top_edit, top_pair = _extract_edit_pair(args)
    if has_top_edit:
        if top_pair is None:
            return sim_texts, True
        pair_groups.append([top_pair])

    has_existing_heading = bool(_AUTH_HEADING_RE.search(norm_old))
    for pairs in pair_groups:
        evaluated_any = True
        if len(pairs) == 1:
            t_s, r_s = pairs[0]
            if norm_old and t_s in norm_old:
                sim_texts.append(norm_old.replace(t_s, r_s))
            elif has_existing_heading or re.search(
                r"Authorized\s+Test\s+Modifications", f"{t_s}\n{r_s}", re.IGNORECASE
            ):
                ambiguous = True
        else:
            if not norm_old:
                ambiguous = True
                continue
            spans: List[Tuple[int, int, str]] = []
            group_bad = False
            for t_s, r_s in pairs:
                pos = 0
                found_for_pair = 0
                while True:
                    idx = norm_old.find(t_s, pos)
                    if idx == -1:
                        break
                    spans.append((idx, idx + len(t_s), r_s))
                    found_for_pair += 1
                    pos = idx + len(t_s)
                if found_for_pair == 0:
                    group_bad = True
                    break
            if not group_bad:
                spans.sort(key=lambda item: (item[0], item[1]))
                for idx in range(1, len(spans)):
                    if spans[idx - 1][1] > spans[idx][0]:
                        group_bad = True
                        break
            if group_bad:
                ambiguous = True
                continue
            out_parts: List[str] = []
            cursor = 0
            for s_start, s_end, r_s in spans:
                out_parts.append(norm_old[cursor:s_start])
                out_parts.append(r_s)
                cursor = s_end
            out_parts.append(norm_old[cursor:])
            sim_texts.append("".join(out_parts))

    if not evaluated_any:
        ambiguous = True
    return sim_texts, ambiguous


def _write_mutates_authorized_test_section(
    target: str,
    args: Dict[str, Any],
    base_dir: Optional[Path],
    *,
    allow_stale_reset: bool = True,
    conv_id: str = "",
) -> bool:
    norm_target, disk_path, is_target_symlink, read_ok, norm_old = _resolve_tasks_md_state(target, base_dir)
    if norm_target is None:
        return is_target_symlink
    if Path(norm_target).name.lower() != "tasks.md":
        return False
    if not read_ok:
        return True
    reset_disk_path: Optional[Path] = disk_path if (allow_stale_reset and not is_target_symlink) else None
    sim_texts, ambiguous = _simulate_tasks_write_candidates(norm_old, args)
    for sim_text in sim_texts:
        if _auth_sections_differ(norm_old, sim_text, disk_path=reset_disk_path, conv_id=conv_id):
            return True
    return ambiguous


def _summarize_authorized_test_mutation_diff(
    target: str,
    args: Dict[str, Any],
    base_dir: Optional[Path],
) -> str:
    """Returns a concise operator-readable summary of test path(s) and diff in `## Authorized Test Modifications`."""
    norm_target, _disk_path, _is_sym, read_ok, old_text = _resolve_tasks_md_state(target, base_dir)
    label = norm_target or target.strip()
    if norm_target is None or not read_ok:
        return f"target `{label}` (unable to simulate exact section diff; inspect edit arguments)"

    sim_texts, _ambiguous = _simulate_tasks_write_candidates(old_text, args)
    old_sec = _extract_normalized_auth_section(old_text)
    sim_text: Optional[str] = None
    for cand in sim_texts:
        if _extract_normalized_auth_section(cand) != old_sec:
            sim_text = cand
            break
    if sim_text is None and sim_texts:
        sim_text = sim_texts[0]
    if sim_text is None:
        return f"target `{label}` (unable to simulate exact section diff; inspect edit arguments)"

    new_sec = _extract_normalized_auth_section(sim_text)
    old_lines = [l for l in old_sec.splitlines() if l.strip()]
    new_lines = [l for l in new_sec.splitlines() if l.strip()]
    added_lines = max(0, len([l for l in new_lines if l not in old_lines]))
    removed_lines = max(0, len([l for l in old_lines if l not in new_lines]))
    delta = f"+{added_lines}/-{removed_lines} section lines"

    try:
        from guard.test_boundary import TestBoundaryGuard

        old_paths = TestBoundaryGuard.parse_authorized_tasks_text(old_text)
        new_paths = TestBoundaryGuard.parse_authorized_tasks_text(sim_text)
        added_paths = sorted(new_paths - old_paths)
        removed_paths = sorted(old_paths - new_paths)
        parts: List[str] = []
        if added_paths:
            shown = ", ".join(f"`{p}`" for p in added_paths[:3])
            extra = f" (+{len(added_paths) - 3} more)" if len(added_paths) > 3 else ""
            parts.append(f"adds {shown}{extra}")
        if removed_paths:
            shown = ", ".join(f"`{p}`" for p in removed_paths[:3])
            extra = f" (+{len(removed_paths) - 3} more)" if len(removed_paths) > 3 else ""
            parts.append(f"removes {shown}{extra}")
        if not parts and new_paths:
            shown = ", ".join(f"`{p}`" for p in sorted(new_paths)[:3])
            parts.append(f"edits entries for {shown}")
        if parts:
            return f"{'; '.join(parts)} ({delta})"
    except Exception as exc:
        sys.stderr.write(f"[Harness Write Guard] Failed to summarize authorized test diff ({type(exc).__name__}): {exc}\n")
    return f"modifies section in `{label}` ({delta})"
