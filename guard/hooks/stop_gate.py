"""
guard/hooks/stop_gate.py — Stop completion gate, diff/test-boundary scanner & flight-recorder reconciliation (ADR-0008).
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import os
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import tomllib as _default_tomllib  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    _default_tomllib = None  # type: ignore[assignment]

from guard.paths import HOOK_LOCK_TIMEOUT, is_within

from .common import (
    MAX_STRIKES,
    _EMPTY_AUTH_TOKENS,
    _FENCE_RE,
    _HEX_OID_RE,
    _INLINE_CODE_RE,
    _UNRECOVERED_FLIGHT_STATES,
    _LazyRegex,
    _conversation_id,
    _extract_latest_user_prompt,
    _extract_normalized_auth_section,
    _extract_user_request_prose,
    _facade,
    _facade_attr,
    _flight_recorder_file,
    _is_git_repo_workspace,
    _prune_missing_flight_workspaces,
    _read_ledger_checked,
    _read_ledger_safe,
    _repo_root,
    _safe_int,
    _utc_now_iso,
    _workspaces_from_payload,
    atomic_write_json,
    config_dir,
    configured_config_dir,
    file_lock,
    json,
    state_dir,
    subprocess,
)


# Stop-gate diff inspection regexes
_TAUTOLOGY_PY_RE = _LazyRegex(
    r"^\+\s*(?:"
    r"assert\s+([A-Za-z0-9_.]+)\s*==\s*\1(?:\s|$|,|#)|"
    r"assert\s+True(?:\s|$|,|#)|"
    r"self\.assertEqual\(\s*([A-Za-z0-9_.]+)\s*,\s*\2\s*\)|"
    r"self\.assertTrue\(\s*True\s*\)"
    r")"
)

_TAUTOLOGY_JS_RE = _LazyRegex(
    r"^\+\s*expect\(\s*([A-Za-z0-9_.]+)\s*\)\.(?:toBe|toEqual|toStrictEqual)\(\s*\1\s*\)"
)

_COMMENT_ADDED_LINE_RE = _LazyRegex(r"^\+\s*(?:#|//)")

_TEST_RUNNER_SNIFF_RE = _LazyRegex(
    r"^\+.*?(?:"
    r"PYTEST_" r"CURRENT_TEST|"
    r"UNITTEST_" r"RUNNING|"
    r"sys\.modules(?:\.get\s*\(|\s*\[)\s*['\"](?:unittest|pytest)['\"]|"
    r"['\"](?:unittest|pytest)['\"]\s+in\s+sys\.modules|"
    r"NODE_ENV\s*===\s*['\"]test['\"]|"
    r"NODE_ENV\s*==\s*['\"]test['\"]|"
    r"process\.env\.JEST_WORKER_ID|"
    r"process\.env\.VITEST"
    r")"
)

_TEST_SKIP_RE = _LazyRegex(
    r"^\+\s*(?:"
    r"@pytest\.mark\.(?:skip(?:if)?|xfail)\b|"
    r"@unittest\.(?:skip(?:If|Unless)?|expectedFailure)\b|"
    r"pytest\.(?:skip|xfail)\s*\(|"
    r"self\.skipTest\s*\(|"
    r"unittest\.SkipTest\s*\(|"
    r"(?:it|test|describe)\.(?:skip|todo)\s*\(|"
    r"(?:xit|xtest|xdescribe)\s*\("
    r")"
)

# Files inside the harness repo that legitimately mention test-runner env vars as scanner patterns
_SCANNER_EXEMPT_SUFFIXES = (
    "guard/agy_hooks.py",
    "guard/hooks/stop_gate.py",
    "porter/sanitizer.py",
    "scripts/verify_invariants.py",
    ".harness/manifest.json",
)


def _is_exempt_harness_scanner_path(norm_path: str, workspace: Optional[Path]) -> bool:
    if norm_path not in _SCANNER_EXEMPT_SUFFIXES:
        return False
    if workspace is None:
        return True
    return (workspace / ".harness" / "manifest.json").is_file() or (
        (workspace / "guard" / "agy_hooks.py").is_file() and (workspace / "porter" / "sanitizer.py").is_file()
    )

def _extract_latest_assistant_message(payload: Dict[str, Any]) -> str:
    """Returns the latest assistant response text from payload or transcriptPath JSONL."""
    for key in ("lastAssistantMessage", "assistantMessage", "response"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()

    transcript = payload.get("transcriptPath") or payload.get("transcript_path")
    if isinstance(transcript, str) and transcript.strip():
        path = Path(transcript).expanduser()
        if path.is_file():
            try:
                with path.open("rb") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - 131072), os.SEEK_SET)
                    lines = f.read().decode("utf-8", errors="replace").splitlines()
                for raw in reversed(lines):
                    raw = raw.strip()
                    if not raw.startswith("{"):
                        continue
                    try:
                        entry = json.loads(raw)
                    except ValueError:
                        continue
                    if str(entry.get("type", "")).upper() == "PLANNER_RESPONSE":
                        content = entry.get("content")
                        if isinstance(content, str) and content.strip():
                            return content.strip()
            except OSError:
                pass
    return ""

def _record_flight_stop(
    workspace: Optional[Path],
    conv_id: str,
    findings_count: int,
    *,
    workspace_clean: bool = False,
    deferred_question: bool = False,
    create_if_missing: bool = False,
) -> None:
    """
    Reconciles the workspace flight record when a turn reaches `handle_stop` normally,
    transitioning `status` from `"in_flight"` to `"turn_complete"` (`0` findings) or
    `"in_progress_blocked"` (`>0` findings), without allowing a read-only turn in a new
    conversation to erase an unrecovered crash/blocked state on a still-dirty workspace.
    """
    flight_file = _flight_recorder_file()
    if workspace is None or not workspace.is_dir():
        if workspace is not None and flight_file.is_file():
            try:
                with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
                    ledger = _read_ledger_safe(flight_file)
                    if _prune_missing_flight_workspaces(ledger):
                        atomic_write_json(flight_file, ledger)
            except (OSError, RuntimeError, TimeoutError):
                pass
        return
    if not flight_file.is_file() and not (create_if_missing and findings_count > 0):
        return
    try:
        ws_key = str(workspace.resolve())
        with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
            ledger = _read_ledger_safe(flight_file)
            pruned_dead = _prune_missing_flight_workspaces(ledger)
            entry = ledger.get(ws_key)
            if not isinstance(entry, dict):
                if not (create_if_missing and findings_count > 0):
                    if pruned_dead:
                        atomic_write_json(flight_file, ledger)
                    return
                ledger[ws_key] = {
                    "workspace": ws_key,
                    "conversation_id": conv_id,
                    "status": "in_progress_blocked",
                    "seq": 1,
                    "updated_at": _utc_now_iso(),
                    "base_head": "",
                    "pre_edit_stash": "",
                    "last_tool": "stop",
                    "last_target": "(workspace diff)",
                    "touched_files": [],
                    "last_stop_findings_count": _safe_int(findings_count, default=0),
                }
                while len(ledger) > 50:
                    oldest = next(iter(ledger))
                    del ledger[oldest]
                atomic_write_json(flight_file, ledger)
                return
            prev_conv = str(entry.get("conversation_id") or "")
            prev_status = str(entry.get("status") or "")

            if deferred_question:
                if prev_conv != conv_id or prev_status != "in_flight":
                    return
                prior_findings = _safe_int(entry.get("last_stop_findings_count"), default=0)
                updated = dict(entry)
                updated["status"] = "in_progress_blocked" if prior_findings > 0 else "turn_complete"
                updated["updated_at"] = _utc_now_iso()
                ledger[ws_key] = updated
                atomic_write_json(flight_file, ledger)
                return

            if (
                findings_count == 0
                and prev_conv != conv_id
                and not workspace_clean
                and prev_status in _UNRECOVERED_FLIGHT_STATES
            ):
                return

            updated = dict(entry)
            updated["conversation_id"] = conv_id
            updated["status"] = "turn_complete" if findings_count == 0 else "in_progress_blocked"
            updated["last_stop_findings_count"] = _safe_int(findings_count, default=0)
            updated["updated_at"] = _utc_now_iso()
            ledger[ws_key] = updated
            atomic_write_json(flight_file, ledger)
    except (OSError, RuntimeError, TimeoutError):
        pass

# ----------------------------------------------------------------------
# 3. Stop: Completion & Diff Integrity Gate (with 3-Strike Circuit Breaker)
# ----------------------------------------------------------------------
def _is_test_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/").lstrip("./")
    parts = norm.split("/")
    name = parts[-1] if parts else norm
    if any(p in ("tests", "test", "__tests__") for p in parts[:-1]):
        return True
    return (
        name.startswith("test_")
        or name.endswith(("_test.py", "_test.go", ".test.ts", ".test.tsx", ".test.js", ".spec.ts", ".spec.tsx", ".spec.js"))
    )

def _is_deferrable_question(assistant_text: str) -> bool:
    """
    True when the assistant is asking the user a clarifying question rather than claiming
    task completion (commands_at_questions: defer).
    """
    if not assistant_text:
        return False
    if "### Delivery Block" in assistant_text or "[COMPLETE]" in assistant_text:
        return False
    stripped = re.sub(r"[*_`>\s]+$", "", assistant_text.strip())
    return stripped.endswith("?")

def _authorized_test_modification_text(workspace: Optional[Path]) -> str:
    """
    Extracts the normalized authorization text under `## Authorized Test Modifications`
    (supporting both the inline `## Authorized Test Modifications: [file: reason]` format from
    skills/harness/SKILL.md and multi-line section bodies). Returns "" if absent or placeholder.
    """
    if workspace is None:
        return ""
    tasks_file = workspace / "tasks.md"
    if tasks_file.is_file():
        try:
            sec = _extract_normalized_auth_section(tasks_file.read_text(encoding="utf-8", errors="replace"))
            if sec:
                return sec
        except OSError:
            pass
    from guard.test_boundary import TestBoundaryGuard

    main_root = TestBoundaryGuard.resolve_linked_worktree_root(workspace)
    if main_root is None or not (main_root / "tasks.md").is_file():
        return ""
    try:
        text = (main_root / "tasks.md").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return _extract_normalized_auth_section(text)

def _has_authorized_test_modifications(workspace: Path, rel_path: str = "") -> bool:
    from guard.test_boundary import TestBoundaryGuard

    auth_paths = {
        p.replace("\\", "/").lstrip("./")
        for p in TestBoundaryGuard.load_authorized_from_tasks_md(workspace)
        if p.lower() not in _EMPTY_AUTH_TOKENS
    }
    if not auth_paths:
        return False
    if not rel_path:
        return True
    norm = str(rel_path).replace("\\", "/").lstrip("./")
    return norm in auth_paths

_MD_LINK_RE = re.compile(r"\]\(([^)\s]+)\)")

_PLACEHOLDER_LINK_RE = re.compile(r"(?:[<>{}]|(?:/|^)path/to/|/absolute/path|/your[-_])", re.IGNORECASE)

def validate_structured_content(norm_path: str, content: str) -> List[str]:
    """
    Deterministically validates structured file formats (.json, .toml, .svg) using only
    the Python standard library.
    """
    lower = norm_path.lower()
    if lower.endswith(".json"):
        try:
            json.loads(content)
        except json.JSONDecodeError as exc:
            return [
                f"Malformed JSON syntax in `{norm_path}` (`line {exc.lineno}, column {exc.colno}: {exc.msg}`) "
                "— fix JSON syntax before completing (skills/harness/SKILL.md §3B Step 1)."
            ]
        except RecursionError:
            return [
                f"Malformed JSON syntax in `{norm_path}` (`maximum nesting depth exceeded`) "
                "— fix JSON syntax before completing (skills/harness/SKILL.md §3B Step 1)."
            ]
        return []

    _tomllib = _facade_attr("tomllib", _default_tomllib)
    if lower.endswith(".toml") and _tomllib is not None:
        try:
            _tomllib.loads(content)
        except Exception as exc:
            msg = str(exc).splitlines()[0][:80] if str(exc) else "invalid TOML"
            return [
                f"Malformed TOML syntax in `{norm_path}` (`{msg}`) "
                "— fix TOML syntax before completing (skills/harness/SKILL.md §3B Step 1)."
            ]
        return []

    if lower.endswith(".svg"):
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", content, re.IGNORECASE):
            return [
                f"Unsafe XML DOCTYPE/ENTITY declaration in `{norm_path}` (`DOCTYPE/ENTITY`) "
                "— DTD/entity declarations are forbidden in SVG files."
            ]
        try:
            root = ET.fromstring(content)
        except (ET.ParseError, RecursionError) as exc:
            msg = str(exc).splitlines()[0][:80] if str(exc) else "invalid XML"
            return [
                f"Malformed SVG/XML syntax in `{norm_path}` (`{msg}`) "
                "— fix XML structure before completing (skills/harness/SKILL.md §3B Step 1)."
            ]
        tag = root.tag.split("}", 1)[-1] if "}" in root.tag else root.tag
        if tag.lower() != "svg":
            return [
                f"Invalid SVG root element in `{norm_path}` (`<{tag}>`) "
                "— SVG files must have `<svg>` as their root element."
            ]
        return []

    return []

_UI_SLOP_EXTENSIONS = (".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".css")

_UI_SLOP_SCANNER_MOD: Any = None

_UI_SLOP_SCANNER_LOADED = False

def _load_ui_slop_scanner() -> Any:
    """Loads skills/antislop/scripts/check_ui_slop.py from _repo_root() or config_dir()."""
    global _UI_SLOP_SCANNER_MOD, _UI_SLOP_SCANNER_LOADED
    if _UI_SLOP_SCANNER_LOADED and _UI_SLOP_SCANNER_MOD is not None:
        return _UI_SLOP_SCANNER_MOD
    candidates = [
        _repo_root() / "skills" / "antislop" / "scripts" / "check_ui_slop.py",
        config_dir() / "skills" / "antislop" / "scripts" / "check_ui_slop.py",
        configured_config_dir() / "skills" / "antislop" / "scripts" / "check_ui_slop.py",
        Path("/usr/share/antigravity-harness") / "skills" / "antislop" / "scripts" / "check_ui_slop.py",
    ]
    for script_path in candidates:
        if script_path.is_file():
            try:
                spec = importlib.util.spec_from_file_location("_agy_check_ui_slop", script_path)
                if spec is not None and spec.loader is not None:
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules[spec.name] = mod
                    try:
                        spec.loader.exec_module(mod)
                    except BaseException:
                        sys.modules.pop(spec.name, None)
                        raise
                    _UI_SLOP_SCANNER_MOD = mod
                    _UI_SLOP_SCANNER_LOADED = True
                    return mod
            except Exception:
                continue
    return None

def validate_ui_slop_content(norm_path: str, content: str) -> List[str]:
    """
    Runs check_ui_slop.py (`UI-1`–`UI-5`, mode='auto' detecting game/editorial/utility)
    on modified non-test UI/HTML/game prototype files.
    """
    if not norm_path.lower().endswith(_UI_SLOP_EXTENSIONS) or norm_path.startswith("skills/silk-design/assets/"):
        return []
    mod = _load_ui_slop_scanner()
    if mod is None or not hasattr(mod, "scan_text"):
        return []
    try:
        report = mod.scan_text(content, path=norm_path, mode="auto")
    except Exception as exc:
        return [
            f"UI slop scanner failed on `{norm_path}` ({type(exc).__name__}: {exc}) "
            "— verify `skills/antislop/scripts/check_ui_slop.py` health."
        ]
    out: List[str] = []
    for f in getattr(report, "findings", [])[:3]:
        out.append(
            f"UI slop violation [{f.rule_id}] in `{norm_path}` (`L{f.line_number}: {f.matched_span}`) "
            f"— {f.fix_hint} (skills/harness/SKILL.md §3B Step 4b)."
        )
    return out

def _inspect_markdown_added_links(
    norm_path: str,
    raw_added: str,
    workspace: Optional[Path],
    md_doc_cache: Optional[Dict[str, Optional[Tuple[str, str]]]] = None,
) -> List[str]:
    """Checks added Markdown prose lines for broken workspace-local file:// or relative links."""
    if workspace is None or "](" not in raw_added:
        return []
    no_code = _INLINE_CODE_RE.sub(" ", raw_added)
    raw_links = [lnk for lnk in _MD_LINK_RE.findall(no_code) if not _PLACEHOLDER_LINK_RE.search(lnk)]
    if not raw_links:
        return []

    md_disk = workspace / norm_path
    try:
        if md_doc_cache is not None and norm_path in md_doc_cache:
            cached_pair = md_doc_cache[norm_path]
        else:
            cached_pair = None
            if (
                md_disk.is_file()
                and not md_disk.is_symlink()
                and is_within(md_disk, workspace)
                and md_disk.stat().st_size <= 262144
            ):
                full_doc = md_disk.read_text(encoding="utf-8", errors="replace")
                cached_pair = (full_doc, _FENCE_RE.sub(" ", full_doc))
            if md_doc_cache is not None:
                md_doc_cache[norm_path] = cached_pair
        if cached_pair is not None:
            full_doc, unfenced_doc = cached_pair
            if raw_added in full_doc and raw_added not in unfenced_doc:
                return []
    except OSError:
        pass

    issues: List[str] = []
    for raw_link in raw_links:
        if raw_link.startswith("file://"):
            parsed = urllib.parse.urlparse(raw_link)
            unquoted = urllib.parse.unquote(parsed.path or "")
            if not unquoted:
                continue
            target = Path(unquoted)
            if is_within(target, workspace) and not target.exists():
                issues.append(
                    f"Broken workspace link in `{norm_path}` (`{raw_link}`) "
                    "— referenced file does not exist in workspace (skills/harness/SKILL.md §3B Step 3)."
                )
        elif not re.match(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|#|/)", raw_link):
            rel_part = urllib.parse.unquote(raw_link.split("#", 1)[0].split("?", 1)[0])
            if rel_part and is_within(md_disk, workspace):
                resolved = md_disk.parent / rel_part
                if is_within(resolved, workspace) and not resolved.exists():
                    issues.append(
                        f"Broken workspace link in `{norm_path}` (`{raw_link}`) "
                        "— referenced file does not exist in workspace (skills/harness/SKILL.md §3B Step 3)."
                    )
    return issues

_ISO_TIMEBOMB_RE = re.compile(r"['\"]20(?:2[4-9]|[3-9]\d)-\d{2}-\d{2}T\d{2}:\d{2}")

_LIVE_CLOCK_CALL_RE = re.compile(r"\b(?:datetime\.(?:now|utcnow)|time\.time|Date\.now)\s*\(")

_CLOCK_INJECTION_RE = re.compile(
    r"(?:\b(?:now|clock|current_time)\s*=|mock\.patch|monkeypatch|freeze_time|timedelta\s*\()"
)

_STRING_LIT_RE = re.compile(r"'([^'\\\n]{8,120})'|\"([^\"\\\n]{8,120})\"")

_CODE_EXTS_FOR_STALE_NEG = (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs")

def _scan_stale_negative_assertions(
    removed_by_prod_file: Dict[str, List[str]],
    all_added_lines: List[str],
    modified_test_files: set[str],
    workspace: Optional[Path],
) -> List[str]:
    if workspace is None or not removed_by_prod_file:
        return []
    added_blob = "\n".join(all_added_lines)
    candidate_lits: List[Tuple[str, str]] = []
    seen_lits: set[str] = set()
    for prod_path, rem_lines in removed_by_prod_file.items():
        if not prod_path.lower().endswith(_CODE_EXTS_FOR_STALE_NEG):
            continue
        if _is_exempt_harness_scanner_path(prod_path, workspace):
            continue
        prod_disk = workspace / prod_path
        prod_current = ""
        try:
            if prod_disk.is_file() and prod_disk.stat().st_size <= 262144:
                prod_current = prod_disk.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        for rem in rem_lines:
            for m in _STRING_LIT_RE.finditer(rem):
                lit = m.group(1) if m.group(1) is not None else (m.group(2) or "")
                if (
                    lit in seen_lits
                    or not re.search(r"[A-Za-z]", lit)
                    or lit.startswith(("http://", "https://", "/", "./", "../"))
                    or lit in added_blob
                    or (prod_current and lit in prod_current)
                ):
                    continue
                seen_lits.add(lit)
                candidate_lits.append((prod_path, lit))
                if len(candidate_lits) >= 25:
                    break
            if len(candidate_lits) >= 25:
                break
        if len(candidate_lits) >= 25:
            break

    if not candidate_lits:
        return []

    test_files: List[Tuple[str, str]] = []
    tests_root = workspace / "tests"
    scan_roots = [tests_root] if tests_root.is_dir() else [workspace]
    for s_root in scan_roots:
        for root, dirs, files in os.walk(s_root):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules", ".venv", "venv")]
            for fname in sorted(files):
                fpath = Path(root) / fname
                try:
                    rel = fpath.relative_to(workspace).as_posix()
                except ValueError:
                    continue
                if not _is_test_path(rel):
                    continue
                try:
                    if not fpath.is_file() or fpath.is_symlink() or fpath.stat().st_size > 262144:
                        continue
                    test_files.append((rel, fpath.read_text(encoding="utf-8", errors="replace")))
                except OSError:
                    continue
                if len(test_files) >= 60:
                    break
            if len(test_files) >= 60:
                break

    issues: List[str] = []
    fn_split_re = re.compile(r"^\s*(?:async\s+)?def\s+test_|^\s*(?:it|test)\s*\(")
    for prod_path, lit in candidate_lits:
        esc = re.escape(lit)
        neg_re = re.compile(
            rf"(?:assertNotIn\s*\(\s*['\"]{esc}['\"]\s*,|assert\s+['\"]{esc}['\"]\s+not\s+in\b|\.not\.toContain\s*\(\s*['\"]{esc}['\"]\s*\))"
        )
        for test_rel, t_content in test_files:
            fn_blocks: List[List[str]] = [[]]
            for ln in t_content.splitlines():
                if fn_split_re.match(ln) and fn_blocks[-1]:
                    fn_blocks.append([ln])
                else:
                    fn_blocks[-1].append(ln)
            for block_lines in fn_blocks:
                code_only = "\n".join(
                    ln for ln in block_lines if not ln.lstrip().startswith(("#", "//"))
                )
                if neg_re.search(code_only) and lit not in neg_re.sub("", code_only):
                    issues.append(
                        f"Stale negative assertion in `{test_rel}` (`{lit[:60]}`) referencing literal removed from `{prod_path}` "
                        "— update or replace vacuous negative assertions (GEMINI.md Rule 9)."
                    )
                    break
    return issues

_ACTIVE_TEST_ASSERT_RE = re.compile(
    r"^\s*(?!#|//|/\*|\*)(?:"
    r"assert\b|"
    r"(?:await\s+)?(?:self|t|assert|require)\.(?:assert\w*|fail\w*|Equal|NoError|True|False)\s*\(|"
    r"(?:await\s+)?expect\s*\(|"
    r"pytest\.raises\s*\(|"
    r"assert(?:_eq|_ne|!)!\s*\("
    r")"
)

_NEW_FILE_CAPABILITY_SKIP_RE = re.compile(
    r"^\s*@(?:unittest\.skip(?:If|Unless)|pytest\.mark\.skipif)\s*\("
    r"(?!\s*(?:True|False|1|0)\s*(?:,|\)))"
    r"[^#\n]*(?:os\.name|sys\.platform|platform\.system|shutil\.which|os\.geteuid|IS_ROOT|IS_WINDOWS|POSIX)\b"
)

_PY_TEST_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(test_[A-Za-z0-9_]+)\s*\(")

_UNTRACKED_MAX_FILES = 200

_UNTRACKED_MAX_BYTES = 1024 * 1024

_INSCOPE_UNTRACKED_CODE_EXTS = (
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    *_UI_SLOP_EXTENSIONS,
)

def _unquote_git_diff_path(header_line: str, prefix: str = "b/") -> str:
    """
    Parses a unified diff `+++ ...` or `--- ...` header line into a normalized workspace-relative POSIX path,
    decoding C-quoted UTF-8 octal escapes (`+++ "b/tests/\\303\\247..."`) when `core.quotePath` is active.
    """
    raw_spec = header_line[3:].strip()
    if not raw_spec or raw_spec == "/dev/null" or raw_spec.startswith("/dev/null\t"):
        return ""
    if raw_spec.startswith('"'):
        buf = bytearray()
        i = 1
        n = len(raw_spec)
        closed = False
        esc_map = {
            "a": 0x07,
            "b": 0x08,
            "t": 0x09,
            "n": 0x0A,
            "v": 0x0B,
            "f": 0x0C,
            "r": 0x0D,
            "\\": 0x5C,
            '"': 0x22,
        }
        while i < n:
            ch = raw_spec[i]
            if ch == '"':
                closed = True
                break
            if ch == "\\" and i + 1 < n:
                nxt = raw_spec[i + 1]
                if nxt in "01234567":
                    oct_str = nxt
                    j = i + 2
                    while j < n and j < i + 4 and raw_spec[j] in "01234567":
                        oct_str += raw_spec[j]
                        j += 1
                    buf.append(int(oct_str, 8) & 0xFF)
                    i = j
                    continue
                if nxt in esc_map:
                    buf.append(esc_map[nxt])
                    i += 2
                    continue
                buf.extend(nxt.encode("utf-8"))
                i += 2
                continue
            buf.extend(ch.encode("utf-8"))
            i += 1
        decoded = buf.decode("utf-8", errors="replace") if closed else raw_spec.strip('"')
    else:
        decoded = raw_spec.split("\t", 1)[0].strip()

    if not decoded.startswith(prefix):
        return ""
    return decoded[len(prefix) :].replace("\\", "/")

_STRICT_PY_EQ_RE = _LazyRegex(r"^\s*assert\s+(.+?)\s*==\s*(.+?)(?:\s+#.*)?$")

_STRICT_UNITTEST_EQ_RE = _LazyRegex(
    r"^\s*(?:await\s+)?(?:self|t|assert|require)\.(assertEqual|assertListEqual|assertDictEqual|assertSetEqual|assertTupleEqual|Equal)\s*\(\s*([^,]+?)\s*,"
)

_STRICT_JS_EQ_RE = _LazyRegex(
    r"^\s*(?:await\s+)?expect\s*\(\s*(.+?)\s*\)\.(toBe|toEqual|toStrictEqual)\s*\("
)

_RELAXED_PY_CMP_RE = _LazyRegex(
    r"^\s*assert\s+(.+?)\s*(>=|<=|!=|>|<|\bin\b|\bis\s+not\s+None\b)(?:\s+.*)?$"
)

_RELAXED_PY_TRUTHY_RE = _LazyRegex(
    r"^\s*assert\s+(?:bool\s*\(\s*(.+?)\s*\)|([A-Za-z_][A-Za-z0-9_.\[\]()'\"-]*))(?:\s*(?:,\s*['\"].*)?(?:#.*)?)?$"
)

_RELAXED_UNITTEST_RE = _LazyRegex(
    r"^\s*(?:await\s+)?(?:self|t|assert|require)\.(assertGreaterEqual|assertLessEqual|assertGreater|assertLess|assertNotEqual|assertIn|assertIsNotNone|assertTrue)\s*\(\s*([^,)]+?)\s*(?:,|\))"
)

_RELAXED_JS_RE = _LazyRegex(
    r"^\s*(?:await\s+)?expect\s*\(\s*(.+?)\s*\)\.(toBeTruthy|toBeDefined|toBeGreaterThanOrEqual|toBeLessThanOrEqual|not\.toBeNull|not\.toBeUndefined)\s*\("
)

def _normalize_assert_subject(expr: str) -> str:
    return re.sub(r"\s+", "", expr.strip())

def _extract_strict_assert_subject(line_body: str) -> Optional[Tuple[str, str]]:
    m_py = _STRICT_PY_EQ_RE.match(line_body)
    if m_py:
        subj = _normalize_assert_subject(m_py.group(1))
        if subj and "==" not in subj and "!=" not in subj:
            return subj, "=="
    m_ut = _STRICT_UNITTEST_EQ_RE.match(line_body)
    if m_ut:
        return _normalize_assert_subject(m_ut.group(2)), m_ut.group(1)
    m_js = _STRICT_JS_EQ_RE.match(line_body)
    if m_js:
        return _normalize_assert_subject(m_js.group(1)), m_js.group(2)
    return None

def _extract_relaxed_assert_subject(line_body: str) -> Optional[Tuple[str, str]]:
    if _STRICT_PY_EQ_RE.match(line_body):
        return None
    m_cmp = _RELAXED_PY_CMP_RE.match(line_body)
    if m_cmp:
        subj = _normalize_assert_subject(m_cmp.group(1))
        op = re.sub(r"\s+", " ", m_cmp.group(2).strip())
        if subj and "==" not in subj:
            return subj, op
    m_ut = _RELAXED_UNITTEST_RE.match(line_body)
    if m_ut:
        return _normalize_assert_subject(m_ut.group(2)), m_ut.group(1)
    m_js = _RELAXED_JS_RE.match(line_body)
    if m_js:
        return _normalize_assert_subject(m_js.group(1)), m_js.group(2)
    m_tr = _RELAXED_PY_TRUTHY_RE.match(line_body)
    if m_tr:
        raw_subj = m_tr.group(1) or m_tr.group(2) or ""
        subj = _normalize_assert_subject(raw_subj)
        if subj and subj not in ("True", "False"):
            return subj, "truthy"
    return None

def inspect_git_diff(diff_text: str, workspace: Optional[Path] = None) -> List[str]:
    """
    Scans a unified git diff (`git diff -U0`) for:
      1. Tautological assertions & calendar time-bombs in test files
      2. Test-runner environment sniffing in non-test production files (GEMINI.md Rule 9 C9)
      3. Unapproved test skip/weakening markers, net assertion removals/comment-outs/whole-file deletions, & stale negative assertions
      4. Malformed structured files (.json, .toml, .svg), UI/game slop (.html, .jsx, .tsx, .css), and broken workspace-local Markdown links
    """
    from guard.test_boundary import TestBoundaryGuard

    findings: List[str] = []
    current_file = ""
    pending_old_file = ""
    md_fence: Optional[Tuple[str, int]] = None
    file_added_lines: Dict[str, List[str]] = {}
    removed_by_prod_file: Dict[str, List[str]] = {}
    removed_assertions_by_test: Dict[str, int] = {}
    added_assertions_by_test: Dict[str, int] = {}
    removed_strict_by_test: Dict[str, Dict[str, str]] = {}
    added_relaxed_by_test: Dict[str, List[Tuple[str, str, str]]] = {}
    removed_test_defs_by_file: Dict[str, set[str]] = {}
    added_test_defs_by_file: Dict[str, set[str]] = {}
    first_removed_assert: Dict[str, str] = {}
    all_added_lines: List[str] = []
    modified_test_files: set[str] = set()
    deleted_test_files: set[str] = set()
    file_is_new: set[str] = set()
    file_is_partial: set[str] = set()
    md_doc_cache: Dict[str, Optional[Tuple[str, str]]] = {}
    auth_cache: Dict[str, bool] = {}

    def _is_test_authorized(rel_p: str) -> bool:
        if rel_p not in auth_cache:
            auth_cache[rel_p] = _has_authorized_test_modifications(workspace, rel_p) if workspace else False
        return auth_cache[rel_p]

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            pending_old_file = ""
            current_file = ""
            md_fence = None
            continue
        if line.startswith("--- "):
            raw_old = line[3:].strip()
            if raw_old == "/dev/null" or raw_old.startswith("/dev/null\t"):
                pending_old_file = "__DEV_NULL__"
            else:
                pending_old_file = _unquote_git_diff_path(line, prefix="a/")
            continue
        if line.startswith("+++ "):
            new_file = _unquote_git_diff_path(line, prefix="b/")
            if new_file:
                current_file = new_file
                if pending_old_file == "__DEV_NULL__":
                    file_is_new.add(current_file)
            else:
                current_file = pending_old_file if pending_old_file and pending_old_file != "__DEV_NULL__" else ""
                if current_file and _is_test_path(current_file):
                    deleted_test_files.add(current_file)
            pending_old_file = ""
            md_fence = None
            if current_file:
                file_added_lines.setdefault(current_file, [])
                if _is_test_path(current_file):
                    modified_test_files.add(current_file)
            continue
        if not current_file:
            continue

        if line.startswith("@@ "):
            if re.match(r"^@@\s+-0,0\s+\+", line):
                if current_file not in file_is_partial:
                    file_is_new.add(current_file)
            else:
                file_is_partial.add(current_file)
                file_is_new.discard(current_file)
            continue
        if line.startswith("-") and not line.startswith("--- "):
            file_is_partial.add(current_file)
            file_is_new.discard(current_file)
            rem_body = line[1:]
            if _is_test_path(current_file):
                modified_test_files.add(current_file)
                m_tdef = _PY_TEST_DEF_RE.match(rem_body)
                if m_tdef:
                    removed_test_defs_by_file.setdefault(current_file, set()).add(m_tdef.group(1))
                if _ACTIVE_TEST_ASSERT_RE.search(rem_body):
                    removed_assertions_by_test[current_file] = removed_assertions_by_test.get(current_file, 0) + 1
                    first_removed_assert.setdefault(current_file, rem_body.strip()[:80])
                    strict_hit = _extract_strict_assert_subject(rem_body)
                    if strict_hit is not None:
                        removed_strict_by_test.setdefault(current_file, {})[strict_hit[0]] = strict_hit[1]
            else:
                removed_by_prod_file.setdefault(current_file, []).append(rem_body)
            continue
        if not line.startswith("+"):
            continue

        norm_path = current_file
        added_body = line[1:]
        if added_body.startswith("# __AGY_UNINSPECTED_UNTRACKED__:"):
            findings.append(
                f"Uninspected untracked file in `{norm_path}` exceeds Stop-gate scan cap (`1 MiB` / `200` files) "
                "— split or stage/inspect manually before completion (GEMINI.md Rule 8)."
            )
            continue

        file_added_lines.setdefault(norm_path, []).append(added_body)
        all_added_lines.append(added_body)
        is_test = _is_test_path(norm_path)

        if norm_path.lower().endswith((".md", ".mdc")):
            m_fence = re.match(r"^\s*(`{3,}|~{3,})", added_body)
            if m_fence:
                marker = m_fence.group(1)
                if md_fence is None:
                    md_fence = (marker[0], len(marker))
                elif md_fence[0] == marker[0] and len(marker) >= md_fence[1]:
                    md_fence = None
            elif md_fence is None:
                findings.extend(_inspect_markdown_added_links(norm_path, added_body, workspace, md_doc_cache))

        if is_test:
            m_adef = _PY_TEST_DEF_RE.match(added_body)
            if m_adef:
                added_test_defs_by_file.setdefault(norm_path, set()).add(m_adef.group(1))
            is_tautology = bool(_TAUTOLOGY_PY_RE.search(line) or _TAUTOLOGY_JS_RE.search(line))
            if is_tautology:
                findings.append(
                    f"Tautological test assertion in `{norm_path}` (`{added_body.strip()[:80]}`) "
                    "— assertions must verify real behaviour (GEMINI.md Rule 9)."
                )
            elif _ACTIVE_TEST_ASSERT_RE.search(added_body):
                added_assertions_by_test[norm_path] = added_assertions_by_test.get(norm_path, 0) + 1
                relaxed_hit = _extract_relaxed_assert_subject(added_body)
                if relaxed_hit is not None:
                    added_relaxed_by_test.setdefault(norm_path, []).append(
                        (relaxed_hit[0], relaxed_hit[1], added_body.strip()[:80])
                    )

            is_new_test_file = norm_path in file_is_new and norm_path not in file_is_partial
            is_allowed_cap_skip = is_new_test_file and bool(_NEW_FILE_CAPABILITY_SKIP_RE.search(added_body))
            if not is_allowed_cap_skip and (
                _TEST_SKIP_RE.search(line) or bool(TestBoundaryGuard.weakening_lines([added_body]))
            ):
                if not _is_test_authorized(norm_path):
                    findings.append(
                        f"Unapproved test skip or weakening marker in `{norm_path}` (`{added_body.strip()[:80]}`) "
                        "— skipping or commenting out tests without logging the file under "
                        "`## Authorized Test Modifications` in `tasks.md` is forbidden (GEMINI.md Rule 9)."
                    )
        else:
            if not norm_path.lower().endswith((".md", ".mdc")) and not _is_exempt_harness_scanner_path(norm_path, workspace):
                if not _COMMENT_ADDED_LINE_RE.match(line) and _TEST_RUNNER_SNIFF_RE.search(line):
                    findings.append(
                        f"Test-runner detection in production file `{norm_path}` (`{added_body.strip()[:80]}`) "
                        "— branching on test-runner state in production code is forbidden (GEMINI.md Rule 9 C9)."
                    )

    matched_rename_targets: set[str] = set()

    def _deleted_test_is_authorized_rename(del_path: str, rem_cnt: int) -> bool:
        if del_path not in deleted_test_files:
            return False
        rem_defs = removed_test_defs_by_file.get(del_path, set())
        for cand_new in sorted(file_is_new):
            if cand_new in matched_rename_targets or not _is_test_path(cand_new):
                continue
            if not (_is_test_authorized(del_path) or _is_test_authorized(cand_new)):
                continue
            if added_assertions_by_test.get(cand_new, 0) < rem_cnt:
                continue
            if rem_defs and not (rem_defs <= added_test_defs_by_file.get(cand_new, set())):
                continue
            matched_rename_targets.add(cand_new)
            return True
        return False

    for norm_path, rem_cnt in removed_assertions_by_test.items():
        add_cnt = added_assertions_by_test.get(norm_path, 0)
        if rem_cnt > add_cnt and not _is_test_authorized(norm_path):
            if _deleted_test_is_authorized_rename(norm_path, rem_cnt):
                continue
            findings.append(
                f"Unapproved test assertion removal in `{norm_path}` (`{first_removed_assert.get(norm_path, '')}`) "
                f"— net active assertions decreased ({rem_cnt} removed vs {add_cnt} added) without logging `{norm_path}` "
                "under `## Authorized Test Modifications` in `tasks.md` (GEMINI.md Rule 9)."
            )

    for norm_path, strict_map in removed_strict_by_test.items():
        if _is_test_authorized(norm_path):
            continue
        for subj, relaxed_op, raw_line in added_relaxed_by_test.get(norm_path, []):
            if subj in strict_map:
                findings.append(
                    f"Unapproved test assertion relaxation in `{norm_path}` (`{raw_line}`) "
                    f"— strict equality assertion on `{subj}` was weakened without logging `{norm_path}` "
                    "under `## Authorized Test Modifications` in `tasks.md` (GEMINI.md Rule 9)."
                )
                break

    for del_test in sorted(deleted_test_files):
        if (
            removed_assertions_by_test.get(del_test, 0) == 0
            and removed_test_defs_by_file.get(del_test)
            and not _is_test_authorized(del_test)
            and not _deleted_test_is_authorized_rename(del_test, 0)
        ):
            findings.append(
                f"Unapproved test assertion removal in `{del_test}` (`deleted test file`) "
                f"— test file `{del_test}` was deleted without logging it under "
                "`## Authorized Test Modifications` in `tasks.md` (GEMINI.md Rule 9)."
            )

    if workspace is not None and _is_git_repo_workspace(workspace):
        for norm_path in sorted(modified_test_files):
            if not norm_path.lower().endswith(".py") or norm_path not in file_is_partial or _is_test_authorized(norm_path):
                continue
            disk_test = workspace / norm_path
            try:
                if not disk_test.is_file() or disk_test.is_symlink() or disk_test.stat().st_size > 262144:
                    continue
                new_test_src = disk_test.read_text(encoding="utf-8", errors="replace")
                head_blob = subprocess.run(
                    ["git", "-c", "core.quotePath=false", "-C", str(workspace), "show", f"HEAD:{norm_path}"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    stdin=subprocess.DEVNULL,
                )
                if head_blob.returncode == 0 and head_blob.stdout:
                    ast_weak = TestBoundaryGuard.python_weakening(
                        head_blob.stdout, new_test_src, file_added_lines.get(norm_path, ())
                    )
                    for note in ast_weak[:3]:
                        findings.append(
                            f"Test boundary weakening in `{norm_path}` (`{note}`) "
                            "— weakening existing tests without authorization is forbidden (GEMINI.md Rule 9)."
                        )
            except (OSError, subprocess.SubprocessError):
                continue

    # Validate up to 20 modified structured files (.json, .toml, .svg) and non-test UI/game files
    checked_structured = 0
    for norm_path, added_lines in file_added_lines.items():
        lower_path = norm_path.lower()
        is_struct = lower_path.endswith((".json", ".toml", ".svg"))
        is_ui = (not _is_test_path(norm_path)) and lower_path.endswith(_UI_SLOP_EXTENSIONS)
        if not is_struct and not is_ui:
            continue
        if checked_structured >= 20:
            break
        checked_structured += 1
        content_to_check: Optional[str] = None
        skipped_oversized = False
        if workspace is not None:
            disk_path = workspace / norm_path
            try:
                if (
                    disk_path.is_file()
                    and not disk_path.is_symlink()
                    and is_within(disk_path, workspace)
                ):
                    if disk_path.stat().st_size <= 262144:
                        content_to_check = disk_path.read_text(encoding="utf-8", errors="replace")
                    else:
                        skipped_oversized = True
            except OSError:
                content_to_check = None
        if (
            content_to_check is None
            and not skipped_oversized
            and norm_path not in file_is_partial
            and added_lines
            and sum(len(x) for x in added_lines) <= 262144
        ):
            content_to_check = "\n".join(added_lines)
        if content_to_check is not None:
            if is_struct:
                findings.extend(validate_structured_content(norm_path, content_to_check))
            if is_ui:
                findings.extend(validate_ui_slop_content(norm_path, content_to_check))

    # Check added test blocks per test function for calendar time-bombs & tests for stale negative assertions
    _test_fn_boundary_re = re.compile(r"^\s*(?:async\s+)?def\s+test_|^\s*(?:it|test)\s*\(")
    for norm_path, added_lines in file_added_lines.items():
        if not _is_test_path(norm_path) or not added_lines:
            continue
        fn_chunks: List[List[str]] = [[]]
        for ln in added_lines:
            if _test_fn_boundary_re.match(ln) and fn_chunks[-1]:
                fn_chunks.append([ln])
            else:
                fn_chunks[-1].append(ln)
        for chunk_lines in fn_chunks:
            joined_test = "\n".join(chunk_lines)
            m_iso = _ISO_TIMEBOMB_RE.search(joined_test)
            if m_iso and _LIVE_CLOCK_CALL_RE.search(joined_test) and not _CLOCK_INJECTION_RE.search(joined_test):
                findings.append(
                    f"Calendar time-bomb in `{norm_path}` (`{m_iso.group(0)[1:]}`) "
                    "— inject or mock `now` instead of comparing live clocks against hardcoded dates (skills/test-design/SKILL.md)."
                )
                break

    findings.extend(
        _scan_stale_negative_assertions(removed_by_prod_file, all_added_lines, modified_test_files, workspace)
    )

    # Deduplicate while preserving order
    seen = set()
    unique: List[str] = []
    for item in findings:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique

def _resolve_session_flight_base_head(workspace: Path, conv_id: str) -> Tuple[str, bool]:
    """Returns `(base_head, git_error)` for `workspace` in `conv_id` when recorded and different from `HEAD`."""
    if not conv_id:
        return "", False
    flight_file = _flight_recorder_file()
    if not flight_file.is_file():
        return "", False
    try:
        ws_key = str(workspace.resolve())
        with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
            ok, ledger = _read_ledger_checked(flight_file, quarantine=False)
        if not ok:
            return "", True
        entry = ledger.get(ws_key)
        if not isinstance(entry, dict) or str(entry.get("conversation_id") or "") != conv_id:
            return "", False
        base_head = str(entry.get("base_head") or "").strip()
        if not _HEX_OID_RE.match(base_head):
            return "", False
        cur = subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
            stdin=subprocess.DEVNULL,
        )
        if cur.returncode != 0:
            return "", True
        cur_head = cur.stdout.strip()
        if not cur_head or cur_head == base_head:
            return "", False
        anc = subprocess.run(
            ["git", "-C", str(workspace), "merge-base", "--is-ancestor", base_head, "HEAD"],
            capture_output=True,
            timeout=3,
            stdin=subprocess.DEVNULL,
        )
        if anc.returncode == 0:
            return base_head, False
        if anc.returncode == 1 and str(entry.get("status") or "") == "in_flight":
            cat_res = subprocess.run(
                ["git", "-C", str(workspace), "cat-file", "-e", f"{base_head}^{{commit}}"],
                capture_output=True,
                timeout=3,
                stdin=subprocess.DEVNULL,
            )
            if cat_res.returncode == 0:
                return base_head, False
            return "", True
        if anc.returncode > 1:
            return "", True
    except (OSError, TimeoutError, subprocess.SubprocessError):
        return "", True
    return "", False

def _session_flight_base_head(workspace: Path, conv_id: str) -> str:
    """Returns recorded session `base_head` for `workspace` in `conv_id` when valid and different from `HEAD`."""
    return _resolve_session_flight_base_head(workspace, conv_id)[0]

def _collect_workspace_diff_status_ex(workspace: Path, conv_id: str = "") -> Tuple[str, bool, bool]:
    if not _is_git_repo_workspace(workspace):
        return "", True, False
    chunks: List[str] = []
    diff_ok = False
    untracked_ok = False
    git_base = ["git", "-c", "core.quotePath=false", "-C", str(workspace)]
    base_head, base_head_err = _resolve_session_flight_base_head(workspace, conv_id)
    diff_ref = base_head or "HEAD"
    if base_head_err:
        return "", False, True
    try:
        res = subprocess.run(
            [*git_base, "diff", "-U0", diff_ref],
            capture_output=True,
            text=True,
            timeout=5,
            stdin=subprocess.DEVNULL,
        )
        if res.returncode == 0:
            diff_ok = True
            if res.stdout:
                chunks.append(res.stdout)
        else:
            # Unborn HEAD fallback — only valid when `HEAD` is genuinely an unborn branch (not corrupt `.git/HEAD`)
            rev_head = subprocess.run(
                [*git_base, "symbolic-ref", "-q", "HEAD"],
                capture_output=True,
                text=True,
                timeout=3,
                stdin=subprocess.DEVNULL,
            )
            ref_name = (rev_head.stdout or "").strip()
            ref_Verify = (
                subprocess.run(
                    [*git_base, "show-ref", "--verify", "--quiet", ref_name],
                    capture_output=True,
                    timeout=3,
                    stdin=subprocess.DEVNULL,
                ).returncode
                if (rev_head.returncode == 0 and ref_name.startswith("refs/heads/") and ".." not in ref_name)
                else 0
            )
            if rev_head.returncode == 0 and ref_name.startswith("refs/heads/") and ".." not in ref_name and ref_Verify != 0:
                staged = subprocess.run(
                    [*git_base, "diff", "-U0", "--cached"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    stdin=subprocess.DEVNULL,
                )
                unstaged = subprocess.run(
                    [*git_base, "diff", "-U0"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    stdin=subprocess.DEVNULL,
                )
                if staged.returncode == 0 and unstaged.returncode == 0:
                    diff_ok = True
                    if staged.stdout:
                        chunks.append(staged.stdout)
                    if unstaged.stdout:
                        chunks.append(unstaged.stdout)
    except (OSError, subprocess.SubprocessError):
        pass

    # Also synthesize added-line diffs for newly created untracked files so brand-new test/source files are checked
    has_any_untracked = False
    try:
        untracked = subprocess.run(
            [*git_base, "ls-files", "--others", "--exclude-standard", "-z"],
            capture_output=True,
            timeout=3,
            stdin=subprocess.DEVNULL,
        )
        if untracked.returncode == 0:
            untracked_ok = True
            if untracked.stdout:
                rel_paths = [p.decode("utf-8", errors="replace") for p in untracked.stdout.split(b"\0") if p]
                has_any_untracked = bool(rel_paths)
                for idx_u, rel in enumerate(rel_paths):
                    norm_rel = rel.replace("\\", "/")
                    is_inscope = _is_test_path(norm_rel) or norm_rel.lower().endswith(_INSCOPE_UNTRACKED_CODE_EXTS)
                    if idx_u >= _UNTRACKED_MAX_FILES:
                        if is_inscope:
                            chunks.append(
                                f"--- /dev/null\n+++ b/{norm_rel}\n@@ -0,0 +1,1 @@\n+# __AGY_UNINSPECTED_UNTRACKED__:count_cap\n"
                            )
                        continue
                    fpath = workspace / rel
                    try:
                        if fpath.is_symlink() or not fpath.is_file():
                            continue
                        st_size = fpath.stat().st_size
                        if st_size > _UNTRACKED_MAX_BYTES:
                            if is_inscope:
                                chunks.append(
                                    f"--- /dev/null\n+++ b/{norm_rel}\n@@ -0,0 +1,1 @@\n+# __AGY_UNINSPECTED_UNTRACKED__:{st_size}\n"
                                )
                            continue
                        content = fpath.read_text(encoding="utf-8")
                    except (OSError, UnicodeDecodeError):
                        continue
                    line_list = content.splitlines()
                    added_lines = "\n".join(f"+{ln}" for ln in line_list)
                    chunks.append(
                        f"--- /dev/null\n+++ b/{norm_rel}\n@@ -0,0 +1,{max(1, len(line_list))} @@\n{added_lines}\n"
                    )
    except (OSError, subprocess.SubprocessError):
        pass

    joined = "\n".join(chunks)
    git_error = _is_git_repo_workspace(workspace) and not (diff_ok and untracked_ok)
    is_clean = (not git_error) and diff_ok and untracked_ok and not joined.strip() and not has_any_untracked
    return joined, is_clean, git_error

def _collect_workspace_diff_status(workspace: Path) -> Tuple[str, bool]:
    joined, is_clean, _git_err = _collect_workspace_diff_status_ex(workspace)
    return joined, is_clean

def _collect_workspace_diff(workspace: Path) -> str:
    return _collect_workspace_diff_status(workspace)[0]

def _finding_structural_key(finding: str) -> str:
    """Strips the volatile (`line snippet`) portion so A/B edit flipping on a line shares one strike key."""
    return re.sub(r"\s*\(`[^`]*`\)", "", finding)

def _conversation_has_recorded_writes(workspaces: Sequence[Path], conv_id: str) -> bool:
    flight_file = _flight_recorder_file()
    if not flight_file.exists() and not flight_file.is_symlink():
        return False
    try:
        with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
            ok, ledger = _read_ledger_checked(flight_file, quarantine=False)
    except (OSError, TimeoutError):
        return True
    if not ok:
        return True
    for ws in workspaces:
        try:
            ws_key = str(ws.resolve())
        except (OSError, RuntimeError):
            continue
        entry = ledger.get(ws_key)
        if isinstance(entry, dict):
            if str(entry.get("status") or "") == "in_flight":
                return True
            if conv_id and str(entry.get("conversation_id") or "") == conv_id and entry.get("touched_files"):
                return True
    return False

def _verify_workspace_test_boundary(workspace: Path) -> List[str]:
    out: List[str] = []
    try:
        from guard.test_boundary import TestBoundaryGuard

        tbg = TestBoundaryGuard(workspace_dir=workspace)
        snap_src = tbg._snapshot_source(None)
        if os.path.lexists(snap_src):
            authorized = set(TestBoundaryGuard.load_authorized_from_tasks_md(workspace))
            main_root = TestBoundaryGuard.resolve_linked_worktree_root(workspace)
            if main_root is not None and snap_src != tbg.state_file and snap_src != tbg.legacy_state_file:
                authorized |= set(TestBoundaryGuard.load_authorized_from_tasks_md(main_root))
            tb_report = tbg.verify(
                mode="tdd",
                authorized_modifications=authorized,
            )
            if not tb_report.is_intact:
                for viol in tb_report.violations:
                    out.append(f"Test boundary violation in `{workspace.name}`: {viol} (GEMINI.md Rule 9).")
    except Exception:
        out.append(
            f"TestBoundaryGuard verification failed in `{workspace}` — test snapshot integrity could not be verified."
        )
    return out

def _verify_all_workspaces_test_boundary(workspaces: Sequence[Path]) -> List[str]:
    out: List[str] = []
    seen_roots: set[str] = set()
    for ws in workspaces:
        try:
            key = str(ws.resolve())
        except (OSError, RuntimeError):
            key = str(ws)
        if key in seen_roots:
            continue
        seen_roots.add(key)
        for item in _verify_workspace_test_boundary(ws):
            if item not in out:
                out.append(item)
    return out

def _audit_stop_strike(
    event: str,
    *,
    is_warn: bool = True,
    **fields: Any,
) -> None:
    try:
        from guard.audit_log import audit, warn

        if is_warn:
            warn(event, **fields)
        else:
            audit(event, **fields)
    except Exception:
        pass

def _clear_stop_strikes(strikes_file: Path, conv_id: str) -> None:
    try:
        with file_lock(strikes_file, timeout=HOOK_LOCK_TIMEOUT):
            ledger = _read_ledger_safe(strikes_file)
            if conv_id not in ledger:
                return
            prev_entry = ledger.get(conv_id) if isinstance(ledger.get(conv_id), dict) else {}
            cleared_total = _safe_int(
                prev_entry.get("total_strikes"),
                default=_safe_int(prev_entry.get("count"), default=0),
            )
            del ledger[conv_id]
            try:
                atomic_write_json(strikes_file, ledger)
            except OSError as exc:
                sys.stderr.write(f"[Harness Stop Gate] Failed to clear `{strikes_file}`: {exc}\n")
            else:
                if cleared_total > 0:
                    _audit_stop_strike(
                        "stop.strikes_cleared",
                        is_warn=False,
                        conv_id=conv_id or "default",
                        cleared_total=cleared_total,
                    )
    except (OSError, TimeoutError) as exc:
        sys.stderr.write(f"[Harness Stop Gate] Could not update `{strikes_file}` ({type(exc).__name__}): {exc}\n")

_NON_NORMAL_STOP_REASONS = frozenset({
    "error",
    "user_canceled",
    "user_cancelled",
    "max_invocations",
    "max_forced_invocations",
    "max_token_budget_exceeded",
    "terminal_custom_hook",
    "max_steps_exceeded",
})

def handle_stop(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_reason = payload.get("terminationReason")
    if raw_reason is None:
        raw_reason = payload.get("termination_reason")
    reason = str(raw_reason if raw_reason is not None else "NO_TOOL_CALL").strip()
    if reason.lower() in _NON_NORMAL_STOP_REASONS:
        return {}

    workspaces = _workspaces_from_payload(payload)
    workspace = workspaces[0] if workspaces else None
    conv_id = _conversation_id(payload)
    has_session_writes = _conversation_has_recorded_writes(workspaces, conv_id)

    if bool(payload.get("readOnly") or payload.get("read_only")) and not has_session_writes:
        return {}
    raw_prompt, _ = _extract_latest_user_prompt(payload)
    cleaned_prompt = _extract_user_request_prose(raw_prompt) if raw_prompt else ""
    if (
        cleaned_prompt
        and re.match(r"^\s*/(?:audit|retro)\b", cleaned_prompt, re.IGNORECASE)
        and not workspaces
        and not has_session_writes
    ):
        return {}

    assistant_msg = _extract_latest_assistant_message(payload)
    is_question = _is_deferrable_question(assistant_msg)

    findings: List[str] = []
    explicit_diff = payload.get("diffText")
    if isinstance(explicit_diff, str):
        if not explicit_diff.strip():
            if not workspaces:
                if is_question:
                    _record_flight_stop(workspace, conv_id, 0, deferred_question=True)
                    return {}
                _record_flight_stop(workspace, conv_id, 0, workspace_clean=True)
                _clear_stop_strikes(state_dir() / "hook_strikes.json", conv_id)
                return {}
            for ws in workspaces:
                ws_diff, ws_clean, ws_git_error = _collect_workspace_diff_status_ex(ws, conv_id=conv_id)
                ws_findings: List[str] = []
                if ws_git_error:
                    ws_findings.append(
                        f"Git diff inspection failed in `{ws}` (corrupt `.git/HEAD`, locked/corrupt git index, "
                        "or git subprocess error) — workspace diff integrity could not be verified "
                        "(failing closed; GEMINI.md Rule 8 & Rule 9)."
                    )
                if ws_diff.strip() and _session_flight_base_head(ws, conv_id):
                    ws_findings.extend(inspect_git_diff(ws_diff, workspace=ws))
                ws_findings.extend(_verify_workspace_test_boundary(ws))
                if not ws_findings:
                    if is_question:
                        _record_flight_stop(ws, conv_id, 0, deferred_question=True)
                    else:
                        _record_flight_stop(ws, conv_id, 0, workspace_clean=bool(ws_clean))
                else:
                    _record_flight_stop(
                        ws,
                        conv_id,
                        len(ws_findings),
                        workspace_clean=False,
                        create_if_missing=ws_git_error,
                    )
                    for item in ws_findings:
                        if item not in findings:
                            findings.append(item)
            if not findings:
                if is_question:
                    return {}
                _clear_stop_strikes(state_dir() / "hook_strikes.json", conv_id)
                return {}
        else:
            findings.extend(inspect_git_diff(explicit_diff, workspace=workspace))
            if workspaces:
                for ws in workspaces:
                    ws_bh, ws_bh_err = _resolve_session_flight_base_head(ws, conv_id)
                    if ws_bh or ws_bh_err or (len(workspaces) > 1 and ws != workspace):
                        ws_diff, _ws_clean, ws_git_error = _collect_workspace_diff_status_ex(ws, conv_id=conv_id)
                        if ws_git_error:
                            err_msg = (
                                f"Git diff inspection failed in `{ws}` (corrupt `.git/HEAD`, locked/corrupt git index, "
                                "or git subprocess error) — workspace diff integrity could not be verified "
                                "(failing closed; GEMINI.md Rule 8 & Rule 9)."
                            )
                            if err_msg not in findings:
                                findings.append(err_msg)
                        if ws_diff.strip():
                            for item in inspect_git_diff(ws_diff, workspace=ws):
                                if item not in findings:
                                    findings.append(item)
                for item in _verify_all_workspaces_test_boundary(workspaces):
                    if item not in findings:
                        findings.append(item)
            target_workspaces = list(workspaces) if workspaces else ([workspace] if workspace is not None else [None])
            if not findings and is_question:
                for ws in target_workspaces:
                    _record_flight_stop(ws, conv_id, 0, deferred_question=True)
                return {}
            for ws in target_workspaces:
                _record_flight_stop(ws, conv_id, len(findings), workspace_clean=False)
    else:
        if not workspaces:
            if is_question:
                _record_flight_stop(None, conv_id, 0, deferred_question=True)
            return {}
        for ws in workspaces:
            ws_diff, ws_clean, ws_git_error = _collect_workspace_diff_status_ex(ws, conv_id=conv_id)
            ws_findings: List[str] = []
            if ws_git_error:
                ws_findings.append(
                    f"Git diff inspection failed in `{ws}` (corrupt `.git/HEAD`, locked/corrupt git index, "
                    "or git subprocess error) — workspace diff integrity could not be verified "
                    "(failing closed; GEMINI.md Rule 8 & Rule 9)."
                )
            if ws_diff.strip():
                ws_findings.extend(inspect_git_diff(ws_diff, workspace=ws))
            ws_findings.extend(_verify_workspace_test_boundary(ws))

            if not ws_findings:
                if is_question:
                    _record_flight_stop(ws, conv_id, 0, deferred_question=True)
                else:
                    _record_flight_stop(ws, conv_id, 0, workspace_clean=bool(ws_clean))
            else:
                _record_flight_stop(
                    ws,
                    conv_id,
                    len(ws_findings),
                    workspace_clean=False,
                    create_if_missing=ws_git_error,
                )
                for item in ws_findings:
                    if item not in findings:
                        findings.append(item)

        if not findings and is_question:
            return {}

    continuation_active = payload.get("continuationActive") is True
    fully_idle = payload.get("fullyIdle")
    exec_num = _safe_int(payload.get("executionNum"), default=0)

    strikes_file = state_dir() / "hook_strikes.json"
    if not findings:
        _clear_stop_strikes(strikes_file, conv_id)
        return {}
    count = 1
    total_strikes = 1
    stable_keys = sorted({_finding_structural_key(f) for f in findings})
    fingerprint = hashlib.sha256("\n".join(stable_keys).encode("utf-8")).hexdigest()[:16]
    strike_state_error = False
    try:
        with file_lock(strikes_file, timeout=HOOK_LOCK_TIMEOUT):
            strikes_ok, ledger = _read_ledger_checked(strikes_file)
            if not strikes_ok:
                strike_state_error = True

            record = ledger.get(conv_id) if isinstance(ledger.get(conv_id), dict) else {}
            prev_fp = record.get("fingerprint", "")
            prev_total = _safe_int(record.get("total_strikes"), default=_safe_int(record.get("count"), default=0))
            count = (_safe_int(record.get("count"), default=0) + 1) if prev_fp == fingerprint else 1
            total_strikes = prev_total + 1

            if conv_id in ledger:
                del ledger[conv_id]
            ledger[conv_id] = {"fingerprint": fingerprint, "count": count, "total_strikes": total_strikes}
            while len(ledger) > 50:
                oldest = next(iter(ledger))
                del ledger[oldest]
            atomic_write_json(strikes_file, ledger)
    except (OSError, TimeoutError) as exc:
        strike_state_error = True
        sys.stderr.write(f"[Harness Stop Gate] Could not update `{strikes_file}` ({type(exc).__name__}): {exc}\n")
        if not findings:
            return {}
        if continuation_active and exec_num >= (MAX_STRIKES + 2):
            count = MAX_STRIKES
        elif continuation_active and exec_num >= 2:
            count = 2
        else:
            count = 1
        total_strikes = count

    tripped = bool(count >= MAX_STRIKES or total_strikes >= (MAX_STRIKES + 2))
    _audit_stop_strike(
        "stop.circuit_breaker_tripped" if tripped else "stop.strike_recorded",
        is_warn=True,
        conv_id=conv_id or "default",
        strike=count,
        total_strikes=total_strikes,
        max_strikes=MAX_STRIKES,
        fingerprint=fingerprint,
        structural_keys=stable_keys[:20],
        findings_count=len(findings),
        circuit_breaker_tripped=tripped,
        workspaces=[ws.name for ws in workspaces],
        **({"strike_state_error": True} if strike_state_error else {}),
    )

    if tripped:
        # Rule 13 3-strike circuit breaker: allow stop rather than trapping the agent in an infinite loop
        return {}

    state_notes: List[str] = []
    if continuation_active:
        state_notes.append("continuationActive=true")
    if fully_idle is False:
        state_notes.append("fullyIdle=false")
    note_suffix = f" [{' | '.join(state_notes)}]" if state_notes else ""

    bullets = "\n".join(f"- {f}" for f in findings[:5])
    return {
        "decision": "continue",
        "reason": (
            f"[Harness Stop Gate — Strike {count}/{MAX_STRIKES - 1}]{note_suffix} Verification check failed on workspace diff:\n"
            f"{bullets}\n"
            "Fix the violation before completing the turn (after 2 failed retries the circuit breaker will yield)."
        ),
    }
