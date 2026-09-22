"""
porter/frontmatter.py — Strict, dependency-free parser/emitter for Markdown YAML frontmatter.
Zero-dependency: uses the Python standard library only.

Supports the YAML subset used by SKILL.md / agent / .mdc frontmatter:
  - `key: plain scalar`, single- and double-quoted scalars
  - folded (`>`, `>-`, `>+`) and literal (`|`, `|-`, `|+`) block scalars
  - flow sequences (`[a, "b"]`) and indented block sequences (`- item`)
It rejects constructs a real YAML parser rejects in this subset — most importantly a
plain scalar containing ": " ("mapping values are not allowed in this context"), which
is exactly the error that stops Antigravity from loading a skill.
The emitter always writes JSON-style double-quoted strings, which are valid YAML.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

_KEY_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_.-]*):(?:[ \t]+(.*)|[ \t]*)$")
_BLOCK_RE = re.compile(r"^([>|])([1-9])?([+-])?\s*(#.*)?$")


class FrontmatterError(ValueError):
    """Raised when frontmatter is missing or is not valid YAML (for the supported subset)."""


def split_frontmatter(text: str) -> Tuple[Optional[str], str]:
    """Returns (frontmatter_text or None, body)."""
    if text.startswith("﻿"):
        text = text[1:]
    normalized = text.replace("\r\n", "\n")
    if not normalized.startswith("---\n"):
        return None, text
    end = normalized.find("\n---", 3)
    while end != -1:
        tail = normalized[end + 4:end + 5]
        if tail in ("", "\n"):
            fm = normalized[4:end]
            body = normalized[end + 4:]
            return fm, body[1:] if body.startswith("\n") else body
        end = normalized.find("\n---", end + 4)
    raise FrontmatterError("frontmatter opening '---' has no closing '---' line")


def _strip_comment(value: str) -> str:
    idx = value.find(" #")
    return value[:idx].rstrip() if idx != -1 else value


def _parse_double_quoted(s: str, line_no: int) -> Tuple[str, str]:
    i = 1
    while i < len(s):
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == '"':
            try:
                return json.loads(s[: i + 1]), s[i + 1:]
            except ValueError as e:
                raise FrontmatterError(f"line {line_no}: invalid escape in double-quoted scalar ({e})")
        i += 1
    raise FrontmatterError(f"line {line_no}: unterminated double-quoted scalar")


def _parse_single_quoted(s: str, line_no: int) -> Tuple[str, str]:
    out = []
    i = 1
    while i < len(s):
        if s[i] == "'":
            if i + 1 < len(s) and s[i + 1] == "'":
                out.append("'")
                i += 2
                continue
            return "".join(out), s[i + 1:]
        out.append(s[i])
        i += 1
    raise FrontmatterError(f"line {line_no}: found unterminated leading single quote")


def _check_rest(rest: str, line_no: int) -> None:
    rest = rest.strip()
    if rest and not rest.startswith("#"):
        raise FrontmatterError(f"line {line_no}: unexpected content after quoted scalar: {rest!r}")


def _parse_plain(s: str, line_no: int) -> Any:
    value = _strip_comment(s).strip()
    if not value:
        return None
    if value[0] in "&*!%@`|>":
        raise FrontmatterError(f"line {line_no}: plain scalar cannot start with {value[0]!r}; quote the value")
    if value.startswith("- ") or value == "-":
        raise FrontmatterError(f"line {line_no}: block sequence entries are not allowed here")
    if ": " in value or value.endswith(":"):
        raise FrontmatterError(f"line {line_no}: mapping values are not allowed in this context; quote the value")
    lowered = value.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if lowered in ("null", "~"):
        return None
    if re.fullmatch(r"[-+]?\d+", value):
        return int(value)
    return value


def _parse_flow_sequence(s: str, line_no: int) -> List[Any]:
    s = _strip_comment(s).strip()
    if not s.endswith("]"):
        raise FrontmatterError(f"line {line_no}: unterminated flow sequence")
    inner = s[1:-1].strip()
    items: List[Any] = []
    while inner:
        if inner[0] == '"':
            val, inner = _parse_double_quoted(inner, line_no)
        elif inner[0] == "'":
            val, inner = _parse_single_quoted(inner, line_no)
        else:
            comma = inner.find(",")
            token, inner = (inner, "") if comma == -1 else (inner[:comma], inner[comma:])
            token = token.strip()
            if not token:
                raise FrontmatterError(f"line {line_no}: empty flow sequence entry")
            val = _parse_plain(token, line_no) if token[0] not in "*&" else token
        items.append(val)
        inner = inner.strip()
        if inner.startswith(","):
            inner = inner[1:].strip()
        elif inner:
            raise FrontmatterError(f"line {line_no}: expected ',' in flow sequence")
    return items


def _parse_scalar(raw: str, line_no: int) -> Any:
    s = raw.strip()
    if s.startswith('"'):
        val, rest = _parse_double_quoted(s, line_no)
        _check_rest(rest, line_no)
        return val
    if s.startswith("'"):
        val, rest = _parse_single_quoted(s, line_no)
        _check_rest(rest, line_no)
        return val
    if s.startswith("["):
        return _parse_flow_sequence(s, line_no)
    if s.startswith("{"):
        raise FrontmatterError(f"line {line_no}: flow mappings are not supported in frontmatter")
    return _parse_plain(s, line_no)


def _block_scalar(indicator: str, block: List[str], line_no: int, trailing_break: bool = True) -> str:
    m = _BLOCK_RE.match(indicator)
    if not m:
        raise FrontmatterError(f"line {line_no}: invalid block scalar indicator {indicator!r}")
    style, _, chomp = m.group(1), m.group(2), m.group(3)
    content = [l for l in block]
    while content and not content[-1].strip():
        content.pop()
    if not content:
        return ""
    indents = [len(l) - len(l.lstrip(" ")) for l in content if l.strip()]
    base = min(indents) if indents else 0
    lines = [l[base:] if l.strip() else "" for l in content]
    if style == "|":
        text = "\n".join(lines)
    else:
        paragraphs: List[str] = []
        current: List[str] = []
        for l in lines:
            if not l:
                paragraphs.append(" ".join(current))
                current = []
            elif l.startswith(" "):
                current.append("\n" + l if current else l)
            else:
                current.append(l)
        paragraphs.append(" ".join(current))
        text = "\n".join(paragraphs).replace(" \n", "\n")
    if chomp == "-" or not trailing_break:
        return text
    return text + "\n"


def parse_frontmatter_block(fm: str) -> Dict[str, Any]:
    """Parses the text between the '---' fences."""
    lines = fm.split("\n")
    result: Dict[str, Any] = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        line_no = i + 2  # +1 for 1-based, +1 for the opening fence
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if line[0] in " \t":
            raise FrontmatterError(f"line {line_no}: unexpected indentation")
        m = _KEY_RE.match(line)
        if not m:
            raise FrontmatterError(f"line {line_no}: expected 'key: value', got {line.strip()!r}")
        key, raw = m.group(1), (m.group(2) or "")
        if key in result:
            raise FrontmatterError(f"line {line_no}: duplicate key {key!r}")

        j = i + 1
        block: List[str] = []
        while j < len(lines) and (not lines[j].strip() or lines[j][0] in " \t"):
            block.append(lines[j])
            j += 1

        stripped = raw.strip()
        if stripped and stripped[0] in ">|":
            result[key] = _block_scalar(stripped, block, line_no, trailing_break=j < len(lines))
            i = j
            continue
        if not stripped:
            entries = [l for l in block if l.strip()]
            if entries and all(e.strip().startswith("- ") or e.strip() == "-" for e in entries):
                result[key] = [_parse_scalar(e.strip()[1:].strip(), line_no) if e.strip() != "-" else None for e in entries]
            elif entries:
                indents = {len(e) - len(e.lstrip()) for e in entries}
                if len(indents) != 1:
                    raise FrontmatterError(f"line {line_no}: only one level of nested mapping is supported for {key!r}")
                nested: Dict[str, Any] = {}
                for offset, e in enumerate(entries):
                    nm = _KEY_RE.match(e.strip())
                    if not nm or not (nm.group(2) or "").strip():
                        raise FrontmatterError(f"line {line_no + offset + 1}: expected 'key: value' inside {key!r}")
                    nested[nm.group(1)] = _parse_scalar(nm.group(2), line_no + offset + 1)
                result[key] = nested
            else:
                result[key] = None
            i = j
            continue
        if any(l.strip() for l in block):
            # Multi-line scalar continuation: fold line breaks into spaces like YAML does.
            joined = " ".join([stripped] + [l.strip() for l in block if l.strip()])
            result[key] = _parse_scalar(joined, line_no)
            i = j
            continue
        result[key] = _parse_scalar(stripped, line_no)
        i += 1
    return result


def parse_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
    """Returns (metadata, body). Raises FrontmatterError when frontmatter is absent or invalid."""
    fm, body = split_frontmatter(text)
    if fm is None:
        raise FrontmatterError("missing YAML frontmatter (file must start with '---')")
    return parse_frontmatter_block(fm), body


def dump_frontmatter(data: Dict[str, Any]) -> str:
    """Emits frontmatter that any YAML 1.1/1.2 parser accepts (strings are JSON-quoted)."""
    out = ["---"]
    for key, value in data.items():
        if isinstance(value, bool):
            out.append(f"{key}: {'true' if value else 'false'}")
        elif value is None:
            out.append(f"{key}: null")
        elif isinstance(value, (int, float)):
            out.append(f"{key}: {value}")
        elif isinstance(value, (list, tuple)):
            if not value:
                out.append(f"{key}: []")
            else:
                out.append(f"{key}:")
                out.extend(f"  - {json.dumps(str(v), ensure_ascii=False)}" for v in value)
        else:
            out.append(f"{key}: {json.dumps(str(value), ensure_ascii=False)}")
    out.append("---")
    return "\n".join(out) + "\n"


def frontmatter_description(text: str) -> str:
    """Best-effort description for listings (empty string when missing or invalid)."""
    try:
        meta, _ = parse_frontmatter(text)
    except FrontmatterError:
        return ""
    value = meta.get("description")
    return " ".join(str(value).split()) if value else ""
