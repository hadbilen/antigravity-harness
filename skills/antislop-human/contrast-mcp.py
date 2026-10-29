#!/usr/bin/env python3
"""Minimal MCP stdio server exposing the antislop contrast checker as a tool.

All logging goes to stderr; stdout is reserved for JSON-RPC responses.
"""
import json
import math
import re
import sys

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "antislop-contrast"
SERVER_VERSION = "3.2.22"
MAX_LINE_BYTES = 1024 * 1024
_HEX_COLOR_RE = re.compile(r"^#?([0-9A-Fa-f]{6})$")
_HEX_COLOR_SCHEMA_PATTERN = "^#?[0-9A-Fa-f]{6}$"

TOOLS = [
    {
        "name": "check_contrast",
        "description": "Compute the WCAG contrast ratio between two hex colors and the pass or fail verdict for normal and large text. Use this instead of guessing whether a color pairing meets AA.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "foreground": {
                    "type": "string",
                    "pattern": _HEX_COLOR_SCHEMA_PATTERN,
                    "description": "Hex color of the text, for example #777777",
                },
                "background": {
                    "type": "string",
                    "pattern": _HEX_COLOR_SCHEMA_PATTERN,
                    "description": "Hex color of the background, for example #FFFFFF",
                },
            },
            "required": ["foreground", "background"],
        },
    }
]


def _channel(c):
    c = c / 255.0
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color):
    if not isinstance(hex_color, str):
        raise ValueError(f"Expected 6-digit RGB hex string (#RRGGBB), got {type(hex_color).__name__}")
    m = _HEX_COLOR_RE.fullmatch(hex_color.strip())
    if not m:
        raise ValueError(f"Expected 6-digit RGB hex color (#RRGGBB), got {hex_color!r}")
    h = m.group(1)
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def contrast_ratio(fg, bg):
    l1, l2 = relative_luminance(fg), relative_luminance(bg)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def check_contrast(fg, bg):
    raw_ratio = contrast_ratio(fg, bg)
    return {
        "foreground": fg,
        "background": bg,
        "ratio": round(raw_ratio, 2),
        "normal_text": {"threshold": 4.5, "pass": raw_ratio >= 4.5},
        "large_text": {"threshold": 3.0, "pass": raw_ratio >= 3.0},
    }


def _send(msg):
    sys.stdout.write(json.dumps(msg, allow_nan=False) + "\n")
    sys.stdout.flush()


def _text(content):
    return {"content": [{"type": "text", "text": content}], "isError": False}


def _error(message):
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _reply(msg_id, result):
    _send({"jsonrpc": "2.0", "id": msg_id, "result": result})


def _reply_rpc_error(msg_id, code, message):
    _send({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})


def _iter_bounded_lines(stream, max_bytes=MAX_LINE_BYTES):
    buf = getattr(stream, "buffer", None)
    if buf is not None:
        while True:
            chunk = buf.readline(max_bytes + 1)
            if not chunk:
                break
            if len(chunk) > max_bytes:
                while not chunk.endswith(b"\n"):
                    tail = buf.readline(65536)
                    if not tail:
                        break
                    chunk = tail
                yield None, "oversized"
                continue
            try:
                yield chunk.decode("utf-8"), None
            except UnicodeDecodeError:
                yield None, "invalid_utf8"
    else:
        while True:
            text_chunk = stream.readline(max_bytes + 1)
            if not text_chunk:
                break
            if len(text_chunk.encode("utf-8", errors="replace")) > max_bytes:
                while not text_chunk.endswith("\n"):
                    tail = stream.readline(65536)
                    if not tail:
                        break
                    text_chunk = tail
                yield None, "oversized"
                continue
            yield text_chunk, None


def _reject_nonfinite_constant(token):
    raise ValueError(f"Non-standard JSON constant {token!r} is not permitted")


def _is_valid_rpc_id(val):
    if isinstance(val, bool):
        return False
    if isinstance(val, float):
        return math.isfinite(val)
    return val is None or isinstance(val, (str, int))


def main():
    for raw_line, read_err in _iter_bounded_lines(sys.stdin):
        if read_err == "oversized":
            _reply_rpc_error(None, -32600, f"Invalid Request: line exceeds {MAX_LINE_BYTES} byte limit")
            continue
        if read_err == "invalid_utf8":
            _reply_rpc_error(None, -32700, "Parse error: invalid UTF-8 input")
            continue
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line, parse_constant=_reject_nonfinite_constant)
        except (json.JSONDecodeError, ValueError) as exc:
            err_msg = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)
            _reply_rpc_error(None, -32700, f"Parse error: {err_msg}")
            continue

        if not isinstance(msg, dict):
            _reply_rpc_error(None, -32600, "Invalid Request: JSON-RPC message must be an object")
            continue

        has_id = "id" in msg
        msg_id = msg.get("id")
        if has_id and not _is_valid_rpc_id(msg_id):
            _reply_rpc_error(None, -32600, "Invalid Request: invalid JSON-RPC id")
            continue

        if msg.get("jsonrpc") != "2.0":
            if has_id:
                _reply_rpc_error(msg_id, -32600, "Invalid Request: jsonrpc version must be '2.0'")
            continue

        method = msg.get("method")
        if not isinstance(method, str) or not method:
            if has_id:
                _reply_rpc_error(msg_id, -32600, "Invalid Request: missing or non-string method")
            continue

        params = msg.get("params")
        if params is not None and not isinstance(params, dict):
            if has_id:
                _reply_rpc_error(msg_id, -32602, "Invalid params: params must be an object")
            continue

        if not has_id:
            continue

        if method == "initialize":
            _reply(msg_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            })
        elif method == "ping":
            _reply(msg_id, {})
        elif method == "tools/list":
            _reply(msg_id, {"tools": TOOLS})
        elif method == "tools/call":
            params_obj = params or {}
            name = params_obj.get("name")
            args = params_obj.get("arguments")
            if name != "check_contrast":
                _reply_rpc_error(msg_id, -32602, f"Invalid params: unknown tool {name!r}")
            elif not isinstance(args, dict) or "foreground" not in args or "background" not in args:
                _reply_rpc_error(msg_id, -32602, "Invalid params: foreground and background are required")
            else:
                try:
                    result = check_contrast(args["foreground"], args["background"])
                    _reply(msg_id, _text(json.dumps(result, allow_nan=False)))
                except (ValueError, TypeError) as exc:
                    _reply_rpc_error(msg_id, -32602, f"Invalid params: {exc}")
                except Exception as exc:
                    _reply(msg_id, _error("check_contrast failed: " + str(exc)))
        else:
            _reply_rpc_error(msg_id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    main()
