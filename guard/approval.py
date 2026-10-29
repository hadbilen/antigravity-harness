"""
guard/approval.py — Human confirmation gate for Guard administration commands.
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Threat model (honest): the gate stops unattended/headless automation and accidental
invocations. A process running as the same OS user can still bypass any user-space
check; a real boundary requires root-owned files or host-enforced tool policies.
"""

from __future__ import annotations

import builtins
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence

_ORIG_INPUT = builtins.input
_AUTOMATED_ANCESTOR_NAMES = frozenset({
    "script",
    "expect",
    "autoexpect",
    "unbuffer",
    "socat",
    "sshpass",
})


@dataclass
class ApprovalRequest:
    action: str
    summary: str
    details: List[str] = field(default_factory=list)


Approver = Callable[[ApprovalRequest], bool]

_approver_override: Optional[Approver] = None


def set_approver(approver: Optional[Approver]) -> None:
    """Installs an in-process approver (GUI dialogs, unit tests). None restores the TTY gate."""
    global _approver_override
    _approver_override = approver


def _has_pty_or_hook_ancestor() -> bool:
    """Walks Linux `/proc/<pid>` ancestors to reject PTY automation (`script`, `expect`, `socat`) and hook subprocesses."""
    if os.name == "nt" or not hasattr(os, "getppid"):
        return False
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return False
    visited: set[int] = set()
    pid = os.getppid()
    while pid > 1 and pid not in visited and len(visited) < 32:
        visited.add(pid)
        proc_dir = proc_root / str(pid)
        try:
            raw_cmd = (proc_dir / "cmdline").read_bytes()
        except OSError:
            break
        tokens = [tok.decode("utf-8", errors="ignore").strip() for tok in raw_cmd.split(b"\x00") if tok]
        if tokens:
            exe_name = Path(tokens[0]).name.lower()
            if exe_name in _AUTOMATED_ANCESTOR_NAMES:
                return True
            for tok in tokens:
                if Path(tok).name.lower() == "agy_hooks.py" or tok == "guard.agy_hooks":
                    return True
        try:
            comm_name = (proc_dir / "comm").read_text(encoding="utf-8", errors="ignore").strip().lower()
            if comm_name in _AUTOMATED_ANCESTOR_NAMES:
                return True
        except OSError:
            pass
        try:
            stat_text = (proc_dir / "stat").read_text(encoding="utf-8", errors="ignore")
            rparen = stat_text.rfind(")")
            if rparen == -1:
                break
            fields = stat_text[rparen + 2 :].split()
            if len(fields) < 2:
                break
            pid = int(fields[1])
        except (OSError, ValueError):
            break
    return False


def _has_automated_ancestor(*, check_agent_env: bool = True) -> bool:
    """Returns True when invoked beneath an automated agent runner or PTY wrapper."""
    if check_agent_env:
        for env_key in ("ANTIGRAVITY_AGENT", "AGY_AGENT_SUBPROCESS"):
            marker = os.environ.get(env_key, "").strip().lower()
            if marker and marker not in ("0", "false", "no", "off"):
                return True
    return _has_pty_or_hook_ancestor()


def _non_interactive_reason() -> Optional[str]:
    """Returns why human confirmation is unavailable, or None when an interactive controlling terminal exists."""
    try:
        real_stdio = (sys.stdin is sys.__stdin__) and (sys.stdout is sys.__stdout__)
        if _has_automated_ancestor(check_agent_env=real_stdio):
            return "agent environment marker or PTY-automation/hook ancestor process detected"
        if not bool(sys.stdin and sys.stdin.isatty() and sys.stdout and sys.stdout.isatty()):
            return "stdin/stdout is not a terminal (piped or redirected)"
        if real_stdio:
            if os.name == "nt":
                fd = os.open("CONIN$", os.O_RDONLY)
            else:
                fd = os.open("/dev/tty", os.O_RDWR | getattr(os, "O_NOCTTY", 0))
            try:
                if not os.isatty(fd):
                    return "controlling terminal device is not a TTY"
            finally:
                os.close(fd)
        return None
    except (AttributeError, OSError, ValueError) as exc:
        return f"controlling terminal unavailable ({type(exc).__name__}: {exc})"


def is_interactive() -> bool:
    return _non_interactive_reason() is None


def _prompt_controlling_tty(prompt_text: str, tty_path: str = "/dev/tty") -> str:
    if os.name == "nt":
        with open("CONOUT$", "w", encoding="utf-8", errors="replace") as tty_out:
            tty_out.write(prompt_text)
            tty_out.flush()
        with open("CONIN$", "r", encoding="utf-8", errors="replace") as tty_in:
            line = tty_in.readline()
    else:
        fd = os.open(tty_path, os.O_RDWR | getattr(os, "O_NOCTTY", 0))
        try:
            if not os.isatty(fd):
                raise OSError("Controlling terminal is not a TTY")
            import termios

            # Discard type-ahead so only a keystroke typed after the prompt can approve.
            try:
                termios.tcflush(fd, termios.TCIFLUSH)
            except termios.error as exc:
                raise OSError(f"tcflush failed on controlling terminal: {exc}") from exc
            prompt_bytes = prompt_text.encode("utf-8")
            written = 0
            while written < len(prompt_bytes):
                n = os.write(fd, prompt_bytes[written:])
                if n <= 0:
                    raise OSError("Short write to controlling terminal")
                written += n
            buf = bytearray()
            saw_newline = False
            while len(buf) < 4096:
                chunk = os.read(fd, 1)
                if not chunk:
                    break
                buf.extend(chunk)
                if chunk == b"\n":
                    saw_newline = True
                    break
            if len(buf) >= 4096 and not saw_newline:
                while True:
                    extra = os.read(fd, 256)
                    if not extra or b"\n" in extra:
                        break
            line = buf.decode("utf-8", errors="replace")
        finally:
            os.close(fd)
    if line == "":
        raise EOFError
    return line


def tty_approver(request: ApprovalRequest) -> bool:
    """Requires an interactive controlling terminal and an explicit typed 'yes'."""
    reason = _non_interactive_reason()
    if reason is not None:
        from guard.audit_log import warn

        warn("approval.non_interactive", action=request.action, reason=reason)
        print(f"[WARN] Human confirmation unavailable for '{request.action}': {reason}", file=sys.stderr)
        return False
    print(f"\n[ANTIGRAVITY GUARD — HUMAN CONFIRMATION REQUIRED: {request.action}]")
    print(request.summary)
    for line in request.details:
        print(f"  - {line}")
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        if input is not _ORIG_INPUT or builtins.input is not _ORIG_INPUT or sys.stdin is not sys.__stdin__:
            answer = input("Type 'yes' to confirm: ")
        else:
            answer = _prompt_controlling_tty("Type 'yes' to confirm: ")
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return False
    except OSError as exc:
        from guard.audit_log import warn

        warn("approval.tty_error", action=request.action, error=f"{type(exc).__name__}: {exc}")
        print(
            f"[WARN] Controlling terminal I/O failed ({type(exc).__name__}: {exc})",
            file=sys.stderr,
        )
        return False
    return answer.strip().lower() == "yes"


def request_approval(action: str, summary: str, details: Sequence[str] = ()) -> bool:
    from guard.audit_log import audit, warn

    request = ApprovalRequest(action=action, summary=summary, details=list(details))
    approver = _approver_override or tty_approver
    try:
        approved = bool(approver(request))
    except Exception as e:  # noqa: BLE001 - any approver failure fails closed
        warn("approval.error", action=action, error=f"{type(e).__name__}: {e}")
        return False
    audit("approval.granted" if approved else "approval.refused", action=action,
          interactive=is_interactive(), via="override" if _approver_override else "tty")
    return approved


def refusal_message(action: str) -> str:
    return (
        f"'{action}' requires confirmation by a human operator in an interactive terminal "
        f"(or in the Guard GUI). The request was not approved; nothing was changed."
    )
