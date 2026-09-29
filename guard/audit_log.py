"""
guard/audit_log.py — Persistent audit trail and diagnostic log for Guard.
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Every security-relevant decision (lock, unlock, approval granted/refused, lease grant and
close, relock failure, rebaseline, snapshot restore, boot check, policy and notification
changes) is appended as one JSON object per line to a size-rotated log in the per-user
state directory:  <state_dir>/logs/guard.log  (1 MiB x 5 files, mode 0600).

Logging must never break Guard: if the log cannot be opened the logger degrades to a
no-op handler and the operation continues.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

from guard.paths import state_dir

LOGGER_NAME = "antigravity_guard"
MAX_BYTES = 1024 * 1024
BACKUP_COUNT = 5

_configured_for: Optional[str] = None


def log_path() -> Path:
    return state_dir() / "logs" / "guard.log"


def get_logger() -> logging.Logger:
    """Returns the Guard logger, (re)binding its file handler to the current state directory."""
    global _configured_for
    logger = logging.getLogger(LOGGER_NAME)
    target = str(log_path())
    if _configured_for == target and logger.handlers:
        return logger
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except OSError:
            pass
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        path = Path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            fd = os.open(target, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            os.close(fd)
        handler: logging.Handler = RotatingFileHandler(target, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
    except OSError:
        handler = logging.NullHandler()
    logger.addHandler(handler)
    _configured_for = target
    return logger


def audit(event: str, level: int = logging.INFO, **fields: Any) -> None:
    """Appends one structured audit record. Never raises."""
    record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, "pid": os.getpid()}
    record.update({k: (v if isinstance(v, (str, int, float, bool)) or v is None else str(v)) for k, v in fields.items()})
    try:
        get_logger().log(level, json.dumps(record, ensure_ascii=False, sort_keys=False))
    except Exception:  # noqa: BLE001 - the audit trail must never take Guard down
        pass


def warn(event: str, **fields: Any) -> None:
    audit(event, level=logging.WARNING, **fields)


def error(event: str, **fields: Any) -> None:
    audit(event, level=logging.ERROR, **fields)
