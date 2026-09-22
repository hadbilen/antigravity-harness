"""
guard/paths.py — Canonical per-user locations for Guard state, data and runtime files.
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Runtime state (baselines, leases, registry, lock-mode records) deliberately lives
OUTSIDE the protected governance tree so that locking the tree never blocks Guard's
own bookkeeping and so that working-directory changes never select a different state.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Callable, List, Optional

APP_NAME = "antigravity-harness"
IS_WINDOWS = platform.system().lower() == "windows"


def _env_path(name: str) -> Optional[Path]:
    value = os.environ.get(name)
    return Path(value).expanduser() if value else None


def config_dir() -> Path:
    """Antigravity global customization root (governance target)."""
    override = _env_path("ANTIGRAVITY_CONFIG_DIR")
    return (override or Path.home() / ".gemini" / "config").resolve()


def _absolute(path: Path) -> Path:
    # Absolute and normalised, but symlinks are kept (macOS /var -> /private/var, Windows 8.3
    # names): the directory is reported and compared exactly as the user configured it.
    return Path(os.path.abspath(path))


def state_dir() -> Path:
    """
    Per-user mutable state: baselines, leases, registry, lock-mode records.
    Same resolution on every platform (and in the upstream watcher hook):
    AGY_GUARD_STATE_DIR > $XDG_STATE_HOME/antigravity-harness > ~/.local/state/antigravity-harness
    """
    override = _env_path("AGY_GUARD_STATE_DIR")
    if override:
        return _absolute(override)
    xdg = _env_path("XDG_STATE_HOME")
    return _absolute((xdg or Path.home() / ".local" / "state") / APP_NAME)


def data_dir() -> Path:
    """Per-user persistent data (snapshots, installed runtime): AGY_GUARD_DATA_DIR > XDG_DATA_HOME > ~/.local/share."""
    override = _env_path("AGY_GUARD_DATA_DIR")
    if override:
        return _absolute(override)
    xdg = _env_path("XDG_DATA_HOME")
    return _absolute((xdg or Path.home() / ".local" / "share") / APP_NAME)


def runtime_dir() -> Path:
    """Private (0700) per-user directory for ephemeral files such as tray icons."""
    xdg = _env_path("XDG_RUNTIME_DIR")
    if xdg and xdg.is_dir():
        target = xdg / APP_NAME
    else:
        suffix = str(os.getuid()) if hasattr(os, "getuid") else os.environ.get("USERNAME", "user")
        target = Path(tempfile.gettempdir()) / f"{APP_NAME}-{suffix}"
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not IS_WINDOWS:
        st = os.lstat(target)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise PermissionError(f"Refusing to use runtime directory {target}: not a real directory.")
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            raise PermissionError(f"Refusing to use runtime directory {target}: owned by another user.")
        if stat.S_IMODE(st.st_mode) & 0o077:
            os.chmod(target, 0o700)
    return target


def path_key(*parts: Any) -> str:
    """Stable short key for a path (or path set) used to name per-target state files."""
    raw = "\0".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def is_within(path: Path, root: Path) -> bool:
    """True if `path` is `root` or lies beneath it (lexically, after absolutisation)."""
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
        return True
    except ValueError:
        return False


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> Path:
    """Writes text via a same-directory temp file + fsync + os.replace."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if not IS_WINDOWS:
            os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return path


def atomic_write_json(path: Path, payload: Any, mode: int = 0o600) -> Path:
    return atomic_write_text(path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n", mode=mode)


def _clear_copy_restrictions(path: Path) -> None:
    """A copy is an ordinary owner-writable file: drop BSD flags (macOS uchg) and read-only bits."""
    try:
        st = os.lstat(path)
    except OSError:
        return
    if stat.S_ISLNK(st.st_mode):
        return
    if getattr(st, "st_flags", 0) and hasattr(os, "chflags"):
        try:
            os.chflags(path, 0)
        except OSError:
            pass
    if not st.st_mode & stat.S_IWUSR:
        try:
            os.chmod(path, stat.S_IMODE(st.st_mode) | stat.S_IWUSR)
        except OSError:
            pass


def copy_entry(src: Path, dst: Path, ignore: Optional[Callable[[str, List[str]], Any]] = None) -> None:
    """
    Copies a file, directory or symlink. Symlinks stay symlinks, created with the right
    file/directory type on Windows (shutil.copytree does not), or are copied by content when
    the platform refuses to create them. Copies never inherit lock state: no macOS immutable
    flags and no read-only bits, so they can be moved, pruned and re-locked like any file.
    """
    src, dst = Path(src), Path(dst)
    if os.path.islink(src):
        try:
            os.symlink(os.readlink(src), dst, target_is_directory=os.path.isdir(src))
            return
        except (OSError, NotImplementedError):
            real = Path(os.path.realpath(src))
            if not real.exists():
                raise
            src = real
    if src.is_dir():
        dst.mkdir(parents=True, exist_ok=True)
        names = os.listdir(src)
        skipped = set(ignore(str(src), names)) if ignore else set()
        for name in sorted(names):
            if name not in skipped:
                copy_entry(src / name, dst / name, ignore)
        shutil.copystat(src, dst)
    else:
        shutil.copy2(src, dst)
    _clear_copy_restrictions(dst)


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default
