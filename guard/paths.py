"""
guard/paths.py — Canonical per-user locations for Guard state, data and runtime files.
Part of Plumbwork (https://github.com/tozhax/plumbwork)
Zero external dependencies: uses strictly the Python standard library.

Runtime state (baselines, leases, registry, lock-mode records) deliberately lives
OUTSIDE the protected governance tree so that locking the tree never blocks Guard's
own bookkeeping and so that working-directory changes never select a different state.
"""

from __future__ import annotations

import errno
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, List, Optional, Tuple

APP_NAME = "plumbwork"
IS_WINDOWS = os.name == "nt"


def _env_path(name: str) -> Optional[Path]:
    value = (os.environ.get(name) or "").strip()
    return Path(value).expanduser() if value else None


def windows_launcher_dir() -> Path:
    """Canonical Windows per-user launcher directory (`%LOCALAPPDATA%\\Programs\\plumb-guard`)."""
    local_app = _env_path("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
    return Path(os.path.abspath(local_app / "Programs" / "plumb-guard"))


def read_regular_file_nofollow(
    path: Path,
    max_bytes: int,
    *,
    dir_fd: Optional[int] = None,
) -> Tuple[str, Optional[bytes], Optional[str]]:
    """
    Safely reads a regular non-symlink file up to `max_bytes` using `O_NOFOLLOW | O_NONBLOCK`
    and `os.fstat` verification. Returns `(status, raw_bytes, detail)` where `status` is one of
    `"ok"`, `"missing"`, `"symlink"`, `"not_regular"`, `"oversized"`, or `"error"`.
    """
    try:
        path_str = os.fspath(path)
    except (OSError, TypeError, ValueError) as exc:
        return "error", None, str(exc)
    if "\x00" in path_str:
        return "error", None, "NUL byte in path"
    try:
        if dir_fd is None and os.path.islink(path_str):
            return "symlink", None, "symlink"
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        if dir_fd is None:
            fd = os.open(path_str, flags)
        else:
            fd = os.open(path_str, flags, dir_fd=dir_fd)
    except (FileNotFoundError, NotADirectoryError):
        return "missing", None, None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return "symlink", None, "symlink"
        if (
            isinstance(exc, PermissionError)
            and dir_fd is None
            and not os.path.islink(path_str)
            and os.path.isdir(path_str)
        ):
            return "not_regular", None, "not a regular file"
        return "error", None, str(exc)

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return "not_regular", None, "not a regular file"
        if st.st_size > max_bytes:
            return "oversized", None, f"{st.st_size} bytes > {max_bytes}"
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            raw = fh.read(max_bytes + 1)
    except (OSError, ValueError) as exc:
        return "error", None, str(exc)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
    if len(raw) > max_bytes:
        return "oversized", None, f">{max_bytes} bytes"
    return "ok", raw, None


def is_safe_regular_subpath(base_dir: Path, rel_path: Path, *, check_owner: bool = True) -> bool:
    """
    Verifies `base_dir / rel_path` is a regular file with no symlink `base_dir` or subpath
    components, no POSIX world-writable file/directory bits (`0o002`), and (when `check_owner`
    is True on POSIX) owned by root or the current effective UID.
    """
    try:
        base_st = os.lstat(base_dir)
        if not stat.S_ISDIR(base_st.st_mode):
            return False
        is_posix = os.name != "nt" and hasattr(os, "geteuid")
        euid = os.geteuid() if is_posix else None
        if is_posix:
            if base_st.st_mode & 0o002:
                return False
            if check_owner and base_st.st_uid not in (0, euid):
                return False
        cur = base_dir
        parts = rel_path.parts
        if not parts:
            return False
        for idx, part in enumerate(parts):
            if part in ("", ".", ".."):
                return False
            cur = cur / part
            st = os.lstat(cur)
            if stat.S_ISLNK(st.st_mode):
                return False
            is_last = idx == len(parts) - 1
            if is_last:
                if not stat.S_ISREG(st.st_mode):
                    return False
            else:
                if not stat.S_ISDIR(st.st_mode):
                    return False
            if is_posix:
                if st.st_mode & 0o002:
                    return False
                if check_owner and st.st_uid not in (0, euid):
                    return False
        return True
    except OSError:
        return False


def configured_config_dir() -> Path:
    """The governance root exactly as configured (absolute, symlinks NOT resolved)."""
    override = _env_path("ANTIGRAVITY_CONFIG_DIR")
    return Path(os.path.abspath(override or Path.home() / ".gemini" / "config"))


def config_dir() -> Path:
    """Antigravity global customization root (governance target)."""
    return configured_config_dir().resolve()


def config_dir_symlink() -> Optional[Path]:
    """
    The configured governance root if it is itself a symlink, else None. Locking would follow
    the link and write-protect the link target (typically a repository checkout), so callers
    refuse to lock such a root instead of silently protecting the wrong tree.
    """
    raw = configured_config_dir()
    return raw if os.path.islink(raw) else None


def _absolute(path: Path) -> Path:
    # Absolute and normalised, but symlinks are kept (macOS /var -> /private/var, Windows 8.3
    # names): the directory is reported and compared exactly as the user configured it.
    return Path(os.path.abspath(path))


def state_dir() -> Path:
    """
    Per-user mutable state: baselines, leases, registry, lock-mode records.
    Same resolution on every platform (and in the upstream watcher hook):
    PLUMB_GUARD_STATE_DIR > $XDG_STATE_HOME/plumbwork > ~/.local/state/plumbwork
    """
    override = _env_path("PLUMB_GUARD_STATE_DIR")
    if override:
        return _absolute(override)
    xdg = _env_path("XDG_STATE_HOME")
    return _absolute((xdg or Path.home() / ".local" / "state") / APP_NAME)


def data_dir() -> Path:
    """Per-user persistent data (snapshots, installed runtime): PLUMB_GUARD_DATA_DIR > XDG_DATA_HOME > ~/.local/share."""
    override = _env_path("PLUMB_GUARD_DATA_DIR")
    if override:
        return _absolute(override)
    xdg = _env_path("XDG_DATA_HOME")
    return _absolute((xdg or Path.home() / ".local" / "share") / APP_NAME)


def share_dir_candidates() -> list[Path]:
    """System-wide shared payload roots: non-empty PLUMBWORK_SHARE_DIR (absolute) ahead of /usr/share/plumbwork."""
    roots: list[Path] = []
    override = _env_path("PLUMBWORK_SHARE_DIR")
    if override is not None:
        roots.append(_absolute(override))
    default_share = Path("/usr/share/plumbwork")
    if default_share not in roots:
        roots.append(default_share)
    return roots


def runtime_dir() -> Path:
    """Private (0700) per-user directory for ephemeral files such as tray icons."""
    xdg = _env_path("XDG_RUNTIME_DIR")
    if xdg and xdg.is_dir():
        target = xdg / APP_NAME
    else:
        import tempfile

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
    import hashlib

    raw = "\0".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def is_within(path: Path, root: Path) -> bool:
    """True if `path` is `root` or lies beneath it (lexically, after absolutisation)."""
    try:
        p_in = path if isinstance(path, (str, bytes, os.PathLike)) else str(path)
        r_in = root if isinstance(root, (str, bytes, os.PathLike)) else str(root)
        Path(os.path.abspath(p_in)).relative_to(Path(os.path.abspath(r_in)))
        return True
    except (ValueError, TypeError):
        return False


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> Path:
    """Writes text via a same-directory temp file + fsync + os.replace."""
    import tempfile

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
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
    import shutil

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


class CorruptStateError(ValueError):
    """A state file exists but cannot be parsed; callers must fail closed, not treat it as empty."""


def read_json_strict(path: Path) -> Any:
    """Like read_json, but distinguishes "missing" (returns None) from "corrupt" (raises)."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    try:
        return json.loads(text)
    except ValueError as e:
        raise CorruptStateError(f"{path} is not valid JSON ({e})") from e


def move_aside(path: Path, tag: str = "corrupt") -> Optional[Path]:
    """Renames a damaged state file to `<name>.<tag>-<timestamp>` so it is kept for inspection."""
    import time as _time

    path = Path(path)
    target = path.with_name(f"{path.name}.{tag}-{_time.strftime('%Y%m%dT%H%M%S')}")
    try:
        os.replace(path, target)
        return target
    except OSError:
        return None


HOOK_LOCK_TIMEOUT: float = 2.0


@contextmanager
def file_lock(target: Path, timeout: float = HOOK_LOCK_TIMEOUT, stale_after: float = 30.0) -> Iterator[None]:
    """
    Cross-process and cross-thread advisory lock on a persistent `.lock` inode next to `target`.
    Uses kernel `fcntl.flock` on POSIX and `msvcrt.locking` on Windows without unlinking the
    lock file on release, eliminating unlink/recreate inode races.
    """
    import time as _time

    _ = stale_after  # retained for signature compatibility; kernel releases locks on process exit
    lock_path = Path(target).with_name(Path(target).name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = _time.time() + timeout
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    locked = False
    try:
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError:
                if _time.time() > deadline:
                    raise TimeoutError(f"State store is busy ({lock_path}).")
                _time.sleep(0.02)
        try:
            if os.name != "nt" and hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            payload = f"{os.getpid()}\n".encode("utf-8")
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, payload)
        except OSError:
            pass
        yield
    finally:
        if locked:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            os.close(fd)
        except OSError:
            pass
