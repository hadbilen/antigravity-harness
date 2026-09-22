"""
guard/os_adapter.py — Cross-Platform OS Write Protection Adapter
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Protection model (honest): this is a user-space permission lock. It stops accidental
writes and tools that respect file modes; a process running as the same OS user can
restore write bits. Symlinked entries are never followed: a symlink whose target lies
outside the locked tree is reported as UNPROTECTED instead of being silently chmod'ed.
"""

from __future__ import annotations

import json
import os
import platform
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple, Union

TargetInput = Optional[Union[Path, str, Sequence[Union[Path, str]]]]

WRITE_BITS = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
_UF_IMMUTABLE = 0x00000002
_SF_IMMUTABLE = 0x00020000


def _abs(p: Union[Path, str]) -> Path:
    """Absolute path WITHOUT resolving symlinks (symlinks must stay visible)."""
    return Path(os.path.abspath(os.path.expanduser(str(p))))


class OSProtectionAdapter:
    """
    Provides cross-platform file system write protection:
    - Linux: POSIX permission lockdown (a-w) + chattr +i when running as root
    - macOS: BSD user-immutable flag (`chflags uchg` / `nouchg`) + permission lockdown
    - Windows: NTFS ACL denial (`icacls /deny`) + read-only attribute (`attrib +R`)
    Original permission modes are recorded at lock time and restored exactly on unlock.
    """

    def __init__(self, target_dir: Optional[Union[Path, str]] = None, mode_store: Optional[Union[Path, str]] = None):
        self.system = platform.system().lower()
        if target_dir is None:
            config_env = os.environ.get("ANTIGRAVITY_CONFIG_DIR")
            self.target_dir = Path(config_env).resolve() if config_env else Path.home() / ".gemini" / "config"
        else:
            self.target_dir = Path(target_dir).resolve()
        self._mode_store_path = Path(mode_store) if mode_store else None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def get_platform_name(self) -> str:
        if self.system == "linux":
            return "Linux (POSIX permissions / optional chattr)"
        elif self.system == "darwin":
            return "macOS (BSD User Immutable Flags)"
        elif self.system == "windows":
            return "Windows (NTFS Access Control Lists)"
        return f"Generic POSIX ({platform.system()})"

    def protection_kind(self) -> str:
        if self.system == "linux" and hasattr(os, "geteuid") and os.geteuid() == 0:
            return "IMMUTABLE (chattr +i, root)"
        if self.system == "darwin":
            return "USER-IMMUTABLE (chflags uchg, advisory against the same user)"
        return "USER-SPACE LOCK (advisory against the same OS user)"

    def _targets(self, target: TargetInput) -> List[Path]:
        if isinstance(target, (list, tuple, set)):
            return [_abs(p) for p in target if os.path.lexists(_abs(p))]
        path = _abs(target) if target else self.target_dir
        return [path] if os.path.lexists(path) else []

    @property
    def mode_store_path(self) -> Optional[Path]:
        if self._mode_store_path is not None:
            return self._mode_store_path
        try:
            from guard.paths import state_dir
            return state_dir() / "lock_modes.json"
        except Exception:
            return None

    def _load_modes(self) -> Dict[str, int]:
        path = self.mode_store_path
        if not path or not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return {str(k): int(v) for k, v in data.get("modes", {}).items()}
        except (OSError, ValueError, AttributeError):
            return {}

    def _save_modes(self, modes: Dict[str, int]) -> Optional[str]:
        path = self.mode_store_path
        if not path:
            return "lock-mode store unavailable; original modes not recorded"
        try:
            from guard.paths import atomic_write_json
            atomic_write_json(path, {"version": 1, "modes": modes})
            return None
        except OSError as e:
            return f"could not record original modes ({e})"

    @staticmethod
    def _iter_tree(root: Path) -> Iterator[Path]:
        """Yields every entry beneath `root` without following symlinks (sorted, deterministic)."""
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            for name in dirnames:
                yield Path(dirpath) / name
            for name in sorted(filenames):
                yield Path(dirpath) / name

    def _symlink_issue(self, entry: Path, scope_root: Path) -> Optional[str]:
        real = Path(os.path.realpath(entry))
        if not os.path.exists(entry):
            return f"dangling symlink {entry} -> {os.readlink(entry)}"
        try:
            real.relative_to(Path(os.path.realpath(scope_root)))
            return None
        except ValueError:
            return f"symlink {entry} -> {real} points outside the protected tree (target not protected)"

    def _is_writable(self, entry: Path) -> bool:
        st = os.lstat(entry)
        if self.system == "darwin":
            flags = getattr(st, "st_flags", 0)
            if flags & (_UF_IMMUTABLE | _SF_IMMUTABLE):
                return False
        if self.system == "windows":
            if stat.S_ISDIR(st.st_mode):
                return not self._windows_dir_denied(entry)
            return bool(st.st_mode & stat.S_IWRITE)
        return bool(st.st_mode & WRITE_BITS)

    def _windows_dir_denied(self, path: Path) -> bool:
        """Checks the NTFS DACL for an explicit write/delete deny entry (read-only query)."""
        user = os.environ.get("USERNAME", "").lower()
        try:
            res = subprocess.run(["icacls", str(path)], capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    low = line.lower()
                    if "(deny)" in low and (not user or user in low or "everyone" in low):
                        if any(right in low for right in ("(wd", ",wd", "(w,", "(w)", "ad", "de")):
                            return True
                return False
        except (OSError, subprocess.SubprocessError):
            pass
        # Fallback: explicit side-effecting probe with a unique, self-cleaning name.
        try:
            fd, probe = tempfile.mkstemp(prefix=".agy-probe-", dir=str(path))
            os.close(fd)
            os.unlink(probe)
            return False
        except OSError:
            return True

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def protection_issues(self, target: TargetInput = None, recursive: bool = True) -> List[str]:
        """Returns human-readable reasons why the target is NOT fully write-protected."""
        if isinstance(target, (list, tuple, set)):
            requested = [_abs(p) for p in target]
        else:
            requested = [_abs(target) if target else self.target_dir]
        issues: List[str] = []
        for path in requested:
            if not os.path.lexists(path):
                issues.append(f"missing: {path}")
                continue
            if os.path.islink(path):
                issues.append(
                    f"symlink {path} -> {os.path.realpath(path)} cannot be locked in place (target not protected)"
                )
                continue
            try:
                if self._is_writable(path):
                    issues.append(f"writable: {path}")
                if recursive and path.is_dir():
                    for entry in self._iter_tree(path):
                        if os.path.islink(entry):
                            problem = self._symlink_issue(entry, path)
                            if problem:
                                issues.append(problem)
                        elif self._is_writable(entry):
                            issues.append(f"writable: {entry}")
            except OSError as e:
                issues.append(f"unreadable: {path} ({e})")
        return issues

    def is_locked(self, target: TargetInput = None, recursive: bool = True) -> bool:
        """True only if every requested path (and, recursively, its contents) is write-protected."""
        if isinstance(target, (list, tuple, set)):
            paths = self._targets(target)
            if not paths:
                return False
            return not self.protection_issues(paths, recursive=recursive)
        path = _abs(target) if target else self.target_dir
        if not os.path.lexists(path):
            return False
        return not self.protection_issues(path, recursive=recursive)

    # ------------------------------------------------------------------
    # Lock / unlock
    # ------------------------------------------------------------------
    def _run(self, cmd: List[str]) -> Tuple[bool, str]:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                return True, ""
            return False, (res.stderr or res.stdout or f"exit code {res.returncode}").strip()
        except (OSError, subprocess.SubprocessError) as e:
            return False, str(e)

    def lock(self, target: TargetInput = None, recursive: bool = True) -> Tuple[bool, str]:
        """Removes write permission from the target(s). Returns (ok, message); ok is False on ANY failure."""
        if isinstance(target, (list, tuple, set)):
            paths = self._targets(target)
            if not paths:
                return True, "Zero existing governance paths to lock."
        else:
            paths = self._targets(target)
            if not paths:
                missing = _abs(target) if target else self.target_dir
                return False, f"Target path '{missing}' does not exist."
        modes = self._load_modes()
        results = [self._lock_single(p, recursive, modes) for p in paths]
        store_note = self._save_modes(modes)
        all_ok = all(ok for ok, _ in results)
        message = "; ".join(msg for _, msg in results)
        if store_note:
            message = f"{message}; note: {store_note}"
        return all_ok, message

    def _lock_single(self, lock_path: Path, recursive: bool, modes: Dict[str, int]) -> Tuple[bool, str]:
        failures: List[str] = []
        details: List[str] = []
        if os.path.islink(lock_path):
            return False, (
                f"{lock_path} is a symlink to {os.path.realpath(lock_path)}; symlinked entries cannot be locked "
                f"in place. Reinstall in copy mode (python3 install.py) to protect it."
            )
        is_dir = lock_path.is_dir()

        # 1. POSIX permission hardening (also toggles the read-only attribute on Windows files)
        entries = [lock_path]
        if is_dir and recursive:
            entries.extend(self._iter_tree(lock_path))
        changed = 0
        for entry in entries:
            try:
                if os.path.islink(entry):
                    problem = self._symlink_issue(entry, lock_path)
                    if problem:
                        failures.append(problem)
                    continue
                mode = stat.S_IMODE(os.lstat(entry).st_mode)
                new_mode = mode & ~WRITE_BITS
                if new_mode != mode:
                    modes.setdefault(str(entry), mode)
                    os.chmod(entry, new_mode)
                    changed += 1
            except OSError as e:
                failures.append(f"chmod failed for {entry}: {e}")
        details.append(f"stripped write bits on {changed} entr{'y' if changed == 1 else 'ies'}")

        # 2. Platform-native hardening
        if self.system == "darwin":
            cmd = ["chflags"] + (["-R"] if is_dir and recursive else []) + ["uchg", str(lock_path)]
            ok, err = self._run(cmd)
            details.append("applied chflags uchg" if ok else "")
            if not ok:
                failures.append(f"chflags uchg failed: {err}")
        elif self.system == "windows":
            username = os.environ.get("USERNAME", "Everyone")
            rights = "(OI)(CI)(WD,AD,DE,DC)" if is_dir and recursive else "(WD,AD,DE,DC)"
            ok, err = self._run(["icacls", str(lock_path), "/deny", f"{username}:{rights}"])
            if not ok:
                failures.append(f"icacls deny failed: {err}")
            attrib = ["attrib", "+R", str(lock_path)] + (["/S", "/D"] if is_dir and recursive else [])
            ok2, err2 = self._run(attrib)
            if not ok2:
                failures.append(f"attrib +R failed: {err2}")
            if ok and ok2:
                details.append(f"applied NTFS deny ACL and +R for {username}")
        elif self.system == "linux" and hasattr(os, "geteuid") and os.geteuid() == 0:
            cmd = ["chattr"] + (["-R"] if is_dir and recursive else []) + ["+i", str(lock_path)]
            ok, err = self._run(cmd)
            details.append("applied chattr +i" if ok else f"chattr +i unavailable ({err})")

        # 3. Post-condition: verify the lock actually holds
        for issue in self.protection_issues(lock_path, recursive=recursive):
            if issue not in failures:
                failures.append(issue)

        details = [d for d in details if d]
        if failures:
            shown = failures[:8]
            more = f" (+{len(failures) - 8} more)" if len(failures) > 8 else ""
            return False, f"PARTIAL LOCK for {lock_path}: " + "; ".join(shown) + more
        return True, f"Locked {lock_path} ({', '.join(details)})"

    def unlock(self, target: TargetInput = None, recursive: bool = True) -> Tuple[bool, str]:
        """Restores the recorded original permission modes (or owner-write when none was recorded)."""
        if isinstance(target, (list, tuple, set)):
            paths = self._targets(target)
            if not paths:
                return True, "Zero existing governance paths to unlock."
        else:
            paths = self._targets(target)
            if not paths:
                missing = _abs(target) if target else self.target_dir
                return False, f"Target path '{missing}' does not exist."
        modes = self._load_modes()
        results = [self._unlock_single(p, recursive, modes) for p in paths]
        store_note = self._save_modes(modes)
        all_ok = all(ok for ok, _ in results)
        message = "; ".join(msg for _, msg in results)
        if store_note:
            message = f"{message}; note: {store_note}"
        return all_ok, message

    def _unlock_single(self, unlock_path: Path, recursive: bool, modes: Dict[str, int]) -> Tuple[bool, str]:
        if os.path.islink(unlock_path):
            return True, f"Skipped symlink {unlock_path} (targets outside the tree are never modified)"
        failures: List[str] = []
        is_dir = unlock_path.is_dir()

        if self.system == "darwin":
            cmd = ["chflags"] + (["-R"] if is_dir and recursive else []) + ["nouchg", str(unlock_path)]
            ok, err = self._run(cmd)
            if not ok:
                failures.append(f"chflags nouchg failed: {err}")
        elif self.system == "windows":
            username = os.environ.get("USERNAME", "Everyone")
            cmd = ["icacls", str(unlock_path), "/remove:d", username] + (["/t", "/c", "/q"] if is_dir and recursive else ["/q"])
            ok, err = self._run(cmd)
            if not ok:
                failures.append(f"icacls remove deny failed: {err}")
            attrib = ["attrib", "-R", str(unlock_path)] + (["/S", "/D"] if is_dir and recursive else [])
            ok2, err2 = self._run(attrib)
            if not ok2:
                failures.append(f"attrib -R failed: {err2}")
        elif self.system == "linux" and hasattr(os, "geteuid") and os.geteuid() == 0:
            self._run(["chattr"] + (["-R"] if is_dir and recursive else []) + ["-i", str(unlock_path)])

        entries = [unlock_path]
        if is_dir and recursive:
            entries.extend(self._iter_tree(unlock_path))
        restored = 0
        for entry in entries:
            try:
                if os.path.islink(entry):
                    continue
                current = stat.S_IMODE(os.lstat(entry).st_mode)
                key = str(entry)
                original = modes.get(key)
                if original is not None and (current & ~WRITE_BITS) == (original & ~WRITE_BITS):
                    os.chmod(entry, original)
                    modes.pop(key, None)
                    restored += 1
                else:
                    modes.pop(key, None)
                    if not current & stat.S_IWUSR:
                        os.chmod(entry, current | stat.S_IWUSR)
            except OSError as e:
                failures.append(f"permission restore failed for {entry}: {e}")

        if self.system != "windows":
            try:
                if not os.lstat(unlock_path).st_mode & stat.S_IWUSR:
                    failures.append(f"{unlock_path} is still read-only")
            except OSError as e:
                failures.append(str(e))

        if failures:
            return False, f"PARTIAL UNLOCK for {unlock_path}: " + "; ".join(failures[:8])
        return True, f"Unlocked {unlock_path} ({restored} original mode(s) restored)"

    def recover_stale_lock(self, target: TargetInput = None) -> Tuple[bool, str]:
        """Re-engages write protection when a previous session left the target unlocked."""
        if self.is_locked(target):
            return True, "Target is already write-protected; zero stale unlock detected."
        success, msg = self.lock(target)
        return success, f"Stale unlocked state recovered: {msg}"
