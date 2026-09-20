"""
guard/os_adapter.py — Cross-Platform OS Write Protection Adapter
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import os
import platform
import stat
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union

TargetInput = Optional[Union[Path, str, Sequence[Union[Path, str]]]]


class OSProtectionAdapter:
    """
    Provides deterministic, cross-platform file system write protection:
    - Linux: POSIX permission lockdown (read-only 0555/0444) + chattr +i if privileged
    - macOS: BSD user-immutable flag (`chflags uchg` / `nouchg`) + permission lockdown
    - Windows: NTFS ACL denial (`icacls /deny`) + read-only attribute (`attrib +R`)
    """

    def __init__(self, target_dir: Optional[Union[Path, str]] = None):
        self.system = platform.system().lower()
        if target_dir is None:
            config_env = os.environ.get("ANTIGRAVITY_CONFIG_DIR")
            self.target_dir = Path(config_env).resolve() if config_env else Path.home() / ".gemini" / "config"
        else:
            self.target_dir = Path(target_dir).resolve()

    def get_platform_name(self) -> str:
        if self.system == "linux":
            return "Linux (POSIX / Extended Attributes)"
        elif self.system == "darwin":
            return "macOS (BSD User Immutable Flags)"
        elif self.system == "windows":
            return "Windows (NTFS Access Control Lists)"
        return f"Generic POSIX ({platform.system()})"

    def is_locked(self, target: TargetInput = None) -> bool:
        """Determines whether the target directory, file, or collection of paths is currently write-protected."""
        if isinstance(target, (list, tuple, set)):
            paths = [Path(p).resolve() for p in target if Path(p).exists()]
            if not paths:
                return False
            return all(self._is_single_locked(p) for p in paths)
        check_path = (Path(target).resolve() if target else self.target_dir)
        return self._is_single_locked(check_path)

    def _is_single_locked(self, check_path: Path) -> bool:
        if not check_path.exists():
            return False

        if self.system == "darwin":
            # Check macOS uchg flag
            try:
                st = os.stat(check_path)
                flags = getattr(st, "st_flags", 0)
                # UF_IMMUTABLE is 0x00000002
                if flags & 0x00000002:
                    return True
            except Exception:
                pass

        if self.system == "windows":
            if check_path.is_file():
                try:
                    st = os.stat(check_path)
                    if not (st.st_mode & stat.S_IWRITE):
                        return True
                except Exception:
                    pass
            elif check_path.is_dir():
                # On Windows, directories do not reflect read-only status in S_IWRITE.
                # Probe write to test if NTFS write deny or permission lock is active.
                probe_file = check_path / ".guard_probe.tmp"
                try:
                    with open(probe_file, "w") as f:
                        f.write("probe")
                    try:
                        probe_file.unlink(missing_ok=True)
                    except Exception:
                        pass
                    return False
                except (PermissionError, OSError):
                    return True

        # Generic POSIX / Linux check: Is owner write bit cleared?
        try:
            st = os.stat(check_path)
            mode = st.st_mode
            # If owner write (S_IWUSR) is cleared on directory/file
            if not (mode & stat.S_IWUSR):
                return True
        except Exception:
            pass

        return False

    def lock(self, target: TargetInput = None) -> Tuple[bool, str]:
        """Locks the target directory, file, or collection of paths, preventing write, create, or delete operations."""
        if isinstance(target, (list, tuple, set)):
            paths = [Path(p).resolve() for p in target if Path(p).exists()]
            if not paths:
                return True, "Zero existing governance paths to lock."
            all_ok = True
            all_details = []
            for p in paths:
                ok, msg = self._lock_single(p)
                if not ok:
                    all_ok = False
                all_details.append(f"{p.name}: {msg}")
            return all_ok, "; ".join(all_details)

        lock_path = (Path(target).resolve() if target else self.target_dir)
        return self._lock_single(lock_path)

    def _lock_single(self, lock_path: Path) -> Tuple[bool, str]:
        if not lock_path.exists():
            return False, f"Target path '{lock_path}' does not exist."

        details: List[str] = []

        # 1. macOS BSD uchg flag
        if self.system == "darwin":
            try:
                subprocess.run(["chflags", "-R", "uchg", str(lock_path)], check=True, capture_output=True)
                details.append("Applied BSD 'uchg' immutable flag")
            except Exception as e:
                details.append(f"Notice: chflags uchg returned {e}")

        # 2. Windows NTFS ACLs & Read-only attribute
        elif self.system == "windows":
            try:
                username = os.environ.get("USERNAME", "Everyone")
                # Deny Write and Delete rights specifically while preserving Read/Traversal
                subprocess.run(
                    ["icacls", str(lock_path), "/deny", f"{username}:(OI)(CI)(WD,AD,DE,DC)"],
                    check=False,
                    capture_output=True,
                )
                subprocess.run(["attrib", "+R", str(lock_path), "/S", "/D"], check=False, capture_output=True)
                details.append(f"Applied NTFS deny ACL and +R attribute for {username}")
            except Exception as e:
                details.append(f"Windows ACL notice: {e}")

        # 3. Linux / POSIX Permission Hardening (Universal user-space lock)
        # Recursively remove write permissions from all files and directories
        try:
            if lock_path.is_dir():
                for root, dirs, files in os.walk(lock_path):
                    for f in files:
                        file_path = Path(root) / f
                        try:
                            current_mode = file_path.stat().st_mode
                            file_path.chmod(current_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
                        except (PermissionError, OSError):
                            pass
                    for d in dirs:
                        dir_path = Path(root) / d
                        try:
                            current_mode = dir_path.stat().st_mode
                            dir_path.chmod(current_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
                        except (PermissionError, OSError):
                            pass

            top_mode = lock_path.stat().st_mode
            lock_path.chmod(top_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
            details.append("Stripped write permissions (chmod a-w)")
        except Exception as e:
            details.append(f"Permission error: {e}")

        # Optional Linux chattr attempt (if running as root or with capabilities)
        if self.system == "linux":
            try:
                res = subprocess.run(["chattr", "-R", "+i", str(lock_path)], capture_output=True)
                if res.returncode == 0:
                    details.append("Applied ext4/xfs '+i' immutable flag")
            except Exception:
                pass

        return True, "Target locked successfully. " + "; ".join(details)

    def unlock(self, target: TargetInput = None) -> Tuple[bool, str]:
        """Unlocks the target directory, file, or collection of paths to allow maintenance or vetted rule ingestion."""
        if isinstance(target, (list, tuple, set)):
            paths = [Path(p).resolve() for p in target if Path(p).exists()]
            if not paths:
                return True, "Zero existing governance paths to unlock."
            all_ok = True
            all_details = []
            for p in paths:
                ok, msg = self._unlock_single(p)
                if not ok:
                    all_ok = False
                all_details.append(f"{p.name}: {msg}")
            return all_ok, "; ".join(all_details)

        unlock_path = (Path(target).resolve() if target else self.target_dir)
        return self._unlock_single(unlock_path)

    def _unlock_single(self, unlock_path: Path) -> Tuple[bool, str]:
        if not unlock_path.exists():
            return False, f"Target path '{unlock_path}' does not exist."

        details: List[str] = []

        # 1. macOS remove uchg flag
        if self.system == "darwin":
            try:
                subprocess.run(["chflags", "-R", "nouchg", str(unlock_path)], check=True, capture_output=True)
                details.append("Removed BSD 'uchg' immutable flag")
            except Exception as e:
                details.append(f"Notice: chflags nouchg returned {e}")

        # 2. Windows remove deny ACL & attrib
        elif self.system == "windows":
            try:
                username = os.environ.get("USERNAME", "Everyone")
                subprocess.run(
                    ["icacls", str(unlock_path), "/remove:d", username, "/t", "/c", "/q"],
                    check=False,
                    capture_output=True,
                )
                subprocess.run(["attrib", "-R", str(unlock_path), "/S", "/D"], check=False, capture_output=True)
                details.append("Removed NTFS deny ACL and -R attribute")
            except Exception as e:
                details.append(f"Windows ACL notice: {e}")

        # 3. Linux remove chattr +i if present
        if self.system == "linux":
            try:
                res = subprocess.run(["chattr", "-R", "-i", str(unlock_path)], capture_output=True)
                if res.returncode == 0:
                    details.append("Cleared '+i' immutable flag")
            except Exception:
                pass

        # 4. Universal POSIX Permission Restoration
        try:
            top_mode = unlock_path.stat().st_mode
            unlock_path.chmod(top_mode | stat.S_IWUSR)

            if unlock_path.is_dir():
                for root, dirs, files in os.walk(unlock_path):
                    for d in dirs:
                        dir_path = Path(root) / d
                        try:
                            current_mode = dir_path.stat().st_mode
                            dir_path.chmod(current_mode | stat.S_IWUSR)
                        except (PermissionError, OSError):
                            pass
                    for f in files:
                        file_path = Path(root) / f
                        try:
                            current_mode = file_path.stat().st_mode
                            file_path.chmod(current_mode | stat.S_IWUSR)
                        except (PermissionError, OSError):
                            pass

            details.append("Restored owner write permissions (chmod u+w)")
        except Exception as e:
            details.append(f"Permission restore error: {e}")

        return True, "Target unlocked successfully. " + "; ".join(details)

    def recover_stale_lock(self, target: TargetInput = None) -> Tuple[bool, str]:
        """
        Detects if the environment was left unlocked following an abnormal process exit
        or crash, and safely re-engages OS write protection.
        """
        if self.is_locked(target):
            return True, "Target is already write-protected; zero stale unlock detected."
        success, msg = self.lock(target)
        return success, f"Stale unlocked state recovered: {msg}"

