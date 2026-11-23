"""
guard/doctor.py — Health diagnosis for an environment's governance scope (headless, testable).
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

The CLI (`agy-guard doctor`) only renders a DoctorReport; the checks live here so they can
be exercised without a terminal.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from guard.environment import AgentEnvironment, EnvironmentRegistry, RegistryError
from guard.integrity import FileIntegrityMonitor, IntegrityReport
from guard.notifier import load_settings
from guard.paths import move_aside, read_json, state_dir
from guard.plugins import HARNESS_PLUGIN_NAMES


def recover_or_load_registry(
    config_path: Optional[Path] = None,
    *,
    recover: bool = False,
    os_adapter=None,
) -> Tuple[EnvironmentRegistry, Optional[Path]]:
    """Loads EnvironmentRegistry; when `recover=True` and corrupt, quarantines via `move_aside` and re-initializes."""
    try:
        return EnvironmentRegistry(config_path=config_path, os_adapter=os_adapter), None
    except RegistryError as orig_err:
        if not recover:
            raise
        reg_path = Path(config_path).resolve() if config_path is not None else (state_dir() / "environments.json")
        legacy_path = Path.home() / ".gemini" / ".environments.json"
        target = reg_path if os.path.lexists(reg_path) else (legacy_path if os.path.lexists(legacy_path) else reg_path)
        if os.path.lexists(target) and not os.path.islink(target):
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        quarantined = move_aside(target, tag="corrupt")
        if quarantined is None and os.path.lexists(target):
            raise orig_err
        reg = EnvironmentRegistry(config_path=config_path, os_adapter=os_adapter)
        reg.save()
        return reg, quarantined


@dataclass
class DoctorReport:
    env: AgentEnvironment
    root: Path
    monitor: FileIntegrityMonitor
    issues: List[str]
    report: IntegrityReport
    warnings: List[str] = field(default_factory=list)
    infos: List[str] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not self.issues and self.report.is_intact and not self.warnings


def world_writable_ancestors(path: Path, depth: int = 3) -> List[str]:
    """Ancestors (up to `depth`) that any local user may write to (sticky dirs such as /tmp excluded)."""
    if os.name == "nt":
        return []  # st_mode carries no ACL information on Windows; every path would look world-writable
    found = []
    current = Path(os.path.realpath(path))
    for _ in range(depth + 1):
        try:
            mode = os.stat(current).st_mode
            # Sticky world-writable dirs (/tmp) do not let other users replace our entries.
            if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
                found.append(str(current))
        except OSError:
            break
        if current.parent == current:
            break
        current = current.parent
    return found


def grant_statistics(config_json: Path) -> Optional[dict]:
    """Counts risky permission grants WITHOUT printing their contents."""
    try:
        data = json.loads(config_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    user_settings = data.get("userSettings")
    if user_settings is None:
        user_settings = {}
    elif not isinstance(user_settings, dict):
        return None
    grants = user_settings.get("globalPermissionGrants")
    if grants is None:
        grants = {}
    elif not isinstance(grants, dict):
        return None
    allow = grants.get("allow")
    if allow is None:
        allow = []
    elif not isinstance(allow, list):
        return None
    entries = [e if isinstance(e, str) else json.dumps(e) for e in allow]
    governance_markers = (".gemini/config", ".gemini/antigravity-harness")
    return {
        "total": len(entries),
        "governance_writes": sum(1 for e in entries if e.startswith("write_file") and any(m in e for m in governance_markers)),
        "secret_like": sum(1 for e in entries if re.search(r"(token|api[_-]?key|secret|password)=", e, re.I)),
        "unsandboxed": sum(1 for e in entries if e.startswith("unsandboxed")),
        "oversized": sum(1 for e in entries if len(e) > 500),
    }


_HOOK_SCRIPT_SUFFIXES = (".py", ".sh", ".mjs", ".js", ".cjs", ".ps1", ".bat", ".cmd")
_SCRIPT_INTERPRETERS = frozenset({"python", "python3", "py", "node", "bash", "sh", "zsh", "dash", "pwsh", "powershell"})


def _iter_hook_commands(node: object) -> List[str]:
    cmds: List[str] = []
    if isinstance(node, dict):
        cmd = node.get("command")
        if isinstance(cmd, str) and cmd.strip():
            cmds.append(cmd.strip())
        for v in node.values():
            cmds.extend(_iter_hook_commands(v))
    elif isinstance(node, list):
        for item in node:
            cmds.extend(_iter_hook_commands(item))
    return cmds


def _has_disabled_flag(node: object) -> bool:
    if isinstance(node, dict):
        if node.get("enabled") is False:
            return True
        return any(_has_disabled_flag(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_disabled_flag(item) for item in node)
    return False


def _extract_hook_executable(tokens: List[str]) -> Tuple[Optional[str], int, List[str]]:
    """
    Returns `(executable, next_index, effective_tokens)`, skipping leading `env` wrappers
    (including `/usr/bin/env` and `-S <split-string>`) and `VAR=val` assignments.
    """
    eff_tokens = list(tokens)
    idx = 0
    while idx < len(eff_tokens):
        tok = eff_tokens[idx].strip("\"'")
        if not tok:
            idx += 1
            continue
        if Path(tok).name.lower() == "env" and idx + 1 < len(eff_tokens):
            idx += 1
            while idx < len(eff_tokens) and eff_tokens[idx].startswith("-"):
                flag = eff_tokens[idx]
                if flag in ("-S", "--split-string") and idx + 1 < len(eff_tokens):
                    raw_s = eff_tokens[idx + 1]
                    try:
                        import shlex as _shlex

                        sub_toks = _shlex.split(raw_s, posix=(os.name != "nt"))
                    except ValueError:
                        sub_toks = raw_s.split()
                    eff_tokens = eff_tokens[:idx] + sub_toks + eff_tokens[idx + 2 :]
                    continue
                if flag.startswith("--split-string="):
                    raw_s = flag.split("=", 1)[1]
                    try:
                        import shlex as _shlex

                        sub_toks = _shlex.split(raw_s, posix=(os.name != "nt"))
                    except ValueError:
                        sub_toks = raw_s.split()
                    eff_tokens = eff_tokens[:idx] + sub_toks + eff_tokens[idx + 1 :]
                    continue
                idx += 2 if flag in ("-u", "-C", "--unset", "--chdir") and idx + 1 < len(eff_tokens) else 1
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok):
            idx += 1
            continue
        return tok, idx + 1, eff_tokens
    return None, len(eff_tokens), eff_tokens


def _is_path_like_token(tok: str) -> bool:
    return (
        "/" in tok
        or "\\" in tok
        or tok.startswith(".")
        or tok.startswith("~")
        or (len(tok) >= 2 and tok[1] == ":")
    )


def _hook_executable_exists(exe: str, root: Path) -> bool:
    expanded = os.path.expanduser(exe)
    if _is_path_like_token(exe):
        exe_path = Path(expanded)
        if not exe_path.is_absolute():
            exe_path = root / exe_path
        if not exe_path.is_file():
            return False
        if os.name != "nt" and not os.access(exe_path, os.X_OK):
            return False
        return True
    if shutil.which(expanded):
        return True
    if os.name == "nt" and expanded == "python3":
        return bool(shutil.which("python") or shutil.which("py"))
    return False


def _collect_native_deny_rules(root: Path, warnings: Optional[List[str]] = None) -> List[str]:
    """Reads native Antigravity `deny` rules from App `config.json` and CLI `settings.json`."""
    entries: List[str] = []
    for cfg_path, check_global_grants in (
        (root / "config.json", True),
        (root.parent / "antigravity-cli" / "settings.json", False),
    ):
        if not cfg_path.is_file():
            continue
        raw_data = read_json(cfg_path, default=None)
        if raw_data is None:
            if warnings is not None:
                warnings.append(f"Native Antigravity settings file {cfg_path} could not be parsed as valid JSON.")
            continue
        if not isinstance(raw_data, dict):
            continue
        if check_global_grants:
            user_settings = raw_data.get("userSettings")
            if isinstance(user_settings, dict):
                grants = user_settings.get("globalPermissionGrants")
                if isinstance(grants, dict) and isinstance(grants.get("deny"), list):
                    entries.extend(str(e) for e in grants["deny"] if isinstance(e, str))
        perms = raw_data.get("permissions")
        if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
            entries.extend(str(e) for e in perms["deny"] if isinstance(e, str))
    return entries


def _check_native_deny_rules(root: Path, infos: List[str], warnings: Optional[List[str]] = None) -> None:
    """Recommends native Antigravity `deny` rules (`agy-guard unlock`, `--no-verify`) as INFO."""
    deny_entries = _collect_native_deny_rules(root, warnings=warnings)
    lowered = [e.lower() for e in deny_entries]
    has_unlock_deny = any("agy-guard" in e and "unlock" in e for e in lowered)
    has_no_verify_deny = any("--no-verify" in e for e in lowered)
    missing_recs: List[str] = []
    if not has_unlock_deny:
        missing_recs.append("'agy-guard unlock' (e.g. command(agy-guard unlock))")
    if not has_no_verify_deny:
        missing_recs.append("'--no-verify' (e.g. command(regex:.*--no-verify.*))")
    if missing_recs:
        infos.append(
            "Native Antigravity deny rules recommended for defense-in-depth (in config.json "
            "userSettings.globalPermissionGrants.deny or ~/.gemini/antigravity-cli/settings.json "
            f"permissions.deny): {', '.join(missing_recs)}."
        )
    else:
        infos.append("Native Antigravity deny rules cover 'agy-guard unlock' and '--no-verify'.")


def _is_harness_contrast_mcp_arg(arg: str) -> bool:
    from guard.environment import RELOCATED_SKILL_SCRIPTS
    from guard.plugins import PLUGIN_CATALOG

    antislop_spec = PLUGIN_CATALOG.get("antislop")
    canonical = (
        antislop_spec.mcp_script_rel
        if (antislop_spec and antislop_spec.mcp_script_rel)
        else "skills/antislop/scripts/contrast-mcp.py"
    )
    suffixes = {canonical.lower(), f"plugins/antislop/{canonical}".lower()}
    for old_rel, new_rel in RELOCATED_SKILL_SCRIPTS.items():
        if new_rel == canonical:
            suffixes.add(old_rel.lower())
    norm = arg.strip().replace("\\", "/").lower()
    return any(norm == sfx or norm.endswith("/" + sfx) for sfx in suffixes)


def _check_hybrid_plugins(root: Path, warnings: List[str], infos: List[str]) -> None:
    """Detects duplicate skill shadowing, stale global contrast-mcp.py collisions, and emits optional `agy plugin` INFO."""
    plugins_dir = root / "plugins"
    try:
        if os.path.islink(plugins_dir) or not plugins_dir.is_dir():
            return
    except OSError as exc:
        warnings.append(f"Could not inspect plugins directory {plugins_dir} ({exc}); hybrid diagnostics incomplete.")
        return

    installed_harness_packs: List[str] = []
    duplicates: List[Tuple[str, str]] = []
    skills_dir = root / "skills"
    try:
        check_skills = skills_dir.is_dir() and not os.path.islink(skills_dir)
    except OSError as exc:
        warnings.append(f"Could not inspect skills directory {skills_dir} ({exc}); duplicate skill diagnostics incomplete.")
        check_skills = False

    try:
        pack_entries = sorted(plugins_dir.iterdir(), key=lambda p: p.name)
    except OSError as exc:
        warnings.append(f"Could not inspect plugins directory {plugins_dir} ({exc}); hybrid diagnostics incomplete.")
        pack_entries = []

    for pack_dir in pack_entries:
        try:
            is_pack_dir = not os.path.islink(pack_dir) and pack_dir.is_dir()
        except OSError as exc:
            warnings.append(f"Could not inspect plugin directory {pack_dir} ({exc}).")
            continue
        if not is_pack_dir:
            continue
        pack_name = pack_dir.name
        if pack_name in HARNESS_PLUGIN_NAMES:
            installed_harness_packs.append(pack_name)
        if not check_skills:
            continue
        pack_skills_dir = pack_dir / "skills"
        try:
            has_pack_skills = not os.path.islink(pack_skills_dir) and pack_skills_dir.is_dir()
        except OSError as exc:
            warnings.append(f"Could not inspect plugin skills directory {pack_skills_dir} ({exc}).")
            continue
        if not has_pack_skills:
            continue
        try:
            skill_entries = sorted(pack_skills_dir.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            warnings.append(f"Could not inspect plugin skills directory {pack_skills_dir} ({exc}).")
            continue
        for pskill in skill_entries:
            try:
                is_skill_dir = not os.path.islink(pskill) and pskill.is_dir()
            except OSError as exc:
                warnings.append(f"Could not inspect plugin skill directory {pskill} ({exc}).")
                continue
            if not is_skill_dir:
                continue
            slug = pskill.name
            try:
                if os.path.lexists(skills_dir / slug):
                    duplicates.append((slug, pack_name))
            except OSError as exc:
                warnings.append(f"Could not inspect skill entry {skills_dir / slug} ({exc}).")

    repair_hint = _repair_command_hint()
    if duplicates:
        dupes_desc = ", ".join(f"skills/{slug} <-> plugins/{pack}/skills/{slug}" for slug, pack in duplicates)
        warnings.append(
            f"Duplicate skill installation detected (double-loading/shadowing): {dupes_desc}. "
            f"Re-run {repair_hint} with --plugins or --flat-skills to resolve shadowing."
        )

    plugin_mcp = plugins_dir / "antislop" / "mcp_config.json"
    global_mcp = root / "mcp_config.json"
    try:
        has_plugin_mcp = not os.path.islink(plugin_mcp) and plugin_mcp.is_file()
    except OSError as exc:
        warnings.append(f"Could not inspect plugin MCP config {plugin_mcp} ({exc}).")
        has_plugin_mcp = False
    try:
        has_global_mcp = not os.path.islink(global_mcp) and global_mcp.is_file()
    except OSError as exc:
        warnings.append(f"Could not inspect global MCP config {global_mcp} ({exc}).")
        has_global_mcp = False
    if has_plugin_mcp and has_global_mcp:
        mcp_data = read_json(global_mcp, default=None)
        if mcp_data is None:
            warnings.append(
                f"Could not parse {global_mcp} as valid JSON while {plugin_mcp} is active; "
                "inspect mcp_config.json for syntax errors or stale contrast-mcp.py entries."
            )
        elif isinstance(mcp_data, dict) and isinstance(mcp_data.get("mcpServers"), dict):
            stale_keys: List[str] = []
            for server_key, server in mcp_data["mcpServers"].items():
                if not isinstance(server, dict):
                    continue
                args = server.get("args")
                if not isinstance(args, list):
                    continue
                if any(isinstance(a, str) and _is_harness_contrast_mcp_arg(a) for a in args):
                    stale_keys.append(str(server_key))
            if stale_keys:
                warnings.append(
                    f"Stale global contrast-mcp.py server(s) in {global_mcp} ({', '.join(stale_keys)}) "
                    f"collide with {plugin_mcp}; re-run {repair_hint} with --plugins to retire the global entry."
                )

    if installed_harness_packs:
        deny_entries = _collect_native_deny_rules(root, warnings=None)
        lowered = [e.lower() for e in deny_entries]
        has_agy_plugin_deny = any("agy" in e and "plugin" in e for e in lowered)
        if has_agy_plugin_deny:
            infos.append(
                "Native Antigravity deny rules cover 'agy plugin' mutations for installed harness plugins."
            )
        else:
            infos.append(
                "Installed harness plugin pack(s) ("
                + ", ".join(installed_harness_packs)
                + "): optional native Antigravity deny rule recommended for defense-in-depth: "
                "'agy plugin' (e.g. command(regex:.*\\bagy\\s+plugin\\s+(disable|uninstall|install|import)\\b.*))."
            )


def _check_plugins_symlinks(root: Path, warnings: List[str]) -> None:
    """Warns if writable `plugins/` (or `.agents/skills/`) or any entry inside it is a symlink (without following symlinks)."""
    for rel_dir, label in (("plugins", "plugins/"), (".agents/skills", ".agents/skills/")):
        sub_dir = root / rel_dir
        if os.path.islink(sub_dir):
            status_tag = "dangling" if not os.path.exists(sub_dir) else "external/resolved"
            warnings.append(
                f"{label} directory is a symlink ({status_tag}: {sub_dir}); copy-mode protections cannot lock symlinked plugin roots."
            )
            continue
        try:
            if not sub_dir.is_dir():
                continue
        except OSError as exc:
            warnings.append(f"Failed to scan {label} for symlinks: {exc}")
            continue
        symlinks: List[str] = []
        walk_errors: List[str] = []

        def _on_walk_error(err: OSError, _lbl: str = label) -> None:
            walk_errors.append(f"Failed to scan {_lbl} for symlinks: {err}")

        try:
            for cur_root, dirs, files in os.walk(sub_dir, followlinks=False, onerror=_on_walk_error):
                cur_path = Path(cur_root)
                kept_dirs: List[str] = []
                for d in sorted(dirs):
                    entry = cur_path / d
                    if os.path.islink(entry):
                        status_tag = "dangling" if not os.path.exists(entry) else "external/resolved"
                        symlinks.append(f"{entry.relative_to(root).as_posix()} ({status_tag})")
                    else:
                        kept_dirs.append(d)
                dirs[:] = kept_dirs
                for f in sorted(files):
                    entry = cur_path / f
                    if os.path.islink(entry):
                        status_tag = "dangling" if not os.path.exists(entry) else "external/resolved"
                        symlinks.append(f"{entry.relative_to(root).as_posix()} ({status_tag})")
        except OSError as exc:
            warnings.append(f"Failed to scan {label} for symlinks: {exc}")
            continue
        warnings.extend(walk_errors)
        if symlinks:
            preview = ", ".join(symlinks[:10])
            suffix = f" (+{len(symlinks) - 10} more)" if len(symlinks) > 10 else ""
            warnings.append(
                f"Symlink entry detected under writable {label} directory: {preview}{suffix} "
                "(copy-mode protections do not lock symlink targets)."
            )


def _check_hooks_and_runtime_state(root: Path, warnings: List[str], infos: List[str]) -> None:
    import shlex
    from guard import __version__

    hooks_file = root / "hooks.json"
    if hooks_file.is_file():
        try:
            hooks_data = json.loads(hooks_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            hooks_data = None
        if not isinstance(hooks_data, dict):
            warnings.append(f"Lifecycle hooks configuration {hooks_file} is not a valid JSON object.")
        else:
            uw_entry = hooks_data.get("upstream-watchdog")
            uw_schema_invalid = False
            if "upstream-watchdog" not in hooks_data:
                warnings.append(f"Lifecycle hooks configuration {hooks_file} is missing 'upstream-watchdog' (SessionStart).")
                uw_schema_invalid = True
            else:
                if not isinstance(uw_entry, dict):
                    warnings.append(
                        f"Lifecycle hooks configuration {hooks_file} has invalid 'upstream-watchdog' entry (expected JSON object)."
                    )
                    uw_schema_invalid = True
                else:
                    if "SessionStart" not in uw_entry:
                        repair_hint = _repair_command_hint()
                        if "PreInvocation" in uw_entry:
                            warnings.append(
                                f"Lifecycle hooks configuration {hooks_file} registers 'upstream-watchdog' under legacy 'PreInvocation' "
                                f"instead of 'SessionStart' (run {repair_hint})."
                            )
                        else:
                            warnings.append(
                                f"Lifecycle hooks configuration {hooks_file} is missing 'SessionStart' under 'upstream-watchdog' "
                                f"(run {repair_hint})."
                            )
                            uw_schema_invalid = True
                    elif not isinstance(uw_entry.get("SessionStart"), list) or not uw_entry.get("SessionStart"):
                        warnings.append(
                            f"Lifecycle hooks configuration {hooks_file} has invalid or empty 'upstream-watchdog.SessionStart' entry (expected non-empty list)."
                        )
                        uw_schema_invalid = True
                    elif uw_entry.get("PreInvocation"):
                        repair_hint = _repair_command_hint()
                        warnings.append(
                            f"Lifecycle hooks configuration {hooks_file} still registers legacy 'PreInvocation' alongside 'SessionStart' "
                            f"under 'upstream-watchdog' (run {repair_hint})."
                        )
            hg_entry = hooks_data.get("harness-gate")
            hg_schema_invalid = False
            hooks_disabled = False
            if hooks_data.get("enabled") is False:
                warnings.append(
                    f"Lifecycle hooks configuration {hooks_file} sets 'enabled': false; all lifecycle hooks are inactive."
                )
                hooks_disabled = True
            if isinstance(uw_entry, dict) and _has_disabled_flag(uw_entry):
                warnings.append(
                    f"Lifecycle hook group 'upstream-watchdog' in {hooks_file} has 'enabled': false; "
                    "SessionStart upstream checks are inactive."
                )
                hooks_disabled = True
            if "harness-gate" not in hooks_data:
                warnings.append(
                    f"Lifecycle hooks configuration {hooks_file} is missing 'harness-gate' (PreInvocation/PreToolUse/Stop)."
                )
            elif not isinstance(hg_entry, dict):
                warnings.append(
                    f"Lifecycle hooks configuration {hooks_file} has invalid 'harness-gate' entry (expected JSON object)."
                )
                hg_schema_invalid = True
            elif _has_disabled_flag(hg_entry):
                warnings.append(
                    f"Lifecycle hook group 'harness-gate' in {hooks_file} has 'enabled': false; "
                    "PreInvocation/PreToolUse/Stop enforcement is partially or fully inactive."
                )
                hooks_disabled = True
            if isinstance(hg_entry, dict):
                has_ptu = isinstance(hg_entry.get("PreToolUse"), list) and bool(_iter_hook_commands(hg_entry.get("PreToolUse")))
                missing_opt = [
                    ev
                    for ev in ("PreInvocation", "Stop")
                    if not isinstance(hg_entry.get(ev), list) or not _iter_hook_commands(hg_entry.get(ev))
                ]
                if not has_ptu:
                    hg_schema_invalid = True
                    missing_all = ["PreToolUse", *missing_opt]
                    warnings.append(
                        f"Lifecycle hook group 'harness-gate' in {hooks_file} is missing active hook commands for: "
                        f"{', '.join(missing_all)}."
                    )
                elif missing_opt:
                    infos.append(
                        f"Lifecycle hook group 'harness-gate' in {hooks_file} has no active commands for optional events: "
                        f"{', '.join(missing_opt)}."
                    )
            seen_missing = set()
            for cmd in _iter_hook_commands(hooks_data):
                try:
                    tokens = shlex.split(cmd, posix=(os.name != "nt"))
                except ValueError as exc:
                    warnings.append(
                        f"Lifecycle hook command in {hooks_file.name} has unbalanced quotes ({exc}): {cmd[:120]}"
                    )
                    seen_missing.add(cmd[:120])
                    tokens = cmd.split()
                exe, arg_start, eff_tokens = _extract_hook_executable(tokens)
                if not exe:
                    if cmd not in seen_missing:
                        seen_missing.add(cmd)
                        warnings.append(
                            f"Lifecycle hook command in {hooks_file.name} resolves to no executable: {cmd[:120]}"
                        )
                    continue
                if not _hook_executable_exists(exe, root):
                    if exe not in seen_missing:
                        seen_missing.add(exe)
                        warnings.append(
                            f"Lifecycle hook command executable referenced in {hooks_file.name} "
                            f"does not exist, is not executable, or is not on PATH: {exe}"
                        )
                exe_stem = Path(exe).stem.lower()
                is_interpreter = exe_stem in _SCRIPT_INTERPRETERS
                skip_next_arg = False
                checked_interp_script = False
                for tok in eff_tokens[arg_start:]:
                    cleaned = tok.strip("\"'")
                    if not cleaned:
                        continue
                    if skip_next_arg:
                        skip_next_arg = False
                        continue
                    if is_interpreter and cleaned in ("-c", "-m", "-e", "--eval", "-Command", "-EncodedCommand"):
                        skip_next_arg = True
                        checked_interp_script = True
                        continue
                    if is_interpreter and cleaned in ("-W", "-X", "-r", "--require", "--loader", "--import"):
                        skip_next_arg = True
                        continue
                    if cleaned.startswith("-"):
                        continue
                    check_as_script = cleaned.lower().endswith(_HOOK_SCRIPT_SUFFIXES)
                    if check_as_script and is_interpreter and not checked_interp_script:
                        checked_interp_script = True
                    elif not check_as_script and is_interpreter and not checked_interp_script:
                        checked_interp_script = True
                        check_as_script = _is_path_like_token(cleaned)
                    if check_as_script:
                        expanded = os.path.expanduser(cleaned)
                        script_path = Path(expanded) if Path(expanded).is_absolute() else (root / expanded)
                        if not script_path.is_file() and cleaned not in seen_missing:
                            seen_missing.add(cleaned)
                            warnings.append(
                                f"Lifecycle hook script referenced in {hooks_file.name} does not exist: {cleaned}"
                            )
            if (
                "upstream-watchdog" in hooks_data
                and "harness-gate" in hooks_data
                and not seen_missing
                and not uw_schema_invalid
                and not hg_schema_invalid
                and not hooks_disabled
            ):
                infos.append("Native lifecycle hooks ('upstream-watchdog' & 'harness-gate') are registered in hooks.json.")
    elif root.is_dir():
        repair_hint = _repair_command_hint()
        has_harness_tree = (
            (root / "skills").is_dir()
            or (root / "agents").is_dir()
            or (state_dir() / "install_receipt.json").is_file()
        )
        if has_harness_tree:
            warnings.append(f"Lifecycle hooks configuration {hooks_file} is missing; native hooks are inactive (run {repair_hint}).")
        else:
            infos.append(f"Lifecycle hooks configuration {hooks_file} is not present; native hooks are inactive (run {repair_hint}).")

    strikes_file = state_dir() / "hook_strikes.json"
    if strikes_file.is_file():
        try:
            strikes = json.loads(strikes_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            strikes = None
        if not isinstance(strikes, dict):
            warnings.append(f"Stop-hook circuit-breaker ledger {strikes_file} is corrupt or not a JSON object.")
        else:
            tripped: List[str] = []
            malformed_strikes = False
            for k, v in strikes.items():
                if not isinstance(v, dict):
                    malformed_strikes = True
                    continue
                try:
                    if (
                        bool(v.get("tripped"))
                        or int(v.get("count", 0) or 0) >= 3
                        or int(v.get("total_strikes", 0) or 0) >= 5
                    ):
                        tripped.append(str(k))
                except (TypeError, ValueError):
                    malformed_strikes = True
            if malformed_strikes:
                warnings.append(f"Stop-hook circuit-breaker ledger {strikes_file} contains malformed strike count(s).")
            if tripped:
                warnings.append(
                    f"Stop-hook circuit breaker reached max strikes (>= 3) for {len(tripped)} session(s) in {strikes_file}."
                )

    receipt_file = state_dir() / "install_receipt.json"
    if receipt_file.is_file():
        try:
            receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            receipt = None
        if not isinstance(receipt, dict):
            warnings.append(f"Install receipt {receipt_file} is corrupt or not a JSON object.")
        else:
            installed_entries = receipt.get("installed")
            if installed_entries is not None and not isinstance(installed_entries, list):
                warnings.append(f"Install receipt {receipt_file} field 'installed' is not a JSON list.")
            installed_ver = receipt.get("version")
            if installed_ver and str(installed_ver) != str(__version__):
                warnings.append(
                    f"Install receipt version ({installed_ver}) in {receipt_file} does not match active Guard version ({__version__})."
                )

    upstream_file = state_dir() / "upstream_state.json"
    if upstream_file.is_file():
        try:
            upstream_data = json.loads(upstream_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            upstream_data = None
        if not isinstance(upstream_data, dict):
            warnings.append(f"Upstream watchdog state file {upstream_file} is corrupt or not a JSON object.")
        else:
            if "tracked_repositories" in upstream_data and not isinstance(upstream_data.get("tracked_repositories"), dict):
                warnings.append(
                    f"Upstream watchdog state file {upstream_file} field 'tracked_repositories' is not a JSON object."
                )
            if "pending_repo_updates" in upstream_data and not isinstance(upstream_data.get("pending_repo_updates"), dict):
                warnings.append(
                    f"Upstream watchdog state file {upstream_file} field 'pending_repo_updates' is not a JSON object."
                )
            if (
                "known_placeholder_models" in upstream_data
                and upstream_data.get("known_placeholder_models") is not None
                and not isinstance(upstream_data.get("known_placeholder_models"), dict)
            ):
                warnings.append(
                    f"Upstream watchdog state file {upstream_file} field 'known_placeholder_models' is not a JSON object."
                )
            if (
                "model_compaction_ceilings" in upstream_data
                and upstream_data.get("model_compaction_ceilings") is not None
                and not isinstance(upstream_data.get("model_compaction_ceilings"), dict)
            ):
                warnings.append(
                    f"Upstream watchdog state file {upstream_file} field 'model_compaction_ceilings' is not a JSON object."
                )
            if upstream_data.get("last_audit_failed"):
                warnings.append(f"Last upstream repository audit failed in {upstream_file}; check network/rate-limit status.")

    # Warn if both legacy GEMINI.md and canonical rules/antigravity-constitution.md coexist (App/CLI double-load).
    legacy_gemini = root / "GEMINI.md"
    canonical_rule = root / "rules" / "antigravity-constitution.md"
    has_legacy_gemini = legacy_gemini.is_file() or os.path.islink(legacy_gemini)
    has_canonical_rule = canonical_rule.is_file() or os.path.islink(canonical_rule)
    if has_legacy_gemini and has_canonical_rule:
        repair_hint = _repair_command_hint()
        warnings.append(
            f"Global constitution exists in both {legacy_gemini} and {canonical_rule}; Antigravity App/CLI "
            f"will load both cumulatively (double-loading). Remove legacy GEMINI.md or re-run {repair_hint}."
        )

    # Check for unmanaged top-level ~/.gemini/GEMINI.md or ~/.gemini/AGENTS.md shadowing ~/.gemini/config/
    if root.name == "config" and root.parent.name == ".gemini":
        active_const = canonical_rule if has_canonical_rule else legacy_gemini
        for top_md_name in ("GEMINI.md", "AGENTS.md"):
            top_md = root.parent / top_md_name
            if top_md.is_file() or os.path.islink(top_md):
                warnings.append(
                    f"Top-level {top_md} exists alongside {root} and may shadow or duplicate global rules in "
                    f"{active_const}."
                )
    _check_native_deny_rules(root, infos, warnings=warnings)
    _check_workspace_hooks_collision(root, warnings)


def _check_workspace_hooks_collision(ws_root: Path, warnings: List[str]) -> None:
    """Warns if `<ws_root>/.agents/hooks.json` defines or overrides `harness-gate` or `upstream-watchdog`."""
    for rel_ws_hooks in (".agents/hooks.json", ".agent/hooks.json", "_agents/hooks.json", "_agent/hooks.json"):
        ws_hooks_file = ws_root / rel_ws_hooks
        if ws_hooks_file.is_file():
            try:
                ws_hooks_data = json.loads(ws_hooks_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                warnings.append(
                    f"Workspace lifecycle hooks file {rel_ws_hooks} ({ws_hooks_file}) is not a valid JSON object."
                )
                continue
            if isinstance(ws_hooks_data, dict):
                colliding_keys = [k for k in ("harness-gate", "upstream-watchdog") if k in ws_hooks_data]
                if colliding_keys:
                    warnings.append(
                        f"Workspace lifecycle hooks file {rel_ws_hooks} ({ws_hooks_file}) defines {colliding_keys}, which may "
                        "override or disable global Antigravity Harness lifecycle hooks."
                    )


def _repair_command_hint() -> str:
    has_install_py = (Path(__file__).resolve().parent.parent / "install.py").is_file()
    if has_install_py and not os.environ.get("ANTIGRAVITY_SHARE_DIR"):
        return "'python3 install.py'"
    return "'agy-guard init'"


def _is_home_or_ancestor(path: Path) -> bool:
    try:
        resolved = path.resolve()
        home_resolved = Path.home().resolve()
    except OSError:
        return False
    return resolved == home_resolved or home_resolved.is_relative_to(resolved)


def diagnose(env: AgentEnvironment, registry: EnvironmentRegistry, sentinel_active: Optional[bool] = None) -> DoctorReport:
    """Runs every read-only health check for `env`. `sentinel_active` may be injected by callers/tests."""
    root = env.get_root()
    monitor = FileIntegrityMonitor.for_environment(env, os_adapter=registry.os_adapter)
    result = DoctorReport(env=env, root=root, monitor=monitor, issues=registry.protection_issues(env), report=monitor.verify())
    warnings, infos = result.warnings, result.infos

    if not env.is_global:
        if not root.exists():
            warnings.append(
                f"Workspace root {root} for environment '{env.id}' does not exist "
                f"(remove stale entry with 'agy-guard env remove {env.id}')."
            )
        elif _is_home_or_ancestor(root):
            warnings.append(
                f"Non-global environment '{env.id}' is rooted at home/ancestor directory {root} rather than a project workspace "
                f"(review or remove with 'agy-guard env remove {env.id}')."
            )
        else:
            _check_workspace_hooks_collision(root, warnings)

    if result.issues:
        warnings.append(f"Governance scope is not fully write-protected ({len(result.issues)} issue(s)); first: {result.issues[0]}")
    if not result.report.is_intact:
        warnings.append(f"Integrity: {result.report.summary()}")
    if not monitor.is_isolated:
        warnings.append(f"Baseline is stored inside the protected tree ({monitor.state_file}).")
    legacy_baseline = root / ".guard_integrity.json"
    if legacy_baseline.exists():
        warnings.append(f"Legacy baseline {legacy_baseline} is no longer used; remove it after 'agy-guard rebaseline'.")
    legacy_snaps = root / ".guard_snapshots"
    if legacy_snaps.exists():
        warnings.append(
            f"Legacy snapshots in {legacy_snaps} may contain copies of config.json (permission grants, tokens). "
            f"Review and delete them manually."
        )
    moved_legacy = state_dir() / "legacy"
    if moved_legacy.is_dir() and any(moved_legacy.iterdir()):
        warnings.append(
            f"Legacy Guard data moved out of the config tree by the installer is kept in {moved_legacy}; "
            f"it may contain copies of config.json (tokens). Delete it once reviewed."
        )
    backups = sorted(p.name for p in root.glob("backup_*"))
    if backups:
        warnings.append(f"Installer backups inside the config tree: {', '.join(backups)} (move them out).")
    for p in env.get_governance_paths(existing_only=True):
        if os.path.islink(p):
            repair_hint = _repair_command_hint()
            warnings.append(
                f"{p.name} is a symlink (symlink installs cannot be locked); reinstall in copy mode with {repair_hint}."
            )
            break
    writable_sources = set()
    for p in env.get_governance_paths(existing_only=True):
        writable_sources.update(world_writable_ancestors(p))
    if writable_sources:
        warnings.append(f"World-writable locations hold governance content: {', '.join(sorted(writable_sources)[:5])}")
    if env.is_global:
        config_file = root / "config.json"
        stats = grant_statistics(config_file)
        if config_file.is_file() and stats is None:
            warnings.append(f"Antigravity configuration {config_file} is corrupt or not a JSON object.")
        if stats and (stats["governance_writes"] or stats["secret_like"]):
            warnings.append(
                f"Antigravity permission grants: {stats['total']} total, {stats['governance_writes']} persistent write grant(s) "
                f"to governance paths, {stats['secret_like']} containing secret-like values, {stats['unsandboxed']} unsandboxed. "
                f"Review them in Antigravity settings and rotate any exposed tokens."
            )
        _check_hooks_and_runtime_state(root, warnings, infos)
        _check_plugins_symlinks(root, warnings)
        _check_hybrid_plugins(root, warnings, infos)
        missing_ws: List[str] = []
        home_ws: List[str] = []
        for other in registry.list_environments():
            if other.is_global:
                continue
            other_root = other.get_root()
            if not other_root.exists():
                missing_ws.append(f"{other.id} ({other_root})")
            elif _is_home_or_ancestor(other_root):
                home_ws.append(f"{other.id} ({other_root})")
            else:
                _check_workspace_hooks_collision(other_root, warnings)
        if missing_ws:
            warnings.append(
                f"Registered environment(s) point to missing workspace directories: {', '.join(missing_ws)} "
                f"(clean up with 'agy-guard env remove <id>')."
            )
        if home_ws:
            warnings.append(
                f"Non-global workspace environment(s) are rooted at home/ancestor directory: {', '.join(home_ws)} "
                f"(review or remove with 'agy-guard env remove <id>')."
            )
    watcher_log = state_dir() / "logs" / "lease-watcher.log"
    if watcher_log.is_file():
        try:
            tail = watcher_log.read_text(encoding="utf-8", errors="replace")[-4000:]
        except OSError:
            tail = ""
        if "RELOCK FAILED" in tail or "Traceback" in tail:
            warnings.append(f"The auto-relock watcher reported errors recently; see {watcher_log}.")
    if sentinel_active is None:
        from guard.startup import StartupManager
        sentinel_active = bool(StartupManager(root).status().get("active"))
    if not sentinel_active:
        infos.append("Boot sentinel is not enabled ('agy-guard startup enable').")
    if not load_settings().get("enabled", True):
        infos.append("Desktop notifications are disabled ('agy-guard notify enable'); security events still go to the audit log.")
    return result
