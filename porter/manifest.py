"""
porter/manifest.py — Universal Canonical Manifest engine.
Captures the constitution, design contract, every agent, every skill with all of its
support files (text verbatim, binaries base64), in-skill symlinks and executable bits, and
the portable document templates, so emitters can reproduce the harness without content loss.
Runtime state files and runtime configuration are excluded.

Schema 1.2.0 (additive over 1.1.0): skills[].executables lists the support files that carry
an executable bit; `templates` maps each portable templates/<name> to its content. Manifests
without these fields still load.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import re
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from porter.frontmatter import FrontmatterError, frontmatter_description, split_frontmatter
from porter.models import UniversalManifest

# Mutable runtime state that must never be baked into a canonical manifest.
EXCLUDED_SUBFILE_NAMES = {"upstream_state.json", ".DS_Store"}
EXCLUDED_DIR_NAMES = {"__pycache__", "node_modules", ".git"}
EXCLUDED_SUFFIXES = (".pyc", ".pyo")
# templates/ entries that are Antigravity/Guard runtime configuration, not portable documents.
EXCLUDED_TEMPLATE_NAMES = {"config.example.json"}
SCHEMA_VERSION = "1.2.0"
_EXEC_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH


def _link_target(path: Path) -> str:
    """Symlink target with '/' separators (Windows checkouts store them with backslashes)."""
    return os.readlink(path).replace(os.sep, "/")

def content_digest(manifest_dict: Dict[str, Any]) -> str:
    """Stable digest of manifest content (ignores generated_at and the digest itself)."""
    payload = {k: v for k, v in manifest_dict.items() if k not in ("generated_at",)}
    meta = dict(payload.get("metadata") or {})
    meta.pop("content_digest", None)
    payload["metadata"] = meta
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _has_constitution(root: Path) -> bool:
    return (root / "GEMINI.md").is_file() or (root / "rules" / "plumbwork-constitution.md").is_file()


_MAX_CONSTITUTION_BYTES = 524288


def _is_verified_harness_checkout(dir_path: Path) -> bool:
    return (dir_path / ".harness" / "manifest.json").is_file() or (dir_path / "guard" / "agy_hooks.py").is_file()


def is_installed_hybrid_root(root: Path) -> bool:
    """
    Returns True when `root` is a non-checkout installed hybrid profile (contains harness packs
    under `plugins/<pack>/` or is recorded with `layout == "hybrid"` in `install_receipt.json`).
    Source checkouts (`porter.py`/`guard.py`/`install.py`) and flat profiles always return False.
    """
    root_p = Path(root)
    if (
        (root_p / "porter.py").is_file()
        or (root_p / "guard.py").is_file()
        or (root_p / "install.py").is_file()
    ):
        return False
    plugins_dir = root_p / "plugins"
    try:
        from guard.plugins import HARNESS_PLUGIN_NAMES
    except ImportError as exc:
        if plugins_dir.is_dir() and not os.path.islink(plugins_dir):
            import sys
            print(
                f"[WARN] Could not import guard.plugins while inspecting {plugins_dir} ({exc}); "
                "hybrid root detection degraded.",
                file=sys.stderr,
            )
        return False

    try:
        if plugins_dir.is_dir() and not os.path.islink(plugins_dir):
            for pack in HARNESS_PLUGIN_NAMES:
                pack_dir = plugins_dir / pack
                if pack_dir.is_dir() and not os.path.islink(pack_dir):
                    return True
    except OSError:
        pass

    try:
        from guard.paths import state_dir

        receipt_file = state_dir() / "install_receipt.json"
        if receipt_file.is_file() and not os.path.islink(receipt_file):
            raw = _read_bounded_regular_file(receipt_file)
            if raw:
                rdata = json.loads(raw)
                if isinstance(rdata, dict) and isinstance(rdata.get("target"), str) and rdata["target"].strip():
                    if Path(os.path.expanduser(rdata["target"].strip())).resolve() == root_p.resolve():
                        if str(rdata.get("layout") or "").strip().lower() == "hybrid":
                            return True
                        rec_plugs = rdata.get("installed_plugins")
                        if isinstance(rec_plugs, list) and any(
                            isinstance(p, str) and p in HARNESS_PLUGIN_NAMES for p in rec_plugs
                        ):
                            return True
    except (ImportError, OSError, ValueError, RuntimeError) as exc:
        import sys
        print(f"[WARN] Could not evaluate install receipt for hybrid detection ({exc}).", file=sys.stderr)
    return False


def _read_bounded_regular_file(path: Path, max_bytes: int = _MAX_CONSTITUTION_BYTES) -> Optional[str]:
    import stat

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        if os.path.islink(path):
            return None
        fd = os.open(str(path), flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            raw = fh.read(max_bytes + 1)
        if len(raw) > max_bytes:
            return None
        return raw.decode("utf-8", errors="ignore")
    except OSError:
        return None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _read_constitution_text(root: Path) -> Optional[str]:
    gemini_path = root / "GEMINI.md"
    if gemini_path.is_file():
        return gemini_path.read_text(encoding="utf-8", errors="ignore")
    rule_path = root / "rules" / "plumbwork-constitution.md"
    if not rule_path.is_file():
        return None
    raw = rule_path.read_text(encoding="utf-8", errors="ignore")
    try:
        _, body = split_frontmatter(raw)
    except FrontmatterError:
        body = raw
    cleaned = body.lstrip("\r\n")
    m_inc = re.fullmatch(r"@\[[^\]]+\]\(([^)]+)\)\s*", cleaned)
    if m_inc:
        inc_raw = m_inc.group(1).strip()
        inc_path = Path(inc_raw).expanduser()
        if not inc_path.is_absolute():
            inc_path = rule_path.parent / inc_path
        if os.path.islink(inc_path) or inc_path.name != "GEMINI.md":
            return None
        try:
            inc_resolved = inc_path.resolve(strict=True)
            root_resolved = root.resolve()
        except OSError:
            return None
        allowed = False
        try:
            inc_resolved.relative_to(root_resolved)
            allowed = True
        except ValueError:
            allowed = _is_verified_harness_checkout(inc_resolved.parent)
        if not allowed:
            return None
        return _read_bounded_regular_file(inc_resolved)
    return cleaned


def default_harness_root(fallback: Optional[Path] = None) -> Path:
    """Returns `fallback` (or repo root) if it contains constitution + skills/, else config_dir() or /usr/share/plumbwork."""
    root = Path(fallback).resolve() if fallback else Path(__file__).resolve().parent.parent
    if (root / "skills").is_dir() and _has_constitution(root):
        return root
    try:
        from guard.paths import config_dir
        cfg = config_dir()
    except ImportError:
        cfg_env = (os.environ.get("ANTIGRAVITY_CONFIG_DIR") or "").strip()
        cfg = (Path(cfg_env).expanduser() if cfg_env else Path.home() / ".gemini" / "config").resolve()
    if (cfg / "skills").is_dir() and _has_constitution(cfg):
        return cfg
    env_share = os.environ.get("PLUMBWORK_SHARE_DIR", "").strip()
    share_cands = []
    if env_share:
        share_cands.append(Path(env_share).expanduser())
    share_cands.extend([
        root.parent.parent / "share" / "plumbwork",
        Path(__file__).resolve().parent.parent.parent.parent / "share" / "plumbwork",
        Path("/usr/share/plumbwork"),
    ])
    for share_cand in share_cands:
        if (share_cand / "skills").is_dir() and _has_constitution(share_cand):
            return share_cand.resolve()
    return cfg


class ManifestEngine:
    """Reads, generates, and validates the canonical machine-readable harness manifest."""

    def __init__(self, harness_root: Optional[Path] = None):
        self.harness_root = Path(harness_root) if harness_root else default_harness_root()
        self._index_executables: Optional[Set[str]] = None
        self._index_loaded = False

    def _git_index_executables(self) -> Optional[Set[str]]:
        """Paths (root-relative, '/'-separated) recorded with mode 100755 in the git index, or None."""
        if not self._index_loaded:
            self._index_loaded = True
            try:
                out = subprocess.run(["git", "-C", str(self.harness_root), "ls-files", "-s", "-z", "--", "skills"],
                                     capture_output=True, timeout=30, check=True).stdout
            except (OSError, subprocess.SubprocessError):
                return None
            found: Set[str] = set()
            for entry in out.split(b"\0"):
                meta, _, path = entry.partition(b"\t")
                if meta.startswith(b"100755"):
                    found.add(path.decode("utf-8", errors="surrogateescape"))
            self._index_executables = found
        return self._index_executables

    def _recorded_executables(self) -> Set[str]:
        """Executables recorded by the committed manifest (last resort where the OS has no exec bit)."""
        try:
            data = json.loads((self.harness_root / ".harness" / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return set()
        return {f"skills/{s.get('name')}/{rel}" for s in data.get("skills") or [] for rel in s.get("executables") or []}

    def _is_executable(self, path: Path) -> bool:
        """
        POSIX: the file's own mode. Windows has no exec bit, so the git index (or, without git,
        the committed manifest) is consulted: the manifest content must not depend on the OS.
        """
        if os.name != "nt":
            return bool(path.stat().st_mode & _EXEC_BITS)
        rel = path.relative_to(self.harness_root).as_posix()
        index = self._git_index_executables()
        return rel in (index if index is not None else self._recorded_executables())

    @staticmethod
    def _read_subfile(path: Path) -> str:
        data = path.read_bytes()
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return "base64:" + base64.b64encode(data).decode("ascii")

    def _collect_skill_files(self, skill_dir: Path, skill_file: Path) -> Dict[str, Any]:
        subfiles: Dict[str, str] = {}
        links: Dict[str, str] = {}
        executables: List[str] = []
        for dirpath, dirnames, filenames in os.walk(skill_dir, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIR_NAMES)
            base = Path(dirpath)
            for d in list(dirnames):
                if (base / d).is_symlink():
                    links[(base / d).relative_to(skill_dir).as_posix()] = _link_target(base / d)
            for name in sorted(filenames):
                path = base / name
                rel = path.relative_to(skill_dir).as_posix()
                if path == skill_file or name in EXCLUDED_SUBFILE_NAMES or name.endswith(EXCLUDED_SUFFIXES):
                    continue
                if path.is_symlink():
                    links[rel] = _link_target(path)
                    continue
                subfiles[rel] = self._read_subfile(path)
                if self._is_executable(path):
                    executables.append(rel)
        return {"subfiles": subfiles, "links": links, "executables": sorted(executables)}

    def _collect_templates(self) -> Dict[str, str]:
        """Portable document templates (templates/*), excluding runtime configuration and symlinks."""
        templates: Dict[str, str] = {}
        tdir = self.harness_root / "templates"
        if tdir.is_dir():
            for path in sorted(tdir.iterdir()):
                if path.name in EXCLUDED_TEMPLATE_NAMES or path.is_symlink() or not path.is_file():
                    continue
                templates[path.name] = self._read_subfile(path)
        return templates

    def build_manifest(self, deterministic: bool = False) -> UniversalManifest:
        """Inspects all local harness assets and compiles the manifest."""
        from porter import __version__ as PORTER_VERSION

        manifest = UniversalManifest(
            version=PORTER_VERSION,
            schema_version=SCHEMA_VERSION,
            generated_at="" if deterministic else datetime.now(timezone.utc).isoformat(),
            metadata={
                "name": "plumbwork",
                "description": "Engineering harness, behavioral constitution, and auditor subagent ecosystem.",
                "author": "tozhax",
                "repository": "https://github.com/tozhax/plumbwork",
            },
        )

        constitution_content = _read_constitution_text(self.harness_root)
        if constitution_content is not None:
            manifest.constitution = {
                "raw": constitution_content,
                "summary": "Universal Behavioral and Engineering Constitution",
                "extracted_rules": self._extract_rules_from_markdown(constitution_content),
            }

        design_path = self.harness_root / "DESIGN.md"
        if design_path.is_file():
            manifest.design_contract = {
                "raw": design_path.read_text(encoding="utf-8", errors="ignore"),
                "palette": "zinc/slate neutral base with #2563EB (Cobalt Blue) primary and emerald/amber/rose functional accents",
                "contrast_standard": "WCAG AA (4.5:1 text, 3:1 UI borders)",
            }

        agents_dir = self.harness_root / "agents"
        if agents_dir.is_dir():
            for agent_file in sorted(agents_dir.glob("*.md")):
                content = agent_file.read_text(encoding="utf-8", errors="ignore")
                manifest.agents.append({
                    "name": agent_file.stem,
                    "description": frontmatter_description(content),
                    "raw": content,
                })

        skills_dir = self.harness_root / "skills"
        if skills_dir.is_dir():
            for skill_dir in sorted(skills_dir.iterdir()):
                skill_file = skill_dir / "SKILL.md"
                if not skill_dir.is_dir() or not skill_file.is_file():
                    continue
                content = skill_file.read_text(encoding="utf-8", errors="ignore")
                files = self._collect_skill_files(skill_dir, skill_file)
                manifest.skills.append({
                    "name": skill_dir.name,
                    "description": frontmatter_description(content),
                    "raw": content,
                    "subfiles": files["subfiles"],
                    "links": files["links"],
                    "executables": files["executables"],
                })

        manifest.templates = self._collect_templates()
        manifest.metadata["content_digest"] = content_digest(manifest.to_dict())
        return manifest

    def save_manifest(self, output_path: Optional[Path] = None, deterministic: bool = False) -> Path:
        """Compiles and writes the manifest to .harness/manifest.json by default."""
        if is_installed_hybrid_root(self.harness_root):
            raise ValueError(
                f"Refusing to regenerate canonical .harness/manifest.json from installed hybrid profile "
                f"'{self.harness_root}' (only 14 core skills sit under skills/). Run 'python3 porter.py manifest' "
                "from the canonical source checkout, or refresh installed assets via 'python3 install.py --plugins' / "
                "'plumb-guard init --plugins'."
            )
        target = Path(output_path) if output_path else (self.harness_root / ".harness" / "manifest.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        manifest = self.build_manifest(deterministic=deterministic)
        with open(target, "w", encoding="utf-8", newline="\n") as f:
            json.dump(manifest.to_dict(), f, indent=2, ensure_ascii=False)
            f.write("\n")
        return target

    def load_manifest(self, path: Path) -> UniversalManifest:
        """Loads a canonical manifest (older schemas load; unknown top-level keys are ignored)."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        known = {f.name for f in dataclasses.fields(UniversalManifest)}
        return UniversalManifest(**{k: v for k, v in data.items() if k in known})

    def _is_hybrid_up_to_date(self, committed: Dict[str, Any], *, validate_packs: bool = True) -> bool:
        """
        Forward-verifies an installed hybrid profile against canonical `.harness/manifest.json`
        without any inverse-rewriter: core files are forward-transformed with
        `rewrite_core_for_hybrid()` and compared byte-for-byte, and all 4 harness packs are
        verified via `PLUGIN_CATALOG`, `validate_plugin_dir()`, `rewrite_plugin_markdown()`,
        exact `spec.extra_files` parity, and exact file-set / executable-bit equality.
        """
        if not isinstance(committed, dict):
            return False
        meta = committed.get("metadata")
        if isinstance(meta, dict) and isinstance(meta.get("content_digest"), str) and meta["content_digest"]:
            if meta["content_digest"] != content_digest(committed):
                return False

        from guard.plugins import (
            PLUGIN_CATALOG,
            PLUGIN_OWNED_SKILL_SLUGS,
            _TEXT_LF_SUFFIXES,
            _is_plugin_script_path,
            _normalize_lf,
            rewrite_core_for_hybrid,
            rewrite_plugin_markdown,
            validate_plugin_dir,
        )

        def _expected_core_bytes(raw_text: str, rel_path: str) -> bytes:
            rewritten = rewrite_core_for_hybrid(raw_text, rel_path)
            if rewritten != raw_text:
                return rewritten.replace("\r\n", "\n").encode("utf-8")
            return raw_text.encode("utf-8")

        # 1. Constitution
        comm_const = (committed.get("constitution") or {}).get("raw")
        if not isinstance(comm_const, str) or not comm_const:
            return False
        actual_const = _read_constitution_text(self.harness_root)
        if actual_const is None or actual_const.encode("utf-8") != _expected_core_bytes(comm_const, "GEMINI.md"):
            return False

        # 2. Design contract
        comm_design = (committed.get("design_contract") or {}).get("raw")
        if not isinstance(comm_design, str) or not comm_design:
            return False
        design_path = self.harness_root / "DESIGN.md"
        if not design_path.is_file() or os.path.islink(design_path):
            return False
        try:
            if design_path.read_bytes() != _expected_core_bytes(comm_design, "DESIGN.md"):
                return False
        except OSError:
            return False

        # 3. Agents
        for agent in committed.get("agents") or []:
            if not isinstance(agent, dict):
                return False
            a_name = agent.get("name")
            a_raw = agent.get("raw")
            if not isinstance(a_name, str) or not a_name or not isinstance(a_raw, str):
                return False
            a_path = self.harness_root / "agents" / f"{a_name}.md"
            if not a_path.is_file():
                return False
            try:
                if a_path.read_bytes() != _expected_core_bytes(a_raw, f"agents/{a_name}.md"):
                    return False
            except OSError:
                return False

        # 4. 14 Core Skills (and ensure zero shadowing copies of the 6 plugin-owned skills in skills/)
        committed_plugin_skills: Dict[str, Dict[str, Any]] = {}
        for skill in committed.get("skills") or []:
            if not isinstance(skill, dict):
                return False
            s_name = skill.get("name")
            s_raw = skill.get("raw")
            if not isinstance(s_name, str) or not s_name or not isinstance(s_raw, str):
                return False
            if s_name in PLUGIN_OWNED_SKILL_SLUGS:
                committed_plugin_skills[s_name] = skill
                if os.path.lexists(self.harness_root / "skills" / s_name):
                    return False
                continue
            s_dir = self.harness_root / "skills" / s_name
            s_file = s_dir / "SKILL.md"
            if not s_dir.is_dir() or not s_file.is_file():
                return False
            try:
                if s_file.read_bytes() != _expected_core_bytes(s_raw, f"skills/{s_name}/SKILL.md"):
                    return False
                actual_files = self._collect_skill_files(s_dir, s_file)
            except OSError:
                return False
            comm_subfiles = skill.get("subfiles") or {}
            if not isinstance(comm_subfiles, dict):
                return False
            if set(actual_files["subfiles"].keys()) != set(comm_subfiles.keys()):
                return False
            if actual_files["links"] != (skill.get("links") or {}):
                return False
            if actual_files["executables"] != sorted(skill.get("executables") or []):
                return False
            for rel, comm_val in comm_subfiles.items():
                actual_sub = s_dir / rel
                if not actual_sub.is_file():
                    return False
                if isinstance(comm_val, str) and comm_val.startswith("base64:"):
                    exp_bytes = base64.b64decode(comm_val[len("base64:"):])
                else:
                    exp_bytes = _expected_core_bytes(str(comm_val), f"skills/{s_name}/{rel}")
                try:
                    if actual_sub.read_bytes() != exp_bytes:
                        return False
                except OSError:
                    return False

        # 5. Templates
        comm_templates = committed.get("templates") or {}
        if not isinstance(comm_templates, dict):
            return False
        for t_name, t_val in comm_templates.items():
            t_path = self.harness_root / "templates" / t_name
            if not t_path.is_file():
                return False
            if isinstance(t_val, str) and t_val.startswith("base64:"):
                exp_t = base64.b64decode(t_val[len("base64:"):])
            else:
                exp_t = _expected_core_bytes(str(t_val), f"templates/{t_name}")
            try:
                if t_path.read_bytes() != exp_t:
                    return False
            except OSError:
                return False

        # 6. All 4 Plugin Packs via PLUGIN_CATALOG + validate_plugin_dir() + exact file-set, extra_files & skill parity
        plugins_dir = self.harness_root / "plugins"
        if os.path.islink(plugins_dir) or not plugins_dir.is_dir():
            return False
        for pack_name, spec in PLUGIN_CATALOG.items():
            pack_dir = plugins_dir / pack_name
            if os.path.islink(pack_dir) or not pack_dir.is_dir():
                return False
            if validate_packs:
                val = validate_plugin_dir(pack_dir, expected_pack=pack_name)
                if not val.ok:
                    return False
            expected_pack_files: set[str] = {"plugin.json", "README.md", "LICENSE", "assets/logo.svg"}
            if spec.third_party_upstreams:
                expected_pack_files.add("THIRD_PARTY_NOTICES.md")
            if spec.mcp_server_name:
                expected_pack_files.add("mcp_config.json")
            for src_rel, dst_rel in spec.extra_files:
                expected_pack_files.add(dst_rel)
                extra_path = pack_dir / dst_rel
                if os.path.islink(extra_path) or not extra_path.is_file():
                    return False
                if src_rel == "DESIGN.md":
                    src_raw = comm_design
                elif src_rel.startswith("templates/"):
                    t_key = src_rel[len("templates/"):]
                    if t_key not in comm_templates:
                        return False
                    src_raw = comm_templates[t_key]
                else:
                    return False
                if isinstance(src_raw, str) and src_raw.startswith("base64:"):
                    exp_extra = base64.b64decode(src_raw[len("base64:"):])
                elif dst_rel.lower().endswith(".md"):
                    exp_extra = rewrite_plugin_markdown(str(src_raw), pack_name, dst_rel).encode("utf-8")
                elif Path(dst_rel).suffix.lower() in _TEXT_LF_SUFFIXES:
                    exp_extra = _normalize_lf(str(src_raw)).encode("utf-8")
                else:
                    exp_extra = str(src_raw).encode("utf-8")
                try:
                    if extra_path.read_bytes() != exp_extra:
                        return False
                except OSError:
                    return False
            for slug in spec.skills:
                comm_skill = committed_plugin_skills.get(slug)
                if comm_skill is None:
                    return False
                p_skill_dir = pack_dir / "skills" / slug
                p_skill_md = p_skill_dir / "SKILL.md"
                if os.path.islink(p_skill_md) or not p_skill_md.is_file():
                    return False
                expected_pack_files.add(f"skills/{slug}/SKILL.md")
                exp_md = rewrite_plugin_markdown(
                    str(comm_skill.get("raw") or ""), pack_name, f"skills/{slug}/SKILL.md"
                ).encode("utf-8")
                try:
                    if p_skill_md.read_bytes() != exp_md:
                        return False
                except OSError:
                    return False
                for rel, comm_val in (comm_skill.get("subfiles") or {}).items():
                    p_sub = p_skill_dir / rel
                    if os.path.islink(p_sub) or not p_sub.is_file():
                        return False
                    plugin_rel = f"skills/{slug}/{rel}"
                    expected_pack_files.add(plugin_rel)
                    if isinstance(comm_val, str) and comm_val.startswith("base64:"):
                        exp_sub = base64.b64decode(comm_val[len("base64:"):])
                    elif rel.lower().endswith(".md"):
                        exp_sub = rewrite_plugin_markdown(str(comm_val), pack_name, plugin_rel).encode("utf-8")
                    elif Path(rel).suffix.lower() in _TEXT_LF_SUFFIXES:
                        exp_sub = _normalize_lf(str(comm_val)).encode("utf-8")
                    else:
                        exp_sub = str(comm_val).encode("utf-8")
                    try:
                        if p_sub.read_bytes() != exp_sub:
                            return False
                    except OSError:
                        return False
            # Enforce exact file-set equality and executable-bit parity across the pack tree
            actual_pack_files: set[str] = set()
            for dirpath, dirnames, filenames in os.walk(pack_dir, followlinks=False):
                cur_d = Path(dirpath)
                for dn in dirnames:
                    if os.path.islink(cur_d / dn):
                        return False
                for fn in filenames:
                    fp = cur_d / fn
                    if os.path.islink(fp) or not fp.is_file():
                        return False
                    rel_p = fp.relative_to(pack_dir).as_posix()
                    actual_pack_files.add(rel_p)
                    if os.name != "nt":
                        try:
                            is_exec = bool(os.lstat(fp).st_mode & 0o111)
                        except OSError:
                            return False
                        if is_exec != _is_plugin_script_path(rel_p):
                            return False
            if actual_pack_files != expected_pack_files:
                return False
        return True

    def is_up_to_date(
        self,
        path: Optional[Path] = None,
        manifest: Optional[UniversalManifest] = None,
        *,
        validate_packs: bool = True,
    ) -> bool:
        """True when the committed manifest matches a fresh build (or forward-verified hybrid install)."""
        target = Path(path) if path else (self.harness_root / ".harness" / "manifest.json")
        if not target.is_file():
            return False
        try:
            committed = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        if is_installed_hybrid_root(self.harness_root):
            return self._is_hybrid_up_to_date(committed, validate_packs=validate_packs)
        fresh = manifest if manifest is not None else self.build_manifest(deterministic=True)
        return content_digest(committed) == content_digest(fresh.to_dict())

    def _extract_rules_from_markdown(self, content: str) -> List[Dict[str, str]]:
        """Parses numbered sections or rules from GEMINI.md."""
        rules = []
        # Accepts both "1. **Title**: text" and the constitution's "1. **Title:** text" form.
        pattern = re.compile(r"^\s*(\d+)\.\s+\*\*([^*]+?):?\*\*:?\s*(.+)$", re.MULTILINE)
        for match in pattern.finditer(content):
            rules.append({
                "number": match.group(1),
                "title": match.group(2).strip(),
                "summary": match.group(3).strip()[:150],
            })
        return rules
