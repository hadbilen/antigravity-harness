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

from porter.frontmatter import frontmatter_description
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


class ManifestEngine:
    """Reads, generates, and validates the canonical machine-readable harness manifest."""

    def __init__(self, harness_root: Optional[Path] = None):
        self.harness_root = Path(harness_root) if harness_root else Path(__file__).resolve().parent.parent
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
                "name": "antigravity-harness",
                "description": "Engineering harness, behavioral constitution, and auditor subagent ecosystem.",
                "author": "hadbilen",
                "repository": "https://github.com/hadbilen/antigravity-harness",
            },
        )

        gemini_path = self.harness_root / "GEMINI.md"
        if gemini_path.is_file():
            content = gemini_path.read_text(encoding="utf-8", errors="ignore")
            manifest.constitution = {
                "raw": content,
                "summary": "Universal Behavioral and Engineering Constitution",
                "extracted_rules": self._extract_rules_from_markdown(content),
            }

        design_path = self.harness_root / "DESIGN.md"
        if design_path.is_file():
            manifest.design_contract = {
                "raw": design_path.read_text(encoding="utf-8", errors="ignore"),
                "palette": "zinc/slate neutral base with emerald/amber/rose functional accents",
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

    def is_up_to_date(self, path: Optional[Path] = None) -> bool:
        """True when the committed manifest matches a fresh build (ignoring generated_at)."""
        target = Path(path) if path else (self.harness_root / ".harness" / "manifest.json")
        if not target.is_file():
            return False
        try:
            committed = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return content_digest(committed) == content_digest(self.build_manifest(deterministic=True).to_dict())

    def _extract_rules_from_markdown(self, content: str) -> List[Dict[str, str]]:
        """Parses numbered sections or rules from GEMINI.md."""
        rules = []
        pattern = re.compile(r"^(\d+)\.\s+\*\*([^*]+)\*\*:\s*(.+)$", re.MULTILINE)
        for match in pattern.finditer(content):
            rules.append({
                "number": match.group(1),
                "title": match.group(2).strip(),
                "summary": match.group(3).strip()[:150],
            })
        return rules
