"""
porter/manifest.py — Lossless Universal Canonical Manifest engine.
Ensures zero information decay across multi-hop migrations (A -> B -> C).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from porter.models import UniversalManifest


class ManifestEngine:
    """Reads, generates, and validates the canonical machine-readable harness manifest."""

    def __init__(self, harness_root: Optional[Path] = None):
        self.harness_root = harness_root or Path(__file__).resolve().parent.parent

    def build_manifest(self) -> UniversalManifest:
        """Inspects all local harness assets and compiles a complete lossless manifest."""
        try:
            from porter import __version__ as PORTER_VERSION
        except ImportError:
            PORTER_VERSION = "1.2.6"

        manifest = UniversalManifest(
            version=PORTER_VERSION,
            schema_version="1.0.0",
            generated_at=datetime.now(timezone.utc).isoformat(),
            metadata={
                "name": "antigravity-harness",
                "description": "Deterministic engineering harness, behavioral constitution, and autonomous subagent ecosystem.",
                "author": "hadbilen",
                "repository": "https://github.com/hadbilen/antigravity-harness"
            }
        )

        # 1. Ingest Constitution (GEMINI.md)
        gemini_path = self.harness_root / "GEMINI.md"
        if gemini_path.is_file():
            content = gemini_path.read_text(encoding="utf-8", errors="ignore")
            manifest.constitution = {
                "raw": content,
                "summary": "Universal Behavioral and Engineering Constitution",
                "extracted_rules": self._extract_rules_from_markdown(content)
            }

        # 2. Ingest Design Contract (DESIGN.md)
        design_path = self.harness_root / "DESIGN.md"
        if design_path.is_file():
            content = design_path.read_text(encoding="utf-8", errors="ignore")
            manifest.design_contract = {
                "raw": content,
                "palette": "zinc/slate neutral base with emerald/amber/rose functional accents",
                "contrast_standard": "WCAG AA (4.5:1 text, 3:1 UI borders)"
            }

        # 3. Ingest Autonomous Subagents (agents/*.md)
        agents_dir = self.harness_root / "agents"
        if agents_dir.is_dir():
            for agent_file in sorted(agents_dir.glob("*.md")):
                content = agent_file.read_text(encoding="utf-8", errors="ignore")
                desc_match = re.search(r"description:\s*([^\n\r]+)", content)
                desc = desc_match.group(1).strip() if desc_match else ""
                manifest.agents.append({
                    "name": agent_file.stem,
                    "description": desc,
                    "raw": content
                })

        # 4. Ingest Modular Skills (skills/*/SKILL.md and all subfiles)
        skills_dir = self.harness_root / "skills"
        if skills_dir.is_dir():
            for skill_dir in sorted(skills_dir.iterdir()):
                if skill_dir.is_dir():
                    skill_file = skill_dir / "SKILL.md"
                    if skill_file.is_file():
                        content = skill_file.read_text(encoding="utf-8", errors="ignore")
                        desc_match = re.search(r"description:\s*([^\n\r]+)", content)
                        desc = desc_match.group(1).strip() if desc_match else ""

                        # Ingest all supporting subfiles (scripts, references, assets, templates)
                        subfiles = {}
                        for sub_path in sorted(skill_dir.rglob("*")):
                            if sub_path.is_file() and sub_path != skill_file:
                                if "__pycache__" in sub_path.parts or sub_path.suffix in (".pyc", ".pyo"):
                                    continue
                                rel_sub = str(sub_path.relative_to(skill_dir)).replace("\\", "/")
                                try:
                                    sub_content = sub_path.read_text(encoding="utf-8")
                                except UnicodeDecodeError:
                                    import base64
                                    sub_content = "base64:" + base64.b64encode(sub_path.read_bytes()).decode("ascii")
                                subfiles[rel_sub] = sub_content

                        manifest.skills.append({
                            "name": skill_dir.name,
                            "description": desc,
                            "raw": content,
                            "subfiles": subfiles
                        })

        return manifest

    def save_manifest(self, output_path: Optional[Path] = None) -> Path:
        """Compiles and writes manifest to .harness/manifest.json by default."""
        target = output_path or (self.harness_root / ".harness" / "manifest.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        manifest = self.build_manifest()
        with open(target, "w", encoding="utf-8") as f:
            json.dump(manifest.to_dict(), f, indent=2, ensure_ascii=False)
        return target

    def load_manifest(self, path: Path) -> UniversalManifest:
        """Loads and parses a canonical manifest from disk."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return UniversalManifest(**data)

    def _extract_rules_from_markdown(self, content: str) -> List[Dict[str, str]]:
        """Parses numbered sections or rules from GEMINI.md."""
        rules = []
        pattern = re.compile(r"^(\d+)\.\s+\*\*([^*]+)\*\*:\s*(.+)$", re.MULTILINE)
        for match in pattern.finditer(content):
            rules.append({
                "number": match.group(1),
                "title": match.group(2).strip(),
                "summary": match.group(3).strip()[:150]
            })
        return rules
