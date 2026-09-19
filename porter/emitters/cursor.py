"""
porter/emitters/cursor.py — Emitter for Cursor and Windsurf environments.
Generates .cursor/rules/*.mdc files with glob-targeting frontmatter.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer


class CursorEmitter:
    """Exports Antigravity Harness as native Cursor .mdc rules."""

    @classmethod
    def emit(cls, manifest: UniversalManifest, output_dir: Path) -> List[Path]:
        rules_dir = output_dir / ".cursor" / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        emitted_files: List[Path] = []

        # 1. 00-constitution.mdc (Always applied globally)
        const_raw = manifest.constitution.get("raw", "")
        sanitized_const = ConstitutionalSanitizer.sanitize_for_export(const_raw, target="cursor")
        const_mdc = f"""---
description: Universal Behavioral & Engineering Constitution (Test Invariants, Tier Escalation, Zero Sycophancy)
globs: ["*"]
alwaysApply: true
---

# Global Engineering Constitution

{sanitized_const}
"""
        const_path = rules_dir / "00-constitution.mdc"
        const_path.write_text(const_mdc, encoding="utf-8")
        emitted_files.append(const_path)

        # 2. 10-design-antislop.mdc (Frontend & UI only)
        design_raw = manifest.design_contract.get("raw", "")
        sanitized_design = ConstitutionalSanitizer.sanitize_for_export(design_raw, target="cursor")
        design_mdc = f"""---
description: Baseline Design Contract & Antislop Filter (WCAG AA, 5 Component States, Zero Slop)
globs: ["**/*.tsx", "**/*.jsx", "**/*.vue", "**/*.svelte", "**/*.html", "**/*.css"]
alwaysApply: false
---

# UI Design Contract & Antislop Filter

{sanitized_design}
"""
        design_path = rules_dir / "10-design-antislop.mdc"
        design_path.write_text(design_mdc, encoding="utf-8")
        emitted_files.append(design_path)

        # 3. Modular skills as .mdc rules
        for skill in manifest.skills:
            name = skill.get("name")
            desc = skill.get("description", "")
            raw = skill.get("raw", "")
            if not name or not raw:
                continue

            body = re.sub(r"^---\s*\n.*?\n---\s*\n", "", raw, flags=re.DOTALL).strip()
            sanitized_body = ConstitutionalSanitizer.sanitize_for_export(body, target="cursor")

            globs = ["*"]
            if any(k in name for k in ["ui", "design", "css", "html"]):
                globs = ["**/*.tsx", "**/*.jsx", "**/*.html", "**/*.css"]
            elif any(k in name for k in ["database", "migration", "sql"]):
                globs = ["**/*.sql", "**/prisma/**", "**/drizzle/**", "**/migrations/**"]
            elif any(k in name for k in ["test", "diagnos"]):
                globs = ["**/*.test.*", "**/*.spec.*", "**/tests/**"]

            skill_mdc = f"""---
description: {desc}
globs: {globs}
alwaysApply: false
---

# Skill: {name}

{sanitized_body}
"""
            skill_path = rules_dir / f"skill-{name}.mdc"
            skill_path.write_text(skill_mdc, encoding="utf-8")
            emitted_files.append(skill_path)

        return emitted_files
