"""
porter/emitters/generic.py — Emitter for generic/unknown agent environments.
Produces clean, tool-agnostic RULES.md and CONVENTIONS.md.
"""

from __future__ import annotations

from pathlib import Path
from typing import List
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer


class GenericEmitter:
    """Exports Antigravity Harness as universal clean markdown rules."""

    @classmethod
    def emit(cls, manifest: UniversalManifest, output_dir: Path) -> List[Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        rules_path = output_dir / "RULES.md"

        const_raw = manifest.constitution.get("raw", "")
        sanitized_const = ConstitutionalSanitizer.sanitize_for_export(const_raw, target="generic")

        design_raw = manifest.design_contract.get("raw", "")
        sanitized_design = ConstitutionalSanitizer.sanitize_for_export(design_raw, target="generic")

        content = f"""# Engineering Rules & Behavioral Invariants

> Exported from Antigravity Harness v{manifest.version}
> Universal instructions applicable to any model or coding assistant.

---

## Constitution & Engineering Discipline

{sanitized_const}

---

## Design Contract & Quality Standards

{sanitized_design}
"""
        rules_path.write_text(content, encoding="utf-8")
        return [rules_path]
