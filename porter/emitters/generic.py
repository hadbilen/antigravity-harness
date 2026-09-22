"""
porter/emitters/generic.py — Generic emitter for any model or coding assistant.
Generates RULES.md plus verbatim `skills/` and `agents/` directories.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

from porter.emitters.common import Plan, commit, index_section, plan_support_tree
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer


class GenericEmitter:
    """Exports Antigravity Harness as generic Markdown rules."""

    TARGET = "generic"
    SKILLS_DIR = "skills"
    AGENTS_DIR = "agents"

    @classmethod
    def plan(cls, manifest: UniversalManifest, output_dir: Path) -> Tuple[Plan, Dict[Path, str]]:
        plan, links = plan_support_tree(manifest, output_dir / cls.SKILLS_DIR, output_dir / cls.AGENTS_DIR)
        const = ConstitutionalSanitizer.sanitize_for_export(manifest.constitution.get("raw", ""), target=cls.TARGET)
        design = ConstitutionalSanitizer.sanitize_for_export(manifest.design_contract.get("raw", ""), target=cls.TARGET)
        plan[output_dir / "RULES.md"] = f"""# Engineering Rules & Behavioral Invariants

> Exported from Antigravity Harness v{manifest.version}
> Universal instructions applicable to any model or coding assistant.

---

## Constitution & Engineering Discipline

{const}

---

## Design Contract & Quality Standards

{design}

---

{index_section(manifest, cls.SKILLS_DIR, cls.AGENTS_DIR)}
"""
        return plan, links

    @classmethod
    def emit(cls, manifest: UniversalManifest, output_dir: Path, force: bool = False) -> List[Path]:
        plan, links = cls.plan(manifest, Path(output_dir))
        return commit(plan, links, force=force)
