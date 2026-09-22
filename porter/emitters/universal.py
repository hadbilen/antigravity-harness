"""
porter/emitters/universal.py — Universal AGENTS.md emitter (Codex, Copilot and others).
Writes AGENTS.md plus a verbatim `.agents/` support tree (skills with support files, agents).
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

from porter.emitters.common import Plan, commit, index_section, plan_support_tree
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer


class UniversalEmitter:
    """Exports Antigravity Harness as a universal AGENTS.md workspace."""

    TARGET = "universal"
    SKILLS_DIR = ".agents/skills"
    AGENTS_DIR = ".agents/agents"

    @classmethod
    def plan(cls, manifest: UniversalManifest, output_dir: Path) -> Tuple[Plan, Dict[Path, str]]:
        plan, links = plan_support_tree(manifest, output_dir / cls.SKILLS_DIR, output_dir / cls.AGENTS_DIR)
        const = ConstitutionalSanitizer.sanitize_for_export(manifest.constitution.get("raw", ""), target=cls.TARGET)
        design = ConstitutionalSanitizer.sanitize_for_export(manifest.design_contract.get("raw", ""), target=cls.TARGET)
        plan[output_dir / "AGENTS.md"] = f"""# Universal Engineering Harness (AGENTS.md)

> Exported from Antigravity Harness v{manifest.version}. Load a skill from `{cls.SKILLS_DIR}/`
> when its description matches the task; run the auditor roles in `{cls.AGENTS_DIR}/` as
> independent reviews (separate context where the platform supports it) before delivery.

---

## 1. Behavioral & Engineering Constitution

{const}

---

## 2. Baseline Design Contract & Quality Filter

{design}

---

{index_section(manifest, cls.SKILLS_DIR, cls.AGENTS_DIR)}
"""
        return plan, links

    @classmethod
    def emit(cls, manifest: UniversalManifest, output_dir: Path, force: bool = False) -> List[Path]:
        plan, links = cls.plan(manifest, Path(output_dir))
        return commit(plan, links, force=force)
