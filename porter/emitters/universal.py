"""
porter/emitters/universal.py — Emitter for open-standard AGENTS.md.
Compatible with OpenAI, Codex, DeepSeek, Copilot, and open-source models.
"""

from __future__ import annotations

from pathlib import Path
from typing import List
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer


class UniversalEmitter:
    """Exports Antigravity Harness as an open-standard AGENTS.md."""

    @classmethod
    def emit(cls, manifest: UniversalManifest, output_dir: Path) -> List[Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        agents_md_path = output_dir / "AGENTS.md"

        const_raw = manifest.constitution.get("raw", "")
        sanitized_const = ConstitutionalSanitizer.sanitize_for_export(const_raw, target="universal")

        design_raw = manifest.design_contract.get("raw", "")
        sanitized_design = ConstitutionalSanitizer.sanitize_for_export(design_raw, target="universal")

        content = f"""# Universal Engineering Harness (AGENTS.md)

> **Exported from Antigravity Universal Harness v{manifest.version}**
> A deterministic engineering harness enforcing execution discipline, immutable test invariants, and zero context bloat.

---

## 1. Behavioral & Engineering Constitution

{sanitized_const}

---

## 2. Baseline Design Contract & Quality Filter

{sanitized_design}

---

## 3. Autonomous Auditor Roles

All models and subagents working in this workspace must self-evaluate against these audit roles before claiming task completion:

- **Silent Failure Hunter:** Disallow empty catch blocks, unlogged error handling, or speculative fallbacks.
- **Security Boundary Verifier:** Proactively test authorization boundaries, injection vectors, and concurrency race conditions.
- **Specification Gap Auditor:** Identify unhandled edge cases, omitted requirements, and vague adjectives.
- **Consistency Auditor:** Check for internal architectural contradictions, broken links, or circular dependencies.
- **Build Error Resolver:** Proactively isolate TypeScript/compiler breaks with surgical diffs.
"""
        agents_md_path.write_text(content, encoding="utf-8")
        return [agents_md_path]
