"""
porter/emitters/claude.py — Emitter for Claude Code environments.
Generates CLAUDE.md and .claude/commands/ slash command definitions.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional
from porter.manifest import ManifestEngine
from porter.models import UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer


class ClaudeEmitter:
    """Exports Antigravity Harness as a native Claude Code workspace."""

    @classmethod
    def emit(cls, manifest: UniversalManifest, output_dir: Path) -> List[Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        emitted_files: List[Path] = []

        # 1. Build CLAUDE.md
        claude_md_path = output_dir / "CLAUDE.md"
        claude_content = cls._build_claude_md(manifest)
        claude_md_path.write_text(claude_content, encoding="utf-8")
        emitted_files.append(claude_md_path)

        # 2. Build .claude/commands/
        commands_dir = output_dir / ".claude" / "commands"
        commands_dir.mkdir(parents=True, exist_ok=True)

        for skill in manifest.skills:
            name = skill.get("name")
            raw = skill.get("raw", "")
            if not name or not raw:
                continue

            cmd_content = cls._convert_skill_to_command(skill)
            cmd_path = commands_dir / f"{name}.md"
            cmd_path.write_text(cmd_content, encoding="utf-8")
            emitted_files.append(cmd_path)

        return emitted_files

    @classmethod
    def _build_claude_md(cls, manifest: UniversalManifest) -> str:
        const_raw = manifest.constitution.get("raw", "")
        sanitized_const = ConstitutionalSanitizer.sanitize_for_export(const_raw, target="claude")

        design_raw = manifest.design_contract.get("raw", "")
        sanitized_design = ConstitutionalSanitizer.sanitize_for_export(design_raw, target="claude")

        return f"""# Claude Code Engineering Guidelines

> **Exported from Antigravity Universal Harness v{manifest.version}**
> A deterministic engineering harness enforcing execution discipline, immutable test invariants, and zero context bloat.

---

## 1. Behavioral & Engineering Constitution

{sanitized_const}

---

## 2. Baseline Design Contract & Quality Filter

{sanitized_design}

---

## 3. Subagent & Auditor Topology (Run via Claude Subshells)

When evaluating critical boundaries prior to delivery, run these persona profiles in isolated sub-sessions:

- `silent-failure-hunter`: Scans for swallowed exceptions (`catch {{}}`), missing logs, and dangerous fallback returns.
- `security-boundary-verifier`: Audits authorization boundaries, injection vectors, and race conditions (TOCTOU).
- `specification-gap-auditor`: Identifies unhandled edge cases, omissions, and vague adjectives.
- `consistency-auditor`: Checks for axiomatic contradictions and circular dependencies.
- `build-error-resolver`: Isolates compiler/type failures with minimal, non-architectural diffs.

---

## 4. Slash Commands (`.claude/commands/`)
Modular capability commands have been exported to `.claude/commands/`. Run them in Claude Code via `/<command-name>`.
"""

    @classmethod
    def _convert_skill_to_command(cls, skill: Dict) -> str:
        name = skill.get("name", "skill")
        desc = skill.get("description", "")
        raw = skill.get("raw", "")

        # Strip frontmatter
        body = re.sub(r"^---\s*\n.*?\n---\s*\n", "", raw, flags=re.DOTALL).strip()
        sanitized_body = ConstitutionalSanitizer.sanitize_for_export(body, target="claude")

        return f"""# Command: /{name}

> {desc}

{sanitized_body}
"""
