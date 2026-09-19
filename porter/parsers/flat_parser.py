"""
porter/parsers/flat_parser.py — Parser for flat markdown instructions (CLAUDE.md, AGENTS.md, etc.).
"""

from __future__ import annotations

import re
from pathlib import Path
from porter.models import HarnessRule


class FlatParser:
    """Parses unstructured or flat markdown guideline files."""

    @classmethod
    def parse(cls, content: str, filename: str = "") -> HarnessRule:
        name = Path(filename).stem if filename else "external-guidelines"
        name = re.sub(r"[^a-zA-Z0-9_-]", "-", name).lower().strip("-") or "imported-guidelines"

        # Derive description from first heading or first non-empty line
        desc = ""
        for line in content.splitlines():
            line = line.strip()
            if line:
                desc = re.sub(r"^#+\s*", "", line)
                break

        if not desc:
            desc = "Imported external conventions and rules"

        return HarnessRule(
            name=name,
            description=desc,
            content=content.strip(),
            target_type="skill" if "skill" in name else "rule"
        )
