"""
porter/parsers/mdc_parser.py — Parser for Cursor .mdc rule files.
Zero-dependency: uses standard library regex.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional
from porter.models import HarnessRule


class MdcParser:
    """Parses Cursor .mdc files extracting frontmatter metadata and markdown body."""

    @classmethod
    def parse(cls, content: str, filename: str = "") -> HarnessRule:
        desc = ""
        globs: List[str] = []
        body = content

        # Match YAML frontmatter between --- and ---
        fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
        if fm_match:
            frontmatter, body = fm_match.groups()
            # Extract description
            d_match = re.search(r"description:\s*['\"]?([^'\"\n\r]+)['\"]?", frontmatter)
            if d_match:
                desc = d_match.group(1).strip()

            # Extract globs
            g_match = re.search(r"globs:\s*\[(.*?)\]", frontmatter)
            if g_match:
                raw_globs = g_match.group(1)
                globs = [g.strip().strip("'\"") for g in raw_globs.split(",") if g.strip()]

        name = Path(filename).stem if filename else "cursor-rule"
        if not desc:
            first_line = body.strip().splitlines()[0] if body.strip() else ""
            desc = re.sub(r"^#+\s*", "", first_line).strip() or "Imported Cursor rule"

        return HarnessRule(
            name=name,
            description=desc,
            content=body.strip(),
            globs=globs,
            target_type="skill"
        )
