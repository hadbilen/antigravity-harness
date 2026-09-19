"""
porter/parsers/generic_parser.py — Auto-detecting format orchestrator.
"""

from __future__ import annotations

from pathlib import Path
from porter.models import HarnessRule
from porter.parsers.flat_parser import FlatParser
from porter.parsers.mdc_parser import MdcParser


class GenericParser:
    """Detects format automatically and parses incoming rule content."""

    @classmethod
    def parse_file(cls, path: Path) -> HarnessRule:
        content = path.read_text(encoding="utf-8", errors="ignore")
        return cls.parse_content(content, filename=path.name)

    @classmethod
    def parse_content(cls, content: str, filename: str = "") -> HarnessRule:
        if filename.endswith(".mdc") or ("globs:" in content and "---" in content[:100]):
            return MdcParser.parse(content, filename)
        return FlatParser.parse(content, filename)
