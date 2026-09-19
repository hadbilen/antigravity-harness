"""
porter — Universal Bidirectional AI Agent Bridge, Suitability Analyzer, and Transpiler.
Part of Antigravity Harness. Zero external dependencies.
"""

from porter.analyzer import SuitabilityAnalyzer
from porter.manifest import ManifestEngine
from porter.models import HarnessAgent, HarnessRule, HarnessSkill, SuitabilityReport, UniversalManifest
from porter.sanitizer import ConstitutionalSanitizer

__version__ = "1.2.3"

__all__ = [
    "SuitabilityAnalyzer",
    "ConstitutionalSanitizer",
    "ManifestEngine",
    "HarnessRule",
    "HarnessSkill",
    "HarnessAgent",
    "SuitabilityReport",
    "UniversalManifest",
]
