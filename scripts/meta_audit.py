#!/usr/bin/env python3
"""
scripts/meta_audit.py — Meta-Consistency & Self-Audit Engine (GEMINI.md Rule 17)
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Uses the Python standard library; uses PyYAML for frontmatter when it is installed.

Passes:
  1  Frontmatter schema: every skill/agent parses as YAML (what Antigravity needs to load it)
  2  Cross-references: agents/templates named in GEMINI.md, relative Markdown links,
     backticked repository paths and bare *.md references resolve
  3  Mode isolation: mode skills declare an explicit mutual-exclusion section; tier
     thresholds agree across GEMINI.md and skills
  4  Porter parity: every emitter reproduces every skill, support file, link and agent
     verbatim; emitted frontmatter is valid YAML; committed manifest is current; the
     harness passes its own constitutional sanitizer
  5  CLI & documentation sync: README commands exist, README examples parse, numeric
     claims (subcommands, tests, skills, subagents) and policy names match the code
  6  Design contract: DESIGN.md "Measured Contrast Pairs" are recomputed (WCAG 2.x)

Usage:
  python3 scripts/meta_audit.py [--all] [--pass N ...] [--strict] [--json]
Exit status: 1 if any CRITICAL finding (or any WARNING with --strict), else 0.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

MODE_SKILLS = ("chisle", "procoder", "unlazy", "vibecoder")
KNOWN_EXTERNAL_MD = {
    "AGENTS.md", "CLAUDE.md", "CODEX.md", "CONVENTIONS.md", "RULES.md", "GATES.md", "HANDOFF.md",
    "tasks.md", "plan.md", "PLAN.md", "implementation_plan.md", "walkthrough.md", "SKILL.md",
    "MISTAKES.md", "GEMINI.md", "DESIGN.md", "README.md", "CHANGELOG.md", "SECURITY.md",
    "CONTRIBUTING.md", "task.md", "spec.md", "todo.md", "backlog.md", "sprint.md", "ADR.md",
    "RELEASE.md", "template.md",  # files the skills create inside the user's project
}
SKIP_DIRS = {".git", "node_modules", "export", "__pycache__", "dist", "build", ".harness"}


@dataclass
class AuditFinding:
    severity: str  # "CRITICAL", "WARNING", "INFO"
    pass_name: str
    target: str
    message: str
    suggested_fix: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


def _load_yaml_frontmatter(text: str):
    """Returns (dict, error). Prefers PyYAML (independent of the code under audit)."""
    if text.startswith("﻿"):
        text = text[1:]
    m = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", text, re.DOTALL)
    if not m:
        return None, "missing YAML frontmatter markers (---)"
    try:
        import yaml  # type: ignore

        try:
            data = yaml.safe_load(m.group(1))
        except yaml.YAMLError as e:
            return None, f"invalid YAML frontmatter: {str(e).splitlines()[0]}"
    except ImportError:
        from porter.frontmatter import FrontmatterError, parse_frontmatter_block

        try:
            data = parse_frontmatter_block(m.group(1))
        except FrontmatterError as e:
            return None, f"invalid YAML frontmatter: {e}"
    if not isinstance(data, dict):
        return None, "frontmatter is not a mapping"
    return data, None


def _luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    channels = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast_ratio(fg: str, bg: str) -> float:
    a, b = sorted((_luminance(fg), _luminance(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


class MetaAuditEngine:
    """Deterministic meta-auditor verifying the harness's own integrity and consistency."""

    def __init__(self, repo_root: Optional[Path] = None):
        self.repo_root = Path(repo_root or REPO_ROOT).resolve()
        self.findings: List[AuditFinding] = []

    def _add(self, severity: str, pass_name: str, target: str, message: str, fix: str) -> None:
        self.findings.append(AuditFinding(severity, pass_name, target, message, fix))

    def _rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.repo_root).as_posix()
        except ValueError:
            return str(path)

    def _markdown_files(self) -> List[Path]:
        files = []
        for dirpath, dirnames, filenames in os.walk(self.repo_root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            files.extend(Path(dirpath) / f for f in sorted(filenames) if f.endswith(".md"))
        return files

    def run_pass(self, number: int) -> List[AuditFinding]:
        {
            1: self.pass1_schema_validation,
            2: self.pass2_cross_references,
            3: self.pass3_directive_collision_and_mutex,
            4: self.pass4_porter_parity,
            5: self.pass5_cli_doc_sync,
            6: self.pass6_design_contract,
        }[number]()
        return self.findings

    def run_all_passes(self) -> List[AuditFinding]:
        self.findings = []
        for n in range(1, 7):
            self.run_pass(n)
        return self.findings

    # ------------------------------------------------------------------
    # Pass 1
    # ------------------------------------------------------------------
    def pass1_schema_validation(self) -> None:
        name = "Pass 1 (Schema Validation)"
        entries = []
        skills_dir = self.repo_root / "skills"
        if skills_dir.is_dir():
            for d in sorted(p for p in skills_dir.iterdir() if p.is_dir()):
                skill_file = d / "SKILL.md"
                if not skill_file.is_file():
                    self._add("CRITICAL", name, f"skills/{d.name}", f"Missing SKILL.md in skill directory '{d.name}'",
                              f"Create skills/{d.name}/SKILL.md with valid YAML frontmatter.")
                    continue
                entries.append((skill_file, d.name))
        agents_dir = self.repo_root / "agents"
        if agents_dir.is_dir():
            entries.extend((f, f.stem) for f in sorted(agents_dir.glob("*.md")))

        for path, expected in entries:
            data, err = _load_yaml_frontmatter(path.read_text(encoding="utf-8", errors="replace"))
            target = self._rel(path)
            if err:
                self._add("CRITICAL", name, target, f"Frontmatter error: {err} (the platform will not load this file)",
                          "Fix the YAML frontmatter (quote values containing ': ' or use a '>-' block).")
                continue
            if not data.get("name"):
                self._add("CRITICAL", name, target, "Frontmatter is missing required 'name' field", f"Add 'name: {expected}'.")
            elif str(data["name"]).strip() != expected:
                self._add("WARNING", name, target, f"name '{data['name']}' mismatches '{expected}'", f"Use name: {expected}")
            desc = data.get("description")
            if not isinstance(desc, str) or not desc.strip():
                self._add("WARNING", name, target, "Frontmatter has missing or empty 'description' field",
                          "Provide a descriptive summary of when to use it.")

    # ------------------------------------------------------------------
    # Pass 2
    # ------------------------------------------------------------------
    def pass2_cross_references(self) -> None:
        name = "Pass 2 (Cross-Reference Integrity)"
        agents_dir = self.repo_root / "agents"
        available_agents = {f.stem for f in agents_dir.glob("*.md")} if agents_dir.is_dir() else set()

        gemini_md = self.repo_root / "GEMINI.md"
        if gemini_md.is_file():
            content = gemini_md.read_text(encoding="utf-8", errors="ignore")
            for agent in re.findall(r"`([a-z0-9-]+)`\s+(?:subagent|auditor|agent)", content):
                if agent in ("self", "subagent", "build", "fast-path"):
                    continue
                if agent not in available_agents:
                    self._add("CRITICAL", name, "GEMINI.md",
                              f"GEMINI.md mandates dispatch of `{agent}` subagent, but agents/{agent}.md is missing.",
                              f"Create agents/{agent}.md or update the reference.")
            for tmpl in re.findall(r"templates/([a-zA-Z0-9_.-]+)", content):
                if not (self.repo_root / "templates" / tmpl).exists():
                    self._add("CRITICAL", name, "GEMINI.md", f"GEMINI.md references 'templates/{tmpl}', which does not exist.",
                              f"Create templates/{tmpl} or update the path.")

        top_dirs = {"skills", "agents", "scripts", "guard", "porter", "templates", "installers", "tests", "bin"}
        basenames = {p.name for p in self.repo_root.rglob("*") if ".git" not in p.parts}
        for md in self._markdown_files():
            text = md.read_text(encoding="utf-8", errors="ignore")
            target = self._rel(md)
            text_no_code = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
            for link in re.findall(r"\]\(([^)\s]+)\)", text_no_code):
                if re.match(r"^(https?:|mailto:|#|<)", link) or "{" in link:
                    continue
                path_part = link.split("#", 1)[0]
                if path_part and not (md.parent / path_part).exists():
                    self._add("WARNING", name, target, f"Broken relative link '{link}'", "Fix the link target or remove the link.")
            for token in set(re.findall(r"`([^`\s]+)`", text_no_code)):
                clean = token.rstrip(".,:;)")
                if any(c in clean for c in "<>*{}$~") or clean.startswith(("/", "http")):
                    continue
                head = clean.split("/", 1)[0]
                if "/" in clean and head in top_dirs and "." in clean.rsplit("/", 1)[-1]:
                    parts = md.relative_to(self.repo_root).parts
                    skill_root = self.repo_root / parts[0] / parts[1] if len(parts) > 2 and parts[0] == "skills" else md.parent
                    candidates = (self.repo_root / clean, md.parent / clean, skill_root / clean)
                    if not any(c.exists() for c in candidates):
                        self._add("WARNING", name, target, f"Referenced repository path `{clean}` does not exist",
                                  "Update the path or restore the file.")
                elif re.fullmatch(r"[\w.-]+\.md", clean) and clean not in KNOWN_EXTERNAL_MD and clean not in basenames:
                    self._add("WARNING", name, target, f"Referenced file `{clean}` does not exist anywhere in the repository",
                              "Reference the real file path (e.g. skills/<name>/SKILL.md).")

    # ------------------------------------------------------------------
    # Pass 3
    # ------------------------------------------------------------------
    def pass3_directive_collision_and_mutex(self) -> None:
        name = "Pass 3 (Directive Collision & Mutex)"
        skills_dir = self.repo_root / "skills"
        for skill in MODE_SKILLS:
            f = skills_dir / skill / "SKILL.md"
            if not f.is_file():
                continue
            content = f.read_text(encoding="utf-8", errors="ignore")
            section = re.search(r"(?ims)^#+\s*mutual exclusion[^\n]*\n(.*?)(?=^#+\s|\Z)", content)
            body = section.group(1) if section else ""
            missing = []
            if not section:
                missing.append("a '## Mutual Exclusion' section")
            else:
                if "harness" not in body:
                    missing.append("the partner skill 'harness'")
                if not re.search(r"(?i)\b(activat|trigger|exclusively|only when)", body):
                    missing.append("an activation condition")
                if not re.search(r"(?i)\b(deactivat|off only|stop|ends when)", body):
                    missing.append("a deactivation condition")
            if missing:
                self._add("WARNING", name, f"skills/{skill}/SKILL.md",
                          f"Skill '{skill}' lacks an explicit mutual exclusion barrier with 'harness' (missing {', '.join(missing)}).",
                          "Add a '## Mutual Exclusion' section naming the trigger, the deactivation and 'harness'.")

        thresholds = {}
        for rel in ("GEMINI.md", "skills/harness/SKILL.md", "skills/unlazy/SKILL.md"):
            p = self.repo_root / rel
            if p.is_file():
                m = re.search(r"(?is)tier\s*3[^\n]*?\n?.{0,300}?(?:>\s*(\d+)\s*files|\b(\d+)\+\s*files)", p.read_text(encoding="utf-8", errors="ignore"))
                if m:
                    thresholds[rel] = int(m.group(1) or m.group(2)) + (0 if m.group(1) else -1)
        if len(set(thresholds.values())) > 1:
            self._add("WARNING", name, ", ".join(thresholds),
                      f"Tier 3 file thresholds disagree: {thresholds} (as 'more than N files')",
                      "Use one threshold everywhere (GEMINI.md is the source of truth).")

    # ------------------------------------------------------------------
    # Pass 4
    # ------------------------------------------------------------------
    def pass4_porter_parity(self) -> None:
        name = "Pass 4 (Porter Parity)"
        try:
            from porter.emitters import EMITTERS
            from porter.manifest import ManifestEngine
            from porter.sanitizer import find_directives
        except Exception as e:
            self._add("CRITICAL", name, "porter", f"Porter could not be imported: {e}", "Resolve the import error.")
            return

        engine = ManifestEngine(harness_root=self.repo_root)
        manifest = engine.build_manifest(deterministic=True)
        if not manifest.constitution.get("raw"):
            self._add("CRITICAL", name, "porter/manifest.py", "Manifest failed to ingest GEMINI.md.", "Ensure GEMINI.md exists.")

        committed = self.repo_root / ".harness" / "manifest.json"
        if committed.is_file() and not engine.is_up_to_date(committed):
            self._add("CRITICAL", name, ".harness/manifest.json",
                      "Committed manifest is stale (content differs from a fresh build).",
                      "Run 'python3 porter.py manifest' and commit the result.")

        for target, emitter in EMITTERS.items():
            with tempfile.TemporaryDirectory(prefix=f"agy-parity-{target}-") as tmp:
                out = Path(tmp)
                try:
                    emitter.emit(manifest, out, force=True)
                except Exception as e:
                    self._add("CRITICAL", name, f"porter/emitters/{target}.py", f"Emitter crashed: {e}", "Fix the emitter.")
                    continue
                losses = []
                for skill in manifest.skills:
                    base = out / emitter.SKILLS_DIR / skill["name"]
                    try:
                        if (base / "SKILL.md").read_text(encoding="utf-8") != skill["raw"]:
                            losses.append(f"{skill['name']}/SKILL.md altered")
                    except OSError:
                        losses.append(f"{skill['name']}/SKILL.md missing")
                    for rel in skill.get("subfiles", {}):
                        if not (base / rel).is_file():
                            losses.append(f"{skill['name']}/{rel}")
                    for rel in skill.get("links", {}):
                        if not os.path.lexists(base / rel):
                            losses.append(f"{skill['name']}/{rel} (link)")
                for agent in manifest.agents:
                    p = out / emitter.AGENTS_DIR / f"{agent['name']}.md"
                    if not p.is_file() or p.read_text(encoding="utf-8") != agent["raw"]:
                        losses.append(f"agent {agent['name']}")
                if losses:
                    self._add("CRITICAL", name, f"porter/emitters/{target}.py",
                              f"Export to '{target}' lost {len(losses)} item(s): {', '.join(losses[:5])}",
                              "Emit every skill, support file, link and agent verbatim.")
                for f in sorted(out.rglob("*.mdc")):
                    _, err = _load_yaml_frontmatter(f.read_text(encoding="utf-8"))
                    if err:
                        self._add("CRITICAL", name, f"porter/emitters/{target}.py", f"{f.name}: {err}", "Emit frontmatter via dump_frontmatter().")

        sources = [("GEMINI.md", manifest.constitution.get("raw", "")), ("DESIGN.md", manifest.design_contract.get("raw", ""))]
        sources += [(f"skills/{s['name']}/SKILL.md", s["raw"]) for s in manifest.skills]
        sources += [(f"agents/{a['name']}.md", a["raw"]) for a in manifest.agents]
        for rel, text in sources:
            hits = find_directives(text)
            if hits:
                self._add("CRITICAL", name, rel,
                          f"Harness content trips its own sanitizer at line {hits[0].line_start + 1}: \"{hits[0].text[:70]}\"",
                          "Rephrase as an explicit prohibition or fix the sanitizer false positive.")

    # ------------------------------------------------------------------
    # Pass 5
    # ------------------------------------------------------------------
    def pass5_cli_doc_sync(self) -> None:
        name = "Pass 5 (CLI & Doc Sync)"
        readme = self.repo_root / "README.md"
        cli = self.repo_root / "guard" / "cli.py"
        if not readme.is_file() or not cli.is_file():
            return
        text = readme.read_text(encoding="utf-8", errors="ignore")
        try:
            from guard.cli import build_parser
            from guard.environment import VALID_POLICIES
        except Exception as e:
            self._add("CRITICAL", name, "guard/cli.py", f"CLI parser could not be imported: {e}", "Fix guard/cli.py.")
            return
        parser = build_parser()
        sub_action = next(a for a in parser._actions if a.__class__.__name__ == "_SubParsersAction")
        commands = set(sub_action.choices)
        public = commands - {"lease-tick"}

        for cmd in sorted(public):
            if f"agy-guard {cmd}" not in text and f"`{cmd}`" not in text:
                self._add("WARNING", name, "README.md", f"CLI subcommand '{cmd}' is not documented in README.md",
                          f"Document 'agy-guard {cmd}'.")
        workflow_line = next((l for l in text.splitlines() if "Full CLI Workflow" in l), "")
        for m in re.finditer(r"`([a-z][a-z-]+)`", workflow_line.split(":", 1)[-1]):
            if m.group(1) not in commands:
                self._add("CRITICAL", name, "README.md", f"README lists CLI command '{m.group(1)}' which does not exist",
                          "Remove it or implement it.")

        for block in re.findall(r"```(?:bash|sh|shell)?\n(.*?)```", text, re.DOTALL):
            for line in block.splitlines():
                line = line.split(" #", 1)[0].strip()
                if not line.startswith("agy-guard "):
                    continue
                argv = shlex.split(line)[1:]
                try:
                    parser.parse_args(argv)
                except SystemExit:
                    self._add("CRITICAL", name, "README.md", f"README example does not parse: `{line}`",
                              "Fix the example to match the CLI.")

        claims = {
            "subcommands": (r"\((\d+)\s+subcommands\)", len(public)),
            "tests": (r"\((\d+)\s+(?:passing\s+)?tests\)", self._count_tests()),
            "skills": (r"\b(\d+)\s+(?:modular\s+)?skills\b", self._count_dirs("skills")),
            "subagents": (r"\b(\d+)\s+(?:autonomous\s+|read-only\s+|auditor\s+)?subagents?\b", self._count_agents()),
        }
        for label, (pattern, actual) in claims.items():
            for m in re.finditer(pattern, text):
                if int(m.group(1)) != actual:
                    self._add("WARNING", name, "README.md", f"README claims {m.group(1)} {label}; actual is {actual}",
                              f"Update the {label} count.")

        for m in re.finditer(r"(?i)policies\s*\(([^)]*)\)", text):
            names = re.findall(r"`([a-z_]+)`", m.group(1))
            unknown = [n for n in names if n not in VALID_POLICIES]
            if unknown:
                self._add("CRITICAL", name, "README.md", f"README names policies {unknown} that the code does not accept",
                          f"Use {', '.join(VALID_POLICIES)}.")

        guard_py = self.repo_root / "guard.py"
        if guard_py.is_file():
            doc = guard_py.read_text(encoding="utf-8", errors="ignore")
            for cmd in sorted(public):
                if cmd not in doc:
                    self._add("INFO", name, "guard.py", f"Subcommand '{cmd}' is not listed in the guard.py docstring",
                              f"Document 'python3 guard.py {cmd}'.")

    def _count_tests(self) -> int:
        tests = self.repo_root / "tests"
        if not tests.is_dir():
            return 0
        return sum(len(re.findall(r"^\s+def (test_\w+)\(", f.read_text(encoding="utf-8", errors="ignore"), re.M))
                   for f in tests.glob("test_*.py"))

    def _count_dirs(self, rel: str) -> int:
        d = self.repo_root / rel
        return sum(1 for p in d.iterdir() if p.is_dir() and (p / "SKILL.md").is_file()) if d.is_dir() else 0

    def _count_agents(self) -> int:
        d = self.repo_root / "agents"
        return len(list(d.glob("*.md"))) if d.is_dir() else 0

    # ------------------------------------------------------------------
    # Pass 6
    # ------------------------------------------------------------------
    def pass6_design_contract(self) -> None:
        name = "Pass 6 (Design Contract Measurements)"
        design = self.repo_root / "DESIGN.md"
        if not design.is_file():
            return
        text = design.read_text(encoding="utf-8", errors="ignore")
        section = re.search(r"(?is)#+\s*measured contrast pairs\s*\n(.*?)(?=\n#+\s|\Z)", text)
        if not section:
            if re.search(r"\d+\.\d+:1", text):
                self._add("WARNING", name, "DESIGN.md", "Contrast ratios are stated without a machine-checkable 'Measured Contrast Pairs' table.",
                          "Add the table (Pair | Foreground | Background | Ratio | Minimum).")
            return
        for row in section.group(1).splitlines():
            cells = [c.strip().strip("`") for c in row.strip().strip("|").split("|")]
            if len(cells) < 5 or not re.fullmatch(r"#[0-9A-Fa-f]{6}", cells[1] or ""):
                continue
            pair, fg, bg, stated, minimum = cells[:5]
            try:
                stated_v = float(stated.split(":")[0])
                minimum_v = float(minimum.split(":")[0])
            except ValueError:
                continue
            actual = contrast_ratio(fg, bg)
            if abs(actual - stated_v) > 0.05:
                self._add("CRITICAL", name, "DESIGN.md", f"{pair}: stated {stated_v:.2f}:1 but {fg}/{bg} measures {actual:.2f}:1",
                          "Recompute with skills/antislop-human/contrast-check.py.")
            if actual + 1e-9 < minimum_v:
                self._add("CRITICAL", name, "DESIGN.md", f"{pair}: {actual:.2f}:1 is below the required {minimum_v:.1f}:1",
                          "Choose a color pair that meets the minimum.")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="meta_audit", description="Meta-Consistency & Self-Audit Engine for Antigravity Harness")
    parser.add_argument("--all", action="store_true", help="Run all passes (default)")
    parser.add_argument("--pass", dest="passes", type=int, action="append", choices=range(1, 7), help="Run only pass N (repeatable)")
    parser.add_argument("--strict", action="store_true", help="Fail on WARNING findings too")
    parser.add_argument("--json", action="store_true", help="Output findings as structured JSON")
    parser.add_argument("--root", help="Harness root to audit (default: this repository)")
    args = parser.parse_args(argv)

    engine = MetaAuditEngine(repo_root=Path(args.root) if args.root else None)
    if args.passes:
        engine.findings = []
        for n in sorted(set(args.passes)):
            engine.run_pass(n)
        findings = engine.findings
    else:
        findings = engine.run_all_passes()

    criticals = [f for f in findings if f.severity == "CRITICAL"]
    warnings = [f for f in findings if f.severity == "WARNING"]
    infos = [f for f in findings if f.severity == "INFO"]
    failed = bool(criticals) or (args.strict and bool(warnings))

    if args.json:
        print(json.dumps({
            "is_valid": not failed,
            "total_findings": len(findings),
            "critical_count": len(criticals),
            "warning_count": len(warnings),
            "info_count": len(infos),
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
        return 1 if failed else 0

    print("=" * 64)
    print("    Antigravity Harness — Meta-Audit & Self-Check    ")
    print("=" * 64)
    print(f"Target Repository: {engine.repo_root}")
    print(f"Results          : {len(criticals)} Critical, {len(warnings)} Warnings, {len(infos)} Info")
    print("-" * 64)
    for f in findings:
        print(f"[{f.severity}] {f.pass_name} -> {f.target}")
        print(f"   Message : {f.message}")
        print(f"   Fix     : {f.suggested_fix}")
        print("-" * 64)
    if failed:
        print("[FAIL] Meta-consistency violations detected. Blocking delivery.")
        return 1
    print("[PASS] Harness meta-consistency checks passed." + (" (with notices)" if findings else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
