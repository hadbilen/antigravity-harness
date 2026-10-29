---
name: porter
description: >-
  Universal bidirectional ecosystem adapter, suitability analyzer, and rule transpiler between
  Antigravity and any external AI coding agent, IDE assistant, model framework, or autonomous
  environment (Cursor, Claude Code, Hermes, Cline, Aider, Windsurf, or any other agentic system).
  Invoke when the user requests porting, exporting, importing, converting, adapting, evaluating,
  or syncing rules, instructions, conventions, system prompts, constitutions, or skills across
  AI tools or platforms, whether or not the target platform is explicitly named or newly released.
  Not for upgrading application package dependencies or runtimes (use 'dependency-upgrade').
---

# Porter: Universal AI Agent Bridge & Suitability Transpiler

A deterministic bidirectional bridge and compiler connecting Antigravity Harness with any external AI coding environment (Claude Code, Cursor, Windsurf, Hermes, Cline, Aider, Copilot, ChatGPT Codex, or emerging autonomous frameworks).

---

## Core Philosophy

1. **Pre-Flight Inspection Before Mutation:** Never write, copy, or mutate files blindly upon receiving an external rule. Always execute an analysis gate first.
2. **Constitutional Sanitization (Anti-Slop & Test Invariant):** Strip conversational fluff, forced sycophancy, and test-weakening instructions from incoming rules.
3. **Multi-Hop Lossless Manifest (`.harness/manifest.json`):** Prevent the "Telephone Game" (information decay across successive agent migrations A -> B -> C) by anchoring all exports and imports to a machine-readable canonical manifest.
4. **Natural Intent Agnosticism:** Works across any agent framework or custom workflow without requiring rigid keyword invocations.

---

## Operating Protocols

### Protocol 1: Inward Adaptation (Importing External Rules)

When a user provides an external file (e.g. `.mdc`, `.cursorrules`, `CLAUDE.md`, `AGENTS.md`) or a remote URL:

1. **Run Inspection (Dry-Run / Read-Only):**
   ```bash
   porter inspect <file_or_url>
   # Or from the repository checkout:
   python3 porter.py inspect <file_or_url>
   ```
2. **Present the Suitability & Adaptability Report:**
   Output the formatted report to the user detailing:
   - Detected format and proposed classification (`skill`, `agent`, or project rule).
   - Constitutional score (0-100) and any flagged test-weakening or sycophantic directives.
   - Overlap check against every existing skill and subagent in the harness.
   - Clean preview of sanitized content.
   - **Optional Isolated Behavioral Probe (`Propose–Probe–Compose` Sandbox):** When an external rule carries `NEEDS_REVIEW` items or alters $\ge 1$ normative behavioral requirement whose runtime effect cannot be proven by lexical regexes alone, stage the sanitized preview in `<appDataDir>/brain/<conversation-id>/scratch/`, dispatch two isolated read-only subagent runs (`invoke_subagent` with `research` or read-only `self`, passing the candidate clause in the parent-authorized `Task Objective` header, bounded to at most 3 attempts per `GEMINI.md` Rule 13) against a two-case micro-task fixture (one violating scenario and one clean control scenario, without copying literal candidate phrasing per `GEMINI.md` Rule 9 `C9`), and compose only clauses that catch $\ge 1$ target defect with $0$ new false positives and zero over-abstraction, scope inflation, or boundary erosion (`GEMINI.md` Rules 9 & 18).
3. **Interactive Decision Gate:**
   Ask the user how they wish to proceed:
   - `[1]` (Recommended) Sanitize and import as a new modular skill or subagent.
   - `[2]` Merge guidelines into an existing related skill.
   - `[3]` Cancel.
4. **Execute Mutation Upon User Confirmation:**
   ```bash
   porter import <file_or_url> --as-skill <name>
   # Or from the repository checkout:
   python3 porter.py import <file_or_url> --as-skill <name>
   # To stage into a live Guard-protected configuration (human confirmation required):
   agy-guard porter stage <file_or_url> --name <name>
   ```

---

### Protocol 2: Outward Transpilation (Exporting to External Platforms)

When the user asks to prepare or export the project for teammates or external agents:

1. **Identify Target Format:**
   - `claude`: Generates `CLAUDE.md`, `.claude/skills/<name>/SKILL.md` (with support files), `.claude/agents/<name>.md` (native Claude Code subagents with `tools:` allow-lists, plus `.claude/harness/agents/<name>.md` verbatim), and `templates/`.
   - `cursor`: Generates `.cursor/rules/*.mdc` with glob frontmatter, plus `.cursor/skills/`, `.cursor/agents/`, and `templates/`.
   - `universal`: Generates open-standard `AGENTS.md` (OpenAI, Codex, Copilot, DeepSeek) plus verbatim `.agents/skills/`, `.agents/agents/`, and `templates/`.
   - `aider`: Generates `CONVENTIONS.md` and `.aider.conf.yml` plus `.aider/skills/`, `.aider/agents/`, and `templates/`.
   - `generic`: Generates tool-agnostic `RULES.md` plus verbatim `skills/`, `agents/`, and `templates/`.
   - `all`: Exports all supported targets simultaneously.
2. **Compile Manifest & Export:**
   ```bash
   porter export --target <target> --out <destination_directory>
   # Or from the repository checkout:
   python3 porter.py export --target <target> --out <destination_directory>
   ```
3. **Verify Zero Runtime Leaks:**
   Ensure no internal Antigravity tags (`<RULE[...]`, `<appDataDir>/brain/...`) or unresolvable internal tool names (`invoke_subagent`, `manage_task`) remain in the synthesized top-level rule files (`CLAUDE.md`, `.cursor/rules/*.mdc`, `AGENTS.md`, `CONVENTIONS.md`, `RULES.md`), while support trees (`skills/`, `agents/`, `templates/`) remain verbatim for lossless hash parity.

---

### Protocol 3: Generating Universal Manifest

To generate or refresh the lossless machine-readable snapshot:
```bash
porter manifest
# Or from the repository checkout:
python3 porter.py manifest
```
This writes or updates `.harness/manifest.json`.
