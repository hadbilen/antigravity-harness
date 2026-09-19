---
name: porter
description: Universal bidirectional ecosystem adapter, suitability analyzer, and rule transpiler between Antigravity and any external AI coding agent, IDE assistant, model framework, or autonomous environment (whether established or emerging, such as Cursor, Claude Code, Hermes, Cline, Aider, Windsurf, or any other agentic system). Invoke when: the user requests porting, exporting, importing, converting, adapting, evaluating, or syncing rules, instructions, conventions, system prompts, constitutions, or skills across different AI tools or platforms, regardless of whether the target platform is explicitly named or newly released.
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
   python porter.py inspect <file_or_url>
   ```
2. **Present the Suitability & Adaptability Report:**
   Output the formatted report to the user detailing:
   - Detected format and proposed classification (`skill`, `agent`, or project rule).
   - Constitutional score (0-100) and any flagged test-weakening or sycophantic directives.
   - Overlap check against existing 18 skills and 6 subagents.
   - Clean preview of sanitized content.
3. **Interactive Decision Gate:**
   Ask the user how they wish to proceed:
   - `[1]` (Recommended) Sanitize and import as a new modular skill or subagent.
   - `[2]` Merge guidelines into an existing related skill.
   - `[3]` Cancel.
4. **Execute Mutation Upon User Confirmation:**
   ```bash
   python porter.py import <file_or_url> --as-skill <name>
   ```

---

### Protocol 2: Outward Transpilation (Exporting to External Platforms)

When the user asks to prepare or export the project for teammates or external agents:

1. **Identify Target Format:**
   - `claude`: Generates `CLAUDE.md` and `.claude/commands/*.md` (slash commands).
   - `cursor`: Generates `.cursor/rules/*.mdc` with glob frontmatter.
   - `universal`: Generates open-standard `AGENTS.md` (OpenAI, Codex, Copilot, DeepSeek).
   - `aider`: Generates `CONVENTIONS.md` and `.aider.conf.yml`.
   - `generic`: Generates tool-agnostic `RULES.md` and `CONVENTIONS.md`.
   - `all`: Exports all supported targets simultaneously.
2. **Compile Manifest & Export:**
   ```bash
   python porter.py export --target <target> --out <destination_directory>
   ```
3. **Verify Zero Runtime Leaks:**
   Ensure no internal Antigravity tags (`<RULE[...]`) or unresolvable internal tool names (`invoke_subagent`) remain in the exported markdown.

---

### Protocol 3: Generating Universal Manifest

To generate or refresh the lossless machine-readable snapshot:
```bash
python porter.py manifest
```
This writes or updates `.harness/manifest.json`.
