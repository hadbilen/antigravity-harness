# ADR-0004: Tiered MCP Hook Policy, Dual Read-Only Subagent Tool Contract, Fail-Safe Customization Model Gate, and Dual-Layer Linux Package Activation

**Date**: 2026-10-24
**Status**: accepted
**Deciders**: Human Operator, Antigravity Primary Orchestrator (`W1` — `d78c8c42-a161-4b15-aee8-a274232efa51`)

## Context

The unified full-repository audit (`/audit --full --meta --forensics --cognitive`, `36` empirically verified findings: `C-01..C-04`, `H-01..H-18`, `M-01..M-10`, `I-01..I-04`) surfaced four architectural boundary decisions requiring explicit lock-in before multi-worker remediation:
1. Live Antigravity 2.0 runtime transcripts provision `view_file` rather than `read_file` to `access: read-only` custom subagents (`agents/*.md`), whereas `ADR-0001` Decision 5 and `scripts/meta_audit.py` banned `view_file` globally (`H-10`).
2. Model Context Protocol (`MCP`) invocations (`call_mcp_tool` and `mcp_*`) were absent from `hooks.json` and `guard/agy_hooks.py` (`PRE_TOOL_USE_MATCHER_TOOLS` and `_inspect_workflow_script`), leaving shell/debugger-capable MCP tools (`execute_rizin_command`, `gdb_console`, etc.) outside `PreToolUse` governance (`H-03`).
3. `GEMINI.md` Rule 17's customization model/effort gate returned `None` (fail-open) when both the hook payload and transcript lacked model/effort metadata, and ignored effort changes inside `<USER_SETTINGS_CHANGE>` blocks (`M-04`).
4. Linux `.deb`/`.rpm`/Arch system packages staged governance files exclusively under `/usr/share/antigravity-harness/` without a user-profile bootstrap or read fallback in `agy_hooks.py` and `upstream.py` (`H-13`).

## Decision

1. **Dual Read-Only Subagent Tool Contract (`H-10`, refining `ADR-0001` Decision 5):** Permit dual read-tool naming (`read_file` or `view_file`) inside `agents/*.md` (`access: read-only` subagents) in `scripts/meta_audit.py` (`DEPRECATED_V1_TOOLS` / `pass1_frontmatter`) and align `agents/*.md` instructions with the live runtime schema, while keeping `read_file`, `edit_file`, and `write_file` mandatory in main-session `skills/` files.
2. **Tiered MCP Hook & Workflow Policy (`H-03`):** Add `call_mcp_tool|mcp_.*` to `hooks.json` and `guard/agy_hooks.py` (`PRE_TOOL_USE_MATCHER_TOOLS` and `_inspect_workflow_script`): unconditionally `deny` MCP arguments targeting protected governance paths (`~/.gemini/config`, `~/.local/state/antigravity-harness`), `install.py`, or human-only `agy-guard` admin subcommands; return `force_ask` for non-governance calls to shell/debugger/runtime-injection MCP tools (`execute_rizin_command`, `gdb_console`, `rizin_debug_command`, `cutter_command`, `instrument_with_frida`, `load_frida_script`); return `allow` for read-only MCP tools.
3. **Fail-Safe Customization Model & Effort Gate (`M-04`):** Parse both model and effort (`effort` / `thinkingLevel`) from `<USER_SETTINGS_CHANGE>` blocks in `_extract_transcript_model_setting`, return `force_ask` on customization/governance mutations when active model/effort metadata is completely absent from both payload and transcript, and preserve `deny` whenever a non-top model or non-high effort is detected.
4. **Dual-Layer Linux System Package Activation (`H-13`):** Add human-invoked `agy-guard init` in `guard/cli.py` to bootstrap user `~/.gemini/config` and File Integrity Monitor (`FIM`) baselines from `/usr/share/antigravity-harness`, paired with `agy-guard init --uninstall` for per-user teardown before removing Linux `.deb`, `.rpm`, or Arch system packages (matching `install.py --uninstall` for source checkouts and `README.md` documentation), and add `/usr/share/antigravity-harness` read fallbacks in `guard/agy_hooks.py` (`_catalog_top_model_spec`, `_load_ui_slop_scanner`) and `guard/upstream.py` (`UpstreamAuditorBridge.__init__`).

## Alternatives Considered

### Alternative 1: Blanket `deny` or Blanket `force_ask` on All `call_mcp_tool` / `mcp_*` Invocations
- **Pros**: Trivial five-line implementation in `handle_pre_tool_use`.
- **Cons**: Blanket `deny` breaks read-only `contrast-mcp` and static binary inspection tools; blanket `force_ask` floods read-only MCP workflows with confirmation prompts while failing to hard-block `~/.gemini/config` governance tampering.
- **Why not**: Violates surgical least-privilege enforcement; tiered inspection (`deny` on governance/admin targets, `force_ask` on execution/injection tools, `allow` on read-only tools) closes the critical escape vector without degrading read-only MCP ergonomics.

### Alternative 2: Hard `deny` When Payload & Transcript Model Metadata Are Absent (`M-04`)
- **Pros**: Eliminates any interactive prompt on turn-1 cold starts if a host build omits `modelName` from the hook payload.
- **Cons**: As documented in Audit Open Question (unified audit report §6), if an Antigravity host version omits `modelName` before the first `<USER_SETTINGS_CHANGE>` event even when the operator selected `Gemini 4 Argon (High)`, a hard `deny` permanently deadlocks legitimate customization work with no operator escape hatch.
- **Why not**: `force_ask` on missing metadata fails safe (preventing silent background Flash downgrades) while letting the human operator confirm legitimate top-model turns, whereas explicit low-model payloads continue to hard-`deny`.

### Alternative 3: Auto-Mutate `~/.gemini/config` Inside `.deb`/`.rpm` `postinst` Root Maintainer Scripts (`H-13`)
- **Pros**: Zero post-install CLI step after `apt install` or `pacman -S`.
- **Cons**: Root package maintainer scripts cannot deterministically enumerate multi-user `$HOME` directories, risk root-owned files inside user home trees, and violate `GEMINI.md` Rule 12 / Rule 15a boundaries.
- **Why not**: Pairing `/usr/share/antigravity-harness` read-only fallbacks with an explicit per-user `agy-guard init` command preserves standard Linux multi-user packaging hygiene and user-owned permissions.

## Consequences

### Positive
- Eliminates tool-call schema friction in `access: read-only` subagents while preserving strict Antigravity 2.0 tool naming in main-session skills.
- Closes the `call_mcp_tool` / `mcp_*` shell and debugger escape vector across both native tool calls and `run_workflow` orchestration scripts.
- Closes silent fail-open customization edits when model metadata is absent and prevents false-deny lockouts after mid-session effort upgrades.
- Enables clean per-user initialization (`agy-guard init`) and safe per-user teardown (`agy-guard init --uninstall`) before removing or downgrading Linux `.deb`, `.rpm`, and Arch system packages.

### Negative
- Adding `call_mcp_tool|mcp_.*` to `hooks.json` routes MCP calls through `PreToolUse` (~15–30 ms local Python hook overhead per MCP call).
- System package users must run `agy-guard init` once per OS user account to activate user-scoped `~/.gemini/config` hooks and FIM baselines.

### Risks
- **Risk**: Future MCP servers may introduce new command-executing tool names beyond the initial six `rea_rea` debugger/script tools. **Mitigation**: Combine explicit high-risk tool matching with generic argument scanning for governance paths, `install.py`, and `agy-guard` admin subcommands across all MCP tool calls.
