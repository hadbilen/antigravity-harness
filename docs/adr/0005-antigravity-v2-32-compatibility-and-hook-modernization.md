# ADR-0005: Antigravity v2.32.0 Compatibility, Hook Schema Modernization, `/swarm` Governance, and Knowledge Work Hygiene

**Date**: 2026-11-14
**Status**: accepted
**Deciders**: Human Operator, Antigravity Primary Orchestrator (`c8c47792-c9ed-4158-88cc-315a0f09c15a`)

## Context

Antigravity `v2.32.0` introduces new flagship/orchestration models (`Gemini 4 Carbon`, `Gemini 4 Hydrogen (XHigh)`, `Orchestrator (Carbon/Argon)`), expands built-in skills from 9 to 14 (`+ migrate-agent-settings`, `native_swarm`, `swarm_monitor`, `swarm_narrator`, `mcp-app-development`) alongside built-in slash commands (`/grill-me`, `/learn`, `/goal`, `/boost`, `/teamwork`, `/swarm`), deprecates `injectSteps[].ephemeralMessage` in favor of `systemMessage` + `metadata.user_markdown`, adds `continuationActive` and `fullyIdle` fields to `Stop` payloads (`~/.gemini/antigravity/builtin/skills/agy-customizations/docs/hooks.md`), and enforces a `24,000`-byte per-file cap and `20,000`-token `defaultRulesBudget` (`~/.gemini/antigravity/builtin/skills/agy-customizations/docs/rules.md`). Meanwhile, non-git Knowledge Work workspaces hit false-positive git recovery messages, arbitrary `skills/`/`agents/` Rule 17 denials, and over-broad `sweetspot`/`deep-grill` hints, while 6 tracked upstream repositories have pending commits.

## Decision

1. **Model Catalog & Built-in Skill Seed Synchronization (`AC-1`):** Reconcile the pre-existing Hydrogen changes and add `Gemini 4 Carbon (High)`, `Gemini 4 Hydrogen (XHigh)`, and highest-effort `Orchestrator (Carbon/Argon)` support in `skills/upstream-auditor/upstream_state.seed.json` and `guard/agy_hooks.py` while keeping explicit highest-effort suffix enforcement and `"Gemini 4 Argon (High)"` backward compatibility, and sync `recorded_builtin_skills` to all 14 built-in skills.
2. **Native `systemMessage`, Operator-Only `user_markdown` & `Stop` State (`AC-2`):** Migrate `guard/agy_hooks.py` and `skills/upstream-auditor/scripts/upstream_watcher.py` from `ephemeralMessage` to `{"injectSteps": [{"systemMessage": {"systemMessage": ..., "metadata": ...}}]}`, placing watchdog alerts strictly in `metadata.user_markdown` with an empty model `systemMessage: ""` (`GEMINI.md` Rule 5); update `scripts/meta_audit.py` `_extract_pre_invocation_text`; and handle `Stop` `(continuationActive, fullyIdle, executionNum)` state deterministically without bypassing workspace diff or non-git `TestBoundaryGuard` checks:
   - `NO_TOOL_CALL` + clean/deferred-question workspace (or `readOnly` without session writes) returns `{}`; `Stop` always runs `TestBoundaryGuard` even on non-git workspaces (where `_collect_workspace_diff_status_ex` returns `"", True, False`).
   - When findings exist: annotate Strike reasons with `[continuationActive=true | fullyIdle=false]` without suppressing verification; track per-fingerprint `count` and cross-fingerprint `total_strikes` in `hook_strikes.json` (`yield` at `count >= MAX_STRIKES` or `total_strikes >= MAX_STRIKES + 2`); lock/I/O fallback and malformed Stop stdin fail closed (`decision="continue"`) bounded by `continuationActive=true` + `executionNum >= MAX_STRIKES + 2`, while unrecoverable `dispatch_hook` exceptions in `main()` log to `stderr` and degrade to `{}` so turn completion cannot brick the IDE.
3. **`/swarm` `PreToolUse` Gate & `GEMINI.md` Rule 15 Codification (`AC-3`):** Add `swarm` (covering `add`/`model`/`fork`/`kill`/`post_message` actions and `run_workflow` multi-step `swarm` overlays; standalone host `post_message` board tool remains outside `PRE_TOOL_USE_MATCHER_TOOLS` until `tests/test_guard_hardening.py` `expected_tools` parity is expanded via Rule 9 approval) to `PRE_TOOL_USE_MATCHER_TOOLS`, `hooks.json`, `guard/agy_hooks.py`, and `install.py` parity checks to block model downgrades and non-flagship customization delegation (`GEMINI.md` Rule 17), extend `ECOSYSTEM_ROUTING_HINTS`, and codify Antigravity `v2.32.0` Rule 15 resolutions in `GEMINI.md` under a `<= 20,000`-byte operational ceiling (below the `24,000`-byte host hard cap, verified by `scripts/meta_audit.py` `Pass 2`).
4. **Targeted Knowledge Work Hygiene Without a Separate Mode (`AC-4`):** Fix the three root defects in `guard/agy_hooks.py` instead of creating a new mode: gate git recovery instructions behind `_is_git_repo_workspace(workspace)`, scope `_targets_customization_structure` away from ordinary non-harness `skills/`/`agents/` folders while keeping real `.agents/`/`.claude/`/`.cursor/`/`.harness/`/`SKILL.md`/harness-repo checks intact, and narrow `SKILL_HINTS` `sweetspot` and `deep-grill` triggers while preserving existing technical and Turkish test prompts.
5. **Subagent-Isolated 6-Repo Upstream Sync (`AC-5`):** Inspect `anti-slop`, `Chisle`, `everything-claude-code`, `mattpocock-skills`, `procoder`, and `rea` via read-only `research` subagents and `porter inspect`, adopting only constitutionally compliant improvements and refreshing `.harness/manifest.json` and docs.

## Alternatives Considered

### Alternative 1: Create a Dedicated "Knowledge Work Mode" Skill and Rule Profile
- **Pros**: Separates non-coding workspace heuristics from coding rules cleanly on paper.
- **Cons**: Consumes `defaultRulesBudget` tokens every turn, duplicates existing constitutional guidance (violating the `MISTAKES.md` Rule 10 no-redundant-mode invariant), and leaves the underlying `guard/agy_hooks.py` bugs unfixed for normal workspaces.
- **Why not**: Fixing the three exact hook hygiene defects removes false positives across all non-git and non-harness workspaces with zero token overhead (weighted criterion: token budget and zero redundant scaffolding).

### Alternative 2: Keep `ephemeralMessage` or Emit Watchdog Notices in Model-Visible `systemMessage`
- **Pros**: Requires zero edits to the 8 existing test files or `upstream_watcher.py`.
- **Cons**: `ephemeralMessage` is deprecated in `v2.32.0` (`~/.gemini/antigravity/builtin/skills/agy-customizations/docs/hooks.md`), and model-visible watchdog text leaks maintenance notices into agent context in violation of `GEMINI.md` Rule 5.
- **Why not**: `systemMessage: ""` paired with `metadata.user_markdown` structurally enforces operator-only visibility (`mistake-proofing`) once Rule 9 legacy test transitions are authorized.

### Alternative 3: Bypass All `Stop` Checks When `continuationActive` Is True or `fullyIdle` Is False
- **Pros**: Trivially guarantees `Stop` never re-fires during continuation or background tasks.
- **Cons**: Creates a hard security/integrity bypass allowing test-weakening or malformed diffs to slip through whenever background tasks exist or a continuation turn runs.
- **Why not**: Integrity invariant enforcement outweighs loop convenience; `Stop` integrates `continuationActive` and `fullyIdle` alongside the existing 3-strike circuit breaker while never suppressing diff or `TestBoundaryGuard` inspection.

## Consequences

### Positive
- Eliminates deprecated hook output warnings and isolates watchdog maintenance notices from model context (`metadata.user_markdown`).
- Extends Rule 17 model/effort enforcement cleanly to Antigravity `v2.32.0` flagships (`Carbon`, `Hydrogen XHigh`, `Orchestrator`) and `/swarm` worker delegation.
- Prevents hook false positives on non-git Knowledge Work workspaces and non-harness folders without adding rule bloat.

### Negative
- Requires explicit human `[Legacy Test Transition Request]` authorization under `GEMINI.md` Rule 9 to migrate existing `ephemeralMessage` assertions across 8 test files, update `PRE_TOOL_USE_MATCHER_TOOLS` parity in `tests/test_guard_hardening.py`, and finalize the pre-existing `tests/test_security_and_protocol_seams.py` Hydrogen diff.
- Adding `swarm` to `PRE_TOOL_USE_MATCHER` routes `swarm` tool invocations through `PreToolUse` (~15–30 ms local hook overhead per call).

### Risks
- **Risk**: Narrowing `SKILL_HINTS` for `sweetspot` and `deep-grill` or scoping `_targets_customization_structure` could drop a real trigger or create a governance bypass. **Mitigation**: Pin both positive and negative boundary cases in a dedicated regression suite under `tests/` alongside existing `tests/test_agy_hooks.py` and `scripts/meta_audit.py --strict` Pass 7 checks, and verify with Popper's Falsification Gate.
