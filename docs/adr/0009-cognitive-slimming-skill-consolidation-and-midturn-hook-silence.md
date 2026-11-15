# ADR-0009: Constitutional Slimming, 34-to-20 Skill Consolidation, and Mid-Turn PreInvocation Silence

**Date**: 2026-11-15
**Status**: accepted
**Deciders**: Human Operator (`tugay`), Antigravity Harness Maintainers

## Context

Across iterative v2.x incident remediations (`ADR-0001` through `ADR-0008`), always-on prompt and hook surfaces accumulated redundant cognitive load while mechanical enforcement already existed out of band:
1. `GEMINI.md` grew to `17,920` UTF-8 bytes (`~4,300` tokens, duplicated to `35,840` bytes when operating inside the harness source repository), repeating 20+ human-only CLI subcommands in `Rule 12`, `3,378` characters of platform collision sub-clauses in `Rule 15`, and a duplicate domain routing table in `Section 6`, while elevating micro-formatting (`Rule 4: Abbreviation Discipline`) over a first-class *Simplicity First (YAGNI)* rule (`agents/*.md` duplicated that abbreviation-counting mandate across all 9 subagent profiles).
2. `skills/` exposed `34` top-level `SKILL.md` frontmatters (`16,356` bytes) on every turn in `<skills>`, even though `14` of those entries functioned as sub-modules (`antislop-ui`, `antislop-copywriting`, `antislop-human`, `antislop-layoutmobile`, `antislop-code`, `silk-design`), workflow sub-modes (`marathon`, `unlazy`, `architecture-decision-records`, `mistake-proofing`, `dependency-upgrade`, `test-design`), or focused reference lenses (`visualizer`, `security-review`).
3. `guard/hooks/pre_invocation.py` (`handle_pre_invocation`) defaulted `invocationNum` to `1` when omitted by the host and read `explicit_step = 0` in `_extract_latest_user_prompt` without checking trailing non-`USER_INPUT` entries in `transcriptPath`, causing mid-turn tool-continuation steps to falsely emit `[Harness Recovery & Continuity Gate]` and prematurely transition `flight_recorder.json` out of `"in_flight"` before `Stop`; simultaneously, `_detect_transcript_tool_signals` escalated consecutive zero-match `grep`/`rg`/`diff`/`test` exit codes `1`/`2` to `build-error-resolver`.

The decision-driving constraint is **minimizing per-turn constitutional, frontmatter, and hook-injection token pressure without weakening any deterministic `guard/` boundary, losing any skill asset/script, or breaking canonical `Rule 1..18` citations**.

## Decision

We adopt three coordinated Tier-3 architectural invariants:
1. **In-Slot Constitutional Slimming (`GEMINI.md` `<= 6,500` bytes):** Preserve canonical numbered rules `1..18` with single-line lead-in prose (`ManifestEngine._extract_rules_from_markdown` parity), replace `Rule 4` in-slot with **`4. Simplicity First (YAGNI)`**, condense `Rules 5, 8, 10, 11, 12, 13, 15, 16, 17` to concise invariant statements (retaining compact `(a)`–`(h)` tags inside `Rule 15` so existing `Rule 15a`–`15h` hook citations remain anchored), remove the duplicate `Section 6` routing table, and synchronize Core Rule 6 across all 9 `agents/*.md` profiles.
2. **Balanced 34-to-20 Skill Consolidation & Shared MCP Path Migration:** Absorb `14` sub-module and workflow-helper skills into `skills/antislop/`, `skills/harness/`, `skills/technical-writing/`, and `skills/audit/` (`references/` and `scripts/`), retain all `SKILL_HINTS` sub-module triggers in `guard/hooks/pre_invocation.py` pointing to the relocated `references/*.md` files (with `scripts/meta_audit.py` Pass 3 & Pass 7 updated to validate relocated mode files and parent frontmatter `/slash` unions), preserve absorbed skill slugs in `porter/analyzer.py`, and invoke a shared `RELOCATED_SKILL_SCRIPTS` migration helper in both `install.py` (`migrate_mcp_config`) and `guard/cli.py` (`cmd_init`) so existing `mcp_config.json` entries referencing `skills/antislop-human/contrast-mcp.py` repoint automatically (`0o600`, zero symlink/`..` traversal) to `skills/antislop/scripts/contrast-mcp.py`.
3. **Transcript-Aware Mid-Turn `PreInvocation` Silence:** Inspect bounded `transcriptPath` tails even when inline `prompt`/`lastUserInput` fields are populated so invocations with `>= 1` non-`USER_INPUT` entry following the latest `USER_INPUT` (or `invocationNum > 1`) are treated as active mid-turn continuations (suppressing mid-turn `in_flight` recovery alerts across normal and lock-fallback paths while preserving post-crash recovery even on repeated short prompts such as `"devam et"`), and correlate `PLANNER_RESPONSE` `tool_calls` command arguments in `_detect_transcript_tool_signals` so pure `grep`/`egrep`/`fgrep`/`rg`/`diff`/`cmp`/`test`/`[` exit codes `1`/`2` without compiler/traceback markers do not trigger `build-error-resolver`.

## Alternatives Considered

### Alternative 1: Renumber `GEMINI.md` into Rules `1..10`
- **Pros**: Slightly shorter numbering sequence.
- **Cons**: Breaks hundreds of `Rule 7`, `Rule 8`, `Rule 9` (`C9`), `Rule 12`, `Rule 13`, `Rule 15a–h`, `Rule 16`, `Rule 17`, and `Rule 18` citations across `guard/`, `scripts/`, `porter/`, `agents/`, `MISTAKES.md`, and `docs/adr/` with zero additional byte savings.
- **Why not**: In-slot slimming achieves the identical `~65%+` size reduction with zero citation churn.

### Alternative 2: Radical Minimalism (Prune `porter/`, `upstream-auditor`, and `guard/` Hooks)
- **Pros**: Fewer Python files in the repository.
- **Cons**: Out-of-band Python modules consume `0` prompt tokens during normal agent turns while providing deterministic `TestBoundaryGuard`, OS-level governance locks, and cross-agent rule portability.
- **Why not**: Confuses repository file count with active context-window token load and sacrifices non-bypassable safety invariants.

### Alternative 3: Keep All 34 Top-Level `skills/` Directories Unchanged
- **Pros**: Zero path updates in `SKILL_HINTS`, `upstream_state.seed.json`, or test fixtures.
- **Cons**: Permanently injects `14` sub-module/checklist frontmatters (`~6.5 KB`) into `<skills>` on every turn and increases routing boundary overlap.
- **Why not**: Sub-reference `SKILL_HINTS` routing preserves `/slash` ergonomics while removing `41%` of top-level custom skill frontmatter entries.

## Consequences

### Positive
- `GEMINI.md` drops below `6,500` UTF-8 bytes (`>= 63%` reduction) with `Simplicity First (YAGNI)` elevated to `Rule 4` across the constitution and all 9 subagent profiles.
- Top-level custom skills drop from `34` to `20` while keeping 100% of scripts, templates, assets, and `/slash` command routing intact.
- Multi-step tool turns execute without false-positive `[Harness Recovery & Continuity Gate]` or `grep` `build-error-resolver` context injections, and `handle_stop` retains clean `"in_flight" -> "turn_complete"` transitions.
- Existing `mcp_config.json` installations automatically repoint `antislop-contrast` during both `install.py` and `agy-guard init`.

### Negative
- External references or bookmarks to retired `skills/<merged>/SKILL.md` paths must use the new `skills/<parent>/references/<module>.md` paths.
- Upstream synchronization (`upstream-auditor`) maps consolidated repositories (`anti-slop`, `silk-design`, `unlazy`, `everything-claude-code`, `mattpocock-skills`) to sub-reference file paths rather than standalone top-level skill folders.

### Risks
- **Risk**: Internal relative paths inside relocated multi-file skills (`unlazy`, `silk-design`) or retired `mcp_config.json` script pointers could break at runtime if missed by static link checks.
- **Mitigation**: Rebase all internal links/code-spans in `unlazy.md` and `silk-design.md`, expand `meta_audit.py` `top_dirs` to validate `references/` and `assets/` code spans, and enforce shared `RELOCATED_SKILL_SCRIPTS` repointing across `install.py` and `guard/cli.py` with dedicated seam tests.
