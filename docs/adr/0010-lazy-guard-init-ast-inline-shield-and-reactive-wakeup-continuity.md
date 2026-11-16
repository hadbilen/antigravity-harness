# ADR-0010: PEP 562 Lazy `guard` Package Init, Unified Read-Only Python AST Inline Shield, Reactive Wakeup Continuity, Hermetic Test Isolation, and Multi-Model Placeholder Mapping

**Date**: 2026-11-16
**Status**: accepted
**Amends**: [ADR-0008](0008-agy-hooks-lazy-package-modularization.md) (partial: lazy `guard/hooks/_workflow_ast.py` carve-out), [ADR-0009](0009-cognitive-slimming-skill-consolidation-and-midturn-hook-silence.md) (partial: reactive wakeup `tx_mid_turn` continuity & consecutive build-signal filter)
**Deciders**: Human Operator (`tugay`), Antigravity Harness Maintainers

## Context

Post-`v2.1.1` (`d37f55e`) `cProfile` and Popperian runtime falsification exposed five coupled lifecycle, security, and test-hygiene gaps: (1) `guard/__init__.py` eagerly imported 11 non-hook submodules (`250.9 ms`, pulling in `porter/sanitizer.py`'s `38` regexes) on every `guard/agy_hooks.py` subprocess startup while `guard/hooks/{pre_tool_use,pre_invocation}.py` compiled `110+` module-level and uncached per-root regexes (`669.5 ms` `pre-tool-use` / `537.2 ms` `pre-invocation` `N=5` medians); (2) `_command_mutates_governance` and `_shell_has_unquoted_mutation` split inline interpreter checks across an asymmetric literal-root block (rejecting `#` comments in read-only `python3 -c` probes and recording false `"in_flight"` writes) and a bypassable regex denylist on `Path.home()` / `<<` heredocs (missing `touch`, `truncate`, `FileIO`, `sqlite3`, `tarfile`, and `getattr`); (3) `handle_pre_invocation` forced `is_mid_turn = False` whenever `invocationNum == 1`, clobbering `tx_mid_turn == True` on reactive background-task and subagent wakeups, while `_detect_transcript_tool_signals` counted shell `126`/`127` and short non-compiler CLI statuses across intervening `exit 0` steps; (4) four `tests/test_*.py` modules lacked `import hermetic`; and (5) `upstream_state.seed.json` tracked only a single `last_pbtxt_model` string rather than concurrently approved Gemini 4 flagship placeholders. The decision-driving constraint is **eliminating synchronous hook cold-start slack, regex-denylist governance bypasses, and mid-turn false alarms simultaneously without weakening `GEMINI.md` Rule 9 (`0` existing test line removals), `ADR-0008`'s `52`-attribute facade contract, or `ADR-0009` crash recovery**.

## Decision

We adopt five coordinated architectural invariants across the `W1..W3` campaign:
1. **PEP 562 Lazy `guard/__init__.py`, `_LazyRegex` Conversion, Root-Regex Caching & Lazy `guard/hooks/_workflow_ast.py` Extraction (`AC-1`):** Replace eager submodule imports in `guard/__init__.py` with PEP 562 `__getattr__` and `__dir__` preserving `100%` of `guard.__all__` (plus lazy submodule attribute resolution); convert non-Pass-7 module-level `re.compile` definitions in `guard/hooks/{common,pre_invocation,pre_tool_use}.py` into `_LazyRegex` (retaining `re.Pattern` on `SKILL_HINTS` and `ECOSYSTEM_ROUTING_HINTS` for `scripts/meta_audit.py` Pass 7); cache per-root boundary regexes in `_command_mutates_governance` via `functools.lru_cache`; and extract `_inspect_workflow_script` plus its private workflow-AST helpers into `guard/hooks/_workflow_ast.py` loaded on demand (delegating the 4 workflow entrypoints lazily from `guard/hooks/pre_tool_use.py` and re-exporting all 27 workflow-AST symbols through `guard/agy_hooks.py`).
2. **Unified `ast.parse` Read-Only Python Inline/Heredoc Allowlist (`AC-2`):** Replace regex-denylist and unconditional `-c` interpreter branches in `_command_mutates_governance` and `_shell_has_unquoted_mutation` (`guard/hooks/pre_tool_use.py`) with a deterministic `ast.parse` pure read-only Python subset allowlist over single-quoted/unexpanded `-c` and `<<EOF` snippets, permitting verified read-only diagnostics (`json.loads`, `read_text`, `read_bytes`, `iterdir`, `rglob`, `glob`, `stat`, `lstat`, `is_symlink`, `is_file`, `is_dir`, `exists`, `print`, including `#` comments) without `"in_flight"` false positives while failing closed (`"deny"`) on `touch`, `truncate`, `FileIO`, `sqlite3`, `tarfile`, `zipfile`, `getattr`, dunders, dynamic/mutating calls, shell expansions in double-quoted/unquoted-heredoc payloads, piped stdin (`| python3`), and all non-Python `-e`/`<<` interpreters targeting protected roots.
3. **Reactive Wakeup `tx_mid_turn` Continuity & True-Consecutive Build Signal Filter (`AC-3`):** Preserve `is_mid_turn = True` in `handle_pre_invocation` (`guard/hooks/pre_invocation.py`) on `invocationNum == 1` whenever `has_tx and tx_mid_turn` holds (reactive task/subagent wakeup with trailing non-`USER_INPUT` entries and matching user prompt), and update `_detect_transcript_tool_signals` to reset `consec_build_fails = 0` on any clean `exit 0` shell result while excluding shell `126`/`127` exits and short (`<= 25` lines) non-compiler CLI status exits lacking `_COMPILER_TRACE_MARKER_RE`.
4. **Pure-Additive Hermetic Test Isolation & Static Gate (`AC-4`):** Prepend `import hermetic` (`0` removed lines under `TestBoundaryGuard` `mode="tdd"`) to `tests/test_agy_hooks.py`, `tests/test_code_map.py`, `tests/test_media_studio.py`, and `tests/test_rustify_and_codemap.py`, add pure-additive `setUp`/`tearDown` temp-dir isolation on `TestPorterSanitizerNewPatterns`, and enforce `hermetic` presence across `tests/test_*.py` in `scripts/meta_audit.py`.
5. **Backward-Compatible `known_placeholder_models` Map (`AC-5`):** Add `known_placeholder_models` (`MODEL_PLACEHOLDER_M417`, `MODEL_PLACEHOLDER_M427`, `MODEL_PLACEHOLDER_M528`) alongside `last_pbtxt_model` in `skills/upstream-auditor/upstream_state.seed.json` and wire lookup across `skills/upstream-auditor/scripts/upstream_watcher.py`, `guard/upstream.py`, and `guard/hooks/pre_tool_use.py` while keeping unknown `MODEL_PLACEHOLDER_*` IDs fail-closed (`force_ask`).

## Alternatives Considered

### Alternative 1: Expand the Inline Interpreter Regex Denylist (`touch|truncate|FileIO|sqlite3|...`)
- **Pros**: Small diff inside `guard/hooks/pre_tool_use.py`.
- **Cons**: Critical security and usability failure mode: Python string concatenation (`getattr(p, 'un' + 'link')`), aliasing, and newly used stdlib modules continue to bypass a regex denylist, while literal protected paths inside `#` comments or `read_text()` probes remain blocked by `L1780`.
- **Why not**: Rejected under `mistake-proofing`: parsing Python syntax once at the boundary into a closed read-only AST subset eliminates the entire denylist-evasion class while restoring safe read-only diagnostics.

### Alternative 2: Bypass `guard/__init__.py` by Rewriting Hook Imports Without PEP 562 Package Laziness
- **Pros**: Avoids editing `guard/__init__.py`.
- **Cons**: Python always executes `guard/__init__.py` before resolving `from guard.paths import ...` or `import guard.agy_hooks`; only PEP 562 lazy `__getattr__` inside `guard/__init__.py` eliminates the `250.9 ms` 11-module import tax for every `guard.*` consumer while keeping `from guard import <Symbol>` intact.
- **Why not**: Violates Python's package-import semantics and fails to solve the measured root cause.

### Alternative 3: Treat Every `invocationNum == 1` as a Fresh User Turn Regardless of `tx_mid_turn`
- **Pros**: Zero change to `handle_pre_invocation`.
- **Cons**: Antigravity resets `invocationNum` to `1` on reactive background-task (`> WaitMsBeforeAsync`) and subagent wakeups even though no new `USER_INPUT` occurred (`tx_mid_turn == True`), causing false `[Harness Recovery & Continuity Gate]` injections and premature `"in_flight" -> "interrupted_notified"` state transitions before `Stop`.
- **Why not**: Checking `has_tx and tx_mid_turn` distinguishes reactive mid-turn wakeups from genuine new `USER_INPUT` turns (`trailing_non_user == 0` or `explicit_differs == True`) without regressing post-crash recovery.

## Consequences

### Positive
- Importing `guard.paths` or `guard.agy_hooks` loads `0` non-hook `guard.*` submodules (`porter`, `snapshot`, `lease`, `integrity`, `environment`), and `run_workflow` AST tables load only when `run_workflow` (or a workflow-AST symbol) is invoked, cutting synchronous hook cold-start latency by `>= 35%` with `100%` `ADR-0008` facade parity.
- Read-only `python3 -c` and `<<'EOF'` diagnostics execute cleanly without `"in_flight"` false positives, while mutating or obfuscated Python/non-Python inline scripts targeting governance trees fail closed (`"deny"`).
- Reactive task/subagent wakeups stay silent mid-turn, `build-error-resolver` fires only on genuine `>500`-line/truncated traces or `>= 2` consecutive compiler/test failures, and standalone `unittest` runs stay `100%` hermetic.

### Negative
- Complex read-only `python3 -c` scripts that use constructs outside the conservative AST subset (such as `class` definitions, `getattr`, or unquoted shell `$` expansions) fall back to conservative mutation classification when targeting governance paths or recording flight state.
- Adding a new public export to `guard/__init__.py` requires updating both `_LAZY_EXPORTS` and `__all__`.

### Risks
- **Shell-expansion smuggling inside `python3 -c "..."` or unquoted `<<EOF`**: Mitigated by rejecting double-quoted `-c` or unquoted heredoc bodies containing `$` or `` ` `` (requiring literal single-quoted `-c '...'`, quoted `<<'EOF'`, or expansion-free source) and never short-circuiting outer shell redirection/pipe/compound checks.
- **Submodule lazy-isolation drift on `guard/hooks/_workflow_ast.py`**: Mitigated by loading `_workflow_ast` via lazy delegators only on workflow calls so `dispatch_hook('pre-tool-use', {'read_file'})` still imports strictly `guard.hooks.common` and `guard.hooks.pre_tool_use`, verified by `tests/test_agy_hooks_facade_parity.py` and `tests/test_v212_evaluation_remediation.py`.
