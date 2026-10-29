# ADR-0002: Standalone `renew` Skill (Including Legacy Game Profile) and Integration of Media Salvage & Fidelity-Bounded Upscaling into `media-studio`

**Date**: 2026-10-24
**Status**: accepted
**Deciders**: Human Operator (hadbilen), Antigravity Primary Engineering Session

## Context

Two capability additions were evaluated for `antigravity-harness`:
1. **`renew`:** Modernizing, porting, or reviving generationally obsolete or unbuildable applications (and potentially classic games) on modern operating systems, runtimes, and user interfaces while preserving core domain behavior and data/save-file compatibility.
2. **`enhance`:** Repairing damaged/corrupted legacy audio and visual files without altering their original essence, and enhancing low-quality media files without introducing artificial distortions or generative hallucinations.

Inspection of the 32-skill catalog and `guard/agy_hooks.py` (`SKILL_HINTS`) showed an asymmetric overlap profile:
- Legacy software modernization falls into an unserved dead zone: `skills/dependency-upgrade/SKILL.md` §2 explicitly halts when a version bump crosses into a generational migration rewrite, while `skills/refactoring/SKILL.md` requires the unchanged codebase to already build and execute today with zero platform or observable contract shift.
- Conversely, `skills/media-studio/SKILL.md` and `skills/media-studio/scripts/media_qc.py` already enforce non-destructive file discipline (`Probe -> Plan -> Process -> Verify`), ordered audio/video signal restoration, and bilingual `"ses/video/görüntü kalitesini düzelt"` / `"onarım"` auto-routing in `guard/agy_hooks.py`, while lacking (a) broken container/header salvage, (b) still-image/photo restoration, and (c) hallucination-bounded upscaling and side-by-side fidelity verification.

## Decision

1. **Create `skills/renew/SKILL.md` as a standalone top-level skill (`33` skills total):** Enforce a five-stage modernization discipline (`Silent Autopsy -> Renewal Contract via ask_question -> Golden Master or Equivalence Ledger -> Layered Strangler Cutover & Security Sanitization -> Parity Gate`), incorporate a **Legacy Game & Interactive Simulation Profile** that delegates simulation-loop and HUD vitality rules to `skills/game-engineering/SKILL.md`, and anchor `SKILL_HINTS` strictly on `/renew` and explicit software-modernization phrases so bare `"renew"` tokens in auth/billing prompts never false-trigger.
2. **Integrate media salvage, still-image restoration, and fidelity-bounded enhancement into `skills/media-studio/` instead of creating a separate `enhance` skill:** Keep `skills/media-studio/SKILL.md` concise, add `skills/media-studio/references/salvage-and-enhancement.md` for deep container-salvage, still-photo, and two-tier (deterministic mathematical default vs. user-approved local neural model) enhancement protocols, and extend `skills/media-studio/scripts/media_qc.py` with `salvage`, full still-image `check`/`compare`, aspect-drift rejection, and `ab-sheet` side-by-side visual verification.

## Alternatives Considered

### Alternative 1: Create Both `renew` and `enhance` as Separate Top-Level Skills
- **Pros**: Mirrors the initial two-skill brainstorm directly as two slash commands (`/renew` and `/enhance`).
- **Cons**: Critical routing and governance collision—`media-studio` already owns `"ses/video/görüntü kalitesini düzelt"` and `Probe -> Plan -> Process -> Verify`; a second top-level skill would double-load on media repair prompts, split quality gates across two skills, add permanent Turn-1 `<skills>` prompt overhead, and risk broad false positives on the generic English verb `"enhance"` (UI, SQL, prompts, performance).
- **Why not**: Rejected because the critical failure mode of split-brain media pipelines and `SKILL_HINTS` double-loading outweighs having a separate `/enhance` command.

### Alternative 2: Split Legacy Games into a Third `renew-game` Skill or Exclude Games from `renew`
- **Pros**: Keeps `renew` scoped strictly to non-game business/CLI/desktop software.
- **Cons**: Leaves classic game ports (DOS, Win32, Flash, SDL1, Python 2 Pygame) homeless because `game-engineering` assumes an active modern stack rather than reviving dead toolchains, CRT non-square pixel aspect ratios (`320x200` `SAR 5:6`), CPU-coupled tick loops, and binary save/asset formats; meanwhile a third `renew-game` skill would duplicate 80% of `renew`'s autopsy, oracle-pinning, and strangler-cutover workflow.
- **Why not**: Rejected in favor of a 4-rule Legacy Game Profile inside `renew` that co-loads `game-engineering` and `media-studio`.

### Alternative 3: Add Legacy Software Modernization into `dependency-upgrade` or `refactoring`
- **Pros**: Avoids adding a 33rd top-level skill.
- **Cons**: Violates the core safety invariant of both existing skills—`refactoring` forbids any observable behavior or platform contract change, and `dependency-upgrade` enforces one-package-at-a-time lockfile bumps on an already-building project. Mixing generational rewrites or dead-runtime ports into either skill would weaken their strict single-change-set guardrails.
- **Why not**: Rejected to preserve the sharp invariants of `refactoring` and `dependency-upgrade`, linking `dependency-upgrade` §2's halt condition cleanly to `renew`.

## Consequences

### Positive
- Closes the exact methodological gap between `dependency-upgrade`, `refactoring`, `reverse-engineer-anything`, and `game-engineering` with a bounded 3–4 question `ask_question` contract after silent codebase autopsy.
- Upgrades `media-studio` and `media_qc.py` from pure decodable A/V production into a complete archival salvage, still-image, and hallucination-guarded enhancement pipeline with deterministic CLI gates (`salvage`, aspect-locked `compare`, `ab-sheet`).
- Preserves clean single-owner routing in `SKILL_HINTS` and zero Turn-1 prompt duplication for media tasks.

### Negative
- Increases the canonical skill count from `32` to `33`, requiring synchronized updates across `README.md`, `CHANGELOG.md`, and `.harness/manifest.json`.
- `media_qc.py` grows by ~560 lines to support hardened container salvage, still-image/EXIF decode and comparison, audio/visual A/B sheets, and non-destructive output staging.

### Risks
- **Risk**: Bare `"renew"` words in developer prompts (`"renew access token"`, `"renew SSL cert"`) or file paths (`"src/renew/service.py"`) could false-trigger `renew`.
  **Mitigation**: Guard `/renew` with path-safe delimiters in `SKILL_HINTS`, require software/legacy qualifiers on natural-language phrases, and enforce negative boundary unit tests in `tests/test_renew_and_media_salvage.py`.
- **Risk**: Generative/neural upscalers could alter facial identity, text legibility, or vocal timbre ("aslını bozma") or leak personal media to external cloud services.
  **Mitigation**: Default Mode 2 enhancement to zero-hallucination mathematical filters, require explicit user opt-in + pinned local-only weights (`GEMINI.md` Rule 12) for neural models, and mandate `media_qc.py ab-sheet` visual inspection via `read_file` before delivery.
