# Native agent dispatch

Use this contract whenever orchestrated mode has two or more independent `READY` leaves. Unlazy records native launches; the host creates the agent sessions.

For one wave, every native launch call and every `start` record must finish before the first wait, join, result read, or return record.

## Open and seal a launch wave

Claim every leaf first. Partition more `READY` leaves into later waves when they exceed the host's current concurrency limit. Then open one wave with the exact ids:

```text
node <unlazy-dir>/scripts/dispatch-check.mjs open --scope <scope> --wave ready-1 --leaf leaf-1.1.1 --leaf leaf-1.1.2
```

For each leaf, call the host's native nonblocking launch tool and record the opaque, nonsecret handle it returns:

```text
node <unlazy-dir>/scripts/dispatch-check.mjs start --scope <scope> --wave ready-1 --leaf leaf-1.1.1 --handle <host-agent-id-1>
node <unlazy-dir>/scripts/dispatch-check.mjs start --scope <scope> --wave ready-1 --leaf leaf-1.1.2 --handle <host-agent-id-2>
```

Seal the wave before waiting for any result:

```text
node <unlazy-dir>/scripts/dispatch-check.mjs seal --scope <scope> --wave ready-1
```

Seal fails until every declared leaf has a distinct start handle. `return` fails before seal. These refusals catch the serial pattern where a driver launches one leaf, waits for it, and only then launches the next.

When a native agent finishes, record the return before parent re-verification:

```text
node <unlazy-dir>/scripts/dispatch-check.mjs return --scope <scope> --wave ready-1 --leaf leaf-1.1.1
```

A return records scheduler completion, including a failed worker result. It does not mark the leaf `VERIFIED`; the parent still runs the leaf gates and reviews manual evidence.

Check the finished wave with:

```text
node <unlazy-dir>/scripts/dispatch-check.mjs status --scope <scope> --wave ready-1
```

`status` exits `0` only after every declared leaf returned. Dispatch state and timestamps live in `.unlazy/<scope>/dispatch.json`; lifecycle events also append to the scope status log. The atomic state transition is authoritative: if the later audit-log append is refused, the transition command still succeeds and prints a bounded warning that the state was committed. Inspect state before deciding what to do next; do not blindly repeat the transition.

The state loader requires string ids, handles, and abandonment reasons plus a possible transition history: returns require an all-started sealed wave, terminal timestamps must exist and follow prior transitions, and a fully returned wave must be complete. Hand-editing an impossible terminal state fails closed. The primary `gate-check.mjs --scope <scope>` reduction includes this aggregate state and cannot print `ALL MET` while a wave is open, sealed, abandoned, or invalid.

## Codex adapter

[Current Codex releases support parallel subagents](https://developers.openai.com/codex/agent-configuration/subagents). Use the native subagent tools available in the host. When the tools are named `spawn_agent` and `wait_agent`, follow this exact order:

1. call `spawn_agent` once for each leaf in the open wave
2. record each returned agent id with `dispatch-check start`
3. seal the wave
4. call `wait_agent` only after seal
5. record each completion with `dispatch-check return`, then reverify it

Do not use `codex exec` as a substitute. It creates a separate CLI process rather than a native subagent owned and visible through the current host.

## Claude Code adapter

[Claude Code background subagents run concurrently](https://code.claude.com/docs/en/sub-agents#run-subagents-in-foreground-or-background). Launch every leaf as a background `Agent` task, record every returned task or agent id, and seal before reading any result. Do not issue foreground Agent calls one after another.

For a large regular fan-out, prefer a [Dynamic Workflow](https://code.claude.com/docs/en/workflows). Its `pipeline()` primitive runs agent work across a list under the runtime's concurrency limit. The workflow must still preserve the same semantic barrier: schedule the whole fan-out before collecting its first result. Open a CLI dispatch wave only when the workflow surface exposes a distinct native handle for each agent. Otherwise retain the generated workflow script and runtime progress as branch evidence without claiming a CLI-verified wave.

Do not use `claude -p` as a substitute for an available native background Agent or workflow. A shell process farm loses the current session's native scheduling and observability.

## Antigravity adapter

Antigravity supports three native fan-out mechanisms depending on leaf coupling and isolation needs:

### 1. Subagent waves (`invoke_subagent`)
Use `invoke_subagent` (`TypeName: "self"`, `Model: "inherit"`) with strictly disjoint file ownership across parallel leaves:

1. open the wave with `dispatch-check.mjs open` for all `READY` leaves in the wave
2. call `invoke_subagent` (`TypeName: "self"`, `Model: "inherit"`) once per leaf in the open wave, assigning disjoint write scopes
3. record each returned `conversationId` handle with `dispatch-check.mjs start`
4. seal the wave with `dispatch-check.mjs seal` before awaiting subagent completion notifications
5. record each subagent return with `dispatch-check.mjs return`, then run parent re-verification gates

### 2. Swarm worktree waves (`swarm` / `native_swarm`)
Use `swarm` (`~/.gemini/antigravity/builtin/skills/native_swarm/SKILL.md`) when parallel coding leaves benefit from isolated git working copies (`workspace:"share"` or `"branch"`) and a persistent `#seq` message board:

1. open the wave with `dispatch-check.mjs open` and claim every leaf's `OWNS:` lease via `gate-check.mjs --claim`
2. spawn each author leaf via `swarm{action:"add", name:<leaf-role>, workspace:"share", brief:<OWNS + GATES contract>}` (use `workspace:"share"` or `"branch"` for writers, `workspace:"inherit"` for read-only/verifier leaves, and leave `model` unset by default for all workers and verifiers unless user-requested or quota-exhausted, honoring the `A1` three-tier customization policy on governance targets: approved flagship models `allow`, Pro-class Orchestrators `force_ask`, Flash workers `deny` per `.agents/rules/harness-maintainer.md` Rules 15f & 17; load `swarm_pane` to maintain `.system_generated/swarm/plan.json` for the Swarm UI Overview instead of adding a default `narrator`, adding `narrator` only when requested by name, and add `monitor` using `swarm_monitor` with `CronExpression: "*/3 * * * *"` and `IsDaemon: true` when present in the active skill list, outside `dispatch-check` leaf leases)
3. record each spawned member identifier with `dispatch-check.mjs start` and seal the wave with `dispatch-check.mjs seal` before waiting on `swarm_wait` or reading results with `read_board` (because `post_message`, `read_board`, and `swarm_wait` arrive on the turn after the first `swarm{action:"add"}`, launch every leaf in the wave and seal before ending the launch turn)
4. on `#seq` completion posts, record `dispatch-check.mjs return`, merge or cherry-pick the validated `workspace:"share"` commit into the parent workspace *before* calling `swarm{action:"kill"}` (which deletes the share worktree), then run `gate-check.mjs --reverify` and `gate-check.mjs --release --leaf ...` before opening dependent waves

Note the evidence boundary: `workspace:"share"` gives each author leaf its own working tree, while `gate-check.mjs` leases and parent `--reverify` remain responsible for logical `OWNS:` non-overlap and integrated verification.

### 3. Dynamic workflows (`run_workflow`) & native lifecycle hooks
When orchestrating larger waves through `run_workflow`, keep workflow scripts strictly as orchestration glue (`agent`, `parallel`, `pipeline`, `phase`, `trajectory`, `call_tool`), never execute child processes (`subprocess`, `os.system`) or direct filesystem writes that bypass `PreToolUse`, default `model` to `"inherit"`, and never downgrade `model` to `"flash"` or `"flash_lite"` when modifying customization or governance files (`.agents/rules/harness-maintainer.md` Rules 15e & 17).

Never run `references/unlazy/scripts/install-hooks.mjs` in Antigravity: `references/unlazy/scripts/install-hooks.mjs` configures Claude Code `.claude/settings*.json` Stop hooks exclusively, whereas Antigravity enforces lifecycle gates (`SessionStart`, `PreInvocation`, `PreToolUse`, `Stop`) natively via `hooks.json` and `~/.local/share/plumbwork/runtime/guard/agy_hooks.py` across `invoke_subagent`, `swarm`, `run_workflow`, and board/messaging/schedule tools.

## Failure and fallback

If a native launch fails before returning a handle, leave the wave open, fix the launch problem, and retry that leaf. Do not seal a partial wave. If recovery is impossible, preserve the audit trail instead of inventing a handle or deleting state:

```text
node <unlazy-dir>/scripts/dispatch-check.mjs abandon --scope <scope> --wave ready-1 --reason "<bounded nonblank reason>"
```

An abandoned wave is terminal and `status` exits `1`. The Stop hook does not block on it, but emits a bounded `HANDOFF REQUIRED` message naming the wave without copying its free-form reason into the privileged host message. Surface the reason from dispatch state in the final handoff. If the host has no nonblocking launch capability, record the limitation in `PLAN.md`, execute a declared sequential fallback, and do not open or describe a parallel wave.

Opening a wave is an execution claim. Do not invent handles, record a foreground result as a start, or call simultaneous work proved merely because commands ran quickly.

## Evidence boundary

The launch barrier proves that the host accepted every native start before the driver accepted a return. It does not prove worker honesty, exact CPU overlap, filesystem isolation, or successful integration. Leases, parent re-verification, and branch gates remain separate requirements.
