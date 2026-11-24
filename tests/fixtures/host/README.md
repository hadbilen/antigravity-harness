# Host Hook Payload Fixtures (`tests/fixtures/host/`)

This directory holds reference payloads used to validate `guard/agy_hooks.py` against Antigravity's lifecycle hook events (`PreInvocation`, `PreToolUse`, `Stop`).

## Fixture Provenance: Synthetic vs. Live Host Captures

- **Existing baseline files (`pre_invocation_host.json`, `pre_tool_use_host.json`, `stop_termination_reasons.json`):** Hand-authored **synthetic unit fixtures** used by offline regression tests (`tests/test_w5_evaluation_remediation.py`). Keep these synthetic files separate from recorded live captures so unit test expectations remain deterministic.
- **Recorded live captures (`captured_*.json`, optional):** Real sanitized payloads recorded directly from a live Antigravity build via `AGY_RECORD_HOST_FIXTURES=1`. Never overwrite the synthetic fixtures with unreviewed runtime dumps.

## One-Shot Live Capture Workflow (`AGY_RECORD_HOST_FIXTURES=1`)

To inspect the exact JSON schema your installed Antigravity build sends on `PreInvocation`, `PreToolUse`, and `Stop` (for example, verifying `0`-indexed vs. `1`-indexed `invocationNum`, `transcriptPath`, `workspacePaths`, `toolCall`, and `terminationReason`):

1. **Enable recording for a single session** (either in the shell launching Antigravity CLI/App or temporarily in a test copy of your hook wrapper; `~/.gemini/config/hooks.json` is human-owned per `GEMINI.md` Rule 12):
   ```bash
   AGY_RECORD_HOST_FIXTURES=1 agy
   ```
2. **Trigger all three hook events once** inside a throwaway scratch workspace (submit one prompt, run one read-only tool call, and let the turn complete cleanly).
3. **Inspect the sanitized captures** written atomically under your platform's `guard.paths.state_dir()` (`~/.local/state/plumbwork/host_fixtures/` on Linux, `~/Library/Application Support/plumbwork/host_fixtures/` on macOS, `%LOCALAPPDATA%\plumbwork\host_fixtures\` on Windows; each event overwrites its latest file and silently ignores I/O write errors so live hooks never crash):
   ```bash
   ls -la ~/.local/state/plumbwork/host_fixtures/
   # Expected files when triggered via hooks.json CLI events (pre-invocation / pre-tool-use / stop):
   #   latest_pre-invocation.json
   #   latest_pre-tool-use.json
   #   latest_stop.json
   ```
4. **Disable recording immediately** by closing the temporary `AGY_RECORD_HOST_FIXTURES=1` session (or unsetting the variable) so normal sessions do not write capture files on every hook event.

## Built-In Redaction & Human Review

`_sanitize_host_fixture_payload()` in `guard/hooks/common.py` automatically:
- Replaces values for any key whose normalized name contains `apikey`, `api_key`, `token`, `secret`, `authorization`, `password`, `passwd`, `cookie`, `credential`, `private_key`, or `privatekey` (case-insensitive substring match) with `"<redacted>"`.
- Scrubs inline secret patterns (`Bearer ...`, `ANTIGRAVITY_CSRF_TOKEN=...`, `ghp_`/`github_pat_`, `sk-...`, `AKIA...`) inside string values before truncating strings to `512` characters and lists to `20` items (recursion depth `<= 8`).

Because workspace paths, usernames, or custom environment fields may still appear in captured JSON, **manually inspect and anonymize every field** before copying any live capture into `tests/fixtures/host/captured_<event>.json`.

## Replay & Schema Verification

Replay any captured fixture through the real hook dispatcher in an isolated temporary state directory and throwaway workspace without touching your live config:

```bash
PYTHONPATH=. python3 - <<'PY'
import json, os, tempfile
from pathlib import Path
from unittest import mock
import guard.agy_hooks as agy_hooks

cap = json.loads(Path("~/.local/state/plumbwork/host_fixtures/latest_pre-invocation.json").expanduser().read_text("utf-8"))
payload = dict(cap["payload"])
with tempfile.TemporaryDirectory() as tmp:
    payload["workspacePaths"] = [tmp]
    env = {"PLUMB_GUARD_STATE_DIR": tmp, "PLUMB_GUARD_NOTIFY": "off", "AGY_RECORD_HOST_FIXTURES": "0"}
    with mock.patch.dict(os.environ, env):
        res = agy_hooks.dispatch_hook(cap["hookEventName"], payload)
        print("Event:", cap["hookEventName"], "Keys:", sorted(payload.keys()))
        print("Response:", json.dumps(res, ensure_ascii=False))
PY
```

Run the synthetic fixture & recording regression suite:

```bash
python3 -m unittest tests.test_w5_evaluation_remediation -v
```
