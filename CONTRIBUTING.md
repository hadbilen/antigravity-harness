# Contributing

Plumbwork is maintained by its owner. Suggestions and pull requests are welcome, and the maintainer decides what is merged.

## How contributions are handled

- **Maintainer's discretion.** A pull request may be accepted, changed, or declined. Merged code may later be modified, reverted, or removed like any other code in the repository.
- **License.** Contributions are accepted under the repository's MIT license (see `LICENSE`).
- **Open an issue first** for anything larger than a small fix, so the direction can be agreed before you invest time.

## Before you open a pull request

Run the same gates CI runs:

```bash
python3 -m compileall -q guard porter installers skills tests scripts install.py porter.py guard.py
python3 -m unittest discover -s tests -v
python3 scripts/verify_invariants.py --all
python3 scripts/meta_audit.py --all --strict
python3 porter.py manifest --check
python3 scripts/build_plugins.py --out /tmp/plumbwork-plugins-check --validate --zip
```

- Existing tests may be **extended, never weakened**: do not relax, skip, or delete assertions to make a change pass (constitution Rule 9). If a contract genuinely changes, explain why in the pull request.
- Keep the core dependency-free (Python standard library only, Python 3.10+).
- Governance changes (`GEMINI.md`, `skills/`, `agents/`) must keep `meta_audit --all --strict` at zero findings.
- Default installs remain Flat Layout in `v3.0.0`; opt-in Hybrid Layout (`--plugins`) and the 4 standalone domain plugin packs (`guard/plugins.py`, `guard/plugin_assets/*.svg`, `scripts/build_plugins.py`) must remain standalone-clean, pass `scripts/build_plugins.py --validate --zip`, and preserve the `PreToolUse` `agy plugin` security boundary (harness packs OS-locked and gated behind `force_ask`; third-party plugins exempt).

## CI and trust

Workflow runs for pull requests from forks wait for the maintainer's approval. For external pull requests, the CI result is advisory: the maintainer reviews the diff before approving a run or merging, paying particular attention to `tests/`, `.github/`, `scripts/`, and `guard/__init__.py`. Do not expect a green check alone to get a change merged.

## Reporting security issues

Please do not open a public issue for a vulnerability. Contact the maintainer privately through GitHub (the repository owner's profile) and allow time for a fix before disclosure.
