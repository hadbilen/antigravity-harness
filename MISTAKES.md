# Failure Log (MISTAKES.md)

This log records unexpected failures, broken contracts, or user corrections across the Antigravity engineering environment. Entries are prepended chronologically.

Per Rule 10 of the Antigravity Constitution, each entry must contain the following four mandatory fields:
1. **Date & Incident:** Summary of what broke.
2. **Root Cause:** What flawed assumption or missing validation triggered the defect?
3. **Impact:** What was disrupted or regressed?
4. **Preventive Invariant:** Concrete rule or automated guard to prevent recurrence.

*(Any failure pattern occurring 3 times must be promoted to permanent constitutional rules.)*

---

<!-- Entries are prepended below this line -->

### 2026-09-22: Guard and Porter Claims Outran What the Code Enforced
- **Date & Incident:** Five external audit reports (121 validated findings) showed that the live Guard install protected almost nothing (symlinked seams, lock followed links, 0777 source tree), that `--auto-approve` let an agent approve its own unlock, that baselines and snapshots lived inside the tree they protected (snapshots copied token-bearing `config.json`), that the lease never relocked on its own, and that "lossless" export dropped support files and agents. README/CHANGELOG stated tamper-resistance, Merkle trees and SSRF immunity that did not exist.
- **Root Cause:**
  1. Security properties were described from intent, not verified against a live install or an adversarial test.
  2. Tests asserted exit codes like `(0, 1)` or hex literals instead of the behaviour, so regressions passed.
  3. The self-audit checked the shape of files, not whether documented commands, counts and ratios were true.
- **Impact:** Governance files were writable by any same-user process while the status output said PROTECTED; users could not trust the README, the self-audit or the release notes.
- **Preventive Invariant:**
  1. Every protection claim needs an end-to-end test against a real temporary tree (`tests/test_protection.py`), and the README must state the threat model (same-user lock is advisory).
  2. Administration actions require a human (`guard/approval.py`); no flag may bypass it (GEMINI.md Rule 12).
  3. `meta_audit --strict` parses every README `agy-guard` example, checks numeric claims, export parity by content and the DESIGN.md measured-contrast table; CI blocks on any warning.

### 2026-09-19: Porter Remote Fetch SSRF, Incomplete Manifest Subfiles, and Sanitizer Bypass
- **Date & Incident:** GPT external architectural audit identified SSRF exposure in `porter.py fetch_target_content()`, loss of skill subfiles (scripts, references, assets) in `ManifestEngine`, incomplete sanitization leaving test-weakening directives intact, and platform-specific hardcoded `python3 ~/.gemini/config/...` in hooks.
- **Root Cause:**
  1. `fetch_target_content()` performed raw `urllib.request.urlopen` without socket DNS IP resolution against private/loopback/link-local CIDR ranges.
  2. `build_manifest()` only ingested root `SKILL.md` files without traversing nested subdirectories.
  3. `sanitize_for_import()` only stripped sycophancy patterns, ignoring `TEST_WEAKENING_PATTERNS`.
  4. `hooks.json` assumed a Unix environment and fixed `~/.gemini/config/` path.
- **Impact:** Skills with nested scripts or assets (`silk-design`, `unlazy`, `upstream-auditor`, `antislop-human`) lost 76 auxiliary files in canonical manifest export; remote URL inspection could theoretically query internal network resources; cross-platform portability on Windows broke.
- **Preventive Invariant:**
  1. Any remote URL ingestion function must resolve hostnames to IP addresses and block private/loopback/link-local ranges before issuing requests (`_validate_safe_url`).
  2. Canonical manifest compilers must recursively bundle all skill subfiles (`subfiles: Dict[str, str]`).
  3. Sanitizers must actively neutralize detected invariant violations rather than solely raising audit warnings.
  4. Machine-enforced invariant verification (`scripts/verify_invariants.py`) must be executed prior to any release delivery.

