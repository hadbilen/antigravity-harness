# Antigravity Harness v1.2.0 — Antigravity Guard, OS Write Protection & Staging Suite

A major milestone release elevating **Antigravity Harness** from an agentic framework and transpiler into an **OS-governed, tamper-proof, and multi-platform development suite**. v1.2.0 introduces **Antigravity Guard (`agy-guard`)**, a dual-interface (CLI + Desktop GUI) governance companion that hardens the developer environment against unauthorized modifications, enforces atomic rule ingestion gates, tracks upstream ecosystem drift with zero LLM token consumption, and provides instant 1-click state rollback across Linux, macOS, and Windows.

---

### Core Philosophy: Tamper Resistance & Safe Staging

As agentic models grow more capable and autonomous, an overlooked security and reliability risk emerges: **environment mutation drift**. Hallucinating agents, rogue sub-processes, or third-party IDE extensions can inadvertently mutate prompt contracts, disable verification gates, or overwrite customized skills in `~/.gemini/config/`.

Furthermore, external rules imported from disparate platforms must never bypass human review or inject unchecked prompt vulnerabilities. 

**v1.2.0 eliminates these vectors** by locking the configuration at the operating system level, verifying files via cryptographic SHA-256 integrity trees, and requiring all external rules to pass through an atomic **Staging & Promotion Gate** before touching the filesystem.

---

### What's New in v1.2.0

#### 1. Antigravity Guard (`agy-guard` CLI & GUI Suite)

* **Cross-Platform OS Write Protection:**
  * **Linux:** Universal POSIX permission lockdown (`chmod a-w` / `0555` user-space lock) paired with optional ext4/xfs immutable flags (`chattr -R +i`) to make configuration directories impervious to deletion or editing.
  * **macOS:** Native BSD user-immutable flags (`chflags -R uchg` / `nouchg`), providing non-root tamper resistance.
  * **Windows:** NTFS Access Control Lists (`icacls /deny Everyone:(W,D)`) and read-only attributes (`attrib +R /S /D`).
* **Cryptographic File Integrity Monitor (FIM):**
  * Computes deterministic SHA-256 checksums across all constitutional files, skills, subagents, and configurations.
  * Detects modified bytes, unauthorized file additions, or unexpected deletions, generating structured integrity reports.
* **Atomic Snapshot & 1-Click Rollback Engine:**
  * Captures timestamped state snapshots before any rule ingestion or configuration change.
  * Provides instant 1-click restoration (`agy-guard snapshot restore <id>`) to return the environment to a guaranteed clean state.
* **Porter Staging Gate:**
  * Integrates the Porter transpiler into a seamless visual and terminal workflow.
  * Computes Pre-Flight Suitability scores (0–100), flags test-weakening or sycophancy directives, and renders side-by-side split diffs.
  * Implements the **Atomic Promotion Gate**: automatically unlocks destination, writes sanitized rules, recomputes the SHA-256 integrity manifest, and immediately re-engages write protection.
* **Proactive Upstream Auditor Watchdog:**
  * Periodically queries the 7 tracked community repositories (`anti-slop`, `chisle`, `procoder`, `unlazy`, `silk-design`, `everything-claude-code`, `skills`) and Antigravity runtime updates via parallel git head requests.
  * Operates with **zero LLM token expenditure**, alerting the developer to upstream updates before starting a session.

#### 2. Dual Operational Interfaces (Ergonomic CLI + Dark GUI)

* **CLI Ergonomics (`bin/agy-guard`):** Full headless support for scriptability and terminal-first developers:
  * `agy-guard status`: Displays write protection shield, FIM integrity, and active model.
  * `agy-guard lock` / `agy-guard unlock`: Toggles OS-level write protection.
  * `agy-guard verify` / `agy-guard rebaseline`: Audits and updates cryptographic integrity manifests.
  * `agy-guard snapshot [create|list|restore|prune]`: Manages state checkpoints.
  * `agy-guard porter [inspect|stage] <source>`: Audits and ingests rules through the staging gate.
  * `agy-guard upstream check`: Inspects commit heads across the 7 tracked repositories.
  * `agy-guard gui`: Launches the desktop interface.
* **Antislop-Compliant Desktop GUI (`guard/gui.py`):**
  * Built strictly on the Python 3 standard library (`tkinter` / `ttk`) with zero external `pip` dependencies.
  * Adheres to `DESIGN.md` (ENERGY 2 / RHYTHM 2 / Dark Zinc neutral palette) with verified WCAG AA contrast.
  * Features an interactive status header, real-time FIM file table, split diff viewer for external rules, and an asynchronous Upstream Auditor dashboard.

#### 3. Native Cross-Platform Launchers & Installers

* **Native Launchers:** Added `bin/agy-guard` (POSIX shell script with symlink resolution), `bin/agy-guard.bat` (Windows CMD), `bin/agy-guard.ps1` (PowerShell), and `antigravity-guard.desktop` (Linux XDG application menu).
* **Installer Automation:** Updated `install.py` and `install.sh` to automatically install `agy-guard` into `~/.local/bin/` so the command is globally available in the user's shell.

#### 4. Hardened Security & Manifest Preservation

* **Server-Side Request Forgery (SSRF) Protection:** Hardened `porter.py` to block loopback addresses, private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local AWS/GCP metadata endpoints (`169.254.169.254`), and non-standard schemes during URL rule ingestion.
* **Lossless Skill Subfile Packaging:** Extended `.harness/manifest.json` and `porter/manifest.py` to recursively package nested skill scripts, templates, references, and contrast checkers into the canonical manifest without information loss.
* **Goodhart's Invariant Enforcement:** Enhanced `porter/sanitizer.py` to systematically detect, suppress, and label test-weakening directives (`skip`, assertion softening) per constitutional invariants.

---

### Installation & Upgrading

#### Upgrading an Existing Installation

```bash
cd ~/.gemini/antigravity-harness
git pull origin main

# Unix / macOS / Linux
chmod +x install.sh
./install.sh

# Windows / Cross-Platform
python3 install.py
```

#### CLI Verification

Verify Antigravity Guard and the universal harness locally:

```bash
# Check environment security and write protection
agy-guard status

# Run cryptographic file integrity verification
agy-guard verify

# Run automated test suite
python3 -m unittest discover -s tests -v

# Run deterministic invariant verification
python3 scripts/verify_invariants.py
```

---

**Full Changelog:** https://github.com/hadbilen/antigravity-harness/compare/v1.1.0...v1.2.0
