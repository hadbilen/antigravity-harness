#!/usr/bin/env python3
"""
guard.py — Antigravity Guard (agy-guard) CLI & GUI Root Launcher
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Usage:
  python3 guard.py status                     # Protection, integrity and lease status
  python3 guard.py lock [--env <id>|--all]    # Write-protect governance seams
  python3 guard.py unlock [--env <id>|--all]  # Remove protection (human confirmation)
  python3 guard.py verify [--env <id>|--all]  # SHA-256 integrity check (FIM)
  python3 guard.py rebaseline [--env <id>]    # Accept current state as trusted (human confirmation)
  python3 guard.py env list|detect|add|remove|policy   # Multi-environment registry
  python3 guard.py request-unlock --env <id>  # Time-bounded lease (human approval, auto-relock)
  python3 guard.py lock-complete [--env <id>] # End a lease early and re-lock
  python3 guard.py lease-tick                 # Internal: expire due leases (auto-relock watcher)
  python3 guard.py drift [--env <id>]         # Drift across environments
  python3 guard.py self-audit [--json|--strict] # Harness meta-consistency audit
  python3 guard.py snapshot create|list|restore|prune  # Governance snapshots
  python3 guard.py porter inspect|stage <path/url>     # Porter inspection and staging gate
  python3 guard.py upstream check             # Tracked upstream repositories
  python3 guard.py test-boundary snapshot|verify|run-reproducible  # Test trust boundary
  python3 guard.py provenance generate|status # Execution provenance manifest
  python3 guard.py startup enable|disable|status # Boot sentinel registration
  python3 guard.py boot-check                 # Headless boot verification and lock
  python3 guard.py doctor [--fix]             # Health check (permissions, legacy state, grants)
  python3 guard.py notify status|enable|disable|quiet|normal  # Desktop notifications
  python3 guard.py gui                        # Launch desktop GUI
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add repository root to python path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from guard.cli import main

if __name__ == "__main__":
    sys.exit(main())
