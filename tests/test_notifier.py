"""
tests/test_notifier.py — Test Low-Frequency Guard Notifier
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from guard.notifier import GuardNotifier, NotificationSeverity


class TestGuardNotifier(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_file = Path(self.temp_dir.name) / ".notify_cache.json"
        self.notifier = GuardNotifier(cache_file=self.cache_file, enabled=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_disabled_notifier_blocks_all(self):
        disabled_notifier = GuardNotifier(cache_file=self.cache_file, enabled=False)
        self.assertFalse(disabled_notifier.can_send(NotificationSeverity.CRITICAL, "T", "M"))
        self.assertFalse(disabled_notifier.notify("T", "M", severity=NotificationSeverity.CRITICAL))

    def test_quiet_mode_permits_critical_only(self):
        quiet_notifier = GuardNotifier(cache_file=self.cache_file, enabled=True, quiet_mode=True)
        self.assertFalse(quiet_notifier.can_send(NotificationSeverity.INFO, "Info", "Details"))
        self.assertFalse(quiet_notifier.can_send(NotificationSeverity.WARNING, "Warn", "Details"))
        self.assertTrue(quiet_notifier.can_send(NotificationSeverity.CRITICAL, "Alert", "Critical!"))

    def test_critical_has_zero_cooldown(self):
        self.assertTrue(self.notifier.can_send(NotificationSeverity.CRITICAL, "Crit", "Msg"))
        with patch("sys.stderr.write"):
            self.assertTrue(self.notifier.notify("Crit", "Msg", severity=NotificationSeverity.CRITICAL))
            # Critical can send immediately again
            self.assertTrue(self.notifier.can_send(NotificationSeverity.CRITICAL, "Crit", "Msg"))

    def test_warning_cooldown_and_cache_persistence(self):
        with patch("sys.stderr.write"):
            # First send should succeed
            res1 = self.notifier.notify("Test Warning", "Something is stale", severity=NotificationSeverity.WARNING)
            self.assertTrue(res1)

            # Second send immediately after should be suppressed by cooldown
            res2 = self.notifier.notify("Test Warning", "Something is stale", severity=NotificationSeverity.WARNING)
            self.assertFalse(res2)

            # Cache file should exist and record the timestamp
            self.assertTrue(self.cache_file.exists())
            cache_data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            self.assertIn("last_sent", cache_data)
            self.assertGreater(len(cache_data["last_sent"]), 0)

            # A new notifier instance sharing the cache file should also respect the cooldown
            new_notifier = GuardNotifier(cache_file=self.cache_file, enabled=True)
            self.assertFalse(new_notifier.can_send(NotificationSeverity.WARNING, "Test Warning", "Something is stale"))

    def test_force_flag_bypasses_cooldown(self):
        with patch("sys.stderr.write"):
            self.notifier.notify("Test", "Message", severity=NotificationSeverity.INFO)
            self.assertFalse(self.notifier.can_send(NotificationSeverity.INFO, "Test", "Message"))
            # Force sends regardless of cooldown
            res = self.notifier.notify("Test", "Message", severity=NotificationSeverity.INFO, force=True)
            self.assertTrue(res)

    def test_custom_cooldown_seconds(self):
        with patch("sys.stderr.write"):
            # Set short custom cooldown of 1 second
            self.assertTrue(self.notifier.notify("Title", "Body", key="custom_key", cooldown_seconds=1))
            self.assertFalse(self.notifier.can_send(NotificationSeverity.INFO, "Title", "Body", key="custom_key", cooldown_seconds=1))

            time.sleep(1.05)
            self.assertTrue(self.notifier.can_send(NotificationSeverity.INFO, "Title", "Body", key="custom_key", cooldown_seconds=1))


if __name__ == "__main__":
    unittest.main()
