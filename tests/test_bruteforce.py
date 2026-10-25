import unittest
from datetime import datetime, timedelta, timezone

from detections.detect_bruteforce import detect


class TestBruteForce(unittest.TestCase):

    def event(self, seconds, ip="198.51.100.10",
              kind="cowrie.login.failed"):
        timestamp = datetime(
            2026, 10, 24, tzinfo=timezone.utc
        ) + timedelta(seconds=seconds)

        return {
            "timestamp": timestamp.isoformat(),
            "eventid": kind,
            "src_ip": ip,
        }

    def test_five_failures_trigger_alert(self):
        events = [self.event(i * 30) for i in range(5)]
        self.assertEqual(len(detect(events)), 1)

    def test_four_failures_no_alert(self):
        events = [self.event(i * 30) for i in range(4)]
        self.assertEqual(len(detect(events)), 0)

    def test_failures_outside_window(self):
        events = [self.event(i * 301) for i in range(5)]
        self.assertEqual(len(detect(events)), 0)

    def test_different_ips_not_combined(self):
        events = [
            self.event(i * 10, ip=f"198.51.100.{i+1}")
            for i in range(5)
        ]
        self.assertEqual(len(detect(events)), 0)

    def test_known_test_ip_excluded(self):
        events = [
            self.event(i * 10, ip="127.0.0.1")
            for i in range(5)
        ]
        self.assertEqual(len(detect(events)), 0)

    def test_successful_logins_ignored(self):
        events = [
            self.event(i * 10, kind="cowrie.login.success")
            for i in range(5)
        ]
        self.assertEqual(len(detect(events)), 0)

    def test_out_of_order_events(self):
        events = [self.event(i * 30) for i in range(5)]
        self.assertEqual(len(detect(list(reversed(events)))), 1)

    def test_two_separate_thresholds(self):
        events = [self.event(i * 10) for i in range(10)]
        self.assertEqual(len(detect(events)), 2)


if __name__ == "__main__":
    unittest.main()
