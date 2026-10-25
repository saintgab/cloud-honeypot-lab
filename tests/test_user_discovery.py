import unittest

from detections.detect_user_discovery import detect


class TestUserDiscovery(unittest.TestCase):

    def event(self, kind, time, ip="195.3.220.7",
              session="session-001", command=None):
        return {
            "timestamp": f"2026-10-24T09:10:{time:02d}Z",
            "eventid": kind,
            "src_ip": ip,
            "session": session,
            "input": command,
        }

    def test_valid_detection(self):
        events = [
            self.event("cowrie.login.success", 10),
            self.event("cowrie.command.input", 11, command="whoami"),
        ]
        self.assertEqual(len(detect(events)), 1)

    def test_command_before_login(self):
        events = [
            self.event("cowrie.command.input", 10, command="whoami"),
            self.event("cowrie.login.success", 11),
        ]
        self.assertEqual(len(detect(events)), 0)

    def test_different_sessions(self):
        events = [
            self.event("cowrie.login.success", 10, session="A"),
            self.event("cowrie.command.input", 11,
                       session="B", command="whoami"),
        ]
        self.assertEqual(len(detect(events)), 0)

    def test_different_source_ips(self):
        events = [
            self.event("cowrie.login.success", 10),
            self.event("cowrie.command.input", 11,
                       ip="203.0.113.10", command="whoami"),
        ]
        self.assertEqual(len(detect(events)), 0)

    def test_own_traffic_excluded(self):
        events = [
            self.event("cowrie.login.success", 10,
                       ip="127.0.0.1"),
            self.event("cowrie.command.input", 11,
                       ip="127.0.0.1", command="whoami"),
        ]
        self.assertEqual(len(detect(events)), 0)

    def test_unrelated_command(self):
        events = [
            self.event("cowrie.login.success", 10),
            self.event("cowrie.command.input", 11, command="echo hello"),
        ]
        self.assertEqual(len(detect(events)), 0)

    def test_command_after_session_closed(self):
        events = [
            self.event("cowrie.login.success", 10),
            self.event("cowrie.session.closed", 11),
            self.event("cowrie.command.input", 12, command="whoami"),
        ]
        self.assertEqual(len(detect(events)), 0)

    def test_events_arriving_out_of_order(self):
        events = [
            self.event("cowrie.command.input", 11, command="id"),
            self.event("cowrie.login.success", 10),
        ]
        self.assertEqual(len(detect(events)), 1)


if __name__ == "__main__":
    unittest.main()
