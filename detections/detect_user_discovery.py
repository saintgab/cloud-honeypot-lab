import json
from pathlib import Path

LOGS = Path("data/cowrie/logs")

from os import getenv

TEST_IPS = {"127.0.0.1", "::1", "172.18.0.1"}
TEST_IPS.update(
    ip.strip()
    for ip in getenv("COWRIE_TEST_IPS", "").split(",")
    if ip.strip()
)

DISCOVERY = {"whoami", "id", "who", "w"}


def detect(events, test_ips=None):
    """Detect user discovery after a successful Cowrie SSH login."""

    if test_ips is None:
        test_ips = TEST_IPS

    events = sorted(
        events,
        key=lambda e: e.get("timestamp", ""),
    )

    authenticated = set()
    alerts = []

    for event in events:
        ip = event.get("src_ip")
        session = event.get("session")

        if not ip or not session or ip in test_ips:
            continue

        key = (ip, session)
        event_type = event.get("eventid")

        if event_type == "cowrie.login.success":
            authenticated.add(key)

        elif event_type == "cowrie.session.closed":
            authenticated.discard(key)

        elif event_type == "cowrie.command.input":
            command = str(event.get("input") or "").strip().lower()

            if key in authenticated and command in DISCOVERY:
                alerts.append({
                    "rule": "SSH Login Followed by User Discovery",
                    "severity": "medium",
                    "mitre": "T1033",
                    "timestamp": event.get("timestamp"),
                    "source_ip": ip,
                    "session": session,
                    "command": command,
                })

    return alerts


def main():
    events = []

    for path in sorted(LOGS.glob("cowrie.json*")):
        for line in path.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))

    alerts = detect(events)

    print(f"Detection alerts: {len(alerts)}")

    for alert in alerts:
        print(json.dumps(alert, indent=2))


if __name__ == "__main__":
    main()
