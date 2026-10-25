import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque

from detections.detect_user_discovery import TEST_IPS

LOGS = Path("data/cowrie/logs")
THRESHOLD = 5
WINDOW = timedelta(minutes=5)


def parse_time(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            return None
        return result.astimezone(timezone.utc)
    except (ValueError, AttributeError, TypeError):
        return None


def detect(events, test_ips=None):
    if test_ips is None:
        test_ips = TEST_IPS

    failures = []

    for event in events:
        if event.get("eventid") != "cowrie.login.failed":
            continue

        ip = event.get("src_ip")
        timestamp = parse_time(event.get("timestamp"))

        if not ip or ip in test_ips or timestamp is None:
            continue

        failures.append((timestamp, ip))

    failures.sort()

    windows = defaultdict(deque)
    alerts = []

    for timestamp, ip in failures:
        attempts = windows[ip]

        while attempts and timestamp - attempts[0] > WINDOW:
            attempts.popleft()

        attempts.append(timestamp)

        if len(attempts) >= THRESHOLD:
            alerts.append({
                "rule": "Repeated SSH Authentication Failures",
                "severity": "medium",
                "mitre": "T1110",
                "timestamp": timestamp.isoformat(),
                "source_ip": ip,
                "failed_attempts": len(attempts),
                "window_minutes": 5,
            })

            attempts.clear()

    return alerts


def main():
    events = []

    for path in sorted(LOGS.glob("cowrie.json*")):
        with path.open() as file:
            for line in file:
                if line.strip():
                    events.append(json.loads(line))

    alerts = detect(events)

    print(f"Brute-force detection alerts: {len(alerts)}")

    for alert in alerts:
        print(json.dumps(alert, indent=2))


if __name__ == "__main__":
    main()
