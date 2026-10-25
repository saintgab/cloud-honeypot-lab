import json
from pathlib import Path
from collections import Counter

LOG_FILE = Path("cowrie.json")

if not LOG_FILE.exists():
    print("ERROR: cowrie.json not found.")
    raise SystemExit(1)

events = []

with LOG_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

event_counts = Counter(
    event.get("eventid", "unknown")
    for event in events
)

unique_ips = {
    event["src_ip"]
    for event in events
    if event.get("src_ip")
}

sessions = {
    event["session"]
    for event in events
    if event.get("session")
}

commands = [
    event for event in events
    if event.get("eventid") == "cowrie.command.input"
]

print("\n===== COWRIE THREAT ANALYSIS =====")
print(f"Total Events: {len(events)}")
print(f"Unique Source IPs: {len(unique_ips)}")
print(f"Unique Sessions: {len(sessions)}")

print(
    f"Successful Logins: "
    f"{event_counts['cowrie.login.success']}"
)

print(
    f"Failed Logins: "
    f"{event_counts['cowrie.login.failed']}"
)

print(f"Commands Captured: {len(commands)}")

print("\n===== COMMAND HISTORY =====")

for event in commands:
    print(
        f"{event.get('timestamp')} | "
        f"{event.get('input')}"
    )

print("\n===== EVENT TYPES =====")

for event_type, count in event_counts.most_common():
    print(f"{event_type}: {count}")

print("\nAnalysis complete.")
