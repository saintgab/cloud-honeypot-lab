import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from detections.detect_user_discovery import detect as user_discovery
from detections.detect_bruteforce import detect as brute_force

start = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
events = []

def add(eventid, ip, session, seconds, **fields):
    events.append({
        "eventid": eventid,
        "src_ip": ip,
        "session": session,
        "timestamp": (start + timedelta(seconds=seconds)).isoformat(),
        **fields,
    })

# Synthetic discovery session
add("cowrie.session.connect", "203.0.113.10", "demo-001", 0)
add("cowrie.login.success", "203.0.113.10", "demo-001", 1, username="root")
add("cowrie.command.input", "203.0.113.10", "demo-001", 2, input="whoami")
add("cowrie.session.closed", "203.0.113.10", "demo-001", 3)

# Synthetic brute-force activity
for i in range(5):
    add("cowrie.login.failed", "198.51.100.23", "demo-002",
        60 + i * 30, username="admin")

assert len(user_discovery(events)) == 1
assert len(brute_force(events)) == 1

output = Path("examples/cowrie-demo.jsonl")
output.write_text(
    "\n".join(json.dumps(event) for event in events) + "\n"
)

print("PASS: Synthetic demo dataset created")
print("PASS: User-discovery alert generated")
print("PASS: Brute-force alert generated")
print(f"Events: {len(events)}")
