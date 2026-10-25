# Detection Engineering — Sigma and Splunk Compatibility

## Detection 001: SSH Login Followed by User Discovery

MITRE ATT&CK: T1033 — System Owner/User Discovery

Python:
- Detects user-discovery commands following a simulated successful SSH login.
- Correlates activity using source IP and session ID.
- Excludes known lab test IPs.
- Includes automated unit tests.

Sigma:
- Uses temporal_ordered correlation.
- Groups by src_ip and session.
- Validated successfully with Sigma CLI.

Splunk:
- Automatic conversion is unsupported by the installed Splunk backend.
- A native SPL implementation is stored in splunk/cowrie_user_discovery.spl.
- The native query has not been executed against Splunk.
- The native query adds a five-minute limit not present in the Python rule.

## Detection 002: Repeated SSH Authentication Failures

MITRE ATT&CK: T1110 — Brute Force

Python:
- Detects five failed logins from one IP within five minutes.
- Uses a sliding time window.
- Includes automated unit tests.

Sigma:
- Uses event_count correlation.
- Groups by src_ip.
- Validated successfully with Sigma CLI.

Splunk:
- Successfully converted to SPL.
- Generated query uses fixed five-minute time buckets.
- Fixed buckets can produce different results from Python sliding windows.
- Query has not been executed against Splunk.

## Deployment Requirements

Before deploying either Splunk query:

1. Ingest Cowrie JSON logs into the appropriate Splunk index.
2. Confirm timestamp extraction into _time.
3. Verify extraction of eventid, src_ip, session, and input fields.
4. Configure exclusions for authorized lab test traffic.
5. Test positive and negative event sequences.
6. Validate alert accuracy and investigate false positives.

## Validation Status

- Python detection rules: automated tests implemented.
- Sigma rules: Sigma CLI validation passed.
- Splunk brute-force rule: conversion successful.
- Splunk user-discovery rule: native SPL created.
- Live Splunk execution: not performed.

## Security Note

Captured Cowrie sessions are untrusted evidence.
Never execute attacker-supplied commands or payloads.
Keep raw logs and session recordings out of the public repository.
