# Security Investigation Report
## AWS Cowrie Honeypot — SSH User Discovery Activity

### 1. Executive Summary

On October 24, 2026, an external source IP connected to an AWS-hosted Cowrie SSH honeypot.

The honeypot recorded a successful simulated SSH login using the root account, followed by execution of the `whoami` command.

Our Python detection engine identified this activity and generated one medium-severity alert.

The observed behavior is consistent with user discovery following SSH access.

No evidence from this session establishes compromise of the underlying EC2 host.

### 2. Investigation Details

- Investigation type: SSH honeypot activity analysis
- Environment: AWS EC2, Ubuntu, Docker, Cowrie
- AWS Region: us-east-2
- Investigation date: October 24, 2026
- Source IP: 195.3.220.7
- Session ID: 5f35bdf62d29
- Simulated username: root
- Observed command: whoami
- Alert severity: Medium
- MITRE ATT&CK: T1033

### 3. Event Timeline

All timestamps are UTC.

| Time | Event | Observation |
|------|-------|-------------|
| 09:10:29 | SSH connection | External source connected to Cowrie |
| 09:10:30 | Login success | Cowrie simulated successful root authentication |
| 09:10:31 | Command execution | Source executed whoami |
| 09:10:31 | Detection alert | Python detection identified user discovery |

The alert timestamp was approximately 09:10:31.369767 UTC.

### 4. Evidence Sources

The investigation used:

- Cowrie JSON security event logs
- Cowrie session identifiers
- Source IP information
- Simulated authentication events
- Captured command events
- Python detection results
- Streamlit detection dashboard

Evidence was collected from the AWS honeypot and archived to private Amazon S3 storage.

SHA-256 verification was performed on the downloaded October 24 evidence archive.

Raw session recordings and original evidence are not included in the public repository.

### 5. Detection Logic

Detection Rule 001 identifies user-discovery activity after a successful simulated SSH login.

The Python implementation:

1. Identifies successful login events.
2. Tracks the source IP and session identifier.
3. Searches for subsequent user-discovery commands.
4. Requires the activity to belong to the same session.
5. Excludes known authorized test traffic.
6. Prevents correlation after a recorded session closure.

Supported discovery commands include:

- whoami
- id
- who
- w

The observed command was whoami.

### 6. MITRE ATT&CK Mapping

Technique: T1033 — System Owner/User Discovery

The whoami command requests information about the current user account.

In this case, it was executed after a simulated SSH login.

The behavior matches the user-discovery technique, although the available evidence does not establish the operator's identity or broader objectives.

### 7. Investigation Assessment

The activity represents external interaction with the SSH honeypot.

The successful authentication event was simulated by Cowrie.

The subsequent whoami command indicates an attempt to identify the current user context.

The observed sequence is suspicious in a honeypot environment and supports a medium-severity detection.

The available evidence does not establish:

- Compromise of the underlying EC2 host
- Privilege escalation on the actual Ubuntu server
- Malware execution
- Data exfiltration
- Attribution to a specific threat actor

### 8. Security Controls

The environment uses multiple controls to reduce the risk of exposing a honeypot to the internet.

These include:

- HAProxy handling public SSH connections
- Real Ubuntu SSH service and socket masked
- AWS Systems Manager for administration
- Cowrie running inside a restricted Docker container
- All Linux capabilities dropped
- Privilege escalation restricted
- Internal Docker networking
- No published Docker container ports
- Private S3 evidence storage
- Daily automated backups
- SHA-256 integrity verification
- SNS backup-failure notifications

### 9. Detection Validation

The user-discovery Python detector has eight automated unit tests.

Tests cover:

- Valid discovery detection
- Commands occurring before login
- Different SSH sessions
- Different source IP addresses
- Authorized test traffic
- Unrelated commands
- Commands after session closure
- Out-of-order event input

The tests passed.

A corresponding Sigma temporal_ordered rule also passed Sigma CLI validation.

The installed Splunk backend does not support conversion of temporal_ordered correlation.

A native Splunk SPL implementation was created but has not been executed in a live Splunk environment.

### 10. Recommendations

1. Continue collecting Cowrie telemetry while operating the lab.
2. Preserve original logs and session recordings securely.
3. Maintain the existing container isolation controls.
4. Review detection alerts for suspicious command sequences.
5. Periodically verify S3 evidence backups.
6. Validate SIEM queries against ingested test events before deployment.
7. Avoid attributing activity to an individual based only on an IP address.

### 11. Conclusion

The investigation demonstrates successful collection, preservation, and analysis of SSH honeypot telemetry.

A suspicious session was reconstructed using authentication and command events.

A tested Python detection identified user discovery and generated a medium-severity alert.

This case demonstrates practical cloud security monitoring, event correlation, detection engineering, and security investigation skills.

The case is closed for portfolio analysis purposes, not as a claim that the external activity has been remediated.
