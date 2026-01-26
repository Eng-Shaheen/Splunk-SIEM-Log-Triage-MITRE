# Splunk SIEM Log Triage with MITRE ATT&CK Mapping

## Overview
This project demonstrates hands-on SOC analyst skills using Splunk SIEM to perform log triage, detect SSH brute-force activity, and map observed attacker behavior to the MITRE ATT&CK framework. The lab simulates a real-world incident investigation workflow using Linux authentication logs.

The focus is on detection logic, investigation methodology, and threat classification rather than basic tool usage.

---

## Objectives
- Ingest Linux authentication logs into Splunk SIEM
- Detect SSH brute-force attacks
- Identify attacker source IPs
- Correlate failed and successful login attempts
- Perform timeline-based investigation
- Map detections to MITRE ATT&CK techniques

---

## Environment
- SIEM: Splunk Enterprise
- Log Source: Simulated Linux authentication logs
- Log Type: SSH authentication events
- Platform: Kali Linux

---

## Detection Use Cases
- Multiple failed SSH login attempts from a single source
- Brute-force attempts against invalid users
- Successful authentication following repeated failures
- Timeline correlation of attack activity

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name            | Description |
|-------------|--------------------------|-------------|
| T1110       | Brute Force               | Repeated failed SSH login attempts observed from attacker IPs |
| T1078       | Valid Accounts            | Successful login following brute-force attempts |
| T1021.004   | Remote Services: SSH      | SSH used as the access method |

---

## Sample SPL Queries

### SSH Brute Force Detection (T1110)
```spl
index=main "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
```

### Failed to Successful Login Correlation (T1078)
```spl
index=main ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats values(message) by src_ip
```

### Timeline Investigation
```spl
index=main
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| sort _time
```
---

## Investigation Summary
- Multiple failed SSH login attempts were detected from a single external IP.
- Attempts targeted invalid users, indicating brute-force behavior.
- A successful login was observed after repeated failures.
- Timeline analysis supports a credential compromise scenario.

---

## Skills Demonstrated
- SIEM log ingestion and analysis
- Security event triage
- SPL query development
- MITRE ATT&CK mapping
- Incident investigation workflow

