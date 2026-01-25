# Splunk Log Triage & SSH Brute-Force Detection Lab

## Overview
This project demonstrates hands-on SOC analyst skills using Splunk SIEM to analyze Linux authentication logs. The lab focuses on detecting SSH brute-force activity, investigating attacker IPs, and correlating failed and successful login attempts.

## Objectives
- Ingest Linux authentication logs into Splunk
- Detect failed SSH login attempts
- Identify attacker IP addresses
- Correlate failed attempts with successful logins
- Perform timeline-based investigation

## Environment
- SIEM: Splunk Enterprise
- Log Source: Linux authentication logs
- Log Types: SSH login events
- Platform: Kali Linux

## Detection Use Cases
- Multiple failed SSH login attempts
- Successful login following repeated failures
- IP-based threat investigation
- Time-based event correlation

## Sample SPL Queries

Failed SSH login detection:
```spl
index=main "Failed password"
```
IP-based threat investigation:
```spl
index=main
192.168.1.50
```

## Investigation Summary
- Multiple failed SSH login attempts were detected from a single IP address.
- Failed attempts targeted invalid users, indicating brute-force behavior.
- A successful login was observed after repeated failures.
- Timeline analysis supports a potential credential compromise scenario.

## Skills Demonstrated
- SIEM log analysis
- Security event triage
- SSH brute-force detection
- SPL query development
- Incident investigation workflow
