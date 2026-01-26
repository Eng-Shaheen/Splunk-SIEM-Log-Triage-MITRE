# Analyst Observations – Splunk SIEM Log Triage

## Alert Context
Splunk analysis identified multiple failed SSH authentication attempts originating from a single external IP address. The activity was detected during routine log triage of Linux authentication logs.

---

## Initial Findings
- Repeated "Failed password" events targeting invalid users
- High frequency of attempts within a short time window
- Pattern consistent with automated brute-force behavior

---

## Correlation Analysis
Further investigation revealed:
- A successful SSH login occurred after multiple failed attempts
- Same source IP was involved in both failed and successful events
- Indicates possible credential compromise

---

## MITRE ATT&CK Assessment
Observed activity maps to the following MITRE ATT&CK techniques:

- **T1110 – Brute Force**  
  Evidence: Multiple failed SSH authentication attempts

- **T1078 – Valid Accounts**  
  Evidence: Successful login following brute-force attempts

- **T1021.004 – Remote Services: SSH**  
  Evidence: SSH used as the access vector

---

## Risk Assessment
Severity: **High**

A successful login after brute-force attempts suggests attacker access to valid credentials, which could lead to:
- Lateral movement
- Privilege escalation
- Persistence mechanisms

---

## Recommended Actions
- Immediately block the source IP at the firewall level
- Force password reset for affected accounts
- Review SSH configuration (disable root login, enforce key-based auth)
- Enable account lockout policies
- Monitor for further suspicious activity

---

## Analyst Notes
This investigation demonstrates a full SOC workflow:
Detection → Triage → Correlation → Threat Classification → Response Recommendation
