# GitHub listing - copy/paste kit

## 1. Repository name

```
arixa-forensic-timeline
```

## 2. Title (first line of the README)

```
ARIXA Forensic Timeline - Log Forensics & Incident Timeline Reconstruction Tool (DFIR)
```

## 3. "About" box (GitHub limit: 350 characters)

```
Python DFIR tool that turns raw Linux auth.log and Nginx/Apache access logs into one UTC incident timeline: SHA-256 evidence hashing, chain of custody, time zone/DST/clock-skew correction, MITRE ATT&CK-mapped detections, attack graph, Streamlit dashboard, PDF reports and a guarded Gemini AI copilot.
```

Website field: `https://forensic-timeline-showcase-xwfgup.v2.appdeploy.ai/`

## 4. Topics (GitHub allows 20)

```
digital-forensics dfir incident-response log-analysis forensic-timeline cybersecurity blue-team threat-detection threat-hunting mitre-attack chain-of-custody security-tools soc log-parser timeline-analysis python streamlit sqlite typescript gemini-ai
```

---

## 5. Short description

ARIXA Forensic Timeline is a Python DFIR tool that turns raw Linux auth.log and Nginx/Apache
access logs from many servers into one trustworthy UTC incident timeline. It does four things:

- **Protects the evidence:** every file is hashed with SHA-256 and every action is logged in a
  chain of custody.
- **Fixes time:** it corrects time zones, daylight saving time and clock skew.
- **Detects attacks:** 8 rules mapped to MITRE ATT&CK, from brute force and web exploits to
  lateral movement and privilege escalation.
- **Shows the attack:** a kill chain and an attack graph in an interactive Streamlit dashboard.

It exports PDF incident reports and includes an optional Gemini AI copilot that redacts sensitive
data and validates its answers.

Tested on 3 attack scenarios (16/16 alerts, 0 false positives) and on real public SSH and Nginx
logs. It is also available as a browser-only version.

The full README is in `README.md`.
