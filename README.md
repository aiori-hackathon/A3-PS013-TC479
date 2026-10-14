# A3-PS013-TC479
ARIXA Forensic Timeline: DFIR tool that rebuilds incident timelines from Linux auth.log and Nginx/Apache logs. SHA-256 chain of custody, UTC normalisation with DST and clock-skew fix, 8 MITRE ATT&amp;CK detections, kill chain and attack graph, Streamlit dashboard, PDF reports and a guarded Gemini AI copilot.

video link : https://youtu.be/ZrGx7xmoWVo


# ARIXA Forensic Timeline

**Log forensics and incident timeline reconstruction tool for DFIR (Digital Forensics & Incident Response).**
Built for the **AIORI-3 Hackathon - Problem Statement PS-013**.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-dashboard-FF4B4B?logo=streamlit&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-timeline-003B57?logo=sqlite&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-C8102E)
![Tests](https://img.shields.io/badge/tests-14%20passing-brightgreen)

**Live demo (runs fully in your browser, no upload to any server):**
https://forensic-timeline-showcase-xwfgup.v2.appdeploy.ai/

---

## About

ARIXA Forensic Timeline turns raw **Linux auth.log** and **Nginx/Apache access logs** from many
servers into **one UTC incident timeline**. It does four things:

- **Protects the evidence:** every file is hashed with SHA-256 and every action goes into a
  chain-of-custody log.
- **Fixes time:** it corrects time zones, daylight saving time and clock skew.
- **Detects attacks:** 8 rules mapped to MITRE ATT&CK.
- **Shows the attack:** a kill chain and an attack graph in an interactive Streamlit dashboard.

It exports a Markdown or PDF incident report. An optional, guarded Google Gemini copilot can
explain the incident in plain English.

It is **defensive and read-only**. It never connects to or changes a live system.

---

## Why it matters

After a breach, analysts receive logs in different formats and time zones, often from
servers whose clocks are wrong. A **3-minute clock drift** is enough to make an attacker's lateral
movement appear *before* the break-in, which hides the real story. ARIXA lines everything up
correctly, proves the evidence was never changed, and points straight at the attack.

---

## Key features

| Feature | What you get |
|---|---|
| **Evidence integrity** | SHA-256 hash, read-only copy, manifest, append-only **chain of custody**, `verify` tamper check |
| **Log parsing** | Linux `auth.log` (SSH, sudo, user changes) and Nginx/Apache combined `access.log`; unreadable lines go to a **parsing-gaps** report, never dropped silently |
| **Time normalisation** | UTC with IANA time zones, **DST**, per-source **clock skew** correction, year inference for syslog |
| **Detections** | 8 transparent rules mapped to **MITRE ATT&CK**, each citing its exact event IDs |
| **Visualisation** | Kill-chain strip, attacker → host → user **attack graph**, brush-to-zoom activity chart |
| **Dashboard** | Filters (text, severity, IP, user, source, time), click-to-pivot event details, drag-and-drop upload, dark/light mode |
| **Reporting** | Incident report (Markdown + PDF), case bundle ZIP, CSV and JSON exports |
| **AI copilot (optional)** | Gemini incident narrative, natural-language search, parser suggestions; PII redaction, prompts logged in custody, cited IDs validated |
| **Validation** | Built-in scorecard plus tests on real public log datasets |

### Detection rules

| Rule | Detects | MITRE ATT&CK |
|---|---|---|
| R1 | SSH brute force / password spraying | T1110 |
| R2 | Successful login after failures | T1078 |
| R3 | Web scanning (404 bursts across 8+ paths) | T1595 |
| R4 | Scan followed by exploitation | T1190 |
| R5 | SQL injection, path traversal, web shell | T1190, T1505.003 |
| R6 | Lateral movement over SSH | T1021.004 |
| R7 | Privilege escalation via sudo | T1548 |
| R8 | Sensitive sudo commands (shadow dump, new user, SSH key, cron, SUID, data staging) | T1003.008, T1136.001, T1098.004, T1053.003, T1548.001, T1005 |

---

## Results

- **Synthetic scenarios:** 3 of 3 reconstructed, **16 of 16 expected alerts, 0 false positives**,
  and every hash verified.
- **Clock-skew proof:** we checked when the attacker's pivot appears under three time views:

  | Time view | Pivot appears | Result |
  |---|---|---|
  | Raw local time | 9 h 32 min before the break-in | missed |
  | UTC, no skew fix | 2 min 5 s before | missed |
  | **UTC with skew fix** | **25 s after** | **detected** |

- **Real public logs** (cross-checked against an independent regex count):
  - LogHub OpenSSH: 2,000 lines, 0 parsing gaps, 9 brute-force IPs found.
  - Elastic Nginx: 51,462 requests and 0 false alarms. A naive 404 rule would flag 624 IPs.
- **Quality:** 14 pytest tests pass. A Python ↔ TypeScript parity test confirms the browser
  version gives identical results.

---

## Quick start

Requires **Python 3.10+**.

```bash
git clone https://github.com/komalganjave32-glitch/A3-PS013-TC479.git
cd A3-PS013-TC479/src
pip install -r requirements.txt

python run.py demo        # ingest 3 sample incidents, detect, verify, write the report
streamlit run app.py      # open the dashboard at http://localhost:8501
```

### Commands

| Command | What it does |
|---|---|
| `python run.py ingest <file-or-folder>` | Hash, copy read-only, parse, convert to UTC, store, detect |
| `python run.py verify` | Re-hash all evidence and print `OK` / `MISMATCH` |
| `python run.py report` | Write `output/incident_report.md` (and `.pdf`) |
| `python run.py demo` | Fresh run on all three sample scenarios |
| `python run.py validate` | Scorecard, real-world test and clock-skew proof (your case is untouched) |
| `python -m pytest -q` | Run the tests |

### Using the dashboard

1. **Add evidence.** Drag `auth.log` / `access.log` files into the sidebar, pick the server's
   time zone and clock skew, and click **Analyse**. Ready-made files are in `sample_uploads/`.
2. **Investigate.** Use the Overview for the kill chain, attack graph and attack chain. Filter in
   the sidebar, drag across the chart to zoom, or click any timeline row to pivot.
3. **Prove it.** The **Validation** tab shows the scorecard and the clock-skew proof. The
   **Evidence** tab re-verifies the hashes.
4. **Report.** Use *Case → Export* to download the report, CSVs, evidence copies and the custody
   log as one ZIP.

### Adding your own logs from the CLI

Set the time zone and skew per source in `config.py` → `SOURCE_SETTINGS`:

```python
"web01/access.log": {"skew_seconds": 0},
"db01/auth.log":    {"timezone": "America/New_York", "skew_seconds": 180},
```

Then run `python run.py ingest my_case/`. Use time zone names like `America/New_York`, never
fixed offsets, so DST stays correct.

### Optional AI copilot (Gemini)

1. Copy `.env.example` to `.env`.
2. Add your key from https://aistudio.google.com/apikey.
3. Restart the dashboard.

The safety measures:

- IPs and usernames are replaced with tokens before anything is sent.
- Only flagged events are sent, never whole logs.
- Every call is logged in the chain of custody with a SHA-256 of the prompt.
- Every event ID the AI cites must exist, or the answer is rejected.
- AI output is labelled *"AI-generated - analyst verification required."*

> **Never commit `.env`** - it is already in `.gitignore`.

---

## Live tamper demo

```bash
python run.py verify      # every file shows OK
```

Edit any copy in `evidence/` (remove read-only first), then run `verify` again. That file now
shows **MISMATCH** and the event is recorded in the chain of custody. The browser version has a
one-click tamper button.

---

## Architecture

```
log files ─► evidence.py ─► parsers.py ─► normalize.py ─► database.py ─► detect.py ─► report.py
             SHA-256 +      auth.log /    UTC, DST,       SQLite         R1-R8 +        Markdown /
             custody log    access.log    clock skew      timeline       MITRE ATT&CK   PDF / ZIP
                            + gaps                                         │
                                                     attack_map.py ◄───────┤
                                                     kill chain + graph    ▼
                                                                    app.py (Streamlit)
                                                                    ai_helper.py (Gemini, guarded)
```

The flow follows **NIST SP 800-86**:

1. Collection (`evidence.py`)
2. Examination (`parsers.py`, `normalize.py`)
3. Analysis (`detect.py`)
4. Reporting (`report.py`)

### Project layout

```
app.py              Streamlit dashboard
run.py              command line (ingest / verify / report / demo / validate)
config.py           time zones, clock skew, rule thresholds, AI settings
src/evidence.py     SHA-256, manifest, chain of custody, verify
src/parsers.py      auth.log + access.log parsers, gap reasons
src/normalize.py    time zone / DST / skew -> UTC
src/database.py     SQLite storage and safe searches
src/detect.py       detection rules R1-R8
src/attack_map.py   MITRE kill chain and attack graph
src/report.py       Markdown / PDF report, case bundle
src/ai_helper.py    optional Gemini copilot with redaction and validation
src/pipeline.py     ingest -> parse -> store -> detect
src/validate.py     scorecard and clock-skew proof
src/realworld.py    real-world dataset test
sample_logs/        3 synthetic attack scenarios
sample_uploads/     ready-to-upload demo logs
real_logs/          public real-world datasets (sources and licences inside)
tests/              pytest tests
```

### Where output is saved

| Path | Contents |
|---|---|
| `evidence/` | Read-only evidence copies, `manifest.json`, `chain_of_custody.log` |
| `output/timeline.db` | SQLite timeline |
| `output/parsing_gaps.jsonl` | Lines that could not be parsed |
| `output/incident_report.md / .pdf` | The incident report |

---

## Tech stack

**Python** · Streamlit · SQLite · pandas · Altair · Graphviz · fpdf2 · zoneinfo/tzdata · hashlib ·
Google Gemini (`google-genai`) · pytest.
**Browser edition:** TypeScript · Vite · Web Crypto API · Intl API. It runs 100% client-side.

## Limitations

- Two log formats only. Other formats are reported as parsing gaps.
- The 8 rules use fixed thresholds.
- Clock skew is one constant per source.
- It is built for a single analyst on one machine.

**Roadmap:** Windows Event Logs, Sigma rules, automatic skew estimation, DuckDB for large logs,
HMAC-signed custody.

## Scope and ethics

Defensive and **read-only**. It does not connect to or change live systems, does not remove
malware, and is not a certified forensic product. The sample data is synthetic (documentation and
private IP ranges). The real-world datasets are public and credited in `real_logs/README.md`.

---

**Keywords:** digital forensics, DFIR, incident response, log analysis, forensic timeline,
SOC, blue team, threat detection, threat hunting, MITRE ATT&CK, chain of custody, SHA-256,
log parsing, UTC normalisation, clock skew, brute force, SQL injection, web shell, lateral
movement, privilege escalation, Python, Streamlit, SQLite, TypeScript, Google Gemini, cybersecurity.
