"""
report.py - writes the incident report.

Always produces Markdown (output/incident_report.md).
Also produces a PDF if the small 'fpdf2' package is installed.
build_case_bundle() packs the whole case (report, data, evidence) into one ZIP.
"""
import csv
import io
import json
import zipfile

import config
from src import database, evidence

AI_LABEL = "AI-generated - analyst verification required."


# ---------------------------------------------------------------------------
# Rule-based summary (no AI). Also used as the fallback when AI fails.
# ---------------------------------------------------------------------------
def rule_based_summary(conn) -> str:
    detections = database.get_detections(conn)
    s = database.stats(conn)
    if not detections:
        return (f"{s['events']} events from {s['sources']} source(s) were reviewed. "
                "No rule-based detections fired.")
    lines = [f"{s['events']} events from {s['sources']} source(s) were placed on one UTC timeline "
             f"({s['first']} to {s['last']}). {len(detections)} suspicious pattern(s) were found, "
             "in time order:"]
    for d in detections:
        ids = ", ".join(f"#{i}" for i in d["event_ids"][:3])
        more = "..." if len(d["event_ids"]) > 3 else ""
        lines.append(f"- {d['first_seen']} [{d['severity']}] {d['title']} ({d['mitre']}): "
                     f"{d['description']} (events {ids}{more})")
    return "\n".join(lines)


def _md_escape(text) -> str:
    """Stop '|' inside log lines from breaking Markdown tables."""
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def _load_ai_summary():
    if not config.AI_SUMMARY_PATH.exists():
        return None
    try:
        return json.loads(config.AI_SUMMARY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------
def build_markdown(conn) -> str:
    s = database.stats(conn)
    detections = database.get_detections(conn)
    flagged = database.get_events_by_ids(conn, database.flagged_event_ids(conn))
    gaps = database.get_gaps(conn)
    notes = database.get_source_notes(conn)
    manifest = evidence.load_manifest()
    verify = {r["evidence_file"]: r["status"] for r in evidence.verify()}
    timing = json.loads(config.TIMING_PATH.read_text()) if config.TIMING_PATH.exists() else None

    md = []
    md.append("# Incident Report - ARIXA Forensic Timeline (PS-013)\n")
    md.append(f"*Generated {evidence.now_utc_iso()} by ARIXA Forensic Timeline. "
              "All times are UTC. Original logs were not modified; analysis ran on "
              "read-only, hash-verified copies.*\n")

    md.append("## 1. Summary\n")
    md.append(rule_based_summary(conn) + "\n")
    sev = ", ".join(f"{k}: {s['by_severity'].get(k, 0)}" for k in database.SEVERITIES)
    md.append(f"- Events: **{s['events']}**  |  Sources: **{s['sources']}**  |  "
              f"Detections: **{s['detections']}**  |  Parsing gaps: **{s['gaps']}**")
    md.append(f"- Events by severity: {sev}\n")

    md.append("## 2. AI incident narrative (optional)\n")
    ai = _load_ai_summary()
    if ai:
        md.append(f"> **{AI_LABEL}**  Model: `{ai.get('model')}`, generated {ai.get('generated_utc')}. "
                  "Every event ID it cites was checked against the database.\n")
        md.append(ai.get("narrative", "") + "\n")
    else:
        md.append("Not used. The summary above is fully rule-based (the AI helper is optional).\n")

    md.append("## 3. Detections\n")
    if detections:
        md.append("| # | Severity | Rule | MITRE | First seen (UTC) | Last seen (UTC) | IP | User | Details |")
        md.append("|---|---|---|---|---|---|---|---|---|")
        for i, d in enumerate(detections, 1):
            md.append(f"| {i} | {d['severity']} | {_md_escape(d['title'])} | {d['mitre']} | "
                      f"{d['first_seen']} | {d['last_seen']} | {_md_escape(d['source_ip'])} | "
                      f"{_md_escape(d['username'])} | {_md_escape(d['description'])} |")
    else:
        md.append("No detections.")
    md.append("")

    from src import attack_map                       # local import keeps the module order simple
    chain = attack_map.kill_chain(detections)
    reached = [t for t in chain if t["count"]]
    md.append("### MITRE ATT&CK kill chain\n")
    md.append(f"The activity reached **{len(reached)} of {len(chain)}** tactics: "
              + (" -> ".join(t["name"] for t in reached) or "none") + ".\n")
    md.append("| Tactic | ID | Alerts | Worst severity | Techniques |")
    md.append("|---|---|---|---|---|")
    for t in chain:
        md.append(f"| {t['name']} | {t['id']} | {t['count'] or '-'} | {t['severity'] or '-'} | "
                  f"{', '.join(t['techniques']) or '-'} |")
    md.append("")

    md.append("## 4. Timeline of flagged events (UTC)\n")
    md.append("| ID | Time (UTC) | Severity | Source | IP | User | What happened |")
    md.append("|---|---|---|---|---|---|---|")
    for e in flagged:
        md.append(f"| #{e['id']} | {e['timestamp_utc']} | {e['severity']} | {e['source_file']} | "
                  f"{_md_escape(e['source_ip'])} | {_md_escape(e['username'])} | "
                  f"{_md_escape(e['event_summary'])} |")
    md.append("")

    md.append("## 5. Evidence integrity (SHA-256)\n")
    md.append("| Source | Evidence copy | SHA-256 | Size (bytes) | Collected (UTC) | Verify |")
    md.append("|---|---|---|---|---|---|")
    for m in manifest:
        md.append(f"| {m['source_label']} | {m['evidence_file']} | `{m['sha256']}` | "
                  f"{m['size_bytes']} | {m['ingested_utc']} | {verify.get(m['evidence_file'], '?')} |")
    md.append(f"\nChain of custody: `{config.CUSTODY_LOG_PATH.name}` "
              f"({len(evidence.read_custody_log())} entries).\n")

    md.append("## 6. Time normalisation and assumptions\n")
    md.append("Every timestamp was converted to UTC. The following assumptions and "
              "corrections were applied per source:\n")
    for source, items in notes.items():
        md.append(f"- **{source}**")
        for n in items:
            md.append(f"  - {n}")
    md.append("")

    md.append("## 7. Parsing gaps\n")
    md.append(f"{len(gaps)} line(s) could not be parsed and were kept aside (not dropped). "
              f"Full list: `{config.GAPS_PATH.name}`.\n")
    if gaps:
        md.append("| Source | Line | Reason | Raw line |")
        md.append("|---|---|---|---|")
        for g in gaps:
            md.append(f"| {g['source_file']} | {g['line_number']} | {g['reason']} | "
                      f"`{_md_escape(g['raw_line'][:120])}` |")
    md.append("")

    md.append("## 8. Triage time vs manual baseline\n")
    if timing:
        secs = timing["tool_seconds"]
        manual = timing["manual_baseline_minutes"] * 60
        speed = f"about {manual / secs:,.0f}x faster" if secs > 0 else "n/a"
        md.append(f"- Tool: **{secs:.2f} s** to hash, parse, normalise, store and analyse "
                  f"{timing['files']} file(s) / {timing['events']} events.")
        md.append(f"- Manual baseline (estimate from config): **{timing['manual_baseline_minutes']} min**.")
        md.append(f"- Result: {speed} (analyst review time not included).\n")
    else:
        md.append("No timing recorded yet - run an ingest first.\n")

    md.append("## 9. Method (NIST SP 800-86)\n")
    md.append("- **Collection** - logs copied read-only, SHA-256 hashed, manifest + chain of custody.")
    md.append("- **Examination** - two parsers (Linux auth.log, Nginx/Apache access.log); times "
              "normalised to UTC with time-zone, DST and clock-skew handling; gaps recorded.")
    md.append("- **Analysis** - rule-based detections with MITRE ATT&CK labels.")
    md.append("- **Reporting** - this document.\n")
    md.append("*Scope: defensive log analysis only. No live-system access, no malware removal, "
              "not a forensic certification.*")
    return "\n".join(md) + "\n"


# ---------------------------------------------------------------------------
# PDF (optional)
# ---------------------------------------------------------------------------
def _latin1(text: str) -> str:
    """The built-in PDF fonts only know Latin-1, so swap anything else for '?'."""
    return text.encode("latin-1", "replace").decode("latin-1")


def write_pdf(markdown_text: str, path) -> bool:
    """A simple PDF from the Markdown text. Returns False if fpdf2 is not installed."""
    try:
        from fpdf import FPDF
    except ImportError:
        return False
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()
    for raw in markdown_text.splitlines():
        line = _latin1(raw.replace("**", "").replace("`", ""))
        if line.startswith("|---"):
            continue                                       # skip table divider rows
        pdf.set_x(pdf.l_margin)
        if line.startswith("# "):
            pdf.set_font("Helvetica", "B", 15)
            pdf.multi_cell(0, 8, line[2:])
        elif line.startswith("## "):
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 12)
            pdf.multi_cell(0, 7, line[3:])
        elif line.startswith("|"):
            pdf.set_font("Courier", "", 6.5)               # tables in a small fixed-width font
            cells = [c.strip() for c in line.strip("|").split(" | ")]
            pdf.multi_cell(0, 3.4, " | ".join(cells), wrapmode="CHAR")
        else:
            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(0, 4.6, line.lstrip("> ") or " ", wrapmode="CHAR")
    pdf.output(str(path))
    return True


def export(conn=None, pdf=True) -> dict:
    """Write the report files and log the export in the chain of custody."""
    own = conn is None
    conn = conn or database.connect()
    text = build_markdown(conn)
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    config.REPORT_MD_PATH.write_text(text, encoding="utf-8")
    result = {"markdown": config.REPORT_MD_PATH, "pdf": None}
    if pdf and write_pdf(text, config.REPORT_PDF_PATH):
        result["pdf"] = config.REPORT_PDF_PATH
    evidence.log_custody("REPORT_EXPORTED", {
        "markdown": config.REPORT_MD_PATH.name,
        "markdown_sha256": evidence.sha256_file(config.REPORT_MD_PATH),
        "pdf": config.REPORT_PDF_PATH.name if result["pdf"] else None})
    if own:
        conn.close()
    return result


# ---------------------------------------------------------------------------
# Case bundle (one ZIP with everything an analyst needs to hand over)
# ---------------------------------------------------------------------------
def _csv(rows: list) -> str:
    if not rows:
        return ""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


CASE_README = """ARIXA Forensic Timeline - case export
=====================================
incident_report.md / .pdf   the incident report
timeline.csv                every event, UTC, sorted by time (raw_log = original line)
detections.csv              rule-based detections with MITRE ATT&CK labels
parsing_gaps.csv            lines that could not be parsed
evidence_manifest.json      SHA-256, size and collection time of every evidence copy
evidence/                   the read-only evidence copies themselves
chain_of_custody.log        append-only log of every action
Re-hash the files in evidence/ and compare with evidence_manifest.json to confirm integrity.
"""


def build_case_bundle(conn) -> bytes:
    """Return a ZIP (as bytes) of the full case, and record the export in the custody log."""
    out = export(conn)                                   # fresh report (also logged)
    detections = database.get_detections(conn)
    for d in detections:
        d["event_ids"] = " ".join(str(i) for i in d["event_ids"])

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("README.txt", CASE_README)
        z.write(out["markdown"], "incident_report.md")
        if out["pdf"]:
            z.write(out["pdf"], "incident_report.pdf")
        z.writestr("timeline.csv", _csv(database.all_events(conn)))
        z.writestr("detections.csv", _csv(detections))
        z.writestr("parsing_gaps.csv", _csv(database.get_gaps(conn)))
        manifest = evidence.load_manifest()
        z.writestr("evidence_manifest.json", json.dumps(manifest, indent=2))
        for entry in manifest:
            copy = evidence.evidence_path(entry)
            if copy.exists():
                z.write(copy, f"evidence/{entry['evidence_file']}")
        if config.CUSTODY_LOG_PATH.exists():
            z.write(config.CUSTODY_LOG_PATH, "chain_of_custody.log")
    data = buf.getvalue()
    evidence.log_custody("CASE_EXPORTED", {"zip_sha256": evidence.sha256_bytes(data),
                                           "size_bytes": len(data)})
    return data
