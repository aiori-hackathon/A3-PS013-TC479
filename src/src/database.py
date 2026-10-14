"""
database.py - one small local SQLite file holds the whole timeline.

Tables:
  timeline_events  - every parsed log line (the schema from the brief, unchanged)
  detections       - suspicious patterns found by detect.py
  parsing_gaps     - lines we could not understand
  source_notes     - assumptions made per source (year, time zone, skew)

All searches use "?" placeholders, so user input is never pasted into SQL.
"""
import json
import sqlite3

import config

SEVERITIES = ["INFO", "WARN", "HIGH", "CRITICAL"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

SCHEMA = """
CREATE TABLE IF NOT EXISTS timeline_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,     -- ISO-8601: YYYY-MM-DDTHH:MM:SSZ
    source_file   TEXT NOT NULL,
    log_format    TEXT NOT NULL,     -- 'Linux Auth' or 'Nginx Access'
    source_ip     TEXT,
    username      TEXT,
    severity      TEXT CHECK(severity IN ('INFO','WARN','HIGH','CRITICAL')),
    event_summary TEXT NOT NULL,     -- short human-readable description
    raw_log       TEXT NOT NULL      -- the original line, untouched
);
CREATE INDEX IF NOT EXISTS idx_timeline_utc ON timeline_events(timestamp_utc);

CREATE TABLE IF NOT EXISTS detections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    mitre       TEXT,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    source_ip   TEXT,
    username    TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    event_ids   TEXT NOT NULL        -- JSON list of timeline_events ids
);

CREATE TABLE IF NOT EXISTS parsing_gaps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    reason      TEXT NOT NULL,
    raw_line    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_notes (
    source_file TEXT NOT NULL,
    note        TEXT NOT NULL
);
"""


def connect(db_path=None) -> sqlite3.Connection:
    """Open (and if needed create) the database."""
    path = db_path or config.DB_PATH
    if str(path) != ":memory:":
        config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row           # rows behave like dicts: row["username"]
    conn.executescript(SCHEMA)
    return conn


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------
def clear_all(conn) -> None:
    """Remove every row and restart event IDs at 1 (used for a fresh demo run)."""
    with conn:
        for table in ("timeline_events", "detections", "parsing_gaps", "source_notes"):
            conn.execute(f"DELETE FROM {table}")
        conn.execute("DELETE FROM sqlite_sequence")    # resets the AUTOINCREMENT counters



def replace_source(conn, source_file: str, events: list, gaps: list, notes: list) -> None:
    """Store one file's results, replacing anything stored earlier for that same file."""
    with conn:                                 # one transaction: all or nothing
        conn.execute("DELETE FROM timeline_events WHERE source_file = ?", (source_file,))
        conn.execute("DELETE FROM parsing_gaps WHERE source_file = ?", (source_file,))
        conn.execute("DELETE FROM source_notes WHERE source_file = ?", (source_file,))
        conn.executemany(
            "INSERT INTO timeline_events (timestamp_utc, source_file, log_format, source_ip, "
            "username, severity, event_summary, raw_log) VALUES (?,?,?,?,?,?,?,?)",
            [(e["timestamp_utc"], e["source_file"], e["log_format"], e["source_ip"],
              e["username"], e["severity"], e["event_summary"], e["raw_log"]) for e in events])
        conn.executemany(
            "INSERT INTO parsing_gaps (source_file, line_number, reason, raw_line) VALUES (?,?,?,?)",
            [(g["source_file"], g["line_number"], g["reason"], g["raw_line"]) for g in gaps])
        conn.executemany("INSERT INTO source_notes (source_file, note) VALUES (?,?)",
                         [(source_file, n) for n in notes])


def save_detections(conn, detections: list) -> None:
    """Replace all detections, and raise the severity of the events involved."""
    with conn:
        conn.execute("DELETE FROM detections")
        for d in detections:
            conn.execute(
                "INSERT INTO detections (rule, severity, mitre, title, description, source_ip, "
                "username, first_seen, last_seen, event_ids) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (d["rule"], d["severity"], d.get("mitre"), d["title"], d["description"],
                 d.get("source_ip"), d.get("username"), d.get("first_seen"),
                 d.get("last_seen"), json.dumps(d["event_ids"])))
            # Only ever raise a severity (WARN -> HIGH), never lower it.
            for event_id in d["event_ids"]:
                row = conn.execute("SELECT severity FROM timeline_events WHERE id = ?",
                                   (event_id,)).fetchone()
                if row and SEVERITY_RANK[d["severity"]] > SEVERITY_RANK[row["severity"]]:
                    conn.execute("UPDATE timeline_events SET severity = ? WHERE id = ?",
                                 (d["severity"], event_id))


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
def all_events(conn) -> list[dict]:
    rows = conn.execute("SELECT * FROM timeline_events ORDER BY timestamp_utc, id").fetchall()
    return [dict(r) for r in rows]


def search(conn, ip=None, user=None, severity=None, after=None, before=None,
           text=None, flagged_only=False, limit=5000) -> list[dict]:
    """
    Filter the timeline. Every argument is optional.
      severity - one value or a list, e.g. ["HIGH", "CRITICAL"]
      after / before - ISO-8601 UTC strings (inclusive)
      text - free text matched against the summary and the raw line
    """
    sql = "SELECT * FROM timeline_events WHERE 1=1"
    params = []
    if ip:
        sql += " AND source_ip = ?"
        params.append(ip.strip())
    if user:
        sql += " AND username = ?"
        params.append(user.strip())
    if severity:
        values = [severity] if isinstance(severity, str) else list(severity)
        sql += f" AND severity IN ({','.join('?' * len(values))})"
        params.extend(values)
    if after:
        sql += " AND timestamp_utc >= ?"
        params.append(after)
    if before:
        sql += " AND timestamp_utc <= ?"
        params.append(before)
    if text:
        sql += " AND (event_summary LIKE ? OR raw_log LIKE ?)"
        params.extend([f"%{text}%", f"%{text}%"])
    if flagged_only:
        ids = flagged_event_ids(conn)
        sql += f" AND id IN ({','.join('?' * len(ids)) or 'NULL'})"
        params.extend(sorted(ids))
    sql += " ORDER BY timestamp_utc, id LIMIT ?"
    params.append(int(limit))
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_events_by_ids(conn, ids) -> list[dict]:
    ids = list(ids)
    if not ids:
        return []
    rows = conn.execute(
        f"SELECT * FROM timeline_events WHERE id IN ({','.join('?' * len(ids))}) "
        "ORDER BY timestamp_utc, id", ids).fetchall()
    return [dict(r) for r in rows]


def get_detections(conn) -> list[dict]:
    rows = conn.execute("SELECT * FROM detections ORDER BY first_seen, id").fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["event_ids"] = json.loads(d["event_ids"])
        result.append(d)
    return result


def flagged_event_ids(conn) -> set:
    ids = set()
    for d in get_detections(conn):
        ids.update(d["event_ids"])
    return ids


def get_gaps(conn) -> list[dict]:
    rows = conn.execute("SELECT * FROM parsing_gaps ORDER BY source_file, line_number").fetchall()
    return [dict(r) for r in rows]


def get_source_notes(conn) -> dict:
    notes = {}
    for r in conn.execute("SELECT source_file, note FROM source_notes ORDER BY source_file, note"):
        notes.setdefault(r["source_file"], []).append(r["note"])
    return notes


def distinct_values(conn, column: str) -> list:
    """List distinct IPs or usernames for dropdowns (column name is whitelisted)."""
    if column not in ("source_ip", "username", "source_file"):
        raise ValueError("column not allowed")
    rows = conn.execute(f"SELECT DISTINCT {column} FROM timeline_events "
                        f"WHERE {column} IS NOT NULL ORDER BY {column}").fetchall()
    return [r[0] for r in rows]


def source_summary(conn) -> list[dict]:
    """One row per log file: format, event count, first/last time, gap count."""
    rows = conn.execute(
        "SELECT source_file, log_format, COUNT(*) AS events, MIN(timestamp_utc) AS first, "
        "MAX(timestamp_utc) AS last FROM timeline_events GROUP BY source_file ORDER BY source_file"
    ).fetchall()
    gaps = {r[0]: r[1] for r in conn.execute(
        "SELECT source_file, COUNT(*) FROM parsing_gaps GROUP BY source_file")}
    return [dict(r) | {"gaps": gaps.get(r["source_file"], 0)} for r in rows]


def stats(conn) -> dict:
    row = conn.execute("SELECT COUNT(*) AS n, MIN(timestamp_utc) AS first, "
                       "MAX(timestamp_utc) AS last FROM timeline_events").fetchone()
    by_sev = {r["severity"]: r["c"] for r in conn.execute(
        "SELECT severity, COUNT(*) AS c FROM timeline_events GROUP BY severity")}
    return {"events": row["n"], "first": row["first"], "last": row["last"],
            "by_severity": by_sev,
            "detections": conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0],
            "gaps": conn.execute("SELECT COUNT(*) FROM parsing_gaps").fetchone()[0],
            "sources": len(distinct_values(conn, "source_file"))}
