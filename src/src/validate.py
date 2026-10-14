"""
validate.py - proves the tool works, with numbers.

  run()               re-runs the three built-in scenarios in a THROWAWAY case (temporary
                      folders; your real evidence and timeline are never touched) and
                      compares what was found with what should be found.
  clock_comparison()  shows scenario 3 three ways - raw local time, UTC without the clock
                      fix, UTC with the clock fix - to prove why time normalisation matters.

Run from the command line:   python run.py validate
The dashboard calls:         python -m src.validate --json   (a separate process)
"""
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

import config
from src import evidence, normalize, parsers

# What each built-in scenario SHOULD produce (see sample_logs/README.md).
EXPECTED = {
    "scenario1_ssh_bruteforce": {
        "title": "SSH brute force",
        "rules": ["R1-brute-force", "R2-successful-brute-force", "R7-privilege-escalation",
                  "R8-T1003.008", "R8-T1136.001"],
        "events": 32, "gaps": 3,
    },
    "scenario2_web_exploit": {
        "title": "Web app exploit",
        "rules": ["R3-web-scan", "R4-scan-then-exploit", "R5-sqli", "R5-lfi", "R5-webshell"],
        "events": 26, "gaps": 2,
    },
    "scenario3_multi_timezone": {
        "title": "Multi-time-zone breach",
        "rules": ["R3-web-scan", "R4-scan-then-exploit", "R5-webshell", "R6-lateral-movement",
                  "R7-privilege-escalation", "R8-T1005"],
        "events": 27, "gaps": 1,
    },
}

RULE_NAMES = {
    "R1-brute-force": "Brute force", "R2-successful-brute-force": "Successful brute force",
    "R3-web-scan": "Web scan", "R4-scan-then-exploit": "Scan then exploit",
    "R5-sqli": "SQL injection", "R5-lfi": "Path traversal", "R5-webshell": "Web shell",
    "R6-lateral-movement": "Lateral movement", "R7-privilege-escalation": "Privilege use",
    "R8-T1003.008": "Read /etc/shadow", "R8-T1136.001": "Account created", "R8-T1005": "Database dumped",
}

PATH_SETTINGS = ("EVIDENCE_DIR", "OUTPUT_DIR", "MANIFEST_PATH", "CUSTODY_LOG_PATH", "DB_PATH",
                 "GAPS_PATH", "TIMING_PATH", "AI_SUMMARY_PATH", "REPORT_MD_PATH", "REPORT_PDF_PATH",
                 "UPLOADS_DIR")


def _point_config_at(folder: Path) -> None:
    """Send every file the pipeline writes into `folder` (a throwaway case)."""
    config.EVIDENCE_DIR = folder / "evidence"
    config.OUTPUT_DIR = folder / "output"
    config.UPLOADS_DIR = folder / "uploads"
    config.MANIFEST_PATH = config.EVIDENCE_DIR / "manifest.json"
    config.CUSTODY_LOG_PATH = config.EVIDENCE_DIR / "chain_of_custody.log"
    config.DB_PATH = config.OUTPUT_DIR / "timeline.db"
    config.GAPS_PATH = config.OUTPUT_DIR / "parsing_gaps.jsonl"
    config.TIMING_PATH = config.OUTPUT_DIR / "triage_times.json"
    config.AI_SUMMARY_PATH = config.OUTPUT_DIR / "ai_summary.json"
    config.REPORT_MD_PATH = config.OUTPUT_DIR / "incident_report.md"
    config.REPORT_PDF_PATH = config.OUTPUT_DIR / "incident_report.pdf"


def _remove(folder: Path) -> None:
    """Delete the throwaway case (evidence copies are read-only, so unlock them first)."""
    for path in folder.rglob("*"):
        if path.is_file():
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    shutil.rmtree(folder, ignore_errors=True)


def run() -> dict:
    """Run every built-in scenario on its own and score it."""
    from src import database, pipeline          # imported here so the config redirect applies

    saved = {name: getattr(config, name) for name in PATH_SETTINGS}
    work = Path(tempfile.mkdtemp(prefix="ft_validate_"))
    results = []
    try:
        for folder, exp in EXPECTED.items():
            scenario_dir = config.SAMPLE_LOGS_DIR / folder
            if not scenario_dir.is_dir():
                continue
            _point_config_at(work / folder)
            start = time.perf_counter()
            stats = pipeline.ingest([scenario_dir], verbose=False)
            seconds = time.perf_counter() - start

            conn = database.connect()
            found = sorted({d["rule"] for d in database.get_detections(conn)})
            conn.close()
            integrity = evidence.verify(log=False)
            missing = [r for r in exp["rules"] if r not in found]
            extra = [r for r in found if r not in exp["rules"]]
            baseline = config.MANUAL_BASELINE_MINUTES_PER_SCENARIO.get(folder)
            results.append({
                "scenario": folder, "title": exp["title"],
                "expected": exp["rules"], "found": found, "missing": missing, "unexpected": extra,
                "events": stats["events"], "events_expected": exp["events"],
                "gaps": stats["gaps"], "gaps_expected": exp["gaps"],
                "hashes_ok": sum(1 for r in integrity if r["status"] == "OK"), "hashes": len(integrity),
                "seconds": round(seconds, 3), "manual_minutes": baseline,
                "passed": not missing and not extra and stats["gaps"] == exp["gaps"]
                          and all(r["status"] == "OK" for r in integrity),
            })
    finally:
        for name, value in saved.items():          # put the real paths back
            setattr(config, name, value)
        _remove(work)

    return {
        "scenarios": results,
        "passed": sum(r["passed"] for r in results), "total": len(results),
        "alerts_expected": sum(len(r["expected"]) for r in results),
        "alerts_found": sum(len(r["expected"]) - len(r["missing"]) for r in results),
        "false_positives": sum(len(r["unexpected"]) for r in results),
        "tool_seconds": round(sum(r["seconds"] for r in results), 3),
        "manual_minutes": sum(r["manual_minutes"] or 0 for r in results),
        "rule_names": RULE_NAMES,
        "ran_utc": evidence.now_utc_iso(),
    }


# ---------------------------------------------------------------------------
# Before / after: why UTC + clock-skew correction matters
# ---------------------------------------------------------------------------
def _local_time(line: str, year: int):
    """The time exactly as written in the log, ignoring any zone or offset (a naive reading)."""
    m = parsers.ACCESS_RE.match(line)
    if m:
        day, mon, rest = m["time"].split(" ")[0].split("/")
        yy, hh, mm, ss = (int(x) for x in rest.split(":"))
        return datetime(yy, normalize.MONTHS[mon], int(day), hh, mm, ss)
    m = parsers.SYSLOG_RE.match(line)
    if m:
        hh, mm, ss = (int(x) for x in m["time"].split(":"))
        return datetime(year, normalize.MONTHS[m["month"]], int(m["day"]), hh, mm, ss)
    return None


def _describe(details: dict, event: dict, host: str) -> str:
    if details.get("attack") == "webshell":
        return f"Web shell command on {host}: {details.get('path', '')[:40]}"
    if details.get("kind") == "auth_success":
        return f"SSH login to {host} as {event['username']} from {event['source_ip']}"
    return f"{event['event_summary'][:60]} ({host})"


def _closest_login(rows: list, key: str):
    """The login on another host closest in time to a web shell, and the gap in seconds."""
    best = None
    for shell in (r for r in rows if r["kind"] == "webshell"):
        for login in (r for r in rows if r["kind"] == "auth_success" and r["host"] != shell["host"]):
            delta = (login[key] - shell[key]).total_seconds()
            hit = 0 <= delta <= config.LATERAL_WINDOW_SECONDS
            score = (not hit, abs(delta))                 # a real hit wins, then the nearest one
            if best is None or score < best[0]:
                best = (score, login, delta)
    return (best[1], best[2]) if best else (None, None)


def _lateral_verdict(rows: list, key: str) -> dict:
    """Would 'login on another server within 15 min after a web shell' (rule R6) fire on this clock?"""
    login, delta = _closest_login(rows, key)
    if login is None:
        return {"detected": False, "text": "not enough events"}
    if 0 <= delta <= config.LATERAL_WINDOW_SECONDS:
        return {"detected": True, "text": f"login {int(delta)} s AFTER the web shell - pivot detected"}
    span = abs(int(delta))
    when = f"{span // 3600} h {span % 3600 // 60} min" if span >= 3600 else f"{span // 60} min {span % 60} s"
    return {"detected": False,
            "text": f"login {when} {'BEFORE' if delta < 0 else 'after'} the web shell - pivot missed"}


def clock_comparison(scenario: str = "scenario3_multi_timezone") -> dict:
    """Key events of a scenario read three ways: raw local, UTC without skew fix, UTC with it."""
    folder = config.SAMPLE_LOGS_DIR / scenario
    rows, sources = [], []
    for path in sorted(folder.glob("*.log")):
        settings = normalize.settings_for(path)
        label = evidence.source_label(path)
        host = path.stem.split("_")[0]
        has_offset = "access" in path.stem
        sources.append({
            "file": label, "host": host,
            "zone": "offset written in each line (+0530)" if has_offset else settings["timezone"],
            "skew": settings.get("skew_seconds", 0),
        })
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            fixed, _ = parsers.parse_line(line, label, settings, set())
            if not fixed:
                continue
            details = parsers.details_from_raw(fixed["log_format"], line)
            kind = "webshell" if details.get("attack") == "webshell" else details.get("kind")
            if kind not in ("webshell", "auth_success", "sudo"):
                continue
            no_skew, _ = parsers.parse_line(line, label, {**settings, "skew_seconds": 0}, set())
            utc_fixed = normalize.from_iso(fixed["timestamp_utc"]).replace(tzinfo=None)
            rows.append({
                "what": _describe(details, fixed, host), "host": host, "kind": kind,
                "user": fixed["username"],
                "local": _local_time(line, utc_fixed.year),
                "utc_raw": normalize.from_iso(no_skew["timestamp_utc"]).replace(tzinfo=None),
                "utc_fixed": utc_fixed,
            })

    # Mark the attack path (on the TRUE clock): web shells, the pivot login and that user's sudo.
    pivot, _ = _closest_login(rows, "utc_fixed")
    for r in rows:
        on_path = r["kind"] == "webshell" or (
            pivot is not None and r["host"] == pivot["host"] and r["user"] == pivot["user"])
        r["role"] = "attack" if on_path else "context"

    views = {}
    for key in ("local", "utc_raw", "utc_fixed"):
        ordered = sorted(rows, key=lambda r: r[key])
        views[key] = {
            "order": [{"time": r[key].strftime("%H:%M:%S"), "what": r["what"], "host": r["host"],
                       "kind": r["kind"], "role": r["role"]} for r in ordered],
            "verdict": _lateral_verdict(rows, key),
        }
    return {"scenario": scenario, "sources": sources, "views": views}


if __name__ == "__main__":
    if "--json" in sys.argv:
        from src import realworld
        print(json.dumps(run() | {"real_world": realworld.run()}))
