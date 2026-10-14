"""
pipeline.py - ties everything together.

    collect (hash + read-only copy)  ->  parse  ->  normalise to UTC  ->  store  ->  detect

This is the order NIST SP 800-86 describes: Collection -> Examination -> Analysis.
"""
import json
import os
import shutil
import stat
import time
from pathlib import Path

import config
from src import database, detect, evidence, normalize, parsers

LOG_SUFFIXES = {".log", ".txt", ""}     # files we treat as logs when given a folder


def find_log_files(paths) -> list[Path]:
    """Expand files and folders into a sorted list of log files."""
    files = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            files += [f for f in sorted(p.rglob("*"))
                      if f.is_file() and f.suffix.lower() in LOG_SUFFIXES]
        elif p.is_file():
            files.append(p)
        else:
            print(f"  ! not found, skipped: {p}")
    return files


def write_gaps_file(conn) -> None:
    """Export every parsing gap to output/parsing_gaps.jsonl (one JSON object per line)."""
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.GAPS_PATH, "w", encoding="utf-8") as f:
        for g in database.get_gaps(conn):
            f.write(json.dumps(g) + "\n")


def save_timing(seconds: float, files: int, events: int) -> None:
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    config.TIMING_PATH.write_text(json.dumps({
        "tool_seconds": round(seconds, 3), "files": files, "events": events,
        "manual_baseline_minutes": config.MANUAL_BASELINE_MINUTES,
        "measured_utc": evidence.now_utc_iso(),
    }, indent=2), encoding="utf-8")


def reset_outputs() -> None:
    """Start a fresh timeline (evidence/ and the custody log are kept on purpose)."""
    # Empty the tables rather than deleting the file: on Windows the file cannot be
    # deleted while the dashboard has it open.
    conn = database.connect()
    database.clear_all(conn)
    conn.close()
    for path in (config.GAPS_PATH, config.AI_SUMMARY_PATH):
        if path.exists():
            path.unlink()


def delete_session() -> dict:
    """
    Wipe the current case: timeline, outputs, uploaded files and evidence copies.
    Never touches the analyst's original files or sample_logs/. The chain-of-custody
    log is kept (it is the audit trail) and records that the session was deleted.
    """
    conn = database.connect()
    database.clear_all(conn)
    conn.close()
    for path in (config.GAPS_PATH, config.AI_SUMMARY_PATH, config.TIMING_PATH,
                 config.REPORT_MD_PATH, config.REPORT_PDF_PATH):
        if path.exists():
            path.unlink()

    removed = []
    for entry in evidence.load_manifest():
        copy = evidence.evidence_path(entry)
        if copy.exists():
            os.chmod(copy, stat.S_IWRITE | stat.S_IREAD)   # copies are read-only by design
            copy.unlink()
            removed.append(entry["evidence_file"])
    if config.MANIFEST_PATH.exists():
        config.MANIFEST_PATH.unlink()
    shutil.rmtree(config.UPLOADS_DIR, ignore_errors=True)   # copies of files dropped in the dashboard

    evidence.log_custody("SESSION_DELETED", {"evidence_copies_removed": removed})
    return {"evidence_removed": len(removed)}


def ingest(paths, verbose=True, overrides=None, progress=None) -> dict:
    """
    Run the whole pipeline on files/folders. Returns a small summary dict.
    overrides - optional {"timezone": ..., "skew_seconds": ...} applied to every file
                (used by the dashboard's drag-and-drop upload).
    progress  - optional callback(stage, label, fraction 0..1) so the dashboard can show a loading
                bar. Time spent inside it is NOT counted in the measured triage time.
    """
    say = print if verbose else (lambda *a, **k: None)
    start = time.perf_counter()
    paused = 0.0

    def report(stage, label, fraction):
        nonlocal paused
        if progress:
            t = time.perf_counter()
            progress(stage, label, fraction)
            paused += time.perf_counter() - t

    files = find_log_files(paths)
    conn = database.connect()

    for i, path in enumerate(files):
        share = 0.8 / max(len(files), 1)          # files take 0-80% of the bar, analysis the rest
        # 1. Collection: hash and keep a read-only copy. We parse the COPY, not the original.
        report("hash", f"Hashing {path.name} (SHA-256) and sealing a read-only copy", i * share)
        entry = evidence.collect(path)
        report("parse", f"Parsing {path.name} and converting every timestamp to UTC", i * share + share / 2)
        settings = normalize.settings_for(path)
        if overrides:
            settings.update(overrides)
            settings["matched_key"] = "set by analyst at upload"
        source = entry["source_label"]

        # 2. Examination: parse each line and convert its time to UTC.
        events, gaps, notes = parsers.parse_file(evidence.evidence_path(entry), source, settings)
        if overrides:
            notes.append("time zone and clock skew chosen by the analyst at upload")
        elif settings["matched_key"] is None:
            notes.append(f"source not listed in config.SOURCE_SETTINGS; used defaults "
                         f"(time zone {settings['timezone']}, no skew)")
        database.replace_source(conn, source, events, gaps, notes)
        say(f"  + {source:45s} sha256={entry['sha256'][:16]}...  "
            f"{len(events):3d} events, {len(gaps)} gaps")

    # 3. Analysis: run the detection rules over the whole timeline.
    report("detect", "Running 8 detection rules and mapping MITRE ATT&CK", 0.85)
    detections = detect.run_detections(conn)
    write_gaps_file(conn)
    if config.AI_SUMMARY_PATH.exists():
        config.AI_SUMMARY_PATH.unlink()          # the timeline changed, so an old AI narrative is stale
    report("custody", "Recording the chain of custody", 0.95)

    elapsed = time.perf_counter() - start - paused
    stats = database.stats(conn)
    save_timing(elapsed, len(files), stats["events"])
    evidence.log_custody("TIMELINE_BUILT", {"files": [evidence.source_label(f) for f in files],
                                            "events": stats["events"],
                                            "detections": len(detections),
                                            "gaps": stats["gaps"],
                                            "seconds": round(elapsed, 3)})
    conn.close()
    stats["seconds"] = elapsed
    stats["files"] = len(files)
    return stats
