"""
config.py - all the settings an analyst might want to change, in one place.

The most important part is SOURCE_SETTINGS: it tells the tool which time zone
each log came from and whether that server's clock was wrong (clock skew).
"""
from pathlib import Path

# ---------------------------------------------------------------------------
# Folders (everything lives next to this file, nothing is sent anywhere)
# ---------------------------------------------------------------------------
PROJECT_DIR = Path(__file__).resolve().parent
SAMPLE_LOGS_DIR = PROJECT_DIR / "sample_logs"
EVIDENCE_DIR = PROJECT_DIR / "evidence"            # read-only copies of the input logs
OUTPUT_DIR = PROJECT_DIR / "output"                # database, gaps file, reports
UPLOADS_DIR = PROJECT_DIR / "uploads"              # logs dropped into the dashboard (originals)

DB_PATH = OUTPUT_DIR / "timeline.db"
MANIFEST_PATH = EVIDENCE_DIR / "manifest.json"     # filename, SHA-256, size, ingest time
CUSTODY_LOG_PATH = EVIDENCE_DIR / "chain_of_custody.log"   # append-only action log
GAPS_PATH = OUTPUT_DIR / "parsing_gaps.jsonl"      # lines we could not understand
TIMING_PATH = OUTPUT_DIR / "triage_times.json"     # how long each run took
REPORT_MD_PATH = OUTPUT_DIR / "incident_report.md"
REPORT_PDF_PATH = OUTPUT_DIR / "incident_report.pdf"
AI_SUMMARY_PATH = OUTPUT_DIR / "ai_summary.json"   # saved AI narrative (optional)

# ---------------------------------------------------------------------------
# Time settings
# ---------------------------------------------------------------------------
# Linux auth.log lines have NO time zone and NO year, so we must assume them.
DEFAULT_TIMEZONE = "Asia/Kolkata"   # used when a source is not listed below
DEFAULT_YEAR = None                 # None = "current year" (rolled back one year if the date would be in the future)

# Per-source settings. The key is matched against the END of the file path,
# so "scenario3_multi_timezone/db01_auth.log" matches that file wherever it lives.
#
#   timezone      - IANA zone name. Always use names like "America/New_York",
#                   never a fixed offset, so daylight saving time is handled.
#   skew_seconds  - correction ADDED to every timestamp from this source.
#                   A clock that runs 3 minutes SLOW needs +180.
#                   A clock that runs 2 minutes FAST needs -120.
#   year          - optional fixed year for logs that do not include one.
SOURCE_SETTINGS = {
    "scenario1_ssh_bruteforce/auth.log": {
        "timezone": "Asia/Kolkata",
        "skew_seconds": 0,
        "year": 2026,
    },
    "scenario2_web_exploit/access.log": {
        # access.log already contains "+0530", so only skew matters here
        "skew_seconds": 0,
    },
    "scenario3_multi_timezone/web01_access.log": {
        "skew_seconds": 0,
    },
    "scenario3_multi_timezone/db01_auth.log": {
        "timezone": "America/New_York",   # the DB server sits in a US data centre
        "skew_seconds": 180,              # its clock was found to be 3 minutes slow
        "year": 2026,
    },
}

# ---------------------------------------------------------------------------
# Detection rule thresholds (see src/detect.py)
# ---------------------------------------------------------------------------
BRUTE_FORCE_MIN_FAILS = 5          # this many failed logins ...
BRUTE_FORCE_WINDOW_SECONDS = 300   # ... within 5 minutes = brute force
SUCCESS_AFTER_FAILS_SECONDS = 600  # success within 10 min of the last failure
PRIV_ESC_WINDOW_SECONDS = 1800     # sudo within 30 min of a suspicious login
SCAN_MIN_404S = 10                 # this many 404s ...
SCAN_WINDOW_SECONDS = 300          # ... within 5 minutes = scanning
SCAN_MIN_DISTINCT_PATHS = 8        # ... across this many DIFFERENT paths. Tuned on a real web log:
                                   # update clients re-request the same 1-2 missing files (not a scan).
EXPLOIT_AFTER_SCAN_SECONDS = 1800  # a 200 to an odd path within 30 min of the scan
LATERAL_WINDOW_SECONDS = 900       # server login within 15 min of a web-shell hit

# ---------------------------------------------------------------------------
# Triage-time comparison
# ---------------------------------------------------------------------------
# Rough estimate of how long an analyst needs to do the same work by hand
# (open each log, convert time zones, sort, spot the pattern). Change this to
# your own measured number before the demo.
MANUAL_BASELINE_MINUTES_PER_SCENARIO = {
    "scenario1_ssh_bruteforce": 10,     # read ~35 lines, count failures, spot the login + sudo
    "scenario2_web_exploit": 15,        # pick the scan out of normal traffic, decode the payloads
    "scenario3_multi_timezone": 20,     # convert two time zones by hand, correct the clock, line them up
}
MANUAL_BASELINE_MINUTES = sum(MANUAL_BASELINE_MINUTES_PER_SCENARIO.values())   # 45

# ---------------------------------------------------------------------------
# Optional AI helper (Gemini). The tool works fully without it.
# ---------------------------------------------------------------------------
AI_MODEL = "gemini-flash-latest"          # alias, so it does not go stale
AI_FALLBACK_MODEL = "gemini-3.5-flash-lite"
AI_MAX_EVENTS = 60                        # cap how many flagged events we send
AI_TIMEOUT_SECONDS = 20                  # give up on a slow model and try the fallback
