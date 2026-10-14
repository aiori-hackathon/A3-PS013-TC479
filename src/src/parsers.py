"""
parsers.py - reads log lines and pulls out the useful fields.

Two formats are supported:
  * 'Linux Auth'   - syslog style, e.g.
        Oct  9 02:31:07 bastion01 sshd[2203]: Failed password for root from 203.0.113.45 port 40112 ssh2
  * 'Nginx Access' - NCSA combined style (Nginx and Apache), e.g.
        203.0.113.99 - - [09/Oct/2026:11:02:00 +0530] "GET /admin/ HTTP/1.1" 404 153 "-" "agent"

Any line that matches neither format is NOT silently dropped: it becomes a
"parsing gap" with the reason, so the analyst can see what was missed.
"""
import re
from urllib.parse import unquote_plus

from src import normalize

AUTH = "Linux Auth"
ACCESS = "Nginx Access"

# ---------------------------------------------------------------------------
# Line patterns
# ---------------------------------------------------------------------------
# <Mon> <day> <HH:MM:SS> <host> <program>[<pid>]: <message>
SYSLOG_RE = re.compile(
    r"^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<program>[A-Za-z0-9_.\-/()]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

# <ip> <ident> <user> [<time>] "<method> <path> <protocol>" <status> <bytes> ["<referer>" "<agent>"]
ACCESS_RE = re.compile(
    r'^(?P<ip>[0-9A-Fa-f.:]+) \S+ (?P<user>\S+) '
    r'\[(?P<time>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?\s*$'
)

# What the message part of an auth.log line can mean. First match wins.
AUTH_MESSAGES = [
    ("auth_fail", "WARN",
     re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")),
    ("auth_success", "INFO",
     re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")),
    ("invalid_user", "WARN",
     re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")),
    ("sudo", "WARN",
     re.compile(r"^\s*(?P<user>\S+) : TTY=\S+ ; PWD=\S+ ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.+)$")),
    ("disconnect", "INFO",
     re.compile(r"Disconnected from user (?P<user>\S+) (?P<ip>\S+)")),
    ("session_open", "INFO",
     re.compile(r"session opened for user (?P<user>\S+)")),
    ("session_close", "INFO",
     re.compile(r"session closed for user (?P<user>\S+)")),
    ("conn_closed", "INFO",
     re.compile(r"Connection closed by (?P<ip>\S+)")),
]

# Request paths that look like attacks. Used for severity and detection.
ATTACK_PATTERNS = [
    ("webshell", re.compile(r"(cmd|exec|command)=|shell\.php|/(uploads|static|img|images)/.*\.(php|jsp|aspx)", re.I)),
    ("sqli", re.compile(r"union\s+select|'\s*or\s*'|'\s*or\s+1\s*=\s*1|sleep\(|;\s*drop\s", re.I)),
    ("lfi", re.compile(r"\.\./|/etc/passwd|php://", re.I)),
]


def attack_type(path: str):
    """Return 'webshell', 'sqli', 'lfi' or None for a request path."""
    decoded = unquote_plus(path)          # turn %27 into ' and + into space first
    for name, pattern in ATTACK_PATTERNS:
        if pattern.search(decoded):
            return name
    return None


# ---------------------------------------------------------------------------
# Understanding the message part
# ---------------------------------------------------------------------------
def describe_auth(program: str, message: str) -> dict:
    """Work out kind, user, ip, severity and a short summary for an auth.log message."""
    for kind, severity, pattern in AUTH_MESSAGES:
        m = pattern.search(message)
        if not m:
            continue
        g = m.groupdict()
        user, ip = g.get("user"), g.get("ip")
        summaries = {
            "auth_fail": f"SSH login failed for '{user}' from {ip}",
            "auth_success": f"SSH login succeeded for '{user}' from {ip} ({g.get('method')})",
            "invalid_user": f"SSH attempt with unknown user '{user}' from {ip}",
            "sudo": f"Privileged command (sudo) by '{user}' as {g.get('target')}: {g.get('cmd', '').strip()}",
            "disconnect": f"SSH session ended for '{user}' from {ip}",
            "session_open": f"Session opened for '{user}' ({program})",
            "session_close": f"Session closed for '{user}' ({program})",
            "conn_closed": f"Connection closed by {ip}",
        }
        return {"kind": kind, "severity": severity, "user": user, "ip": ip,
                "summary": summaries[kind]}
    # A well-formed syslog line from a program we do not interpret: keep it as INFO.
    return {"kind": "other", "severity": "INFO", "user": None, "ip": None,
            "summary": f"{program}: {message[:120]}"}


def describe_access(g: dict) -> dict:
    """Work out kind, severity and summary for one web request."""
    status = int(g["status"])
    attack = attack_type(g["path"])
    if attack == "webshell":
        severity = "CRITICAL"
    elif attack in ("sqli", "lfi"):
        severity = "HIGH"
    elif status >= 500:
        severity = "WARN"
    else:
        severity = "INFO"
    summary = f"HTTP {status} {g['method']} {g['path'][:150]}"
    if attack:
        summary += f"  [looks like {attack.upper()}]"
    return {"kind": "http", "severity": severity, "status": status, "path": g["path"],
            "method": g["method"], "attack": attack, "summary": summary}


def details_from_raw(log_format: str, raw: str) -> dict:
    """
    Re-read the original raw line and return its details (kind, host, status, path...).
    The detection rules use this, so the raw line stays the single source of truth.
    """
    if log_format == AUTH:
        m = SYSLOG_RE.match(raw)
        if m:
            d = describe_auth(m["program"], m["message"])
            d["host"] = m["host"]
            return d
    elif log_format == ACCESS:
        m = ACCESS_RE.match(raw)
        if m:
            return describe_access(m.groupdict())
    return {"kind": "unknown"}


# ---------------------------------------------------------------------------
# Parsing a whole line / file
# ---------------------------------------------------------------------------
def parse_line(line: str, source_file: str, settings: dict, notes: set):
    """
    Try both formats on one line.
    Returns (event_dict, None) on success or (None, reason) if it is a parsing gap.
    `notes` collects any assumptions we made (year, time zone, skew).
    """
    m = ACCESS_RE.match(line)
    if m:
        g = m.groupdict()
        utc = normalize.offset_to_utc(g["time"])
        d = describe_access(g)
        user = None if g["user"] == "-" else g["user"]
        fmt, ip = ACCESS, g["ip"]
        notes.add("access.log times carry their own UTC offset; used as written")
    else:
        m = SYSLOG_RE.match(line)
        if not m:
            return None, _gap_reason(line)
        g = m.groupdict()
        try:
            utc, year_notes = normalize.syslog_to_utc(
                g["month"], int(g["day"]), g["time"], settings["timezone"], settings.get("year"))
        except ValueError as exc:                     # e.g. 'Feb 30' or '25:61:00'
            return None, f"invalid date/time: {exc}"
        notes.update(year_notes)
        if settings.get("year"):
            notes.add(f"no year in log; used configured year {settings['year']}")
        notes.add(f"no time zone in log; assumed {settings['timezone']} (DST-aware via zoneinfo)")
        d = describe_auth(g["program"], g["message"])
        fmt, ip, user = AUTH, d["ip"], d["user"]

    skew = settings.get("skew_seconds", 0) or 0
    if skew:
        utc = normalize.apply_skew(utc, skew)
        notes.add(f"clock skew correction of {skew:+} seconds applied")

    event = {
        "timestamp_utc": normalize.to_iso(utc),
        "source_file": source_file,
        "log_format": fmt,
        "source_ip": ip,
        "username": user,
        "severity": d["severity"],
        "event_summary": d["summary"],
        "raw_log": line,
    }
    return event, None


def _gap_reason(line: str) -> str:
    """Give a helpful reason why a line could not be read."""
    if re.match(r"^\d{4}-\d{2}-\d{2}T", line):
        return "ISO-8601 / RFC 5424 style timestamp (not classic syslog)"
    if re.match(r"^<\d+>\d? ", line):
        return "RFC 5424 syslog with priority header"
    if re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} W3SVC", line):
        return "IIS W3C extended log format"
    if re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s", line):
        return "looks like syslog but is truncated or incomplete"
    if re.match(r"^[0-9.]+ \S+ \S+ \[", line):
        return "looks like an access.log line but is truncated or incomplete"
    return "unrecognised format"


def parse_file(path, source_file: str, settings: dict):
    """
    Parse every line of a file.
    Returns (events, gaps, notes). The file is opened read-only and never changed.
    """
    events, gaps, notes = [], [], set()
    # errors="replace" means unreadable bytes become '?' instead of crashing.
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, raw in enumerate(f, start=1):
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue                               # blank lines are not evidence
            event, reason = parse_line(line, source_file, settings, notes)
            if event:
                events.append(event)
            else:
                gaps.append({"source_file": source_file, "line_number": line_no,
                             "reason": reason, "raw_line": line})
    return events, gaps, sorted(notes)
