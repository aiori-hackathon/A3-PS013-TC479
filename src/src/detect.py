"""
detect.py - simple, explainable rules that flag suspicious patterns.

No AI here. Each rule is a few lines of plain Python with a comment saying what
it looks for and which MITRE ATT&CK technique it relates to (as a text label).

Rules:
  R1  5+ failed logins from one IP in a short window       -> HIGH     T1110   brute force
  R2  failed-login streak, then a success from the same IP -> CRITICAL T1078   successful brute force (valid account)
  R3  burst of 404s on many different paths from one IP   -> WARN     T1595   scanning
  R4  scan followed by a 200 to an unusual path            -> HIGH     T1190   scan then exploit
  R5  request containing SQLi / LFI / web-shell patterns   -> HIGH/CRIT T1190 / T1505.003
  R6  server login shortly after web-shell activity        -> HIGH     T1021   possible lateral movement
  R7  sudo shortly after a suspicious login                -> HIGH     T1548   privilege escalation
  R8  sudo command that is risky on its own (read /etc/shadow, add a user, change cron,
      add an SSH key, set SUID, dump a database)          -> WARN/HIGH, technique per command
"""
import re
from collections import defaultdict

import config
from src import database, normalize, parsers


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _load(conn) -> list[dict]:
    """All events, sorted by UTC time, with extra details re-read from the raw line."""
    events = database.all_events(conn)
    for e in events:
        e.update(parsers.details_from_raw(e["log_format"], e["raw_log"]))
        e["dt"] = normalize.from_iso(e["timestamp_utc"])
    return events


def _streaks(events: list, max_gap_seconds: int) -> list[list]:
    """Split time-sorted events into groups where each event is close to the previous one."""
    groups = []
    for e in events:
        if groups and (e["dt"] - groups[-1][-1]["dt"]).total_seconds() <= max_gap_seconds:
            groups[-1].append(e)
        else:
            groups.append([e])
    return groups


def _has_dense_window(group: list, count: int, window_seconds: int) -> bool:
    """True if any `count` consecutive events in the group fit inside `window_seconds`."""
    for i in range(len(group) - count + 1):
        if (group[i + count - 1]["dt"] - group[i]["dt"]).total_seconds() <= window_seconds:
            return True
    return False


def _detection(rule, severity, mitre, title, description, events, ip=None, user=None) -> dict:
    return {
        "rule": rule, "severity": severity, "mitre": mitre, "title": title,
        "description": description, "source_ip": ip, "username": user,
        "first_seen": min(e["timestamp_utc"] for e in events),
        "last_seen": max(e["timestamp_utc"] for e in events),
        "event_ids": [e["id"] for e in events],
    }


def _by_ip(events: list, kind: str) -> dict:
    grouped = defaultdict(list)
    for e in events:
        if e.get("kind") == kind and e.get("source_ip"):
            grouped[e["source_ip"]].append(e)
    return grouped


# ---------------------------------------------------------------------------
# SSH rules
# ---------------------------------------------------------------------------
def rule_brute_force(events):
    """R1 + R2: many failed logins from one IP, and whether a success followed."""
    found, suspicious_logins = [], []
    fails_by_ip = _by_ip(events, "auth_fail")
    for ip, fails in fails_by_ip.items():
        for streak in _streaks(fails, config.BRUTE_FORCE_WINDOW_SECONDS):
            if len(streak) < config.BRUTE_FORCE_MIN_FAILS:
                continue
            if not _has_dense_window(streak, config.BRUTE_FORCE_MIN_FAILS,
                                     config.BRUTE_FORCE_WINDOW_SECONDS):
                continue
            users = sorted({e["username"] for e in streak if e["username"]})
            found.append(_detection(
                "R1-brute-force", "HIGH", "T1110",
                "Possible brute force",
                f"{len(streak)} failed SSH logins from {ip} against users {', '.join(users)}.",
                streak, ip=ip))

            # R2: the next auth event from this IP is a SUCCESS, soon after the last failure.
            last_fail = streak[-1]
            later = [e for e in events
                     if e.get("source_ip") == ip and e["dt"] >= last_fail["dt"]
                     and e.get("kind") in ("auth_fail", "auth_success") and e is not last_fail]
            if later and later[0]["kind"] == "auth_success" and \
                    (later[0]["dt"] - last_fail["dt"]).total_seconds() <= config.SUCCESS_AFTER_FAILS_SECONDS:
                win = later[0]
                found.append(_detection(
                    "R2-successful-brute-force", "CRITICAL", "T1078",      # Valid Accounts
                    "Possible successful brute force",
                    f"After {len(streak)} failures (last at {last_fail['timestamp_utc']}), "
                    f"{ip} logged in successfully as '{win['username']}'.",
                    [win], ip=ip, user=win["username"]))
                suspicious_logins.append(win)
    return found, suspicious_logins


def rule_privilege_escalation(events, suspicious_logins):
    """R7: the same user runs sudo on the same host soon after a suspicious login."""
    found = []
    for login in suspicious_logins:
        sudos = [e for e in events
                 if e.get("kind") == "sudo" and e["username"] == login["username"]
                 and e.get("host") == login.get("host")
                 and 0 <= (e["dt"] - login["dt"]).total_seconds() <= config.PRIV_ESC_WINDOW_SECONDS]
        if sudos:
            cmds = "; ".join(e["event_summary"].split(": ", 1)[-1] for e in sudos)
            found.append(_detection(
                "R7-privilege-escalation", "HIGH", "T1548",
                "Privilege use after suspicious login",
                f"'{login['username']}' used sudo {len(sudos)} time(s) on {login.get('host')} "
                f"after a suspicious login: {cmds}",
                [login] + sudos, ip=login["source_ip"], user=login["username"]))
    return found


# R8: commands that are suspicious whoever runs them. (pattern, MITRE id, title, severity)
SENSITIVE_COMMANDS = [
    (re.compile(r"/etc/shadow"), "T1003.008", "Password hashes read (/etc/shadow)", "HIGH"),
    (re.compile(r"\b(useradd|adduser)\b"), "T1136.001", "Local account created", "HIGH"),
    (re.compile(r"authorized_keys"), "T1098.004", "SSH key added", "HIGH"),
    (re.compile(r"\bcrontab\b|/etc/cron"), "T1053.003", "Scheduled task (cron) changed", "WARN"),
    (re.compile(r"chmod\s+(u\+s|\+s|[46]7[0-7]{2})"), "T1548.001", "SUID bit set", "HIGH"),
    (re.compile(r"\b(pg_dump|mysqldump|mongodump)\b"), "T1005", "Database dumped", "HIGH"),
]


def rule_sensitive_commands(events):
    """R8: group risky sudo commands per host + user + technique."""
    grouped = defaultdict(list)
    for e in events:
        if e.get("kind") != "sudo":
            continue
        command = e["event_summary"].split(": ", 1)[-1]
        for pattern, mitre, title, severity in SENSITIVE_COMMANDS:
            if pattern.search(command):
                grouped[(e.get("host"), e["username"], mitre, title, severity)].append(e)
    found = []
    for (host, user, mitre, title, severity), hits in grouped.items():
        cmds = "; ".join(sorted({h["event_summary"].split(": ", 1)[-1] for h in hits}))
        found.append(_detection(f"R8-{mitre}", severity, mitre, title,
                                f"'{user}' on {host}: {cmds}", hits, user=user))
    return found


# ---------------------------------------------------------------------------
# Web rules
# ---------------------------------------------------------------------------
def rule_scan_then_exploit(events):
    """R3 + R4: a burst of 404s (scanning), then a 200 to an unusual path."""
    found = []
    http = [e for e in events if e.get("kind") == "http"]
    for ip, requests in _by_ip(http, "http").items():
        not_found = [e for e in requests if e["status"] == 404]
        for burst in _streaks(not_found, config.SCAN_WINDOW_SECONDS):
            if len(burst) < config.SCAN_MIN_404S:
                continue
            # A scanner probes many DIFFERENT paths; a broken update client repeats the same one.
            if len({e["path"] for e in burst}) < config.SCAN_MIN_DISTINCT_PATHS:
                continue
            found.append(_detection(
                "R3-web-scan", "WARN", "T1595",
                "Web scanning (burst of 404s)",
                f"{len(burst)} requests for missing pages from {ip} in "
                f"{int((burst[-1]['dt'] - burst[0]['dt']).total_seconds())} seconds.",
                burst, ip=ip))
            # R4: after the scan, a successful (200) request to a path that looks like an attack.
            end = burst[-1]["dt"]
            hits = [e for e in requests
                    if e["status"] == 200 and e.get("attack")
                    and 0 < (e["dt"] - end).total_seconds() <= config.EXPLOIT_AFTER_SCAN_SECONDS]
            if hits:
                found.append(_detection(
                    "R4-scan-then-exploit", "HIGH", "T1190",
                    "Possible scan then exploit",
                    f"After scanning (ended {burst[-1]['timestamp_utc']}), {ip} got {len(hits)} "
                    "successful response(s) to suspicious paths: "
                    + ", ".join(sorted({h['path'][:60] for h in hits})),
                    hits, ip=ip))
    return found


def rule_attack_patterns(events):
    """R5: any request whose path looks like SQL injection, file inclusion or a web shell."""
    found = []
    grouped = defaultdict(list)
    for e in events:
        if e.get("kind") == "http" and e.get("attack"):
            grouped[(e["source_ip"], e["attack"])].append(e)
    labels = {
        "sqli": ("HIGH", "T1190", "SQL injection attempt"),
        "lfi": ("HIGH", "T1190", "Path traversal / file inclusion attempt"),
        "webshell": ("CRITICAL", "T1505.003", "Web shell access"),
    }
    for (ip, attack), hits in grouped.items():
        severity, mitre, title = labels[attack]
        ok = sum(1 for h in hits if h["status"] == 200)
        found.append(_detection(
            f"R5-{attack}", severity, mitre, title,
            f"{len(hits)} request(s) from {ip} ({ok} answered with 200).",
            hits, ip=ip))
    return found


def rule_lateral_movement(events):
    """
    R6: a successful SSH login to a server soon after web-shell activity elsewhere.
    This only works if both logs are on the same (UTC, skew-corrected) clock -
    which is exactly what scenario 3 demonstrates.
    """
    found, suspicious_logins = [], []
    shells = [e for e in events if e.get("attack") == "webshell" and e.get("status") == 200]
    if not shells:
        return found, suspicious_logins
    for login in (e for e in events if e.get("kind") == "auth_success"):
        before = [s for s in shells
                  if s["source_file"] != login["source_file"]
                  and 0 <= (login["dt"] - s["dt"]).total_seconds() <= config.LATERAL_WINDOW_SECONDS]
        if before:
            gap = int((login["dt"] - before[-1]["dt"]).total_seconds())
            found.append(_detection(
                "R6-lateral-movement", "HIGH", "T1021.004",
                "Possible lateral movement after web shell",
                f"'{login['username']}' logged in to {login.get('host')} from {login['source_ip']} "
                f"{gap} seconds after web-shell activity on {before[-1]['source_file']}.",
                [before[-1], login], ip=login["source_ip"], user=login["username"]))
            suspicious_logins.append(login)
    return found, suspicious_logins


# ---------------------------------------------------------------------------
# Run everything
# ---------------------------------------------------------------------------
def run_detections(conn) -> list[dict]:
    events = _load(conn)
    brute, brute_logins = rule_brute_force(events)
    lateral, lateral_logins = rule_lateral_movement(events)
    detections = (brute + lateral
                  + rule_privilege_escalation(events, brute_logins + lateral_logins)
                  + rule_sensitive_commands(events)
                  + rule_scan_then_exploit(events)
                  + rule_attack_patterns(events))
    detections.sort(key=lambda d: (d["first_seen"], d["rule"]))
    database.save_detections(conn, detections)
    return detections
