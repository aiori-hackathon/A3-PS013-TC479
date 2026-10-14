"""
realworld.py - test the tool on PUBLIC logs from REAL servers (not our synthetic scenarios).

Real logs come without an answer key, so every result is cross-checked against an
INDEPENDENT count: a few lines of plain regex that do not use the tool's parser or rules.
If the tool and the independent count disagree, the check fails.

Datasets (downloaded into real_logs/, see real_logs/README.md):
  * LogHub OpenSSH - 2,000 lines from a real lab server under real SSH attack
  * Elastic nginx_logs - 51,462 real requests to a web server over three weeks
"""
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote_plus

import config
from src import evidence

DATASETS = [
    {
        "id": "loghub_openssh", "kind": "ssh",
        "file": "real_logs/loghub_openssh/OpenSSH_2k.log",
        "title": "Real SSH server under attack",
        "source": "LogHub OpenSSH sample (lab server 'LabSZ') - github.com/logpai/loghub, free for research use",
        "settings": {"timezone": "UTC", "skew_seconds": 0},
        "assumption": "No time zone or year in the file: UTC assumed, year inferred (see notes).",
    },
    {
        "id": "elastic_nginx", "kind": "web",
        "file": "real_logs/elastic_nginx/nginx_access.log",
        "title": "Real web server traffic (3 weeks)",
        "source": "Elastic examples 'nginx_logs' - github.com/elastic/examples, Apache-2.0",
        "settings": {"timezone": "UTC", "skew_seconds": 0},
        "assumption": "Offsets are written in each line (+0000).",
    },
]

# Independent patterns - deliberately NOT the tool's parser.
SSH_TIME = re.compile(r"^(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) ")
SSH_FAILED = re.compile(r"Failed password for (?:invalid user )?\S+ from (\S+)")
SSH_ACCEPTED = re.compile(r"Accepted \S+ for \S+ from \S+")
WEB_LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "\S+ (\S+)[^"]*" (\d{3}) ')
ATTACK_WORDS = re.compile(r"union\s+select|\.\./|/etc/passwd|php://|cmd=|exec=|shell\.php|'\s*or\s*'", re.I)
MONTH = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
                                     "Oct", "Nov", "Dec"], 1)}


def _bursts(times_by_key: dict, gap: int, minimum: int, extra=lambda burst: True) -> set:
    """Keys with a run of >= minimum items, each within `gap` seconds of the previous one."""
    hits = set()
    for key, items in times_by_key.items():
        items.sort()
        run = [items[0]]
        for item in items[1:] + [None]:
            if item is not None and (item[0] - run[-1][0]) <= gap:
                run.append(item)
                continue
            if len(run) >= minimum and extra(run):
                hits.add(key)
            if item is not None:
                run = [item]
    return hits


def independent_ssh(lines: list) -> dict:
    fails = defaultdict(list)
    for line in lines:
        m, t = SSH_FAILED.search(line), SSH_TIME.match(line)
        if m and t:
            mon, day, hh, mm, ss = t.groups()
            # Seconds since an arbitrary epoch: only differences matter for the window.
            secs = ((MONTH[mon] * 31 + int(day)) * 24 + int(hh)) * 3600 + int(mm) * 60 + int(ss)
            fails[m.group(1)].append((secs, None))
    # >= 5 failures with at most 5 minutes between consecutive ones, and 5 of them within 5 minutes.
    def dense(run):
        return any(run[i + 4][0] - run[i][0] <= config.BRUTE_FORCE_WINDOW_SECONDS for i in range(len(run) - 4))
    return {
        "failed": sum(len(v) for v in fails.values()),
        "accepted": sum(1 for line in lines if SSH_ACCEPTED.search(line)),
        "brute_force_ips": _bursts(fails, config.BRUTE_FORCE_WINDOW_SECONDS, config.BRUTE_FORCE_MIN_FAILS, dense),
    }


def independent_web(lines: list) -> dict:
    not_found = defaultdict(list)
    count_404, attacks, clients = 0, 0, set()
    for line in lines:
        m = WEB_LINE.match(line)
        if not m:
            continue
        ip, when, path, status = m.groups()
        clients.add(ip)
        if ATTACK_WORDS.search(unquote_plus(path)):
            attacks += 1
        if status == "404":
            count_404 += 1
            t = datetime.strptime(when, "%d/%b/%Y:%H:%M:%S %z").timestamp()
            not_found[ip].append((t, path))
    distinct = lambda run: len({p for _, p in run}) >= config.SCAN_MIN_DISTINCT_PATHS
    return {
        "count_404": count_404, "attack_requests": attacks, "clients": len(clients),
        "scanner_ips": _bursts(not_found, config.SCAN_WINDOW_SECONDS, config.SCAN_MIN_404S, distinct),
        # What a naive "10 x 404" rule would report on this real traffic (shows why R3 was tuned).
        "naive_scan_ips": _bursts(not_found, config.SCAN_WINDOW_SECONDS, config.SCAN_MIN_404S),
    }


def _check(name: str, expected, actual) -> dict:
    return {"name": name, "expected": expected, "actual": actual, "ok": expected == actual}


def run() -> dict:
    """Ingest each real dataset into a throwaway case and cross-check the tool's results."""
    from src import database, pipeline, validate   # imported here so the config redirect applies

    saved = {name: getattr(config, name) for name in validate.PATH_SETTINGS}
    import tempfile
    work = Path(tempfile.mkdtemp(prefix="ft_realworld_"))
    results = []
    try:
        for ds in DATASETS:
            path = config.PROJECT_DIR / ds["file"]
            if not path.exists():
                results.append({"id": ds["id"], "title": ds["title"], "missing": True, "file": ds["file"]})
                continue
            lines = [l.rstrip("\r\n") for l in path.read_text(encoding="utf-8", errors="replace").splitlines()]
            lines = [l for l in lines if l.strip()]

            validate._point_config_at(work / ds["id"])
            start = time.perf_counter()
            stats = pipeline.ingest([path], verbose=False, overrides=ds["settings"])
            seconds = time.perf_counter() - start
            conn = database.connect()
            events = database.all_events(conn)
            dets = database.get_detections(conn)
            notes = database.get_source_notes(conn)
            conn.close()
            integrity = evidence.verify(log=False)

            checks = [_check("Every line accounted for (events + parsing gaps = lines in file)",
                             len(lines), stats["events"] + stats["gaps"])]
            if ds["kind"] == "ssh":
                ind = independent_ssh(lines)
                tool_bf = {d["source_ip"] for d in dets if d["rule"] == "R1-brute-force"}
                checks += [
                    _check("'Failed password' lines parsed as failed logins", ind["failed"],
                           sum(1 for e in events if e["event_summary"].startswith("SSH login failed"))),
                    _check("'Accepted' lines parsed as successful logins", ind["accepted"],
                           sum(1 for e in events if e["event_summary"].startswith("SSH login succeeded"))),
                    _check("Brute-force attacker IPs match an independent count",
                           sorted(ind["brute_force_ips"]), sorted(tool_bf)),
                ]
                fails = Counter(e["source_ip"] for e in events if e["event_summary"].startswith("SSH login failed"))
                users = Counter()
                for e in events:
                    if e["event_summary"].startswith(("SSH login failed", "SSH attempt with unknown user")) and e["username"]:
                        users[e["username"]] += 1
                highlights = {
                    "attackers": [{"ip": ip, "failures": fails[ip]} for ip in sorted(tool_bf, key=lambda i: -fails[i])],
                    "top_usernames": users.most_common(8),
                    "failed_total": ind["failed"], "accepted_total": ind["accepted"],
                }
            else:
                ind = independent_web(lines)
                tool_scan = {d["source_ip"] for d in dets if d["rule"] == "R3-web-scan"}
                tool_attacks = sum(1 for e in events if "[looks like" in e["event_summary"])
                checks += [
                    _check("HTTP 404 responses counted", ind["count_404"],
                           sum(1 for e in events if e["event_summary"].startswith("HTTP 404 "))),
                    _check("Scanner IPs match an independent count", sorted(ind["scanner_ips"]), sorted(tool_scan)),
                    _check("Attack payloads (SQLi / traversal / web shell) match an independent search",
                           ind["attack_requests"], tool_attacks),
                ]
                top_404 = Counter(e["event_summary"].split(" ")[3] for e in events
                                  if e["event_summary"].startswith("HTTP 404 ")).most_common(3)
                highlights = {
                    "clients": ind["clients"], "count_404": ind["count_404"], "alerts": len(dets),
                    "naive_alarms": len(ind["naive_scan_ips"]), "top_404_paths": top_404,
                }
            checks.append(_check("Evidence SHA-256 re-verified", True, all(r["status"] == "OK" for r in integrity)))

            results.append({
                "id": ds["id"], "kind": ds["kind"], "title": ds["title"], "source": ds["source"],
                "assumption": ds["assumption"], "notes": next(iter(notes.values()), []),
                "lines": len(lines), "events": stats["events"], "gaps": stats["gaps"],
                "first": stats["first"], "last": stats["last"], "seconds": round(seconds, 3),
                "alerts": len(dets), "alerts_by_rule": Counter(d["rule"] for d in dets).most_common(),
                "sha256": integrity[0]["actual_sha256"] if integrity else None,
                "checks": [c | {"expected": _jsonable(c["expected"]), "actual": _jsonable(c["actual"])} for c in checks],
                "passed": all(c["ok"] for c in checks), "highlights": highlights,
            })
    finally:
        for name, value in saved.items():
            setattr(config, name, value)
        validate._remove(work)
    return {"datasets": results, "passed": sum(1 for r in results if r.get("passed")),
            "total": len(results), "ran_utc": evidence.now_utc_iso()}


def _jsonable(value):
    """Long IP lists become a count in the summary (the full list is in the highlights)."""
    if isinstance(value, list) and len(value) > 6:
        return f"{len(value)} IPs"
    return value
