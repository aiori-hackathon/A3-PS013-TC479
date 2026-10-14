"""
Basic tests. Run with:   python -m pytest -q
They use temporary folders, so they never touch your real evidence or database.
"""
import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))   # so "import config" works

import config  # noqa: E402
from src import ai_helper, database, detect, evidence, normalize, parsers  # noqa: E402

KOLKATA = {"timezone": "Asia/Kolkata", "skew_seconds": 0, "year": 2026}


@pytest.fixture(autouse=True)
def temp_dirs(tmp_path, monkeypatch):
    """Point every output path at a temporary folder for each test."""
    monkeypatch.setattr(config, "EVIDENCE_DIR", tmp_path / "evidence")
    monkeypatch.setattr(config, "OUTPUT_DIR", tmp_path / "output")
    monkeypatch.setattr(config, "MANIFEST_PATH", tmp_path / "evidence" / "manifest.json")
    monkeypatch.setattr(config, "CUSTODY_LOG_PATH", tmp_path / "evidence" / "custody.log")
    monkeypatch.setattr(config, "AI_SUMMARY_PATH", tmp_path / "output" / "ai_summary.json")
    for name, file in (("DB_PATH", "timeline.db"), ("GAPS_PATH", "gaps.jsonl"),
                       ("TIMING_PATH", "timing.json"), ("REPORT_MD_PATH", "report.md"),
                       ("REPORT_PDF_PATH", "report.pdf")):
        monkeypatch.setattr(config, name, tmp_path / "output" / file)
    monkeypatch.setattr(config, "UPLOADS_DIR", tmp_path / "uploads")
    return tmp_path


def test_sha256_known_value():
    # SHA-256("abc") is a published test vector (FIPS 180-2).
    assert evidence.sha256_text("abc") == \
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_auth_parser_extracts_ip_and_user():
    line = "Oct  9 02:31:15 bastion01 sshd[2204]: Failed password for root from 203.0.113.45 port 40118 ssh2"
    event, reason = parsers.parse_line(line, "test/auth.log", KOLKATA, set())
    assert reason is None
    assert event["source_ip"] == "203.0.113.45"
    assert event["username"] == "root"
    assert event["log_format"] == parsers.AUTH
    # 02:31:15 in India (UTC+5:30) is 21:01:15 UTC on the previous day
    assert event["timestamp_utc"] == "2026-10-08T21:01:15Z"


def test_access_parser_converts_offset_to_utc():
    line = ('203.0.113.99 - - [10/Oct/2026:13:55:36 +0530] "GET /x HTTP/1.1" 404 153 "-" "test"')
    event, reason = parsers.parse_line(line, "test/access.log", {"skew_seconds": 0}, set())
    assert reason is None
    assert event["timestamp_utc"] == "2026-10-10T08:25:36Z"     # 13:55:36 - 5:30


def test_dst_and_skew():
    # New York is UTC-4 in October (daylight time) but UTC-5 in December.
    oct_utc, _ = normalize.syslog_to_utc("Oct", 9, "04:30:05", "America/New_York", 2026)
    dec_utc, _ = normalize.syslog_to_utc("Dec", 9, "04:30:05", "America/New_York", 2026)
    assert normalize.to_iso(oct_utc) == "2026-10-09T08:30:05Z"
    assert normalize.to_iso(dec_utc) == "2026-12-09T09:30:05Z"
    assert normalize.to_iso(normalize.apply_skew(oct_utc, 180)) == "2026-10-09T08:33:05Z"


def test_brute_force_is_flagged():
    conn = database.connect(":memory:")
    lines = [f"Oct  9 02:31:{10 + i:02d} host1 sshd[1]: Failed password for root from 203.0.113.45 port 4000{i} ssh2"
             for i in range(6)]
    lines.append("Oct  9 02:31:30 host1 sshd[2]: Accepted password for root from 203.0.113.45 port 40010 ssh2")
    events = [parsers.parse_line(l, "t/auth.log", KOLKATA, set())[0] for l in lines]
    database.replace_source(conn, "t/auth.log", events, [], [])
    rules = {d["rule"] for d in detect.run_detections(conn)}
    assert "R1-brute-force" in rules
    assert "R2-successful-brute-force" in rules


def test_gap_logger_captures_malformed_line(tmp_path):
    log = tmp_path / "mixed.log"
    log.write_text(
        "Oct  9 02:31:15 host1 sshd[1]: Failed password for root from 10.0.0.9 port 1 ssh2\n"
        "@@@@ this is not a log line @@@@\n", encoding="utf-8")
    events, gaps, _ = parsers.parse_file(log, "t/mixed.log", KOLKATA)
    assert len(events) == 1
    assert len(gaps) == 1
    assert gaps[0]["line_number"] == 2
    assert "@@@@" in gaps[0]["raw_line"]


def test_verify_detects_tampering(tmp_path):
    original = tmp_path / "src" / "auth.log"
    original.parent.mkdir()
    original.write_text("Oct  9 02:31:15 h sshd[1]: test\n", encoding="utf-8")
    entry = evidence.collect(original)
    assert all(r["status"] == "OK" for r in evidence.verify())
    copy = evidence.evidence_path(entry)
    copy.chmod(0o666)                                 # undo read-only to simulate an attacker
    copy.write_text("tampered\n", encoding="utf-8")
    assert evidence.verify()[0]["status"] == "MISMATCH"


def test_ai_narrative_with_unknown_id_is_rejected(monkeypatch):
    conn = database.connect(":memory:")
    line = "Oct  9 02:31:10 h sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2"
    database.replace_source(conn, "t/auth.log", [parsers.parse_line(line, "t/auth.log", KOLKATA, set())[0]], [], [])
    database.save_detections(conn, [{"rule": "x", "severity": "HIGH", "title": "t", "description": "d",
                                     "event_ids": [1]}])
    monkeypatch.setattr(ai_helper, "status", lambda: (True, "mock"))
    # A hallucinated ID hidden inside a grouped citation must still be caught.
    monkeypatch.setattr(ai_helper, "_ask_gemini",
                        lambda p, f: {"narrative": "Brute force [#1, #999].", "_model": "mock"})
    assert ai_helper.explain_incident(conn)["source"] == "rule-based"
    monkeypatch.setattr(ai_helper, "_ask_gemini",
                        lambda p, f: {"narrative": "Brute force [#1].", "_model": "mock"})
    assert ai_helper.explain_incident(conn)["source"] == "ai"


def test_redactor_round_trip():
    r = ai_helper.Redactor(["deploy"])
    text = "deploy logged in from 203.0.113.45"
    hidden = r.redact(text)
    assert "203.0.113.45" not in hidden and "deploy" not in hidden
    assert r.unredact(hidden) == text


def test_sample_uploads_detected_with_upload_settings():
    """The drag-and-drop sample files produce the detections their README promises."""
    from src import pipeline
    samples = Path(__file__).resolve().parents[1] / "sample_uploads"
    pipeline.ingest([samples / "mail01_auth.log"], verbose=False,
                    overrides={"timezone": "Europe/London", "skew_seconds": -120})
    pipeline.ingest([samples / "shop_access.log"], verbose=False,
                    overrides={"timezone": "Europe/London", "skew_seconds": 0})
    conn = database.connect()
    rules = {d["rule"] for d in database.get_detections(conn)}
    assert {"R1-brute-force", "R2-successful-brute-force", "R7-privilege-escalation",
            "R3-web-scan", "R4-scan-then-exploit", "R5-webshell"} <= rules
    # 06:12:51 London (UTC+1 in October) minus the 2-minute fast clock = 05:10:51 UTC
    grace = database.search(conn, user="grace", text="succeeded")[0]
    assert grace["timestamp_utc"] == "2026-10-10T05:10:51Z"


def test_case_bundle_and_delete_session(tmp_path):
    import zipfile
    from src import pipeline, report
    log = tmp_path / "case" / "auth.log"
    log.parent.mkdir()
    log.write_text("Oct  9 02:31:15 h sshd[1]: Failed password for root from 10.0.0.9 port 1 ssh2\n",
                   encoding="utf-8")
    pipeline.ingest([log], verbose=False)
    conn = database.connect()

    names = zipfile.ZipFile(io.BytesIO(report.build_case_bundle(conn))).namelist()
    assert {"timeline.csv", "detections.csv", "incident_report.md", "evidence_manifest.json",
            "chain_of_custody.log"} <= set(names)
    assert any(n.startswith("evidence/") for n in names)
    conn.close()

    pipeline.delete_session()
    assert database.stats(database.connect())["events"] == 0
    assert evidence.load_manifest() == []
    assert log.exists()                                   # the analyst's original is never deleted
    assert "SESSION_DELETED" in evidence.read_custody_log()[-1]


def test_sensitive_sudo_commands_and_kill_chain():
    from src import attack_map
    conn = database.connect(":memory:")
    lines = ["Oct  9 02:35:02 h1 sudo:   bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
             "Oct  9 02:36:02 h1 sudo:   bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/sbin/useradd -m x"]
    events = [parsers.parse_line(l, "t/auth.log", KOLKATA, set())[0] for l in lines]
    database.replace_source(conn, "t/auth.log", events, [], [])
    dets = detect.run_detections(conn)
    assert {d["mitre"] for d in dets} == {"T1003.008", "T1136.001"}
    lit = {t["name"] for t in attack_map.kill_chain(dets) if t["count"]}
    assert lit == {"Credential Access", "Persistence"}
    dot = attack_map.attack_graph_dot(conn, dets, {
        "attacker": "#000", "internal": "#000", "host": "#000", "shell": "#000", "account": "#000",
        "privileged": "#000", "border": "#000", "text": "#000",
        "sev": {s: "#000" for s in database.SEVERITIES}})
    assert '"acct:h1:bob" -> "acct:h1:root"' in dot


def test_validation_scorecard_and_clock_proof():
    from src import validate
    v = validate.run()
    assert v["passed"] == v["total"] == 3
    assert v["alerts_found"] == v["alerts_expected"] and v["false_positives"] == 0
    views = validate.clock_comparison()["views"]
    # Only UTC + clock fix puts the database login after the web shell.
    assert [views[k]["verdict"]["detected"] for k in ("local", "utc_raw", "utc_fixed")] == [False, False, True]


def test_real_world_logs_cross_check():
    """Real public logs: every tool result must match an independent count."""
    from src import realworld
    if not all((config.PROJECT_DIR / d["file"]).exists() for d in realworld.DATASETS):
        pytest.skip("real_logs/ not downloaded (see real_logs/README.md)")
    r = realworld.run()
    for d in r["datasets"]:
        assert d["passed"], [c for c in d["checks"] if not c["ok"]]
