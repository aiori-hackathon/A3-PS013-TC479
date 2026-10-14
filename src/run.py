"""
run.py - command-line entry point.

    python run.py ingest <file-or-folder> [more...]   hash, parse, normalise, store, detect
    python run.py verify                              re-check evidence hashes (OK / MISMATCH)
    python run.py report                              export the incident report
    python run.py demo                                fresh run on all three sample scenarios
"""
import argparse
import sys

import config
from src import database, evidence, pipeline, report

# Make sure printing never crashes on a Windows console with an old code page.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def print_timing(seconds: float) -> None:
    manual = config.MANUAL_BASELINE_MINUTES * 60
    print(f"\n  Triage time: tool {seconds:.2f} s  vs  manual baseline ~{config.MANUAL_BASELINE_MINUTES} min"
          f"  (about {manual / max(seconds, 0.001):,.0f}x faster)")


def cmd_ingest(paths) -> None:
    print("Ingesting logs (hash -> read-only copy -> parse -> UTC -> store -> detect)...")
    s = pipeline.ingest(paths)
    print(f"\n  Timeline: {s['events']} events from {s['sources']} source(s), "
          f"{s['first']}  ->  {s['last']}")
    print(f"  Detections: {s['detections']}   Parsing gaps: {s['gaps']} "
          f"(see {config.GAPS_PATH.relative_to(config.PROJECT_DIR)})")
    print_timing(s["seconds"])


def cmd_verify() -> bool:
    print("Verifying evidence copies against the manifest...")
    results = evidence.verify()
    if not results:
        print("  No evidence collected yet. Run 'python run.py demo' or 'ingest' first.")
        return True
    for r in results:
        print(f"  [{r['status']:8s}] {r['evidence_file']}")
        if r["status"] != "OK":
            print(f"             expected {r['expected_sha256']}")
            print(f"             actual   {r['actual_sha256']}")
    ok = all(r["status"] == "OK" for r in results)
    print("  All evidence intact." if ok else "  WARNING: evidence does not match the manifest!")
    return ok


def cmd_report() -> None:
    print("Exporting incident report...")
    out = report.export()
    print(f"  Markdown: {out['markdown']}")
    print(f"  PDF:      {out['pdf'] or '(skipped - install fpdf2 for PDF output)'}")


def cmd_validate() -> bool:
    """Re-run the three scenarios in a throwaway case and score them (real data untouched)."""
    from src import validate
    print("Validating against the three synthetic scenarios (throwaway case)...\n")
    v = validate.run()
    for r in v["scenarios"]:
        mark = "PASS" if r["passed"] else "FAIL"
        print(f"  [{mark}] {r['title']:24s} alerts {len(r['expected']) - len(r['missing'])}/{len(r['expected'])}"
              f"  extra {len(r['unexpected'])}  gaps {r['gaps']}/{r['gaps_expected']}"
              f"  hashes {r['hashes_ok']}/{r['hashes']}  {r['seconds']:.2f} s vs ~{r['manual_minutes']} min manual")
        for rule in r["missing"]:
            print(f"           missing: {rule}")
        for rule in r["unexpected"]:
            print(f"           unexpected: {rule}")
    print(f"\n  {v['passed']}/{v['total']} scenarios passed, {v['alerts_found']}/{v['alerts_expected']} expected "
          f"alerts, {v['false_positives']} false positives.")
    print_timing(v["tool_seconds"])

    print("\nReal-world logs (public data from real servers, cross-checked independently):")
    from src import realworld
    rw = realworld.run()
    for d in rw["datasets"]:
        if d.get("missing"):
            print(f"  [SKIP] {d['title']}: {d['file']} not found (see real_logs/README.md)")
            continue
        ok = sum(c["ok"] for c in d["checks"])
        print(f"  [{'PASS' if d['passed'] else 'FAIL'}] {d['title']:34s} {d['lines']:,} lines, {d['alerts']} alerts, "
              f"{ok}/{len(d['checks'])} cross-checks, {d['seconds']:.2f} s")
        for c in d["checks"]:
            if not c["ok"]:
                print(f"           {c['name']}: expected {c['expected']}, tool {c['actual']}")

    print("\nWhy UTC + clock-skew correction matters (scenario 3):")
    from src.validate import clock_comparison
    views = clock_comparison()["views"]
    for key, label in (("local", "Raw local time  "), ("utc_raw", "UTC, no skew fix"),
                       ("utc_fixed", "UTC + skew fix  ")):
        verdict = views[key]["verdict"]
        print(f"  {label}: {'DETECTED' if verdict['detected'] else 'missed  '} - {verdict['text']}")
    return v["passed"] == v["total"]


def cmd_demo() -> None:
    print("=== ARIXA Forensic Timeline - DEMO: three synthetic incident scenarios ===\n")
    pipeline.reset_outputs()
    folders = sorted(p for p in config.SAMPLE_LOGS_DIR.iterdir() if p.is_dir())
    cmd_ingest(folders)

    conn = database.connect()
    print("\nDetections (UTC order):")
    for d in database.get_detections(conn):
        print(f"  {d['first_seen']}  {d['severity']:8s} {d['mitre']:10s} {d['title']}")
    conn.close()

    print()
    cmd_verify()
    print()
    cmd_report()
    print("\nNext: open the dashboard with   streamlit run app.py")


def main() -> None:
    parser = argparse.ArgumentParser(description="ARIXA Forensic Timeline (PS-013)")
    sub = parser.add_subparsers(dest="command", required=True)
    p_ingest = sub.add_parser("ingest", help="ingest log files or folders")
    p_ingest.add_argument("paths", nargs="+", help="log file(s) or folder(s)")
    sub.add_parser("verify", help="re-check evidence hashes")
    sub.add_parser("report", help="export the incident report")
    sub.add_parser("demo", help="run all three sample scenarios")
    sub.add_parser("validate", help="score the tool against the three scenarios")
    args = parser.parse_args()

    if args.command == "ingest":
        cmd_ingest(args.paths)
    elif args.command == "verify":
        sys.exit(0 if cmd_verify() else 1)
    elif args.command == "report":
        cmd_report()
    elif args.command == "demo":
        cmd_demo()
    elif args.command == "validate":
        sys.exit(0 if cmd_validate() else 1)


if __name__ == "__main__":
    main()
