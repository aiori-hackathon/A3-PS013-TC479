"""
export_showcase.py - export the tool's real results on the three synthetic scenarios to one
JSON file, for the read-only web showcase.

    python export_showcase.py <output.json>

It runs in a throwaway case (like `run.py validate`), so your own evidence and uploads are
never included or changed. Only synthetic sample data ends up in the file.
"""
import json
import sys
import tempfile
from pathlib import Path

import config
from src import attack_map, validate


def export(out_path: Path) -> dict:
    from src import database, evidence, pipeline

    saved = {name: getattr(config, name) for name in validate.PATH_SETTINGS}
    work = Path(tempfile.mkdtemp(prefix="ft_showcase_"))
    try:
        validate._point_config_at(work / "case")
        stats = pipeline.ingest(sorted(p for p in config.SAMPLE_LOGS_DIR.iterdir() if p.is_dir()),
                                verbose=False)
        conn = database.connect()
        detections = database.get_detections(conn)
        flagged = database.flagged_event_ids(conn)
        notes = database.get_source_notes(conn)
        data = {
            "generated_utc": evidence.now_utc_iso(),
            "stats": {k: stats[k] for k in ("events", "sources", "detections", "gaps", "first", "last",
                                            "by_severity")} | {"seconds": round(stats["seconds"], 3)},
            "sources": [s | {"notes": notes.get(s["source_file"], [])} for s in database.source_summary(conn)],
            "events": [{"id": e["id"], "t": e["timestamp_utc"], "sev": e["severity"], "src": e["source_file"],
                        "fmt": e["log_format"], "ip": e["source_ip"], "user": e["username"],
                        "summary": e["event_summary"], "raw": e["raw_log"], "flagged": e["id"] in flagged}
                       for e in database.all_events(conn)],
            "detections": detections,
            "kill_chain": attack_map.kill_chain(detections),
            "graph": attack_map.attack_graph_data(conn, detections),
            "gaps": database.get_gaps(conn),
            "manifest": [{"source": m["source_label"], "sha256": m["sha256"], "size": m["size_bytes"],
                          "status": "OK"} for m in evidence.load_manifest()],
        }
        conn.close()
    finally:
        for name, value in saved.items():
            setattr(config, name, value)
        validate._remove(work)

    data["validation"] = validate.run()
    clock = validate.clock_comparison()
    data["clock"] = {"sources": clock["sources"], "views": clock["views"]}
    out_path.write_text(json.dumps(data, indent=1), encoding="utf-8")
    return data


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "showcase_data.json")
    d = export(target)
    print(f"Wrote {target}: {len(d['events'])} events, {len(d['detections'])} detections, "
          f"validation {d['validation']['passed']}/{d['validation']['total']}")
