"""
evidence.py - keeps the evidence safe and provable.

What happens here:
  1. Every input log is hashed with SHA-256 the moment we read it.
  2. A copy is placed in the evidence/ folder and marked READ-ONLY.
     The original file is never opened for writing.
  3. A manifest (evidence/manifest.json) lists each copy: name, hash, size, time.
  4. Every action is appended to evidence/chain_of_custody.log.
  5. verify() re-hashes every copy and says OK or MISMATCH (the tamper check).
"""
import hashlib
import json
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path

import config


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------
def sha256_bytes(data: bytes) -> str:
    """SHA-256 of raw bytes, as a 64-character hex string."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """SHA-256 of a text string (encoded as UTF-8)."""
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path) -> str:
    """SHA-256 of a file, read in 64 KB chunks so huge logs do not fill memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:                       # "rb" = read-only, binary
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def now_utc_iso() -> str:
    """Current time in UTC, e.g. 2026-10-10T08:00:00Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Chain of custody (append-only log of every action)
# ---------------------------------------------------------------------------
def log_custody(action: str, details: dict) -> None:
    """Append one line: '<utc time> | <ACTION> | <json details>'. Never rewrites old lines."""
    config.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    line = f"{now_utc_iso()} | {action} | {json.dumps(details, sort_keys=True)}\n"
    with open(config.CUSTODY_LOG_PATH, "a", encoding="utf-8") as f:   # "a" = append only
        f.write(line)


def read_custody_log() -> list[str]:
    if not config.CUSTODY_LOG_PATH.exists():
        return []
    return config.CUSTODY_LOG_PATH.read_text(encoding="utf-8").splitlines()


# ---------------------------------------------------------------------------
# Manifest (the list of evidence copies and their hashes)
# ---------------------------------------------------------------------------
def load_manifest() -> list[dict]:
    if not config.MANIFEST_PATH.exists():
        return []
    return json.loads(config.MANIFEST_PATH.read_text(encoding="utf-8"))


def _save_manifest(entries: list[dict]) -> None:
    config.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    config.MANIFEST_PATH.write_text(json.dumps(entries, indent=2), encoding="utf-8")


def source_label(path) -> str:
    """Short readable name for a log: '<parent folder>/<file name>'."""
    p = Path(path).resolve()
    return f"{p.parent.name}/{p.name}"


def collect(original_path) -> dict:
    """
    Hash a log file and store a read-only copy in evidence/.
    Returns the manifest entry for that copy.
    If the exact same content was collected before, the existing entry is reused.
    """
    original = Path(original_path).resolve()
    file_hash = sha256_file(original)
    label = source_label(original)

    # Same label + same hash already collected? Reuse it - but only if the copy is still intact.
    manifest = load_manifest()
    copy_name = f"{file_hash[:12]}_{label.replace('/', '__')}"
    for entry in manifest:
        if entry["sha256"] == file_hash and entry["source_label"] == label:
            path = evidence_path(entry)
            if path.exists() and sha256_file(path) == file_hash:
                log_custody("FILE_ALREADY_COLLECTED", {"source": label, "sha256": file_hash})
                return entry
            # The stored copy was changed or deleted: keep the record, take a fresh copy.
            log_custody("EVIDENCE_COPY_MISMATCH", {"source": label, "evidence_file": entry["evidence_file"]})
            copy_name = f"{file_hash[:12]}_{now_utc_iso().replace(':', '')}_{label.replace('/', '__')}"

    # Copy name starts with part of the hash, so two versions never overwrite each other.
    copy_path = config.EVIDENCE_DIR / copy_name
    config.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    if not copy_path.exists():
        shutil.copy2(original, copy_path)             # copy2 also keeps the file timestamps
        os.chmod(copy_path, stat.S_IREAD)             # mark the copy read-only

    # Hash the copy too, to prove the copy is identical to the original.
    copy_hash = sha256_file(copy_path)
    if copy_hash != file_hash:
        raise RuntimeError(f"Copy of {label} does not match the original hash!")

    entry = {
        "source_label": label,
        "original_path": str(original),
        "evidence_file": copy_name,
        "sha256": file_hash,
        "size_bytes": original.stat().st_size,
        "ingested_utc": now_utc_iso(),
    }
    manifest.append(entry)
    _save_manifest(manifest)
    log_custody("FILE_INGESTED", {"source": label, "evidence_file": copy_name,
                                  "sha256": file_hash, "size_bytes": entry["size_bytes"]})
    return entry


def evidence_path(entry: dict) -> Path:
    return config.EVIDENCE_DIR / entry["evidence_file"]


# ---------------------------------------------------------------------------
# Verify (tamper check)
# ---------------------------------------------------------------------------
def verify(log: bool = True) -> list[dict]:
    """Re-hash every evidence copy and compare with the manifest.
    log=False is used by the dashboard's status badge so it does not fill the custody log."""
    results = []
    for entry in load_manifest():
        path = evidence_path(entry)
        if not path.exists():
            actual, status = None, "MISSING"
        else:
            actual = sha256_file(path)
            status = "OK" if actual == entry["sha256"] else "MISMATCH"
        results.append({
            "evidence_file": entry["evidence_file"],
            "source_label": entry["source_label"],
            "expected_sha256": entry["sha256"],
            "actual_sha256": actual,
            "status": status,
        })
    if log:
        summary = {r["evidence_file"]: r["status"] for r in results}
        log_custody("EVIDENCE_VERIFIED", {"results": summary})
    return results
