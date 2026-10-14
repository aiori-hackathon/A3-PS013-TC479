"""
ai_helper.py - OPTIONAL Gemini helper. The tool works fully without it.

Safety rules built in:
  * Off unless GEMINI_API_KEY is set (in the environment or in a .env file).
  * IPs and usernames are replaced with tokens (IP_1, USER_2) BEFORE anything is
    sent, and mapped back locally afterwards.
  * Only small pieces are sent (flagged events or gap lines), never whole logs.
  * Every call is written to the chain-of-custody log with the model name and a
    SHA-256 hash of the exact prompt (the hash, not the text).
  * Answers must be JSON and are validated. Anything odd -> fall back to the
    normal, non-AI result.
  * The AI never writes or runs SQL. It only returns a small filter; our own
    code (database.search) runs the query.
"""
import json
import os
import re

import config
from src import database, evidence, normalize, report

PLACEHOLDER_KEYS = {"", "your_key_here"}


# ---------------------------------------------------------------------------
# Is AI available?
# ---------------------------------------------------------------------------
def _read_env_file() -> dict:
    """Tiny .env reader (KEY=value lines) so we do not need another package."""
    values = {}
    env_path = config.PROJECT_DIR / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def get_api_key():
    key = os.environ.get("GEMINI_API_KEY") or _read_env_file().get("GEMINI_API_KEY", "")
    return None if key in PLACEHOLDER_KEYS else key


def status() -> tuple[bool, str]:
    """(enabled, message) - e.g. (False, 'AI: disabled (no key)')."""
    if not get_api_key():
        return False, "AI: disabled (no key)"
    try:
        from google import genai  # noqa: F401
    except ImportError:
        return False, "AI: disabled (google-genai not installed)"
    return True, f"AI: enabled (model {config.AI_MODEL}, fallback {config.AI_FALLBACK_MODEL})"


# ---------------------------------------------------------------------------
# Redaction: real values never leave the machine
# ---------------------------------------------------------------------------
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TOKEN_RE = re.compile(r"\b(?:IP|USER)_\d+\b")


class Redactor:
    """Swaps IPs and usernames for tokens, and remembers how to swap them back."""

    def __init__(self, usernames=()):
        self.to_token, self.to_real = {}, {}
        # Longest names first so 'admin2' is replaced before 'admin'.
        names = sorted({u for u in usernames if u and len(u) > 1}, key=len, reverse=True)
        self.user_re = re.compile(r"\b(" + "|".join(map(re.escape, names)) + r")\b") if names else None

    def _token(self, real: str, prefix: str) -> str:
        if real not in self.to_token:
            count = sum(1 for t in self.to_real if t.startswith(prefix)) + 1
            token = f"{prefix}_{count}"
            self.to_token[real], self.to_real[token] = token, real
        return self.to_token[real]

    def redact(self, text: str) -> str:
        text = IP_RE.sub(lambda m: self._token(m.group(0), "IP"), text)
        if self.user_re:
            text = self.user_re.sub(lambda m: self._token(m.group(0), "USER"), text)
        return text

    def unredact(self, text: str) -> str:
        return TOKEN_RE.sub(lambda m: self.to_real.get(m.group(0), m.group(0)), text)


def _redactor_for(conn) -> Redactor:
    return Redactor(database.distinct_values(conn, "username"))


# ---------------------------------------------------------------------------
# The one place that talks to Gemini
# ---------------------------------------------------------------------------
def _ask_gemini(prompt: str, feature: str):
    """Send a prompt, expect JSON back. Returns a parsed dict, or None on ANY problem."""
    enabled, _ = status()
    if not enabled:
        return None
    try:
        from google import genai
        from google.genai import types
        # Time limit per call (in ms) and no automatic retries, so a busy model
        # quickly hands over to the fallback model instead of hanging the dashboard.
        client = genai.Client(api_key=get_api_key(), http_options=types.HttpOptions(
            timeout=config.AI_TIMEOUT_SECONDS * 1000,
            retry_options=types.HttpRetryOptions(attempts=1)))
    except Exception:
        return None

    for model in (config.AI_MODEL, config.AI_FALLBACK_MODEL):
        # Record the call BEFORE sending: model + hash of the exact prompt text.
        evidence.log_custody("AI_CALL", {"feature": feature, "model": model,
                                         "prompt_sha256": evidence.sha256_text(prompt)})
        try:
            response = client.models.generate_content(
                model=model, contents=prompt,
                config=types.GenerateContentConfig(response_mime_type="application/json",
                                                   temperature=0.2))
            data = json.loads(response.text)
            if isinstance(data, dict):
                data["_model"] = model
                return data
        except Exception as exc:                     # network, quota, bad JSON, retired model...
            evidence.log_custody("AI_CALL_FAILED", {"feature": feature, "model": model,
                                                    "error": type(exc).__name__})
    return None


def _flagged_lines(conn, redactor: Redactor) -> tuple[list[str], set]:
    """Flagged events as short redacted text lines, plus the set of their IDs."""
    events = database.get_events_by_ids(conn, database.flagged_event_ids(conn))
    events = events[:config.AI_MAX_EVENTS]
    lines = [redactor.redact(f"[#{e['id']}] {e['timestamp_utc']} {e['severity']} "
                             f"{e['source_file']}: {e['event_summary']}") for e in events]
    return lines, {e["id"] for e in events}


# ---------------------------------------------------------------------------
# Feature 1: "Explain this incident"
# ---------------------------------------------------------------------------
def explain_incident(conn) -> dict:
    """
    Returns {"source": "ai"|"rule-based", "text": ..., "model": ...}.
    The AI narrative is only kept if every [#id] it cites is a real flagged event.
    """
    fallback = {"source": "rule-based", "text": report.rule_based_summary(conn), "model": None}
    redactor = _redactor_for(conn)
    lines, valid_ids = _flagged_lines(conn, redactor)
    if not lines:
        return fallback
    detections = [redactor.redact(f"{d['severity']} {d['title']} ({d['mitre']}): {d['description']}")
                  for d in database.get_detections(conn)]

    prompt = (
        "You are assisting a defensive security analyst. Below are already-flagged events "
        "from a synthetic incident timeline (times are UTC; IPs and usernames are replaced "
        "by tokens such as IP_1 and USER_1 - keep the tokens exactly as written).\n"
        "Write a short plain-English incident narrative (120-250 words) in time order. "
        "Every factual sentence must cite event IDs in the form [#12]. Use ONLY IDs that "
        "appear below. Do not invent events.\n"
        'Reply as JSON: {"narrative": "..."}\n\n'
        "DETECTIONS:\n" + "\n".join(detections) + "\n\nFLAGGED EVENTS:\n" + "\n".join(lines))

    data = _ask_gemini(prompt, "explain_incident")
    narrative = data.get("narrative") if data else None
    if not isinstance(narrative, str) or not narrative.strip():
        return fallback

    # Collect every ID, including grouped citations like [#8, #9].
    cited = {int(x) for group in re.findall(r"\[(#[^\]]*)\]", narrative)
             for x in re.findall(r"#\s*(\d+)", group)}
    if not cited or not cited.issubset(valid_ids):  # unknown or missing IDs -> discard
        return fallback

    text = redactor.unredact(narrative)
    result = {"source": "ai", "text": text, "model": data["_model"]}
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    config.AI_SUMMARY_PATH.write_text(json.dumps({
        "label": report.AI_LABEL, "model": data["_model"], "generated_utc": evidence.now_utc_iso(),
        "narrative": text, "cited_event_ids": sorted(cited)}, indent=2), encoding="utf-8")
    return result


# ---------------------------------------------------------------------------
# Feature 2: natural-language search -> validated JSON filter
# ---------------------------------------------------------------------------
FILTER_KEYS = {"ip", "user", "severity", "after_time", "before_time", "text"}


def _clean_time(value):
    """Accept an ISO time from the AI only if it really parses; return our UTC format."""
    try:
        return normalize.to_iso(normalize.from_iso(str(value)))
    except (ValueError, TypeError):
        return None


def validate_filter(raw: dict, redactor: Redactor):
    """Keep only known keys with sane values. Returns a clean filter dict or None."""
    if not isinstance(raw, dict):
        return None
    clean = {}
    for key, value in raw.items():
        if key not in FILTER_KEYS or value in (None, "", []):
            continue
        if key in ("ip", "user", "text"):
            if not isinstance(value, str) or len(value) > 100:
                return None
            clean[key] = redactor.unredact(value.strip())
        elif key == "severity":
            values = [value] if isinstance(value, str) else value
            if not isinstance(values, list):
                return None
            values = [str(v).upper() for v in values]
            if not all(v in database.SEVERITIES for v in values):
                return None
            clean[key] = values
        else:                                          # after_time / before_time
            t = _clean_time(value)
            if not t:
                return None
            clean[key] = t
    if "ip" in clean and not IP_RE.fullmatch(clean["ip"]):
        return None                                    # an unmapped token or junk -> reject
    return clean


def natural_language_search(conn, question: str) -> dict:
    """
    Returns {"ok": bool, "filter": {...}, "results": [...], "message": str}.
    The AI only proposes a filter; database.search() runs it with safe placeholders.
    """
    redactor = _redactor_for(conn)
    lines, _ = _flagged_lines(conn, redactor)
    s = database.stats(conn)
    prompt = (
        "Convert the analyst's question into a JSON search filter for a security timeline. "
        "Allowed keys only: ip, user, severity (list of INFO/WARN/HIGH/CRITICAL), "
        "after_time, before_time (ISO-8601 UTC like 2026-10-09T08:00:00Z), text. "
        "Omit keys you do not need. IPs and users appear as tokens (IP_1, USER_1); "
        "use the tokens exactly. Return ONLY the JSON object.\n"
        f"Timeline covers {s['first']} to {s['last']}.\n"
        "Key flagged events for context:\n" + "\n".join(lines) +
        "\n\nQUESTION: " + redactor.redact(question))

    data = _ask_gemini(prompt, "natural_language_search")
    if data is None:
        return {"ok": False, "filter": None, "results": [],
                "message": "AI did not return a usable answer - use the normal filters instead."}
    data.pop("_model", None)
    clean = validate_filter(data, redactor)
    if clean is None:
        return {"ok": False, "filter": data, "results": [],
                "message": "AI filter failed validation and was ignored."}
    results = database.search(conn, ip=clean.get("ip"), user=clean.get("user"),
                              severity=clean.get("severity"), after=clean.get("after_time"),
                              before=clean.get("before_time"), text=clean.get("text"))
    return {"ok": True, "filter": clean, "results": results,
            "message": f"{len(results)} event(s) matched the AI-proposed filter."}


# ---------------------------------------------------------------------------
# Feature 3: parsing-gap helper (suggestions only, never applied automatically)
# ---------------------------------------------------------------------------
def suggest_gap_regex(conn, max_lines: int = 10) -> list[dict]:
    gaps = database.get_gaps(conn)[:max_lines]
    if not gaps:
        return []
    redactor = _redactor_for(conn)
    numbered = [f"{i}: {redactor.redact(g['raw_line'])}" for i, g in enumerate(gaps)]
    prompt = (
        "These log lines could not be parsed by a tool that understands classic syslog "
        "auth.log and NCSA combined access.log. For each line, guess the log format and "
        "suggest one Python regular expression with named groups that would parse lines "
        "like it. IPs/users are replaced by tokens; write generic patterns, not the tokens. "
        'Reply as JSON: {"suggestions": [{"line": 0, "likely_format": "...", '
        '"regex": "...", "explanation": "..."}]}\n\n' + "\n".join(numbered))

    data = _ask_gemini(prompt, "gap_regex_helper")
    if not data or not isinstance(data.get("suggestions"), list):
        return []
    out = []
    for s in data["suggestions"]:
        if not isinstance(s, dict) or not isinstance(s.get("line"), int) \
                or not 0 <= s["line"] < len(gaps):
            continue
        gap = gaps[s["line"]]
        regex = str(s.get("regex", ""))
        try:
            matches = bool(re.search(regex, redactor.redact(gap["raw_line"])))
            valid = True
        except re.error:
            matches, valid = False, False
        out.append({"source_file": gap["source_file"], "line_number": gap["line_number"],
                    "raw_line": gap["raw_line"],
                    "likely_format": str(s.get("likely_format", ""))[:100],
                    "regex": regex, "regex_compiles": valid, "matches_sample": matches,
                    "explanation": redactor.unredact(str(s.get("explanation", ""))[:400])})
    return out
