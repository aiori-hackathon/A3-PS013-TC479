"""
normalize.py - turns every timestamp into one shared clock: UTC.

Why this matters: a web server in India (+05:30) and a database server in New
York (-04:00 in summer) write very different local times for the same moment.
Only after converting both to UTC (and fixing any clock that runs fast or slow)
can we put events in the right order.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import config

MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
          "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def settings_for(path) -> dict:
    """
    Look up the time settings for one log file in config.SOURCE_SETTINGS.
    A key matches if the file path ENDS with it. Unknown files get the defaults.
    """
    posix = Path(path).resolve().as_posix()
    result = {"timezone": config.DEFAULT_TIMEZONE, "skew_seconds": 0,
              "year": config.DEFAULT_YEAR, "matched_key": None}
    for key, values in config.SOURCE_SETTINGS.items():
        if posix.endswith("/" + key) or posix == key:
            result.update(values)
            result["matched_key"] = key
            break
    return result


def to_iso(dt: datetime) -> str:
    """Format any aware datetime as ISO-8601 UTC: YYYY-MM-DDTHH:MM:SSZ."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def from_iso(text: str) -> datetime:
    """Read back a 'YYYY-MM-DDTHH:MM:SSZ' string as an aware UTC datetime."""
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def apply_skew(dt: datetime, skew_seconds: float) -> datetime:
    """Correct a server clock: add skew_seconds (negative for a clock that ran fast)."""
    return dt + timedelta(seconds=skew_seconds)


def syslog_to_utc(month: str, day: int, time_str: str, tz_name: str,
                  year=None, now=None) -> tuple[datetime, list[str]]:
    """
    Convert an auth.log time like ('Oct', 9, '02:31:07') to UTC.

    auth.log has no year and no time zone, so:
      * the time zone comes from config (tz_name), via zoneinfo so DST is correct;
      * the year comes from config, or else the current year - and if that would
        put the event in the future, we use the previous year (e.g. a 'Dec 31'
        line read on Jan 2).
    Returns (utc_datetime, list_of_assumption_notes).
    """
    notes = []
    zone = ZoneInfo(tz_name)
    hour, minute, second = (int(x) for x in time_str.split(":"))
    now = now or datetime.now(zone)

    if year is None:
        year = now.year
        local = datetime(year, MONTHS[month], day, hour, minute, second, tzinfo=zone)
        if local > now + timedelta(days=1):           # a date in the future is impossible
            year -= 1
            notes.append(f"date {month} {day} would be in the future; assumed year {year}")
        else:
            notes.append(f"no year in log; assumed current year {year}")

    # tzinfo=ZoneInfo(...) picks the right offset for that exact date (DST aware).
    # For the one repeated hour when clocks go back, Python uses the first one (fold=0).
    local = datetime(year, MONTHS[month], day, hour, minute, second, tzinfo=zone)
    return local.astimezone(timezone.utc), notes


def offset_to_utc(text: str) -> datetime:
    """
    Convert an access.log time like '10/Oct/2026:13:55:36 +0530' to UTC.
    The offset is written in the log, so we just use it.
    (Month names are mapped by hand so the result never depends on the PC's language.)
    """
    date_part, offset = text.split(" ")
    day, mon, rest = date_part.split("/")
    year, hh, mm, ss = rest.split(":")
    sign = 1 if offset[0] == "+" else -1
    tz = timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5])))
    local = datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=tz)
    return local.astimezone(timezone.utc)
