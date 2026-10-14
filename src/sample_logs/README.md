# Synthetic test scenarios

All data here is made up for testing. IPs come from the documentation range
`203.0.113.0/24` and private ranges (`10.x`, `192.168.x`); usernames are fictional.
Each file also contains a few deliberately broken or foreign-format lines so the
parsing-gap logger has something real to catch.

## 1. SSH brute force - `scenario1_ssh_bruteforce/auth.log`
Host `bastion01`, local time Asia/Kolkata (UTC+05:30).
`203.0.113.45` makes 15 failed SSH password attempts in about 2 minutes, then logs
in as `deploy`, then runs `sudo cat /etc/shadow` and `sudo useradd`. Normal lines
(cron, user `alice`, one honest typo) are mixed in.
**Expected:** brute force (HIGH, T1110) → successful brute force (CRITICAL, T1110)
→ privilege use (HIGH, T1548). Gaps: an ISO-timestamp line, a truncated line, a corrupted line.

## 2. Web app exploit - `scenario2_web_exploit/access.log`
Nginx combined log, offset `+0530`. `203.0.113.99` requests 14 missing pages in 13
seconds (scanning), then a SQL-injection-style query, a `../../etc/passwd` path,
an upload, and finally `/uploads/shell.php?cmd=...`. Payloads are mild and only
meant to trigger detection.
**Expected:** scan (WARN, T1595) → scan then exploit (HIGH, T1190), SQLi + LFI
(HIGH, T1190), web shell (CRITICAL, T1505.003). Gaps: an IIS-format line, a truncated line.

## 3. Multi-time-zone correlated breach - `scenario3_multi_timezone/`
* `web01_access.log` - web server in India, offsets `+0530`.
* `db01_auth.log` - database server in New York (no offset in the file; configured
  as `America/New_York`, which is UTC-4 in October), and **its clock was 3 minutes slow**
  (`skew_seconds: 180` in `config.py`).

| What | Local time in log | UTC without skew fix | UTC with skew fix |
|---|---|---|---|
| Web shell `avatar.php?cmd=id` on web01 | 14:02:10 +0530 | 08:32:10 | 08:32:10 |
| `dbadmin` SSH login to db01 from web01 (`10.0.0.15`) | 04:30:05 | **08:30:05** (looks *before* the shell) | **08:33:05** (55 s *after* the shell) |
| `sudo pg_dump customers` on db01 | 04:31:20 | 08:31:20 | 08:34:20 |

Sorting the raw local times puts the DB events (04:30) hours before the web events
(14:02). Converting to UTC brings them together, and only the skew correction puts
them in the true order: web shell → pivot to the database → data dump.
**Expected:** web shell (CRITICAL) → lateral movement (HIGH, T1021.004) →
privilege use on db01 (HIGH, T1548). Set `skew_seconds` to `0` and re-run the demo
to watch the lateral-movement detection disappear. Gap: an RFC 5424 syslog line.
