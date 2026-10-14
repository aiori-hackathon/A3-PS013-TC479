# Sample files for the drag-and-drop upload

Synthetic logs (documentation IP ranges, made-up users) for trying the dashboard's
**Add evidence** drop zone. They are not part of `python run.py demo`.

## Best for a live demo: `full_demo_auth.log` + `full_demo_access.log`

One busy morning (10 Oct 2026, 09:00-11:40 IST) on server `prod-web01`. Drop **both files together**
and keep the default settings (time zone **Asia/Kolkata**, skew **0**).
Result: 155 events, **16 alerts** (5 critical), 4 parsing gaps.

| Time (IST) | Attacker | What happens | Alerts |
|---|---|---|---|
| 09:15 | 203.0.113.10 | 20 failed SSH logins (root, admin, oracle...) - never gets in | Brute force (HIGH) |
| 09:42 | 203.0.113.20 | 12 failures, then logs in as `deploy`, reads `/etc/shadow`, adds user `sysupdate`, edits crontab | Brute force, **Successful brute force (CRITICAL)**, Privilege use |
| 10:20 | 198.51.100.50 | Password spraying 8 users, gets in as `intern`, sets SUID on bash | Brute force, **Successful brute force (CRITICAL)**, Privilege use |
| 10:30 | 203.0.113.30 | 15 x 404 scan, SQL injection, upload, web shell `shell.php?cmd=...` | Web scan, Scan then exploit, SQL injection, **Web shell (CRITICAL)** |
| 10:48 | 10.0.0.15 | Login as `dbadmin` from the web server 2 min after the web shell, then `pg_dump customers` | Lateral movement, Privilege use |
| 11:00 | 192.0.2.77 | Slow brute force on root | Brute force |
| 11:05 | 203.0.113.40 | `../../etc/passwd`, `..%2F..%2Fetc%2Fshadow`, `php://filter` | Path traversal (HIGH) |
| 11:25 | 198.51.100.60 | Directory scanner, finds nothing | Web scan (WARN) |

Normal traffic (cron jobs, admins alice/bob, shoppers) is mixed in, plus a few broken lines for the gap logger.

## Smaller single-story files

| File | What it shows | Upload settings |
|---|---|---|
| `mail01_auth.log` | Password spraying from `198.51.100.23`: one guess per user (anna, ben, carol...), then a successful login as `grace`, then `sudo crontab -e` and adding an SSH key to root (persistence). | Time zone **Europe/London**, skew **-120** (the mail server's clock ran 2 minutes fast) |
| `shop_access.log` | Web shop: 12 x 404 scan from `192.0.2.66`, a `UNION SELECT` injection, a `../../etc/passwd` download, an upload and a web shell at `/images/avatar_9.php?exec=...`. | Any (access.log has its own `+0100` offset), skew **0** |
| `firewall_mixed.log` | JSON, CEF and IDS lines from a firewall. The tool does not support these formats, so they all appear under **Gaps**. Try the AI Copilot's parsing-gap helper on them. One kernel line is classic syslog and is parsed. | Time zone **Europe/London**, skew **0** |

Expected detections after uploading the first two files:
brute force (HIGH) -> successful brute force (CRITICAL) -> privilege use (HIGH) on mail01, and
web scan (WARN) -> scan then exploit (HIGH) -> SQL injection / path traversal (HIGH) -> web shell (CRITICAL) on the shop.

Upload them one at a time when they need different settings (time zone / skew apply to every file in one upload).
