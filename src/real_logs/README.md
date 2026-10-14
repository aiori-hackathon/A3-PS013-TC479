# Real-world logs

Public log datasets from **real servers**, used by the Validation tab's *Real-world test* and by
`python run.py validate`. They are not synthetic: the IP addresses are real attackers and clients
as published by the dataset authors. They are used read-only, for defensive testing.

| Folder | Dataset | Source | Licence |
|---|---|---|---|
| `loghub_openssh/OpenSSH_2k.log` | 2,000 lines of OpenSSH auth log from a lab server ("LabSZ") under real brute-force attack | LogHub - https://github.com/logpai/loghub (OpenSSH sample) | Free for research and academic use (see the LogHub repository) |
| `elastic_nginx/nginx_access.log` | 51,462 Nginx combined-format requests over three weeks (May-June 2015) | Elastic examples - https://github.com/elastic/examples (Common Data Formats / nginx_logs) | Apache-2.0 |

Re-download (PowerShell):

```powershell
Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log" -OutFile real_logs\loghub_openssh\OpenSSH_2k.log
Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/nginx_logs/nginx_logs" -OutFile real_logs\elastic_nginx\nginx_access.log
```

What the test proves (real logs have no answer key, so results are cross-checked against an
independent regex count that does not use the tool's parser or rules):

* **SSH:** every line parsed; failed/successful login counts and the set of brute-force attacker
  IPs match the independent count exactly (9 attacker IPs, up to 286 attempts each).
* **Web:** all 51,462 requests parsed; 0 false alarms. A naive "10 x 404 = scan" rule would flag 624
  innocent clients (update tools re-requesting the same missing file) - this real data is why rule
  R3 also requires 8+ different paths.
