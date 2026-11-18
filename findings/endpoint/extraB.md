# Extra B — rare-command sweep

Method: normalised every CMD target (lowercase; IPs, numbers, hex/base64 blobs >16 chars, usernames, `/home/<user>`, temp filenames → placeholders; 457,293 CMD rows → 244 normalised patterns) and every PROC_START process/parent chain. Kept patterns on ≤5 hosts and ≤30 rows with no existing finding on the same host within 5 min (144 findings in `findings_endpoint.json`). Full sweep output: `/tmp/rare_cmd.txt`, `/tmp/sweep_out.txt`.

## Kept — endpoint (`findings/extraB_rare.json`, 11 findings)

| Pattern | Hosts | Rows | Example | Category | Why |
|---|---|---|---|---|---|
| `cat ~/.config/google-chrome/Default/Login\ Data` | 1 (WS-1314) | 1 | `cat ~/.config/google-chrome/Default/Login\ Data` @2026-10-16T02:27:00.005Z, bash, nina50 | Host intrusion signs | Hunt 4 credential-store read; missed only because the escaped space (`Login\ Data`) defeats its `Login Data` LIKE filter. |
| `python3 scan.py <ip>/<n> --ports <n>-<n> --slow` | 5 (WS-9056, WS-3074, WS-5464, WS-9063, WS-0159) | 5 | `python3 scan.py 10.2.0.0/24 --ports 20-500 --slow` @2026-10-14T00:02:40.458Z, bash, henry348 | Reconnaissance | Subnet port sweep in the spirit of hunt 3 nmap/masscan; corroborated by `python3` NET_CONNECTs to sequential 10.2.0.x hosts on ports 20/70 starting ~13 s after each CMD. Reported at CMD time (first event, before first NET_CONNECT). |
| PROC_START `miner_worker` (`parent=bash hash=25042c536b12 signed=yes`) | 5 (WS-9868, WS-8931, WS-1122, WS-4803, WS-9393) | 5 | PROC_START @2026-10-12T16:50:36.199Z, WS-9868, user none | Malware delivery | Process name is a cryptominer and every host's `miner_worker` makes outside NET_CONNECTs to the same pool `198.18.20.5:3333`; hunt 6 missed it because it is signed and not a minority variant of a common program. Reported at PROC_START time (first event). |

## Kept — other roles (`findings/extraB_rare_other.json`, 62 findings, Lateral movement)

| Pattern | Hosts | Rows | Example | Category | Why |
|---|---|---|---|---|---|
| `winexe -U <user>%Summer2026! //<ip> 'sc query'` (+1 pass-the-hash variant `winexe -U admin-1%<NT-hash> //<ip> cmd` on WS-7910) | 62 | 62 | `winexe -U alice103%Summer2026! //10.2.0.24 'sc query'` @2026-10-12T15:51:29.652Z, bash | Lateral movement | Remote Windows execution with one shared plaintext password (`Summer2026!`) across many different accounts, plus one NT-hash pass-the-hash row — credential reuse, not per-user admin work. This is Identity-role territory, hence the separate file. |

## Rejected — top 30 rare patterns

| # | Pattern (hosts/rows) | Reason |
|---|---|---|
| 1 | `xfreerdp /u:<user> /v:<ip> [+clipboard]` fragments (526 hosts/547 rows aggregated) | Fleet-wide remote access once usernames are properly collapsed; no credential or payload evidence. |
| 2 | `smbclient //<ip>/share -U <user> -c 'recurse; prompt; mget *'` fragments (218 hosts/218 rows) | Aggregates far above the rarity gate; own-account share access, no exfil destination shown. |
| 3 | `winrs -r:<ip> -u:<user> hostname` fragments (72 hosts aggregated) | Read-only remote hostname check with the caller's own account; no payload. |
| 4 | `winrs -r:<ip> -u:admin-<n> whoami` (5 hosts/5 rows) | Admin service-account check; no payload or credential material. |
| 5 | `wmic /node:<ip> /user:<user> cpu get loadpercentage` fragments (57 hosts aggregated) | Read-only CPU monitoring query, own account. |
| 6 | `winexe …` per-username fragments | Not rejected on merit — aggregated and reported in `_other` (above); fragments only looked rare due to username splitting. |
| 7 | `ssh svc-backup@<ip>` (4 hosts/4 rows, minutes apart) | Service-account SSH burst consistent with scheduled backup tooling; Identity role's call, no endpoint payload. |
| 8 | `ssh svc-monitor@<ip>` (3 hosts/3 rows) | Service-account monitoring SSH; same as above. |
| 9 | `ssh svc-scan@<ip>` (3 hosts/3 rows) | Service-account scanner SSH; same as above. |
| 10 | `nessus --scan <ip>/<n>` (1 host SRV-60/5 rows, daily 01:01) | Signed `svc->nessus` PROC_START on a server, daily schedule, `svc-scan` user — sanctioned vuln scanner. |
| 11 | PROC_START `svc->nessus` (1 host/5 rows) | Same scheduled scanner as #10. |
| 12 | PROC_START `svc->crawler` (1 host SRV-01/5 rows, daily 00:00) | Signed service process on a server with routine web NET_CONNECTs; server baseline. |
| 13 | PROC_START `svc->dirb` (1 host SRV-02/1 row) | Signed, `svc` parent, `svc-monitor` user on an IT server — monitoring tooling, single row, no CMD/NET corroboration. |
| 14 | `tar czf /tmp/.sysdata.tgz /home/ /etc/ 2>/dev/null` (2 hosts/2 rows) | Suspicious staging archive, but hunt 4's required join fails: no USB copy ever on WS-7708/WS-8829 and no exfil NET_CONNECT/CMD afterwards — excluded to protect precision. |
| 15 | `id` (3 SRV hosts/3 rows, `admin-*` users) | Server admin identity check; no attack context. |
| 16 | `whoami; hostname` (3 SRV hosts/3 rows, `admin-*`) | Same admin check family as #15. |
| 17 | `hostname; uptime` (3 SRV hosts/3 rows, `admin-*`) | Same admin check family as #15. |
| 18 | `uname -a` (2 SRV hosts/2 rows, `admin-*`) | Same admin check family as #15. |
| 19 | `last -n 20` (1 host SRV-10, `admin-2`) | Read-only login-history review by a server admin. |
| 20 | `nmap -sV test.bearcorp.com` (1 host SRV-02) | Hunt 3 already adjudicated this exact row as a benign single-target version check from an IT asset. |
| 21 | `masscan <ip>/<n> -p<n>-<n> --rate <n>` CMD rows (3 hosts/3 rows) | Already matched by existing hunt 3 findings at the earlier PROC_START times; CMD rows are the same actions. |
| 22 | `ping -s <n> -c <n> <ip>` unmatched CMD rows (3 hosts) | Already matched by existing hunt 3 C2 findings at PROC_START times; duplicates of known actions. |
| 23 | `apt upgrade -y` (1 host SRV-20/1 row) | Routine server package maintenance. |
| 24 | `systemctl restart app` (1 host SRV-07/1 row) | Routine service restart, no payload path. |
| 25 | `kubectl rollout restart deploy/worker` (1 host SRV-12/1 row) | Routine deployment restart on a server; kubectl is fleet-common (8k+ hosts). |
| 26 | PROC_START `bash->masscan` (3 hosts/3 rows) | Already covered by hunt 3 findings (see #21). |
| 27 | PROC_START `bash->python3` (5 hosts/5 rows) | Not a separate action — these are the interpreter starts for the kept `scan.py` sweeps; reporting both would double-count one action per host. |
| 28 | Browser→shell / office→bash parent chains | None exist: no PROC_START chain with a browser or office parent spawning a shell appears in the ≤5-host chain list at all. |
| 29 | `socat`/`mkfifo`/`perl`/`php`/`openssl s_client` reverse shells, `at`/`systemd` persistence, `wget -O /tmp`, archive `scp` to outside, `shred`/`crontab -r` | Absent from the CMD corpus entirely (zero rows) — the sweep confirms no such patterns were missed. |
| 30 | All remaining per-username fragments of fleet tools (`git`/`cat`/`ssh`/`curl` etc. tails) | Normalisation artefacts of tools run on thousands of hosts; no malicious semantics. |

## Validation

Both output files were run through `berkeley_hackathon_validate.py` against `bearcorp.db`; see the final chat message for the verbatim result.
