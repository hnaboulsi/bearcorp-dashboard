# ExtraA pivot — results

Method: for each of the 144 hosts in `findings_endpoint.json` (144 findings, 1 per host), pulled all host-table rows within ±3h of the finding (CMD, PROC_START, NET_CONNECT to non-10.x, DNS_QUERY, LOGIN_FAIL), excluded anything within 5 min of an existing finding on the same host, and separated attacker vs normal by fleet-wide rarity (distinct hosts per exact/normalised command, per PROC_START variant, per NET_CONNECT process+target, per DNS suffix).

**Result: 0 new endpoint findings and 0 other-role findings.** Every rare in-window event is either the already-reported action itself (seen from a neighbouring event type, e.g. the NET_CONNECT 2s after a reported CMD) or fleet-wide benign noise. Adding any of it would be a false positive under F1 scoring, so both output files are intentionally empty.

Coverage counts (in-window, after the 5-min dedup): 988 CMD, 326 PROC_START, 5,212 non-10.x NET_CONNECT, 5,962 DNS_QUERY, 63 LOGIN_FAIL rows examined.

## Near-misses examined and rejected

| host | ts | command | why attacker (considered) | category |
|---|---|---|---|---|
| WS-9323 | 2026-10-13T00:40:11.065Z | PROC_START sysupdate `hash=19afffcec533 signed=no` | Unsigned impostor of normally-signed sysupdate (1 host) — but it is the same action already reported at its first outside NET_CONNECT 2026-10-13T00:43:00.845Z per hunt-6 rule; excluded as duplicate of the matched action, not a new one | Malware delivery (already in findings_endpoint.json) |
| WS-8703 | 2026-10-13T08:19:24.244Z | PROC_START sysupdate `hash=e78714fecd9e signed=no` | Same unsigned-sysupdate pattern (1 host) — same action already reported at first outside NET_CONNECT 2026-10-13T10:36:21.694Z; duplicate | Malware delivery (already reported) |
| WS-3971 | 2026-10-14T08:27:46.643Z | PROC_START sysupdate `hash=a1c91877a6dc signed=no` | Same unsigned-sysupdate pattern (1 host) — same action already reported at first outside NET_CONNECT 2026-10-14T08:46:47.568Z; duplicate | Malware delivery (already reported) |
| WS-8624 | 2026-10-14T16:41:07.998Z | DNS_QUERY sync_helper `9MG5kFZdaMVfGk0FOFSxqdcD.v6.tunnel-six.net` (155 tunnel queries in window) | DNS-tunnel burst on the only fleet host using tunnel-six — but queries before 16:57:38Z occur while rachel331 is logged in (LOGOUT 2026-10-14T16:57:38.044Z); the scored action is the logged-out activity already reported at 2026-10-14T16:57:38.506Z with user `none`, so the 16:41 row (user rachel331) is not a separate match | Host intrusion signs (already reported) |
| WS-9637 / WS-5615 / WS-2504 | e.g. 2026-10-13T04:31:53.050Z | NET_CONNECT masscan → `10.2.0.42:902` (24–26 distinct ports/host in window) | Internal port-scan fan-out — same masscan actions already reported at their earlier PROC_START times (within the ±3h window, >5 min after the finding only because the scan NET_CONNECTs follow the CMD); duplicates | Reconnaissance (already reported) |
| WS-4885, WS-5746, WS-6503, WS-8145, WS-8832, WS-9398, WS-9604 | e.g. 2026-10-16T02:07:33.407Z | LOGIN_FAIL ×3 within ~1 min (console) | Looked like password guessing — rejected: ≥3 LOGIN_FAIL in 10 min occurs on 3,971 of 8,097 hosts fleet-wide, i.e. baseline noise, not attacker; no category defended | Credential abuse (rejected — benign) |
| 144 hosts (all) | various | CMD `whoami`, `docker ps`, `git pull --rebase`, `curl -s https://api.github.com/zen`, `cat README.md`, … (only ~30 distinct CMD texts in all 988 in-window rows) | In-window CMD pool is entirely fleet-wide work commands (8,200+ hosts each); the only rare CMD texts are the already-reported masscan/ping rows and one `cat ~/.ssh/id_rsa.pub` (public key, 1,796 hosts, benign) | — (rejected — benign) |
| 144 hosts (all) | various | DNS_QUERY `*.d3k4x9.vaultcdn.net`, `*.rpz.shieldops.net`, `*.reputation.shieldops.net`, `*.*.lat/.xyz/.top/.info` (unique subdomain per query) | Rare per exact domain (1 host) but the suffix patterns occur on effectively every host in the fleet — DGA-style background noise owned by the DNS role, with no host/process/timestamp tie to the endpoint kill chain; not reported even in `_other` to avoid flooding another role's caps | Known-bad indicators / Deceptive domains (rejected — fleet noise) |
| WS-3032 | 2026-10-15T13:01:13.516Z | CMD `tar czf ~/docs-backup.tar.gz ~/Documents/` | Archive in window — rejected: same archive text on 67 hosts (benign backup pattern) and no ≥1000 MB USB copy follows on this host, so the hunt-4 Data-theft join fails | Data theft (rejected — benign) |

## Kill-chain check

No host showed a second, distinct kill-chain step (download → execute → persistence → recon → credential access → archive/exfil) inside its ±3h window beyond the one already-reported action: in-window attacker-IP (198.18.0.0/15) NET_CONNECTs, attacker-domain DNS_QUERYs (darkrelay, freewarevault, driversoft-portal, freevault-downloads, crackarchive, installer-bundle, nexusos-patch) and IOC-table values (`evil-c2-01.darkrelay.net`, `malware-drop.badhosting.top`, `creds-phish.securelogin.xyz`, plus 3 IOC URLs — 0 in-window hits) all coincide (within seconds) with an existing finding on that host. Fleet patterns outside the 144 hosts (e.g. `smbclient … -c 'recurse; prompt; mget *'` on 10 other hosts, `net_scan`/`miner_worker`/`ldapsearch` PROC_STARTs) never occur inside any pivot window, so they are out of scope for this pivot and were not reported.

## Outputs

- `findings/extraA_pivot.json` — 0 findings (validated: OK).
- `findings/extraA_pivot_other.json` — 0 findings (validated: OK); no other-role evidence in the pivot windows was strong enough to defend.
