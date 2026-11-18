# Extra C — precision audit of findings_endpoint.json (144 findings)

Method (recomputed from bearcorp.db, read-only): for every finding I (1) recomputed
`user_at(host, timestamp)` with the common.py logic and inspected the raw LOGIN/LOGOUT
rows within ±2 h (exact-second logins/logouts, overlapping sessions); (2) listed all
host rows in the 30 min before the reported timestamp (same-process rows, all CMD rows,
and for ping/masscan/sysupdate all same-process rows within ±2 h) to find an earlier
first event of the same action; (3) compared the process field against the process on
the exact-timestamp row (CMD row where one exists, else PROC_START/DNS_QUERY row);
(4) matched the exact command/target at the reported timestamp against the hunt
definitions 1–7. Validator: `OK: team_id=11 findings=144 hosts=144 warnings=0`.

## Summary

| Check | Findings checked | Flagged |
|---|---|---|
| User (recomputed + raw LOGIN/LOGOUT edge cases) | 144 | 0 |
| Timestamp vs first event (30-min lookback, ±2 h for PROC_START hunts) | 144 | 0 |
| Process vs CMD/PROC_START/DNS row at reported ts | 144 | 0 |
| Category vs hunt definitions 1–7 (exact target at ts) | 144 | 0 |
| **Total proposed fixes** | | **0** |

No finding met the conservative bar (clear evidence) for a change, so
`extraC_fixes.json` is an empty list. Every reported user equals the recomputed
`user_at`; no LOGIN or LOGOUT row falls exactly on a reported timestamp (closest:
WS-8624 LOGOUT 2026-10-14T16:57:38.044Z, 0.46 s before the reported DNS_QUERY —
`none` is correct); every reported process equals the process on the row at the
reported timestamp; every exact-timestamp target matches its category's hunt
definition (e.g. all `nmap` rows are Reconnaissance with the CMD row's process
`bash`, all `curl|sh` by `plugin-host` are Host intrusion signs vs by `bash`
Malware delivery, all credential-file reads are Host intrusion signs, all
archive-before-USB rows are Data theft at archive time).

## Flagged findings

None.

## Reviewed but deliberately not flagged (ambiguous, evidence insufficient)

| Finding | Observation | Why no fix |
|---|---|---|
| WS-2504 Reconnaissance 2026-10-14T06:23:41.313Z masscan, user `none` | masscan CMD is at 06:57:05.171Z (+33.4 min), after a 06:30 LOGIN (henry96) | The reported ts is the masscan PROC_START; fleet-wide there are exactly 3 masscan PROC_STARTs and 3 masscan CMDs (these hosts only), a 1:1 pair, so the PROC_START is this execution's first event and `none` is the user at that first event. Same pattern for WS-9637 (+53.4 min), WS-5615 (+42.9 min) and the ping C2 hosts WS-7972/WS-3224 (+35.6 min; WS-7976 only +3.3 min, within tolerance either way). |
| WS-3971 Malware delivery 2026-10-14T08:46:47.568Z sysupdate | Unsigned PROC_START at 08:27:46.643Z is 19.0 min before the reported NET_CONNECT | Hunt 6 definition explicitly timestamps this action at the first outside NET_CONNECT (198.18.44.11:443), which is the reported row; user/process also match at that row. Same for WS-9323 (PROC_START −2.8 min). |
| doc_reader Host intrusion signs ×11 (e.g. WS-8616 2026-10-12T18:42:20.532Z) and WS-8624 sync_helper 2026-10-14T16:57:38.506Z | Same-process DNS_QUERYs exist up to 30 min before the reported ts, while a user was still logged in | Those earlier rows are logged-in activity; the hunt-6 action is defined as network activity with user `none`, and each reported ts is the first logged-out event on its host (1–15 min after the preceding LOGOUT). Moving the ts earlier would also change the user away from `none`, contradicting the action definition. |
| plugin-host Host intrusion signs ×11 (e.g. WS-6789 2026-10-14T10:55:01.141Z) | plugin-host PROC_START up to ~29 min before the CMD on some hosts | That PROC_START is the plugin host process starting, not the download; the `curl … \| sh` CMD row at the reported ts (process `plugin-host`) is the action's first evidence. Same reasoning for generic `bash` PROC_STARTs before CMD-based findings. |
| Hunt 7 chrome/firefox/updater findings ×16 | Browser PROC_START and unrelated-domain DNS/NET_CONNECT rows precede the reported ts | The reported ts is the first DNS_QUERY for the attacker domain on that host (exact row: attacker domain + 198.18.x NET_CONNECT); earlier rows are other domains or the browser launch, not this download. |
