# Extra D — deep-dive decisions (Role 3 / endpoint)

New endpoint findings: **0** (`findings/extraD.json` is empty). No fixes
(`reports/extraD_fixes.json` = `[]`). Cross-role copies for the DNS/C2 team are in
`findings/extraD_other.json` (12 findings, **do not merge** into endpoint findings).

## 1. Hunt 7 — look-alike updater `updates.nexusos-patch.com`: repeats are NOT separate actions

- Proxy: 145 rows, all identical `GET /v2/manifest`, status 200, `bytes_in=2500`, from only
  3 src IPs (10.1.1.255, 10.1.16.93, 10.1.28.34 → WS-0512, WS-4190, WS-7203).
- Host table: exactly 2 `DNS_QUERY` per host, ~24.1–24.8 h apart (DNS re-resolution), but
  `NET_CONNECT updater → 198.18.44.10:443` is **hourly and continuous** (47–49 connects/host,
  max gap 65–119 min, no break at the second DNS query). Same process (`updater`), same URL,
  same payload size every time — one beaconing implant per host, not daily re-deliveries.
- Decision: keep only the first fetch per host (as hunt7 does). The 3 second DNS queries
  would fall >5 min from the action's first event and match no new action → false positives.
- Missed-host check (all 6 hunt7 domains): for every domain, the set of hosts from host
  `DNS_QUERY`, from proxy `src_ip → IP_ASSIGNED`, and from `NET_CONNECT` to the resolved
  attacker IP (198.18.45.11 / 198.18.44.10) are identical to the 16 hunt7 findings
  (installer-bundle 6, freewarevault 3, freevault-downloads 1, crackarchive 2,
  driversoft-portal 1, nexusos-patch 3). NAT branch: 0 proxy rows for these domains have a
  `10.9.1.1–4` src_ip (327k NAT proxy rows exist overall), so the `nat` table yields no
  additional hosts. **No missed hosts.**

## 2. Hunt 6(b) — logged-out bursts: keep as Host intrusion signs; flag C2 nature cross-role

- `doc_reader` (11 hosts): burst destinations are single-use DGA domains — e.g. WS-8616:
  194 distinct `word-word.lat` names; WS-7057/WS-2698/WS-8207 etc.: random
  `*.xyz/.top/.info` names, each queried once. In the `dns` table they are qtype **A,
  NXDOMAIN** (no TXT, no long subdomain of one parent) — DGA C2 *attempts*, not a
  data-carrying DNS tunnel.
- `sync_helper` on WS-8624 only: 155 queries to `<base64-like chunk>.v6.tunnel-six.net`,
  qtype **AAAA** in `dns` table — a genuine DNS tunnel. All other `sync_helper` hosts use
  only its normal fleetwatch/fleetmetrics/devicemetrics domains.
- Decision: **keep** all 12 in endpoint as `Host intrusion signs` — the official endpoint
  brief #6 explicitly assigns "network activity with user `none`" to that category, and the
  user/timestamp/process evidence lives on the host table. Copies recategorised as
  `Command and control` are in `findings/extraD_other.json` for the DNS/C2 role.
- More such hosts? Re-ran the burst test (≥5 outside events while `user_at=none`, first
  event ≤15 min after LOGOUT) over **all** processes. The only non-background hits are the
  11 `doc_reader` hosts + WS-8624 `sync_helper` already reported. Everything else is
  sched/desktop background noise correctly excluded by hunt6: `sync_helper` normal traffic
  (128 hosts, hourly), `invoice_viewer`, browsers, and `shield-agent`
  `*.reputation.shieldops.net` lookups (hundreds of hosts). **No new hosts.**

## 3. Hunt 3 — masscan/ping timestamp: use PROC_START (no change)

- Each scanner host has exactly **one** `PROC_START` (masscan/ping) and one `CMD`;
  `PROC_START` precedes `CMD` by 3.3 min (WS-7976 ping), 33–53 min (other ping/masscan).
  No scan `NET_CONNECT` occurs in between — the two rows are the action's only events,
  so `PROC_START` is the action's FIRST event and hunt3's choice is correct under the
  "within 5 min of the first event" rule. Using `CMD` would be 33–53 min late for
  5 of 6 scanner/ping findings. Note WS-2504: user at PROC_START is `none`, at CMD is
  `henry96` (login in between) — hunt3's `user_at(earliest_ts)` is self-consistent.
  nmap rows run via `bash` (CMD process) and correctly keep the CMD timestamp/process.

## 4. Hunt 6(a) — other common programs with rare hashes: none

- Recomputed PROC_START hash variants for every process: all processes on ≥100 hosts have
  exactly one signed=yes hash variant, **except** `sysupdate` (dominant signed=yes on
  10,000 hosts + 11 unique signed=no hashes, 1 host each — the 11 already reported).
  All processes on <100 hosts have a single variant each. `usb-helper` (signed=no on all
  rows) remains its own baseline, correctly excluded. **No new impostors.**

## Validation

- `findings/extraD.json`: validated with `berkeley_hackathon_validate.py` (0 findings).
- `findings/extraD_other.json`: validated separately (12 findings, advisory only).
