"""Hunt 6 (Hard): Unsigned programs and empty desks.

Reasoning from exploration (see /tmp/explore6*.py):
(a) Baseline per process (GROUP BY process,target over 327k PROC_START):
    every common program has ONE dominant signed=yes hash on thousands of
    hosts (updater f22d..., telemetry c53d..., sysupdate 657d... signed=yes
    on 49,989 rows/10,000 hosts). The only deviation: sysupdate signed=no
    with 11 unique hashes, 1 host each (11 hosts). Each of those 11 hosts
    later connects (process=sysupdate) to 198.18.44.11:443, an address
    normal sysupdate never uses (normal target is only 10.2.0.10:443,
    100k rows). usb-helper is signed=no on ALL 39 rows -> that is its
    normal baseline, NOT an impostor, so excluded (a program is only
    flagged when signed=no / non-dominant hash is a minority variant of
    a normally-signed, common program).
(b) Browsers/updater/telemetry/etc generate outside traffic 24h on
    thousands of hosts regardless of login -> benign background noise.
    doc_reader is a user process (parent=bash, 505 hosts) that normally
    only queries while its user is logged in (most hosts: 0-1 logged-out
    queries). On 11 hosts it starts querying within seconds/minutes of
    a LOGOUT and keeps going (6-173 logged-out queries, one burst/host):
    WS-8616, WS-7968, WS-7057, WS-2698, WS-8207, WS-3016, WS-2613,
    WS-3926, WS-4664, WS-4885, WS-4697. Same signature for sync_helper
    only on WS-8624, where the logged-out queries are to the anomalous
    *.v6.tunnel-six.net domain (its normal domains are fleetwatch /
    fleetmetrics / devicemetrics on fixed 198.18.6x/3x endpoints, run
    hourly from sched on 128 hosts -> background service, excluded
    except for that one tunnel burst starting at LOGOUT).
    Sched-parent services (updater, telemetry, sysupdate, backup-agent,
    ml-train, invoice_viewer, vaultdrive_sync, sync_helper normal
    traffic, crawler/nessus on always-on SRV hosts with no logins)
    are excluded: they run all the time on many hosts.
(c) 'ssh bastion-01' appears 18,130 times on 8,303 hosts -> normal.
    Only 4 CMD rows use 'ssh -o StrictHostKeyChecking=no admin-N@10.2.0.x',
    1 host each -> attacker. (No UserKnownHostsFile=/dev/null rows exist.)

Precision self-check (most common matched patterns):
 (a) sysupdate signed=no/rare-hash -> 198.18.44.11: 11 rows, unique hash
     per host, nonstandard external target normal sysupdate never uses.
 (b) doc_reader logged-out burst: user process running seconds after
     LOGOUT for hours; cannot be a background service (parent=bash).
 (b) sync_helper tunnel-six logged-out burst: 1 host, domain never used
     by sync_helper anywhere else, starts at LOGOUT.
 (c) ssh StrictHostKeyChecking=no: 4 rows vs 18k normal 'ssh bastion-01'.
"""
import os
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import collapse, con as _con, finding, parse_ts, user_at, write_findings

P = os.path.expanduser("~/Downloads/hackathon-participant-files/threat-hunt")

PARAMS = {
    # (a) a program counts as "common" if seen on at least this many hosts
    "common_min_hosts": 100,
    # (a) a hash variant is "rare" if seen on at most this many hosts
    "rare_hash_max_hosts": 5,
    # (b) logged-out burst must have at least this many outside events
    "burst_min_events": 5,
    # (b) burst must start within this many minutes after a LOGOUT
    "burst_after_logout_min": 15,
    # (b) processes considered (user-launched, not sched background services)
    "desk_processes": ["doc_reader"],
    # (b) extra (process, target-substring) anomalous bursts
    "desk_anomalies": [("sync_helper", "tunnel-six")],
    # (c) ssh options that skip host-key verification
    "ssh_bypass_markers": ["StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null"],
}

_HASH_RE = re.compile(r"hash=(\S+) signed=(yes|no)")

# Evidence for sample printing, keyed by (category, host, process, timestamp)
EVIDENCE = {}


def _sessions(conn):
    """host -> sorted [(ts, event, user)] for LOGIN/LOGOUT."""
    sess = defaultdict(list)
    for ts, host, ev, user in conn.execute(
        "SELECT ts, host, event, user FROM host WHERE event IN ('LOGIN','LOGOUT') ORDER BY host, ts"
    ):
        sess[host].append((ts, ev, user))
    return sess


def _user_at(sess, host, ts):
    import bisect

    rows = sess.get(host)
    if not rows:
        return "none"
    times = [r[0] for r in rows]
    i = bisect.bisect_right(times, ts) - 1
    j = i
    while j >= 0 and rows[j][1] != "LOGIN":
        j -= 1
    if j < 0:
        return "none"
    for k in range(j + 1, i + 1):
        if rows[k][1] == "LOGOUT":
            return "none"
    return rows[j][2]


def _last_logout_before(sess, host, ts):
    last = None
    for t, ev, _u in sess.get(host, []):
        if t > ts:
            break
        if ev == "LOGOUT":
            last = t
    return last


def run(conn, params=PARAMS):
    findings = []
    sess = _sessions(conn)

    # ---- (a) unsigned / rare-hash impostors of common programs ----
    variant_hosts = defaultdict(set)
    variant_rows = defaultdict(list)
    proc_hosts = defaultdict(set)
    for ts, host, proc, target in conn.execute(
        "SELECT ts, host, process, target FROM host WHERE event='PROC_START'"
    ):
        proc_hosts[proc].add(host)
        variant_hosts[(proc, target)].add(host)
        variant_rows[(proc, target)].append((ts, host))
    # dominant (most hosts) variant per process
    dominant = {}
    for (proc, target), hosts in variant_hosts.items():
        if proc not in dominant or len(hosts) > len(variant_hosts[dominant[proc]]):
            dominant[proc] = (proc, target)
    for (proc, target), hosts in variant_hosts.items():
        if len(proc_hosts[proc]) < params["common_min_hosts"]:
            continue
        m = _HASH_RE.search(target or "")
        if not m:
            continue
        dom_target = dominant[proc][1]
        dom_signed = _HASH_RE.search(dom_target).group(2) if _HASH_RE.search(dom_target) else "yes"
        is_rare = len(hosts) <= params["rare_hash_max_hosts"]
        is_unsigned_minority = m.group(2) == "no" and dom_signed == "yes"
        if not (is_unsigned_minority or (target != dom_target and is_rare)):
            continue
        if target == dom_target:
            continue
        for start_ts, host in variant_rows[(proc, target)]:
            row = conn.execute(
                "SELECT ts, target FROM host WHERE host=? AND event='NET_CONNECT' "
                "AND process=? AND ts>? AND target NOT LIKE '10.%' ORDER BY ts LIMIT 1",
                (host, proc, start_ts),
            ).fetchone()
            if not row:
                continue
            net_ts, net_target = row
            user = _user_at(sess, host, net_ts)
            findings.append(finding("Malware delivery", net_ts, host, user, proc))
            EVIDENCE[("Malware delivery", host, proc, net_ts)] = (
                f"PROC_START {target} at {start_ts}; first outside NET_CONNECT {net_target}"
            )

    # ---- (b) outside network activity while nobody is logged in ----
    checks = [(p, None) for p in params["desk_processes"]] + list(params["desk_anomalies"])
    for proc, marker in checks:
        if marker:
            rows = conn.execute(
                "SELECT ts, host, event, target FROM host WHERE event IN ('NET_CONNECT','DNS_QUERY') "
                "AND process=? AND target LIKE ? ORDER BY ts",
                (proc, f"%{marker}%"),
            )
        else:
            rows = conn.execute(
                "SELECT ts, host, event, target FROM host WHERE event IN ('NET_CONNECT','DNS_QUERY') "
                "AND process=? ORDER BY ts",
                (proc,),
            )
        per_host = defaultdict(list)
        for ts, host, ev, target in rows:
            if ev == "NET_CONNECT" and (target or "").startswith("10."):
                continue
            if _user_at(sess, host, ts) == "none":
                per_host[host].append((ts, ev, target))
        for host, evts in per_host.items():
            if len(evts) < params["burst_min_events"]:
                continue
            first_ts, first_ev, first_target = evts[0]
            logout = _last_logout_before(sess, host, first_ts)
            if not logout:
                continue
            gap_min = (parse_ts(first_ts) - parse_ts(logout)).total_seconds() / 60.0
            if gap_min < 0 or gap_min > params["burst_after_logout_min"]:
                continue
            findings.append(finding("Host intrusion signs", first_ts, host, "none", proc))
            EVIDENCE[("Host intrusion signs", host, proc, first_ts)] = (
                f"{first_ev} {first_target} while logged out ({len(evts)} logged-out events, "
                f"LOGOUT at {logout})"
            )

    # ---- (c) ssh skipping host-key checks ----
    for marker in params["ssh_bypass_markers"]:
        for ts, host, proc, target in conn.execute(
            "SELECT ts, host, process, target FROM host WHERE event='CMD' AND target LIKE ?",
            (f"%{marker}%",),
        ):
            user = _user_at(sess, host, ts)
            findings.append(finding("Host intrusion signs", ts, host, user, proc))
            EVIDENCE[("Host intrusion signs", host, proc, ts)] = f"CMD {target}"

    return collapse(findings)


if __name__ == "__main__":
    import random

    conn = _con()
    results = run(conn)
    out = os.path.join(P, "findings", "hunt6.json")
    results = write_findings(out, results)
    print(f"findings: {len(results)}")
    print("per-category:", dict(Counter(f["category"] for f in results)))
    print("distinct hosts:", len({f["host"] for f in results}))
    random.seed(6)
    for f in random.sample(results, min(10, len(results))):
        ev = EVIDENCE.get((f["category"], f["host"], f["process"], f["timestamp"]), "")
        print(f, "|", ev)
    print("wrote", out)
