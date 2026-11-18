"""Hunt 3 (Easy): Temp-folder programs and scanners.

Detections
----------
- Programs started from /tmp or /dev/shm        -> Malware delivery
- nmap / masscan network scans                  -> Reconnaissance
- ping with large packets to a non-10.x address -> Command and control

Exploration summary (CMD rows filtered first, 457k rows; patterns normalised)
-----------------------------------------------------------------------------
Malware-delivery candidates (direct execution of a /tmp or /dev/shm path):
  chmod +x /dev/shm/.x && /dev/shm/.x &            4 hosts  attacker (hidden binary in shm)
  chmod +x /tmp/.cache_update && /tmp/.cache_update &  1 host   attacker (masquerades as updater)
  chmod +x /tmp/update && /tmp/update              1 host   attacker
  /tmp/.dropper --install                          1 host   attacker
  nohup /tmp/xmrig -o pool.hashhaven.net:3333 &    1 host   attacker (miner, still a /tmp program)
  python3 /tmp/tgs.py --spns all --etype rc4 ...  10 hosts  attacker (rare script run from /tmp)

Benign / other-hunt noise excluded:
  python /tmp/pip-install-<hex>/setup.py install  1397 hosts  benign installer (rarity kills it)
  zip/tar/7z ... /tmp/*.zip|tgz, cp Cookies /tmp/ many hosts  /tmp is an OUTPUT path, no program
                                                            is started from /tmp (data-theft hunt)
  crontab/bashrc lines mentioning /tmp/.x etc.    few hosts  persistence references, not a
                                                            program start (intrusion-signs hunt)

Reconnaissance:
  nmap -sS -p- 10.2.0.0/24                         6 hosts  attacker (full-port sweep of subnet)
  masscan 10.2.0.0/24 -p1-1000 --rate 1000         3 hosts  attacker
  nmap -sV test.bearcorp.com (SRV-02, IT server)   1 host   excluded: single-target version
                                                            check from an IT asset, admin-like

Command and control:
  ping -s 1024 -c 600 198.18.23.19                 3 hosts  attacker (large-packet, long-lived
                                                            ICMP tunnel to external address)
  ping -c 4 10.x.x.x                               209 hosts benign connectivity checks (small,
                                                            internal) - excluded

Timestamp rule: report the earliest row of the action. For masscan/ping the
same process also appears in PROC_START; when a PROC_START for the same host
and process precedes the CMD within `proc_start_window_min`, its (earlier)
timestamp is used. Temp-folder executions only occur as CMD rows (process
name carries no path in PROC_START), so the CMD time is the first event.
"""
import os
import random
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import collapse, con, finding, user_at, write_findings  # noqa: E402

P = os.path.expanduser("~/Downloads/hackathon-participant-files/threat-hunt")

PARAMS = {
    # A normalised command pattern run on more distinct hosts than this is
    # fleet-wide admin/setup noise (e.g. pip installs on 1397 hosts).
    "rarity_max_hosts": 25,
    "tmp_dirs": ["/tmp/", "/dev/shm/"],
    # Substrings that make a /tmp execution benign even if rare.
    "tmp_benign_substrings": ["pip-install", "setup.py"],
    "scanner_tools": ["nmap", "masscan"],
    # Single-target admin check to exclude (exact normalised form).
    "scanner_benign_patterns": ["nmap -sv test.bearcorp.com"],
    "ping_min_size": 1000,
    # PROC_START for same host/process this many minutes before the CMD is
    # treated as the same action's first row.
    "proc_start_window_min": 120,
}

# A /tmp or /dev/shm path in execution position: start of command, after
# && / ; / |, after nohup, or as a python/python3 script argument. This
# deliberately does NOT match archive outputs (zip/tar ... /tmp/x.zip),
# copies (cp ... /tmp/x) or cron/echo lines that merely mention the path.
_EXEC_RE = re.compile(
    r"(?:^|&&\s*|;\s*|\|\s*|nohup\s+|python3?\s+)((?:/tmp|/dev/shm)/[^\s;&|'\"]+)"
)
_PING_RE = re.compile(r"^ping\s+.*?-s\s+(\d+)\s+.*?\s(\d{1,3}(?:\.\d{1,3}){3})\s*$")
_SCANNER_RE = re.compile(r"^(nmap|masscan)\s+(.*)$")


def _normalise(cmd):
    s = re.sub(r"\d+\.\d+\.\d+\.\d+(?:/\d+)?", "IP", cmd.lower())
    s = re.sub(r"\b[0-9a-f]{8,}\b", "HEX", s)
    s = re.sub(r"\d+", "N", s)
    return s.strip()


def _earliest_ts(c, host, process, cmd_ts, window_min):
    """Earliest PROC_START for same host/process within window before cmd_ts."""
    row = c.execute(
        "SELECT ts FROM host WHERE event='PROC_START' AND host=? AND lower(process)=lower(?) "
        "AND ts<=? ORDER BY ts DESC LIMIT 1",
        (host, process, cmd_ts),
    ).fetchone()
    if not row:
        return cmd_ts
    from common import parse_ts

    if 0 <= (parse_ts(cmd_ts) - parse_ts(row[0])).total_seconds() <= window_min * 60:
        return row[0]
    return cmd_ts


def run(c, params=PARAMS):
    rows = c.execute(
        "SELECT ts, host, process, target FROM host WHERE event='CMD' AND ("
        " target LIKE '%/tmp/%' OR target LIKE '%/dev/shm/%'"
        " OR lower(target) LIKE 'nmap%' OR lower(target) LIKE 'masscan%'"
        " OR lower(target) LIKE 'ping%') ORDER BY ts"
    ).fetchall()

    # Rarity: distinct hosts per normalised pattern.
    pattern_hosts = defaultdict(set)
    for ts, host, proc, cmd in rows:
        pattern_hosts[_normalise(cmd)].add(host)

    findings, evidence = [], {}
    for ts, host, proc, cmd in rows:
        low = cmd.lower().strip()
        pat = _normalise(cmd)
        if len(pattern_hosts[pat]) > params["rarity_max_hosts"]:
            continue  # fleet-wide admin/setup noise
        category = process = None
        m = _PING_RE.match(low)
        scan = _SCANNER_RE.match(low)
        if m and int(m.group(1)) >= params["ping_min_size"] and not m.group(2).startswith("10."):
            category, process = "Command and control", proc
        elif scan and pat not in params["scanner_benign_patterns"]:
            category, process = "Reconnaissance", proc
        elif _EXEC_RE.search(low) and not any(b in low for b in params["tmp_benign_substrings"]):
            category, process = "Malware delivery", proc
        else:
            continue
        # Only tool-named processes (masscan/ping) have a meaningful PROC_START;
        # a bash PROC_START is just the generic terminal session, not the action.
        ets = _earliest_ts(c, host, process, ts, params["proc_start_window_min"]) \
            if process.lower() in ("masscan", "ping", "nmap") else ts
        f = finding(category, ets, host, user_at(host, ets), process)
        findings.append(f)
        evidence[(category, ets, host, process)] = cmd

    findings = collapse(findings)
    run.evidence = evidence
    return findings


if __name__ == "__main__":
    conn = con()
    out = run(conn)
    path = os.path.join(P, "findings", "hunt3.json")
    write_findings(path, out)
    print(f"findings: {len(out)}")
    print("per-category:", dict(Counter(f["category"] for f in out)))
    print("distinct hosts:", len({f["host"] for f in out}))
    ev = getattr(run, "evidence", {})
    for f in random.Random(3).sample(out, min(10, len(out))):
        cmd = ev.get((f["category"], f["timestamp"], f["host"], f["process"]), "?")
        print(f, "| CMD:", cmd)
