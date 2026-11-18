"""Hunt 7 (Hard) - Risky downloads / Malware delivery.

Exploration reasoning (verified against bearcorp.db):
- Proxy has ~27.6M rows. Executable URLs (.exe/.dll/.scr/.hta, query stripped)
  total only ~200 rows. Grouped by domain:
    staging-downloads.nexusos.com /rel/tool-setup.exe : 174 distinct src IPs,
      host DNS on 174 hosts, browsers (chrome/firefox/chromium), NET_CONNECT to
      203.0.113.29 (benign range used by all normal sites). This is a broad
      staged rollout of one 20MB tool -> BENIGN, excluded via trusted list +
      rarity threshold (>20 distinct IPs/hosts).
    cdn.installer-bundle.net /dl/loader.exe then /dl/stage2.dll exactly 3 min
      later, 6 hosts, chrome, NET_CONNECT 198.18.45.11 -> ATTACKER (loader+
      second-stage pattern named in the hunt).
    dl.freewarevault.net /files/doc.scr, /files/patch.hta : 3 hosts -> ATTACKER
      (untrusted freeware site, .scr/.hta).
    files.freevault-downloads.net /files/setup.exe : 1 host -> ATTACKER.
    get.crackarchive.net /files/update.dll : 2 hosts -> ATTACKER.
    updates.driversoft-portal.net /files/patch.hta : 1 host (LAB-02) -> ATTACKER.
  Single-file downloads appear twice in proxy 45s apart (retry) with one host
  DNS_QUERY; only the first is an action.
- Look-alike updates: real site is updates.nexusos.com (/check?ver=12.4, ~11.6k
  IPs, updater/browser, benign IPs). updates.nexusos-patch.com serves only
  /v2/manifest, seen on 3 hosts with process 'updater' and NET_CONNECT to
  198.18.44.10 (attacker 198.18.0.0/15 range, unlike benign 203.0.113.0/24).
  Host DNS repeats ~daily per host; only the first fetch per host is reported.
- Trusted baseline (many hosts, never flagged): updates.nexusos.com,
  telemetry.nexusos.com, license.nexusos.com, staging-downloads.nexusos.com.
- Host/process are taken from the host table DNS_QUERY row for that domain at
  the proxy timestamp (timestamps coincide exactly); src_ip -> host via
  IP_ASSIGNED (latest at/before ts), with NAT translation for 10.9.1.1-4 via
  the nat table (nat_ip + time window -> internal_ip -> IP_ASSIGNED), used as
  cross-check/fallback. No NAT addresses occurred among the attacker rows.
Precision self-check (15 most common matched patterns): only 6 patterns match
  at all after exclusions - loader.exe (6 hosts, loader+stage2, 198.18 IP),
  stage2.dll (same 6, second stage - collapsed into loader action),
  doc.scr/patch.hta on freewarevault (3, untrusted + dangerous ext),
  setup.exe freevault-downloads (1), update.dll crackarchive (2, crack site),
  patch.hta driversoft-portal (1), nexusos-patch manifest (3, look-alike of
  real update site, updater to 198.18 IP). Each is rare (<=6 hosts), unlike
  staging-downloads (174 hosts, benign IP).
"""
import os
import random
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import collapse, con, finding, write_findings  # noqa: E402

PARAMS = {
    "category": "Malware delivery",
    "extensions": [".exe", ".dll", ".scr", ".hta"],
    # Domains that are normal software/update infrastructure (many hosts).
    "trusted_domains": [
        "updates.nexusos.com",
        "telemetry.nexusos.com",
        "license.nexusos.com",
        "inventory.nexusos.com",
        "staging-downloads.nexusos.com",
    ],
    # Look-alike of the real update site updates.nexusos.com.
    "lookalike_domains": ["updates.nexusos-patch.com"],
    # A domain seen from more distinct src IPs than this is baseline noise.
    "max_distinct_ips": 20,
    # Window to match a host DNS_QUERY to a proxy row.
    "dns_window_min": 10,
    "nat_ips": ["10.9.1.1", "10.9.1.2", "10.9.1.3", "10.9.1.4"],
}


def _parse(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _user_at(conn, host, ts):
    row = conn.execute(
        "SELECT ts, user FROM host WHERE event='LOGIN' AND host=? AND ts<=? "
        "ORDER BY ts DESC LIMIT 1", (host, ts)).fetchone()
    if not row:
        return "none"
    out = conn.execute(
        "SELECT 1 FROM host WHERE event='LOGOUT' AND host=? AND ts>? AND ts<=? LIMIT 1",
        (host, row[0], ts)).fetchone()
    return "none" if out else row[1]


def _ip_to_host(conn, src_ip, ts, params):
    ip = src_ip
    if ip in params["nat_ips"]:
        nat = conn.execute(
            "SELECT internal_ip FROM nat WHERE nat_ip=? AND start<=? AND end>? "
            "ORDER BY start DESC LIMIT 1", (ip, ts, ts)).fetchone()
        if nat:
            ip = nat[0]
    row = conn.execute(
        "SELECT host FROM host WHERE event='IP_ASSIGNED' AND target=? AND ts<=? "
        "ORDER BY ts DESC LIMIT 1", (ip, ts)).fetchone()
    return row[0] if row else None


def _run_pairs(conn, params=PARAMS):
    """Return list of (finding, evidence_text)."""
    exts = tuple(e.lower() for e in params["extensions"])
    trusted = {d.lower() for d in params["trusted_domains"]}
    lookalikes = {d.lower() for d in params["lookalike_domains"]}

    # --- candidate proxy rows: executable downloads + look-alike fetches ---
    like = " OR ".join("lower(url) LIKE ?" for _ in exts)
    dom = " OR ".join("lower(domain)=?" for _ in lookalikes)
    sql = (f"SELECT ts, src_ip, domain, url FROM proxy "
           f"WHERE ({like}) OR ({dom}) ORDER BY ts")
    args = [f"%{e}%" for e in exts] + sorted(lookalikes)
    rows = []
    for ts, src_ip, domain, url in conn.execute(sql, args):
        d = (domain or "").lower()
        path = (url or "").split("?")[0].lower()
        if d in lookalikes or (path.endswith(exts) and d not in trusted):
            rows.append((ts, src_ip, d, url))

    # Rarity: drop domains used by many distinct source IPs (baseline).
    ips_by_domain = {}
    for _, src_ip, d, _ in rows:
        if d not in lookalikes:
            ips_by_domain.setdefault(d, set()).add(src_ip)
    rows = [r for r in rows if r[2] in lookalikes
            or len(ips_by_domain.get(r[2], ())) <= params["max_distinct_ips"]]

    # --- host DNS index for candidate domains ---
    domains = sorted({r[2] for r in rows})
    dns_by_domain = {}
    for d in domains:
        dns_by_domain[d] = conn.execute(
            "SELECT ts, host, process FROM host WHERE event='DNS_QUERY' AND target=? "
            "ORDER BY ts", (d,)).fetchall()

    def dns_lookup(domain, ts):
        best = None
        for dts, host, proc in dns_by_domain.get(domain, []):
            delta = abs((_parse(dts) - _parse(ts)).total_seconds())
            if best is None or delta < best[0]:
                best = (delta, dts, host, proc)
        if best and best[0] <= params["dns_window_min"] * 60:
            return best[2], best[3], best[1]
        return None, None, None

    pairs, seen = [], set()
    for ts, src_ip, domain, url in rows:
        host, proc, dns_ts = dns_lookup(domain, ts)
        if host is None:
            host = _ip_to_host(conn, src_ip, ts, params)
            proc = proc or "chrome"
        if host is None:
            continue
        key = (host, domain)  # one action per host+domain; first event wins
        if key in seen:
            continue
        seen.add(key)
        f = finding(params["category"], dns_ts or ts, host,
                    _user_at(conn, host, dns_ts or ts), proc)
        pairs.append((f, f"{domain}{url} src_ip={src_ip}"))
    pairs.sort(key=lambda p: p[0]["timestamp"])
    return pairs


def run(conn, params=PARAMS) -> list:
    return collapse([f for f, _ in _run_pairs(conn, params)])


if __name__ == "__main__":
    conn = con()
    pairs = _run_pairs(conn, PARAMS)
    findings = collapse([f for f, _ in pairs])
    keep = {(f["category"], f["timestamp"], f["host"], f["user"].lower(),
             f["process"].lower()) for f in findings}
    pairs = [p for p in pairs if (p[0]["category"], p[0]["timestamp"], p[0]["host"],
             p[0]["user"].lower(), p[0]["process"].lower()) in keep]
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "findings", "hunt7.json")
    write_findings(out, findings)
    print(f"findings: {len(findings)}")
    print("per-category:", dict(Counter(f["category"] for f in findings)))
    print("distinct hosts:", len({f["host"] for f in findings}))
    for f, ev in random.Random(7).sample(pairs, min(10, len(pairs))):
        print(f, "| command:", ev)
