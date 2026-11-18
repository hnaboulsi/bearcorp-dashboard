"""Hunt 4 (Medium): Stolen credentials and USB theft.

Reasoning from exploration (457k CMD rows):
- Credential theft -> "Host intrusion signs": commands reading private SSH keys
  (id_rsa / id_ed25519, NOT .pub), cloud creds (~/.aws/credentials, gcloud
  credentials.db, azure accessTokens.json), password files (/etc/shadow,
  /etc/shadow-, /etc/gshadow), browser stores (Cookies). Every such exact
  command text appears on 1-3 hosts only.
- Benign/admin noise excluded: 'cat ~/.ssh/id_rsa.pub' (1796 hosts),
  'ls -l /etc/shadow && cat /etc/passwd | wc -l' (1000 hosts, never reads
  shadow contents), 'cat /etc/passwd' (1000 hosts), 'ssh bastion-01' /
  'history | grep ssh' (8k hosts). Rarity (distinct hosts per exact command)
  separates them cleanly; we additionally hard-exclude .pub.
- Data theft: archive (tar/zip/7z) command shortly before a large USB copy on
  the same host; report the ARCHIVE time/process. Benign archives
  (docs-backup, export.zip, backup-photos, project.zip, build-cache) sit on
  54-67 hosts; theft archives (/tmp/personal.tar.gz, /tmp/photos.zip,
  /tmp/archive.zip over ~/Documents/ ~/Projects/) sit on 3-7 hosts and are
  followed 5-18 min later by USB copies of 2834-7921 MB. USB mb is bimodal:
  791 benign copies <=~1000 MB and 177 copies >2000 MB with nothing between,
  so mb>=1000 + 60-min window is a clean join. The rare
  'tar czf /tmp/.sysdata.tgz /home/ /etc/' (2 hosts) has NO usb copy on those
  hosts at all, so it fails the required join and is excluded.
"""
import os
import random
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import collapse, con, finding, parse_ts, user_at, write_findings

P = os.path.expanduser("~/Downloads/hackathon-participant-files/threat-hunt")

PARAMS = {
    # Substrings marking a sensitive credential file read (matched on CMD target).
    "cred_needles": ["id_rsa", "id_ed25519", ".aws/credentials", "gcloud",
                     "azure", "/etc/shadow", "/etc/gshadow", "Cookies",
                     "Login Data", "logins.json", "key4.db"],
    # Never report public keys.
    "cred_exclude_substrings": [".pub"],
    # Exact command text must appear on at most this many distinct hosts.
    "rarity_max_hosts": 10,
    # Archive creation verbs/tools.
    "archive_needles": ["tar ", "zip ", "7z "],
    # USB copy must be at least this many MB (benign/attacker gap: <=1000 vs >2000).
    "usb_min_mb": 1000,
    # USB copy must start within this many minutes after the archive command.
    "usb_window_min": 60,
}


def _host_counts(c, rows):
    counts = {}
    for _, _, target in rows:
        counts.setdefault(target, set())
    for _, host, target in rows:
        counts[target].add(host)
    return {t: len(hs) for t, hs in counts.items()}


def run(c, params=PARAMS):
    findings = []
    cmd_cache = {}

    def cmd_rows(needles):
        key = tuple(needles)
        if key not in cmd_cache:
            where = " OR ".join("target LIKE ?" for _ in needles)
            cmd_cache[key] = c.execute(
                f"SELECT ts, host, target, process FROM host WHERE event='CMD' AND ({where})",
                [f"%{n}%" for n in needles],
            ).fetchall()
        return cmd_cache[key]

    # --- Host intrusion signs: rare credential-file reads ---
    rows = cmd_rows(params["cred_needles"])
    counts = _host_counts(c, [(ts, h, t) for ts, h, t, _ in rows])
    for ts, host, target, process in rows:
        if any(x in target for x in params["cred_exclude_substrings"]):
            continue
        if counts[target] > params["rarity_max_hosts"]:
            continue
        findings.append(finding("Host intrusion signs", ts, host,
                                user_at(host, ts), process))

    # --- Data theft: rare archive + large USB copy shortly after ---
    arows = cmd_rows(params["archive_needles"])
    acounts = _host_counts(c, [(ts, h, t) for ts, h, t, _ in arows])
    usb = {}
    for uts, host, mb in c.execute(
            "SELECT ts, host, mb FROM usb WHERE action='copy' AND mb >= ?",
            (params["usb_min_mb"],)):
        usb.setdefault(host, []).append(uts)
    for ts, host, target, process in arows:
        if acounts[target] > params["rarity_max_hosts"]:
            continue
        t0 = parse_ts(ts)
        hit = any(0 <= (parse_ts(u) - t0).total_seconds() <= params["usb_window_min"] * 60
                  for u in usb.get(host, []))
        if hit:
            findings.append(finding("Data theft", ts, host,
                                    user_at(host, ts), process))
    return collapse(findings)


def main():
    c = con()
    findings = run(c)
    out = os.path.join(P, "findings", "hunt4.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    write_findings(out, findings)

    by_cat = {}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    print(f"findings: {len(findings)}")
    print(f"per-category: {by_cat}")
    print(f"distinct hosts: {len({f['host'] for f in findings})}")

    cmd_by_key = {}
    rows = c.execute(
        "SELECT ts, host, target FROM host WHERE event='CMD'").fetchall()
    for ts, host, target in rows:
        cmd_by_key.setdefault((ts, host), target)
    print("sample findings (10 random):")
    for f in random.Random(4).sample(findings, min(10, len(findings))):
        print(f, "| CMD:", cmd_by_key.get((f["timestamp"], f["host"]), "?"))


if __name__ == "__main__":
    main()
