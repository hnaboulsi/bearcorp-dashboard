"""Hunt 1 (Easy): Persistence and cleanup commands. Category: Host intrusion signs.

Reasoning from exploration (CMD = 457,293 rows, 1,025 distinct targets):
- Attacker (rare, <=3 distinct hosts per normalised pattern, payloads in hidden /tmp paths):
  * echo 'ssh-ed25519 ...evil/coffee/badfood/deadbeef' >> ~/.ssh/authorized_keys  (4 hosts)
  * (crontab -l; echo '*/5 ... /tmp/.x') | crontab -, @reboot /tmp/.cache_update,
    >> /etc/crontab (/tmp/.sysd), >> /etc/cron.d/syscheck (/tmp/.cache_update)   (5 hosts)
  * useradd -m backupsvc                                                        (3 hosts)
  * echo '/tmp/.cache_update &' >> ~/.bashrc                                    (1 host)
  * rm -f ~/.bash_history && history -c ; unset HISTFILE && history -c ...      (2 hosts)
  * rm -f /var/log/auth.log* /var/log/secure*                                   (3 hosts)
  Total 18 rows. All reference hidden /tmp payloads, fake SSH keys, or a service-like
  account name, and none appears as fleet-wide admin tooling.
- Benign (excluded): 'history | grep ssh' (17,782 rows / 8,220 hosts, read-only) and
  'tail -f /var/log/syslog' (17,830 rows / 8,258 hosts, read-only). A bare mention of
  history/cron/.bashrc or /var/log is NOT enough: detection requires a write/delete
  verb (>>, tee, crontab install, useradd, history -c, rm/shred/truncate on the path)
  plus the rarity gate below, so fleet-wide admin noise can never pass.
"""
import os
import random
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.expanduser("~/Downloads/hackathon-participant-files/threat-hunt/hunts"))
from common import collapse, con, finding, write_findings  # noqa: E402

P = os.path.expanduser("~/Downloads/hackathon-participant-files/threat-hunt")
CATEGORY = "Host intrusion signs"

PARAMS = {
    # Normalised-pattern rarity gate: keep patterns seen on at most this many hosts.
    "max_hosts": 10,
    # Cheap SQL pre-filter substrings (any-of), refined by regexes in Python.
    "prefilter": ["authorized_keys", "crontab", "/etc/cron", "useradd", "adduser",
                  ".bashrc", "history -c", "bash_history", "HISTFILE", "/var/log"],
    # Write/delete-verb regexes per persistence/cleanup sub-type (matched on target).
    "rules": {
        "ssh_key": r"authorized_keys.*(>>|tee\b|>\s*~|>\s*/|cp\s|echo|cat\s*>)|(>>|tee\b).*authorized_keys",
        "cron": r"((crontab|/etc/cron).*(>>|echo)|(>>|echo).*(crontab|/etc/cron)|crontab\s+(-|/)\b|\|\s*crontab\b)",
        "useradd": r"\b(useradd|adduser)\b",
        "bashrc": r"\.bashrc.*(>>|tee\b|>\s*~)|(>>|tee\b).*\.bashrc",
        "history_clear": r"(history\s+-[cw]\b|unset\s+HISTFILE|rm\s+[^|;&]*\.bash_history)",
        "varlog_delete": r"(rm\s+[^|;&]*/var/log|shred\s+[^|;&]*/var/log|truncate\s+[^|;&]*/var/log|>\s*/var/log|cat\s+/dev/null\s*>\s*/var/log)",
    },
}


def _normalise(cmd):
    """Collapse per-incident values so rarity is per pattern, not per literal row."""
    s = re.sub(r"AAAAC3[\w+/=]+", "<KEY>", cmd)
    s = re.sub(r"\b[0-9a-fA-F]{8,}\b", "<HEX>", s)
    s = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b", "<IP>", s)
    s = re.sub(r"\d+", "<N>", s)
    return s


def _user_at(conn, host, ts):
    row = conn.execute(
        "SELECT ts, user FROM host WHERE event='LOGIN' AND host=? AND ts<=? ORDER BY ts DESC LIMIT 1",
        (host, ts)).fetchone()
    if not row:
        return "none"
    login_ts, user = row
    out = conn.execute(
        "SELECT 1 FROM host WHERE event='LOGOUT' AND host=? AND ts>? AND ts<=? LIMIT 1",
        (host, login_ts, ts)).fetchone()
    return "none" if out else user


def _candidates(conn, params):
    likes = " OR ".join("target LIKE ?" for _ in params["prefilter"])
    q = f"SELECT ts, host, process, target FROM host WHERE event='CMD' AND ({likes}) ORDER BY ts"
    return conn.execute(q, tuple(f"%{p}%" for p in params["prefilter"])).fetchall()


def run(conn, params=PARAMS):
    rules = {k: re.compile(v, re.IGNORECASE) for k, v in params["rules"].items()}
    matched = [r for r in _candidates(conn, params) if any(rx.search(r[3]) for rx in rules.values())]
    # Rarity gate: distinct hosts per normalised pattern.
    hosts_by_pat = defaultdict(set)
    for _, host, _, target in matched:
        hosts_by_pat[_normalise(target)].add(host)
    kept = [r for r in matched if len(hosts_by_pat[_normalise(r[3])]) <= params["max_hosts"]]
    findings, cmd_by_key = [], {}
    for ts, host, process, target in kept:
        findings.append(finding(CATEGORY, ts, host, _user_at(conn, host, ts), process))
        cmd_by_key[(ts, host)] = target
    run.last_cmds = cmd_by_key  # for __main__ sampling
    return collapse(findings)


run.last_cmds = {}

if __name__ == "__main__":
    conn = con()
    findings = run(conn)
    out = os.path.join(P, "findings", "hunt1.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    written = write_findings(out, findings)
    print(f"findings: {len(written)}")
    print(f"per-category: {dict(Counter(f['category'] for f in written))}")
    print(f"distinct hosts: {len({f['host'] for f in written})}")
    for f in random.sample(written, min(10, len(written))):
        print(f, "| CMD:", run.last_cmds.get((f["timestamp"], f["host"]), "?"))
