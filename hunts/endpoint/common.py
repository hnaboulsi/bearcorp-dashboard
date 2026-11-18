"""Shared helpers for the Role 3 (endpoint) hunts. Read-only access to bearcorp.db."""
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

P = os.path.expanduser("~/Downloads/hackathon-participant-files/threat-hunt")
DB = os.path.join(P, "dataset", "dataset", "bearcorp.db")
TEAM_ID = os.environ.get("TEAM_ID", "11")  # set once the team agrees on it

CATEGORIES = {
    "Known-bad indicators", "Command and control", "Reconnaissance", "Data theft",
    "Deceptive domains", "Malware delivery", "Host intrusion signs",
    "Lateral movement", "Credential abuse",
}

_con = None


def con():
    """Shared read-only connection."""
    global _con
    if _con is None:
        _con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    return _con


def parse_ts(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def fmt_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def user_at(host, ts):
    """User logged in on host at ts: latest LOGIN at or before ts with no LOGOUT in between, else 'none'."""
    c = con()
    row = c.execute(
        "SELECT ts, user FROM host WHERE event = 'LOGIN' AND host = ? AND ts <= ? ORDER BY ts DESC LIMIT 1",
        (host, ts),
    ).fetchone()
    if not row:
        return "none"
    login_ts, user = row
    out = c.execute(
        "SELECT 1 FROM host WHERE event = 'LOGOUT' AND host = ? AND ts > ? AND ts <= ? LIMIT 1",
        (host, login_ts, ts),
    ).fetchone()
    return "none" if out else user


def finding(category, ts, host, user, process, evidence=None, confidence=None):
    assert category in CATEGORIES, category
    f = {"category": category, "timestamp": ts, "host": host, "user": user, "process": process}
    if evidence:
        f["evidence"] = [str(e) for e in evidence]
    if confidence:
        f["confidence"] = confidence
    return f


def collapse(findings, window_min=10):
    """Keep the first finding per (category, host, process) within window_min, to respect per-category caps."""
    out, last = [], {}
    for f in sorted(findings, key=lambda f: f["timestamp"]):
        key = (f["category"], f["host"], f["process"].lower())
        t = parse_ts(f["timestamp"])
        if key in last and t - last[key] <= timedelta(minutes=window_min):
            continue
        last[key] = t
        out.append(f)
    return out


def write_findings(path, findings):
    seen, uniq = set(), []
    for f in findings:
        k = (f["category"], f["timestamp"], f["host"], f["user"].lower(), f["process"].lower())
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    with open(path, "w") as fh:
        json.dump({"team_id": TEAM_ID, "findings": uniq}, fh, indent=2)
    return uniq
