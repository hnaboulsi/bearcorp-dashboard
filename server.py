#!/usr/bin/env python3
"""Bearcorp threat-hunt dashboard server. Python 3 stdlib only."""
import argparse, json, os, re, sqlite3, sys, time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote

ROOT = Path(__file__).resolve().parent
DETECTIONS = ROOT / "detections"
VALID = {"Known-bad indicators","Command and control","Reconnaissance","Data theft","Deceptive domains","Malware delivery","Host intrusion signs","Lateral movement","Credential abuse"}
DB_PATH = None

def resolve_db(cli):
    cands = []
    if cli: cands.append(cli)
    if os.environ.get("BEARCORP_DB"): cands.append(os.environ["BEARCORP_DB"])
    cands += [str(ROOT/"dataset"/"bearcorp.db"), str(ROOT/".."/"threat-hunt"/"dataset"/"dataset"/"bearcorp.db")]
    for c in cands:
        if c and Path(c).exists(): return str(Path(c).resolve())
    return None

def connect():
    uri = "file:" + quote(str(DB_PATH)) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=60)
    conn.row_factory = sqlite3.Row
    start = time.time()
    def handler():
        return 1 if time.time() - start > 60 else 0
    conn.set_progress_handler(handler, 1000)
    return conn

ROLES = {"dns": "DNS", "web": "Web", "endpoint": "Endpoint", "identity": "Identity"}

def parse_detection(path):
    name, role, category, params = path.stem, "", "", []
    try: rel = path.resolve().relative_to(DETECTIONS.resolve()).as_posix()
    except Exception: rel = path.name
    folder = rel.split("/")[0] if "/" in rel else ""
    folder_role = ROLES.get(folder.lower(), "") if folder else ""
    sql_lines = []
    try: text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e: return {"file": rel, "name": path.stem, "role": folder_role, "category": "", "params": [], "error": str(e)}
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("--"):
            body = s[2:].strip()
            m = re.match(r"name\s*:\s*(.+)", body, re.I)
            if m: name = m.group(1).strip(); continue
            m = re.match(r"role\s*:\s*(.+)", body, re.I)
            if m: role = m.group(1).strip(); continue
            m = re.match(r"category\s*:\s*(.+)", body, re.I)
            if m: category = m.group(1).strip(); continue
            m = re.match(r"param\s*:\s*(.+)", body, re.I)
            if m:
                parts = [p.strip() for p in m.group(1).split("|")]
                if len(parts) >= 2:
                    pname, ptype = parts[0], parts[1].lower()
                    default = parts[2] if len(parts) > 2 else ""
                    desc = parts[3] if len(parts) > 3 else ""
                    # coerce default display value
                    params.append({"name": pname, "type": ptype, "default": default, "description": desc})
                continue
    return {"file": rel, "name": name, "role": folder_role or role, "header_role": role, "folder": folder.lower() if folder_role else "", "category": category, "params": params}

def list_detections():
    if not DETECTIONS.exists(): return []
    return [parse_detection(p) for p in sorted(DETECTIONS.rglob("*.sql"))]

def safe_path(fname):
    if not fname or not str(fname).endswith(".sql"): return None
    parts = Path(str(fname)).parts
    if any(p in ("..", "") for p in parts) or Path(str(fname)).is_absolute(): return None
    p = (DETECTIONS / str(fname)).resolve()
    try: p.relative_to(DETECTIONS.resolve())
    except Exception: return None
    return p if p.exists() else None

def coerce_typed(ptype, v, default=""):
    t = str(ptype or "text").lower()
    try:
        if t == "int": return int(float(v)) if isinstance(v, str) and v.strip() else (int(v) if v not in (None, "") else int(float(default or 0)))
        if t == "float": return float(v) if v not in (None, "") else float(default or 0)
        if t == "list":
            if isinstance(v, list): return json.dumps([str(x).strip() for x in v])
            s = str(v or "").strip()
            if s.startswith("["):
                try: return json.dumps([str(x) for x in json.loads(s)])
                except Exception: pass
            return json.dumps([x.strip() for x in s.split(",") if x.strip()] if s else [])
        return "" if v is None else str(v)
    except Exception: return default

def run_sql(sql, raw_params, param_defs=None):
    params = {}
    defs = {p["name"]: p for p in (param_defs or []) if isinstance(p, dict) and p.get("name")}
    for k, v in (raw_params or {}).items():
        d = defs.get(k)
        params[k] = coerce_typed(d.get("type", "text"), v, d.get("default", "")) if d else (json.dumps([str(x) for x in v]) if isinstance(v, list) else v)
    for n, d in defs.items():
        if n not in params: params[n] = coerce_typed(d.get("type", "text"), d.get("default", ""), d.get("default", ""))
    t0 = time.time(); conn = connect()
    try:
        cur = conn.execute(sql, params)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = [dict(r) for r in cur.fetchall()]
        return cols, rows, round((time.time()-t0)*1000), None, conn
    except sqlite3.Error as e:
        conn.close()
        return [], [], round((time.time()-t0)*1000), str(e), None

def test_detection(sql, raw_params, param_defs=None):
    cols, rows, ms, err, conn = run_sql(sql or "", raw_params, param_defs)
    if err: return {"columns": [], "rows": [], "count": 0, "ms": ms, "error": err, "checklist": [{"label": "Query runs without error", "pass": False, "detail": err}]}
    try:
        req = {"category", "timestamp", "host", "user", "process"}
        checklist = [{"label": "Required columns present (category, timestamp, host, user, process)", "pass": req.issubset(set(cols)), "detail": "missing: " + ", ".join(sorted(req - set(cols))) if not req.issubset(set(cols)) else "all present"}]
        bad_cat = sorted({str(r.get("category")) for r in rows if r.get("category") not in VALID})
        checklist.append({"label": "Categories valid", "pass": not bad_cat, "detail": ("invalid: " + ", ".join(bad_cat)) if bad_cat else (f"all {len(rows)} row(s) valid" if rows else "no rows")})
        bad_ts = 0
        for r in rows:
            try: parse_ts(str(r.get("timestamp", "")))
            except Exception: bad_ts += 1
        checklist.append({"label": "Timestamps parse", "pass": bad_ts == 0, "detail": f"{bad_ts} unparseable" if bad_ts else (f"all {len(rows)} row(s) parse" if rows else "no rows")})
        hosts = {r[0] for r in conn.execute("SELECT hostname FROM assets").fetchall()} if conn else set()
        users = {str(r[0]).lower() for r in conn.execute("SELECT user FROM users").fetchall()} if conn else set()
        bad_h = sorted({str(r.get("host")) for r in rows if r.get("host") not in hosts})
        checklist.append({"label": "Hosts exist in assets", "pass": not bad_h, "detail": ("missing: " + ", ".join(bad_h[:10])) if bad_h else (f"all {len(rows)} row(s) found" if rows else "no rows")})
        bad_u = sorted({str(r.get("user")) for r in rows if str(r.get("user", "")).lower() not in users and str(r.get("user", "")).lower() != "none"})
        checklist.append({"label": "Users exist in users (or 'none')", "pass": not bad_u, "detail": ("missing: " + ", ".join(bad_u[:10])) if bad_u else (f"all {len(rows)} row(s) found or 'none'" if rows else "no rows")})
    finally:
        if conn: conn.close()
    return {"columns": cols, "rows": rows[:50], "count": len(rows), "ms": ms, "error": None, "checklist": checklist}

def save_detection(body):
    role = str(body.get("role", "")).strip().lower()
    if role not in ROLES: return {"error": f"invalid role: {role!r} (expected dns, web, endpoint or identity)"}, 400
    raw_slug = str(body.get("slug", "") or "").strip().lower()
    slug = re.sub(r"[^a-z0-9_]+", "_", raw_slug).strip("_")
    slug = re.sub(r"_+", "_", slug)
    if slug.startswith(role + "_"): slug = slug[len(role)+1:]
    if not slug: return {"error": "slug is required (sanitised to [a-z0-9_])"}, 400
    fname = f"{role}_{slug}.sql"
    folder = DETECTIONS / role; folder.mkdir(parents=True, exist_ok=True)
    dest = folder / fname
    if dest.exists() and not body.get("overwrite"): return {"error": f"file already exists: {role}/{fname} (tick overwrite to replace)", "file": f"{role}/{fname}"}, 409
    name = str(body.get("name", "") or slug).strip()
    category = str(body.get("category", "") or "").strip()
    if category != "multiple" and category not in VALID: return {"error": f"invalid category: {category!r}"}, 400
    sql = str(body.get("sql", "") or "")
    if not sql.strip(): return {"error": "sql is required"}, 400
    # strip any existing generated header lines from the SQL body
    body_lines = [ln for ln in sql.splitlines() if not re.match(r"\s*--\s*(name|role|category|param)\s*:", ln, re.I)]
    header = [f"-- name: {name}", f"-- role: {ROLES[role]}", f"-- category: {category}"]
    for p in (body.get("params") or []):
        if not isinstance(p, dict) or not str(p.get("name", "")).strip(): continue
        header.append(f"-- param: {str(p['name']).strip()} | {str(p.get('type','text')).strip().lower()} | {p.get('default','')} | {p.get('description','')}")
    dest.write_text("\n".join(header) + "\n" + "\n".join(body_lines).lstrip("\n") + ("\n" if not sql.endswith("\n") else ""), encoding="utf-8")
    return {"file": f"{role}/{fname}", "name": name, "role": ROLES[role], "category": category, "slug": slug}, 200

def coerce_params(det, raw):
    raw = raw or {}
    out = {}
    for p in det["params"]:
        n, t = p["name"], p["type"]
        v = raw.get(n, p["default"])
        try:
            if t == "int": out[n] = int(float(v)) if isinstance(v, str) and v.strip() else (int(v) if v is not None and v != "" else 0)
            elif t == "float": out[n] = float(v) if v is not None and v != "" else 0.0
            elif t == "list":
                if isinstance(v, list): out[n] = json.dumps([str(x).strip() for x in v])
                elif isinstance(v, str):
                    s = v.strip()
                    if s.startswith("["):
                        try:
                            arr = json.loads(s); out[n] = json.dumps([str(x) for x in arr]); continue
                        except Exception: pass
                    out[n] = json.dumps([x.strip() for x in s.split(",") if x.strip()] if s else [])
                else: out[n] = json.dumps([])
            else: out[n] = "" if v is None else str(v)
        except (ValueError, TypeError):
            out[n] = p["default"]
            # retry coerce default
            try:
                if t == "int": out[n] = int(p["default"] or 0)
                elif t == "float": out[n] = float(p["default"] or 0)
            except Exception: out[n] = 0
    # pass through any extra params the SQL might use
    for k, v in raw.items():
        if k not in out: out[k] = v
    return out

def run_detection(fname, raw_params):
    p = safe_path(fname)
    if not p: return {"columns": [], "rows": [], "ms": 0, "error": f"detection not found: {fname}", "dropped": 0}
    det = parse_detection(p)
    sql = p.read_text(encoding="utf-8", errors="replace")
    params = coerce_params(det, raw_params)
    t0 = time.time()
    conn = connect()
    try:
        cur = conn.execute(sql, params)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows, dropped = [], 0
        for r in cur.fetchall():
            d = dict(r)
            if "category" in d and d["category"] not in VALID:
                dropped += 1; continue
            rows.append(d)
        return {"columns": cols, "rows": rows, "ms": round((time.time()-t0)*1000), "error": None, "dropped": dropped}
    except sqlite3.Error as e:
        return {"columns": [], "rows": [], "ms": round((time.time()-t0)*1000), "error": str(e), "dropped": 0}
    finally: conn.close()

def parse_ts(s):
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try: return datetime.strptime(s.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError: continue
    raise ValueError(f"bad timestamp: {s!r}")

def fmt_ts(dt): return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n: return {}
        try: return json.loads(self.rfile.read(n) or b"{}")
        except Exception: return {}
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            f = ROOT / "index.html"
            if not f.exists(): self.send_json({"error": "index.html not found"}, 404); return
            body = f.read_bytes()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        if u.path == "/api/detections":
            try: self.send_json({"detections": list_detections()})
            except Exception as e: self.send_json({"detections": [], "error": str(e)}, 500)
            return
        if u.path == "/api/detection":
            fname = (parse_qs(u.query).get("file") or [""])[0]
            p = safe_path(fname)
            if not p: self.send_json({"error": "detection not found"}, 404); return
            det = parse_detection(p)
            det["sql"] = p.read_text(encoding="utf-8", errors="replace")
            self.send_json(det); return
        if u.path == "/api/user":
            name = (parse_qs(u.query).get("name") or [""])[0]
            conn = connect()
            try:
                cur = conn.execute("SELECT * FROM users WHERE user = ? COLLATE NOCASE", (name,))
                row = cur.fetchone()
                self.send_json({"user": dict(row) if row else None})
            except sqlite3.Error as e: self.send_json({"user": None, "error": str(e)})
            finally: conn.close()
            return
        self.send_json({"error": "not found"}, 404)
    def do_POST(self):
        u = urlparse(self.path)
        body = self.read_body()
        if u.path == "/api/run":
            self.send_json(run_detection(body.get("file",""), body.get("params") or {})); return
        if u.path == "/api/test":
            pdefs = body.get("param_defs") or body.get("paramDefs") or []
            # also accept params as list of defs with values
            if not pdefs and "-- param:" in body.get("sql", ""):
                # pasted/uploaded SQL: take the param defaults from its own header
                import tempfile
                with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False) as fh:
                    fh.write(body["sql"])
                try:
                    pdefs = parse_detection(Path(fh.name)).get("params", [])
                finally:
                    os.unlink(fh.name)
            self.send_json(test_detection(body.get("sql",""), body.get("params") or {}, pdefs)); return
        if u.path == "/api/save":
            obj, status = save_detection(body)
            self.send_json(obj, status); return
        if u.path == "/api/timeline":
            host, ts = body.get("host",""), body.get("ts") or body.get("timestamp","")
            try: minutes = float(body.get("minutes", 30))
            except Exception: minutes = 30
            if not host or not ts: self.send_json({"columns": [], "rows": [], "error": "host and ts required"}); return
            try: center = parse_ts(str(ts))
            except ValueError as e: self.send_json({"columns": [], "rows": [], "error": str(e)}); return
            lo, hi = fmt_ts(center - timedelta(minutes=minutes)), fmt_ts(center + timedelta(minutes=minutes))
            conn = connect()
            try:
                cur = conn.execute("SELECT ts, host, event, user, process, target FROM host WHERE host=? AND ts>=? AND ts<=? ORDER BY ts LIMIT 1000", (host, lo, hi))
                cols = [d[0] for d in cur.description]
                self.send_json({"columns": cols, "rows": [dict(r) for r in cur.fetchall()], "error": None})
            except sqlite3.Error as e: self.send_json({"columns": [], "rows": [], "error": str(e)})
            finally: conn.close()
            return
        if u.path == "/api/export":
            team_id = body.get("team_id", "11")
            runs = body.get("runs") or []
            findings, seen = [], set()
            dropped_total = 0
            for run in runs:
                res = run_detection(run.get("file",""), run.get("params") or {})
                if res.get("error"): continue
                dropped_total += res.get("dropped", 0)
                for r in res["rows"]:
                    try:
                        item = {"category": r["category"], "timestamp": r["timestamp"], "host": r["host"], "user": r["user"], "process": r["process"]}
                    except KeyError: continue
                    if "evidence" in r and r["evidence"] is not None: item["evidence"] = r["evidence"] if isinstance(r["evidence"], list) else [str(r["evidence"])]
                    if "confidence" in r and r["confidence"] is not None: item["confidence"] = r["confidence"]
                    key = (item["category"], item["timestamp"], item["host"], str(item["user"]).lower(), str(item["process"]).lower())
                    if key in seen: continue
                    seen.add(key); findings.append(item)
            doc = {"team_id": team_id, "findings": findings}
            try: (ROOT / "findings.json").write_text(json.dumps(doc, indent=2))
            except OSError as e: self.send_json({**doc, "error": f"write failed: {e}"}); return
            self.send_json({**doc, "dropped": dropped_total}); return
        self.send_json({"error": "not found"}, 404)

def main():
    global DB_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=None); ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    DB_PATH = resolve_db(a.db)
    if not DB_PATH:
        print("error: bearcorp.db not found. Pass --db PATH or set BEARCORP_DB (tried ./dataset/bearcorp.db and ../threat-hunt/dataset/dataset/bearcorp.db)", file=sys.stderr); sys.exit(1)
    print(f"Bearcorp dashboard: db={DB_PATH} http://127.0.0.1:{a.port}/")
    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()

if __name__ == "__main__": main()
