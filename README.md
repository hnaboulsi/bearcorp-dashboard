# Bearcorp threat hunt dashboard

One dashboard for a team of 4. Each teammate only adds `.sql` files to `detections/`; the dashboard discovers them automatically — no server restart, no code changes.

## Run

```bash
# DB found automatically at ../threat-hunt/dataset/dataset/bearcorp.db, or pass it:
python3 server.py --db /path/to/bearcorp.db --port 8000
# or: BEARCORP_DB=/path/to/bearcorp.db python3 server.py
```

Open <http://127.0.0.1:8000/>. Python 3 standard library only; the page works offline (no external libraries or fonts).

Use it: pick a detection in the left sidebar, adjust its parameters (findings re-run automatically after 600 ms), click **Run all** to run every enabled detection, click a finding to open the triage drawer (finding fields, evidence, host timeline ±30 min, and the user's row from the `users` table), then **Export findings.json** to download `findings.json` (also written to `./findings.json`).

## Add a detection

Detections live in per-role folders: `detections/dns/`, `detections/web/`, `detections/endpoint/`, `detections/identity/` (files directly in `detections/` are also discovered). The server discovers `*.sql` recursively on every request — no restart needed — and the sidebar groups by role folder (falling back to the `-- role:` header).

Through the dashboard (recommended):

1. Open the dashboard and click **Add detection** in the sidebar.
2. Pick your role, name, category (one of the 9 exact categories or `multiple`), add param rows (name, `int|float|text|list`, default, description), and write SQL in the prefilled template (required columns + user-at-time subquery). Or use **Upload .sql file** to load an existing file into the form.
3. Click **Test** — it runs the SQL read-only (60 s timeout) and shows columns, first 50 rows, count, time, and a pass/fail checklist (required columns, valid categories, parseable timestamps, hosts in `assets`, users in `users` or `'none'`). Fix any failures.
4. Click **Save** (tick **overwrite** only to replace an existing file). This writes `detections/<role>/<role>_<slug>.sql` with a generated header; it then appears in the sidebar. **Edit SQL** on an existing detection reopens the modal prefilled (save asks for overwrite confirmation).

Or by hand: create `detections/<role>/<role>_<slug>.sql`, e.g. `detections/dns/dns_h2_beaconing.sql`, with the header + SQL below.

Then run it in the dashboard, check the findings, export, and validate:

```bash
python3 -I /path/to/berkeley_hackathon_validate.py findings.json --data /path/to/bearcorp.db
```

## Detection file contract

Header comment lines, parsed by the server:

```
-- name: <display name>
-- role: DNS | Web | Endpoint | Identity
-- category: <exact category, or "multiple" if the SELECT returns the category per row>
-- param: <name> | int|float|text|list | <default> | <description>     (repeatable)
```

- The SQL uses named parameters (`:name`) and **must** return columns: `category, timestamp, host, user, process`. Optional columns: `evidence`, `confidence`, plus any extra columns (shown in the table as triage info).
- `list` params are comma-separated text in the UI, passed to SQL as a JSON array string; use them with `json_each(:name)`, e.g. `WHERE domain IN (SELECT value FROM json_each(:keywords))`.
- Valid categories (rows with any other category are dropped server-side and counted): Known-bad indicators, Command and control, Reconnaissance, Data theft, Deceptive domains, Malware delivery, Host intrusion signs, Lateral movement, Credential abuse.

Example: see [endpoint_h1_persistence.sql](detections/endpoint_h1_persistence.sql).

## Team workflow

1. Open the dashboard, click **Add detection**, write/test with **Test**, then **Save** (see above).
2. Commit and push only your role folder:

```bash
git add detections/<role>/
git commit -m "Add <role> detection: <name>"
git pull --rebase
git push
```

Each person only touches their own role folder (`detections/dns/`, `detections/web/`, `detections/endpoint/`, or `detections/identity/`), so merges never conflict. Never edit `server.py` or `index.html` to add a hunt, and never commit the dataset or `findings.json`. The shared `team_id` (top bar, default `11`) goes into every export so the scorer can merge the team's files.
