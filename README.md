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

1. Create `detections/<role>_h<N>_<slug>.sql`, e.g. `detections/dns_h2_beaconing.sql` (roles: `dns`, `web`, `endpoint`, `identity`).
2. Write the header comments and SQL below. It appears in the sidebar on the next page load.
3. Run it in the dashboard, check the findings, export, and validate:

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

Each person adds/edits **only their own** `detections/*.sql` files and pushes — never edit `server.py` or `index.html` to add a hunt, and never commit the dataset or `findings.json`. The shared `team_id` (top bar, default `11`) goes into every export so the scorer can merge the team's files.
