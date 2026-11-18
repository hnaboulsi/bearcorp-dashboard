# Build the Bearcorp team threat-hunt dashboard (Deliverable 1)

Folder: /Users/naboulsi/Downloads/hackathon-participant-files/bearcorp-dashboard (a new git repo; do not run git). Dataset (read-only, 7 GB): /Users/naboulsi/Downloads/hackathon-participant-files/threat-hunt/dataset/dataset/bearcorp.db. Validator: /Users/naboulsi/Downloads/hackathon-participant-files/threat-hunt/dataset/berkeley_hackathon_validate.py. Do NOT copy the dataset into the folder.

Goal: ONE dashboard for a team of 4. Each teammate only adds .sql files to detections/; the dashboard discovers them automatically. Judges try it in person. It must: let someone change a detection's settings (thresholds, keyword lists) and see findings update on screen; show info that helps an analyst triage each finding; have a button to export findings.json.

## Detection file contract (document it in README.md)
- detections/<role>_h<N>_<slug>.sql, e.g. endpoint_h1_persistence.sql (an example exists; keep it).
- Header comment lines, parsed by the server:
  -- name: <display name>
  -- role: DNS | Web | Endpoint | Identity
  -- category: <exact category, or "multiple" if the SELECT returns the category per row>
  -- param: <name> | int|float|text|list | <default> | <description>     (repeatable; list = comma-separated text, passed as a JSON array string; SQL can use json_each(:name))
- The SQL uses named parameters (:name) and MUST return columns: category, timestamp, host, user, process. Optional columns: evidence, confidence, plus any extra columns (shown in the table as triage info).
- Valid categories: Known-bad indicators, Command and control, Reconnaissance, Data theft, Deceptive domains, Malware delivery, Host intrusion signs, Lateral movement, Credential abuse.

## server.py (Python 3 stdlib only: http.server, sqlite3, json)
- python3 server.py [--db PATH] [--port 8000]; DB path also from env BEARCORP_DB; default ./dataset/bearcorp.db, then ../threat-hunt/dataset/dataset/bearcorp.db. Clear startup error if not found.
- Open the DB read-only (file:...?mode=ro, uri=True); one connection per request; a 60-second timeout via set_progress_handler; return errors as JSON with the SQLite message.
- GET / -> index.html. GET /api/detections -> parsed headers for every .sql (re-read on each request so new files appear without restart). POST /api/run {file, params} -> {columns, rows, ms, error}. POST /api/timeline {host, ts, minutes} -> host-table rows on that host within +/- minutes (default 30), ordered by ts (triage context). POST /api/export {team_id, runs:[{file, params}]} -> findings.json body: {"team_id", "findings":[{category,timestamp,host,user,process}+ evidence/confidence if present]}, deduped on (category, timestamp, host, lower(user), lower(process)). Also write it to ./findings.json.
- Validate rows server-side: drop rows whose category is not valid, and report how many were dropped.

## index.html (vanilla JS + CSS, no external libraries or fonts: works offline)
Look: minimal and polished like Linear/Apple: near-black #0b0c0e, panels #141518 with hairline borders rgba(255,255,255,0.06), radius 10px, system-ui font, monospace for ids/timestamps, one indigo accent #7c83ff, status colors only for meaning.
Layout:
- Top bar: title "Bearcorp threat hunt", team_id input (default "11"), total findings count, "Run all" button, "Export findings.json" button (downloads the file).
- Left sidebar: detections grouped by role, each with an on/off checkbox, its category chip, and its finding count after a run.
- Main: the selected detection: name, category, its params as a form (auto-generated from the header; list params as comma text inputs), a Run button, run time; then the findings table (category, timestamp, host, user, process, evidence + extra columns), sortable, with a filter box.
- Triage drawer: clicking a finding opens a right drawer with the finding fields, its evidence, the host timeline (+/-30 min from /api/timeline, with the finding's row highlighted and event types color-coded), and the user's row from the users table if present (add GET /api/user?name=).
- Changing a param re-runs that detection (debounced 600 ms) so findings update on screen.
- "Run all" runs every enabled detection sequentially, showing progress; Export uses each detection's current params.
## Verify
Start the server in the background on port 8765, curl /api/detections and POST /api/run for endpoint_h1_persistence.sql with max_hosts 5, print the count and 3 rows, POST /api/export and run the validator on the exported file (python3 -I /Users/naboulsi/Downloads/hackathon-participant-files/threat-hunt/dataset/berkeley_hackathon_validate.py findings.json --data /Users/naboulsi/Downloads/hackathon-participant-files/threat-hunt/dataset/dataset/bearcorp.db), then stop the server. Write README.md (run, add a detection, file contract, team workflow: each person adds/edits only their own detections/*.sql and pushes). Add .gitignore (dataset/, findings.json, __pycache__, .DS_Store). 15-minute limit. Final message: 6 lines.
