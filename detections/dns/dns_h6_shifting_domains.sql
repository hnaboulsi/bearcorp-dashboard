-- name: Shifting domains (fresh burst, flux, IOC siblings, beaconing)
-- role: DNS
-- category: Command and control
-- param: min_fresh | int | 20 | Minimum never-seen domains per host in one hour
-- param: min_answers | int | 10 | Minimum distinct IPs for one domain (fast flux)
-- param: min_beacon_hits | int | 24 | Minimum lookups for a beacon
-- param: min_beacon_hours | float | 12 | Minimum hours a beacon spans
-- param: max_beacon_cv | float | 0.3 | Maximum gap spread (std divided by mean) for steady timing
-- param: max_beacon_srcs | int | 20 | Domains looked up by more sources than this count as normal
-- param: beacon_exclusions | list | telemetry.nexusos.com, updates.nexusos.com, license.nexusos.com, inventory.nexusos.com, vaultdrive.com | Known-good agent domains to skip
WITH once AS MATERIALIZED (
  SELECT query, MIN(ts) AS ts
  FROM dns
  WHERE qtype = 'A' AND rcode = 'NOERROR'
    AND length(query) - length(replace(query, '.', '')) = 1
  GROUP BY query
  HAVING COUNT(*) = 1
),
fresh_hits AS (
  SELECT h.host, h.process, h.ts, h.target
  FROM once o
  JOIN host h ON h.target = o.query AND h.ts = o.ts AND h.event = 'DNS_QUERY'
),
sig_a AS (
  SELECT host, process, MIN(ts) AS ts,
         'Burst of ' || COUNT(*) || ' never-seen domains in one hour, e.g. ' || MIN(target) AS evidence
  FROM fresh_hits
  GROUP BY host, process, substr(ts, 1, 13)
  HAVING COUNT(*) >= :min_fresh
),
flux AS (
  SELECT query, COUNT(DISTINCT answer) AS answers
  FROM dns
  WHERE qtype = 'A' AND rcode = 'NOERROR'
  GROUP BY query
  HAVING COUNT(DISTINCT answer) >= :min_answers
),
sig_b AS (
  SELECT h.host, h.process, MIN(h.ts) AS ts,
         'Fast-flux domain ' || f.query || ': ' || MAX(f.answers) || ' distinct answers' AS evidence
  FROM host h
  JOIN flux f ON h.target = f.query
  WHERE h.event = 'DNS_QUERY'
  GROUP BY h.host, h.process, f.query
),
ioc_answers AS (
  SELECT DISTINCT answer FROM dns
  WHERE query IN (SELECT value FROM iocs WHERE type = 'domain')
),
siblings AS (
  SELECT DISTINCT query FROM dns
  WHERE answer IN (SELECT answer FROM ioc_answers)
    AND query NOT IN (SELECT value FROM iocs WHERE type = 'domain')
),
sig_c AS (
  SELECT h.host, h.process, MIN(h.ts) AS ts,
         'Resolves to IOC IP: ' || f.query AS evidence
  FROM host h
  JOIN siblings f ON h.target = f.query
  WHERE h.event = 'DNS_QUERY'
  GROUP BY h.host, h.process, f.query
),
few_src AS MATERIALIZED (
  SELECT query FROM dns
  GROUP BY query
  HAVING COUNT(DISTINCT src_ip) <= :max_beacon_srcs
    AND COUNT(*) >= :min_beacon_hits
),
pairs AS MATERIALIZED (
  SELECT src_ip, query FROM dns
  WHERE query IN (SELECT query FROM few_src)
    AND query NOT IN (SELECT value FROM json_each(:beacon_exclusions))
  GROUP BY src_ip, query
  HAVING COUNT(*) >= :min_beacon_hits
    AND (julianday(MAX(ts)) - julianday(MIN(ts))) * 24 >= :min_beacon_hours
),
gaps AS MATERIALIZED (
  SELECT d.ts, d.src_ip, d.query,
         (julianday(d.ts) - julianday(LAG(d.ts) OVER (PARTITION BY d.src_ip, d.query ORDER BY d.ts))) * 86400 AS gap
  FROM dns d
  WHERE d.query IN (SELECT query FROM pairs)
    AND EXISTS (SELECT 1 FROM pairs p WHERE p.src_ip = d.src_ip AND p.query = d.query)
),
beacon AS (
  SELECT src_ip, query, COUNT(gap) AS n, AVG(gap) AS mean_gap,
         sqrt(MAX(AVG(gap * gap) - AVG(gap) * AVG(gap), 0)) / AVG(gap) AS cv
  FROM gaps
  WHERE gap IS NOT NULL
  GROUP BY src_ip, query
  HAVING sqrt(MAX(AVG(gap * gap) - AVG(gap) * AVG(gap), 0)) / AVG(gap) <= :max_beacon_cv
),
sig_d AS (
  SELECT h.host, h.process, MIN(h.ts) AS ts,
         'Beaconing to ' || b.query || ' every ~' || CAST(MAX(b.mean_gap) AS INT) || 's, ' || MAX(b.n) || ' hits' AS evidence
  FROM gaps g
  JOIN beacon b ON b.src_ip = g.src_ip AND b.query = g.query
  JOIN host h ON h.target = g.query AND h.ts = g.ts AND h.event = 'DNS_QUERY'
  GROUP BY h.host, h.process, b.query
),
all_sigs AS (
  SELECT * FROM sig_a
  UNION ALL SELECT * FROM sig_b
  UNION ALL SELECT * FROM sig_c
  UNION ALL SELECT * FROM sig_d
)
SELECT
  'Command and control' AS category,
  a.ts AS timestamp,
  a.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = a.host AND l.ts <= a.ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = a.host
                                AND o.ts > l.ts AND o.ts <= a.ts)
            ORDER BY l.ts DESC LIMIT 1),
           (SELECT u.user FROM users u WHERE u.workstation = a.host LIMIT 1),
           'none') AS user,
  a.process,
  a.evidence
FROM all_sigs a
