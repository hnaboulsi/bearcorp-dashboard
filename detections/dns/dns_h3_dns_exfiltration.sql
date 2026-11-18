-- name: DNS exfiltration (many unique subdomains)
-- role: DNS
-- category: Data theft
-- param: min_unique | int | 20 | Minimum distinct names per source, parent domain and query type
-- param: excluded_parents | list | hashlookup.threatstop.net, rpz.shieldops.net, reputation.shieldops.net, d3k4x9.vaultcdn.net | Parent domains that are known-good lookup services
WITH tx AS MATERIALIZED (
  SELECT ts, src_ip, query, qtype,
         substr(query, instr(query, '.') + 1) AS parent
  FROM dns
  WHERE qtype IN ('TXT', 'AAAA')
),
flagged AS (
  SELECT src_ip, parent, qtype, COUNT(DISTINCT query) AS n
  FROM tx
  GROUP BY src_ip, parent, qtype
  HAVING COUNT(DISTINCT query) >= :min_unique
    AND parent NOT IN (SELECT value FROM json_each(:excluded_parents))
),
hosts AS (
  SELECT h.host, h.process, f.parent, f.qtype, f.src_ip, MAX(f.n) AS n, MIN(h.ts) AS ts
  FROM tx d
  JOIN flagged f ON f.src_ip = d.src_ip AND f.parent = d.parent AND f.qtype = d.qtype
  JOIN host h ON h.target = d.query AND h.ts = d.ts AND h.event = 'DNS_QUERY'
  GROUP BY h.host, h.process, f.parent
)
SELECT
  'Data theft' AS category,
  a.ts AS timestamp,
  a.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = a.host AND l.ts <= a.ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = a.host
                                AND o.ts > l.ts AND o.ts <= a.ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  a.process,
  a.qtype || ' exfil under ' || a.parent || ': ' || a.n || ' distinct names from ' || a.src_ip AS evidence
FROM hosts a
