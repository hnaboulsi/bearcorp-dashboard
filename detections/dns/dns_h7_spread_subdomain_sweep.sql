-- name: Spread subdomain sweep (many hosts guessing)
-- role: DNS
-- category: Reconnaissance
-- param: min_srcs | int | 4 | Minimum distinct source IPs sweeping one parent
-- param: min_subdomains | int | 25 | Minimum distinct subdomains under one parent
-- param: max_per_src | int | 20 | Maximum distinct subdomains per single source IP
-- param: excluded_parents | list | hashlookup.threatstop.net, rpz.shieldops.net, reputation.shieldops.net, d3k4x9.vaultcdn.net | Legit parents to exclude
WITH nx AS MATERIALIZED (
  SELECT ts, src_ip, query,
         substr(query, instr(query, '.') + 1) AS parent
  FROM dns
  WHERE rcode = 'NXDOMAIN'
),
per_src AS (
  SELECT parent, src_ip, COUNT(DISTINCT query) AS n
  FROM nx
  GROUP BY parent, src_ip
),
flagged AS (
  SELECT p.parent
  FROM (SELECT parent,
               COUNT(DISTINCT src_ip) AS srcs,
               COUNT(DISTINCT query) AS subs
        FROM nx GROUP BY parent) p
  JOIN (SELECT parent, MAX(n) AS mx FROM per_src GROUP BY parent) m
    ON m.parent = p.parent
  WHERE p.srcs >= :min_srcs
    AND p.subs >= :min_subdomains
    AND m.mx <= :max_per_src
    AND p.parent NOT IN (SELECT value FROM json_each(:excluded_parents))
),
hosts AS (
  SELECT h.host, h.process, f.parent, MIN(h.ts) AS ts
  FROM nx d
  JOIN flagged f ON f.parent = d.parent
  JOIN host h ON h.event = 'DNS_QUERY' AND h.ts = d.ts AND h.target = d.query
  GROUP BY h.host, h.process, f.parent
)
SELECT
  'Reconnaissance' AS category,
  a.ts AS timestamp,
  a.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = a.host AND l.ts <= a.ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = a.host
                                AND o.ts > l.ts AND o.ts <= a.ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  a.process,
  'Spread NXDOMAIN sweep under ' || a.parent AS evidence
FROM hosts a
