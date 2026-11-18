-- name: Made-up domains (NXDOMAIN DGA / guessing)
-- role: DNS
-- category: Reconnaissance
-- param: min_nxdomain | int | 20 | Minimum distinct NXDOMAIN names per src (branch a) or per src+parent (branch b)
WITH nx AS MATERIALIZED (
  SELECT ts, src_ip, query,
         substr(query, instr(query, '.') + 1) AS parent
  FROM dns
  WHERE rcode = 'NXDOMAIN'
),
flag_src AS (
  SELECT src_ip, COUNT(DISTINCT query) AS n
  FROM nx
  GROUP BY src_ip
  HAVING COUNT(DISTINCT query) >= :min_nxdomain
),
branch_a AS (
  SELECT h.host, h.process, MIN(h.ts) AS ts,
         'NXDOMAIN diverse names: ' || MAX(f.n) || ' distinct from ' || f.src_ip AS evidence
  FROM nx d
  JOIN flag_src f ON f.src_ip = d.src_ip
  JOIN host h ON h.event = 'DNS_QUERY' AND h.ts = d.ts AND h.target = d.query
  GROUP BY h.host, h.process
),
flag_parent AS (
  SELECT src_ip, parent, COUNT(DISTINCT query) AS n
  FROM nx
  GROUP BY src_ip, parent
  HAVING COUNT(DISTINCT query) >= :min_nxdomain
    AND instr(parent, '.') > 0
),
branch_b AS (
  SELECT h.host, h.process, MIN(h.ts) AS ts,
         'NXDOMAIN subdomain guessing under ' || f.parent || ': ' || MAX(f.n) || ' distinct from ' || f.src_ip AS evidence
  FROM nx d
  JOIN flag_parent f ON f.src_ip = d.src_ip AND f.parent = d.parent
  JOIN host h ON h.event = 'DNS_QUERY' AND h.ts = d.ts AND h.target = d.query
  GROUP BY h.host, h.process
),
all_sigs AS (
  SELECT host, process, MIN(ts) AS ts, group_concat(evidence, '; ') AS evidence
  FROM (SELECT * FROM branch_a UNION ALL SELECT * FROM branch_b)
  GROUP BY host, process
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
  a.evidence
FROM all_sigs a
