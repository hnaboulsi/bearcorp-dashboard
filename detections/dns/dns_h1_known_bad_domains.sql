-- name: Known-bad IOC domains
-- role: DNS
-- category: Known-bad indicators
WITH hits AS (
  SELECT host, process, target, MIN(ts) AS ts
  FROM host
  WHERE event = 'DNS_QUERY'
    AND target IN (SELECT value FROM iocs WHERE type = 'domain')
  GROUP BY host, process, target
)
SELECT
  'Known-bad indicators' AS category,
  a.ts AS timestamp,
  a.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = a.host AND l.ts <= a.ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = a.host
                                AND o.ts > l.ts AND o.ts <= a.ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  a.process,
  'IOC domain ' || a.target AS evidence
FROM hits a
