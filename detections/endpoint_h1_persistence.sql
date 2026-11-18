-- name: Persistence and cleanup commands
-- role: Endpoint
-- category: Host intrusion signs
-- param: max_hosts | int | 5 | A command seen on more hosts than this counts as normal admin noise
WITH hits AS (
  SELECT ts, host, process, target
  FROM host
  WHERE event = 'CMD'
    AND (target LIKE '%authorized_keys%'
      OR target LIKE '%crontab%'
      OR target LIKE 'useradd%'
      OR target LIKE '%.bashrc%'
      OR target LIKE '%history -c%'
      OR target LIKE 'rm -f /var/log%')
),
rare AS (
  SELECT target FROM hits
  GROUP BY target
  HAVING COUNT(DISTINCT host) <= :max_hosts
)
SELECT
  'Host intrusion signs' AS category,
  h.ts AS timestamp,
  h.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = h.host AND l.ts <= h.ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = h.host
                                AND o.ts > l.ts AND o.ts <= h.ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  h.process,
  h.target AS evidence
FROM hits h
WHERE h.target IN (SELECT target FROM rare)
