-- name: Kerberos ticket bursts and fake accounts
-- role: Identity
-- category: multiple
-- param: min_services | int | 5 | Minimum distinct ticket services in the burst
-- param: max_span_seconds | int | 300 | Maximum burst span in seconds
-- param: trigger_pattern | text | %tgs.py% | Host CMD pattern that must precede the burst (LIKE)
-- param: trigger_window_minutes | int | 15 | Trigger CMD must be within this many minutes before the burst
-- param: min_fake_users | int | 10 | Minimum distinct fake accounts failing from one source
WITH tickets AS (
  SELECT user, src, MIN(ts) AS first_ts, MAX(ts) AS last_ts,
         COUNT(DISTINCT target) AS services
  FROM auth
  WHERE service = 'kerberos' AND target <> '-'
  GROUP BY user, src
  HAVING COUNT(DISTINCT target) >= :min_services
    AND (julianday(MAX(ts)) - julianday(MIN(ts))) * 86400 <= :max_span_seconds
),
burst_rows AS (
  SELECT 'Credential abuse' AS category, t.first_ts AS timestamp,
         u.workstation AS host, t.user, 'kerberos' AS process,
         t.services || ' Kerberos services in ' ||
           CAST(ROUND((julianday(t.last_ts) - julianday(t.first_ts)) * 86400) AS INTEGER) ||
           's after suspicious host command' AS evidence
  FROM tickets t
  JOIN users u ON u.user = t.user AND u.workstation LIKE 'WS-%'
  WHERE EXISTS (
    SELECT 1 FROM host c
    WHERE c.event = 'CMD' AND c.host = u.workstation
      AND c.target LIKE :trigger_pattern
      AND c.ts <= t.first_ts
      AND (julianday(t.first_ts) - julianday(c.ts)) * 1440 <= :trigger_window_minutes
  )
),
fake AS (
  SELECT src, MIN(ts) AS first_ts, COUNT(DISTINCT user) AS accounts
  FROM auth
  WHERE service = 'kerberos' AND result = 'fail'
    AND user NOT IN (SELECT user FROM users)
  GROUP BY src
  HAVING COUNT(DISTINCT user) >= :min_fake_users
),
fake_hosts AS (
  SELECT f.first_ts, f.accounts, f.src,
         COALESCE((SELECT ia.host FROM host ia
                   WHERE ia.event = 'IP_ASSIGNED' AND ia.target = f.src
                     AND ia.ts <= f.first_ts
                   ORDER BY ia.ts DESC LIMIT 1),
                  (SELECT hostname FROM assets WHERE ip = f.src)) AS host
  FROM fake f
),
fake_rows AS (
  SELECT 'Reconnaissance' AS category, fh.first_ts AS timestamp, fh.host,
         COALESCE((SELECT l.user FROM host l
                   WHERE l.event = 'LOGIN' AND l.host = fh.host AND l.ts <= fh.first_ts
                     AND NOT EXISTS (SELECT 1 FROM host o
                                     WHERE o.event = 'LOGOUT' AND o.host = fh.host
                                       AND o.ts > l.ts AND o.ts <= fh.first_ts)
                   ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
         'kerberos' AS process,
         fh.accounts || ' Kerberos failures for nonexistent accounts from ' || fh.src AS evidence
  FROM fake_hosts fh
  WHERE fh.host IS NOT NULL
)
SELECT * FROM burst_rows
UNION ALL
SELECT * FROM fake_rows
