-- name: SSH as service or night admin account
-- role: Identity
-- category: Credential abuse
-- param: night_start | int | 22 | Night window start hour (local, inclusive)
-- param: night_end | int | 6 | Night window end hour (exclusive)
SELECT
  'Credential abuse' AS category,
  a.ts AS timestamp,
  a.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = a.host AND l.ts <= a.ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = a.host
                                AND o.ts > l.ts AND o.ts <= a.ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  'bash' AS process,
  a.target AS evidence
FROM host a
WHERE a.event = 'CMD'
  AND (
    a.target GLOB 'ssh *svc-*@*'
    OR (a.target GLOB 'ssh *admin-*@*'
        AND (CAST(substr(a.ts, 12, 2) AS INTEGER) >= :night_start
             OR CAST(substr(a.ts, 12, 2) AS INTEGER) < :night_end))
  )
