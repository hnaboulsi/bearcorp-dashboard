-- name: Remote exec with a password shared across many users
-- role: Identity
-- category: Lateral movement
-- param: tools | list | winexe,smbclient | CMD tools whose -U user%password argument is checked
-- param: min_users | int | 5 | A password counts as shared when this many distinct users pass it
WITH cmds AS MATERIALIZED (
  SELECT rowid AS rid, ts, host, target,
         substr(target, instr(target, '-U ') + 3) AS after_u
  FROM host
  WHERE event = 'CMD'
    AND substr(target, 1, instr(target || ' ', ' ') - 1) IN (SELECT value FROM json_each(:tools))
    AND instr(target, '-U ') > 0
),
creds AS (
  SELECT rid, ts, host, target,
         substr(after_u, 1, instr(after_u, '%') - 1) AS cred_user,
         substr(substr(after_u, instr(after_u, '%') + 1), 1,
                instr(substr(after_u, instr(after_u, '%') + 1) || ' ', ' ') - 1) AS password
  FROM cmds
  WHERE instr(after_u, '%') > 0
    AND instr(after_u, '%') < instr(after_u || ' ', ' ')
),
shared AS (
  SELECT password FROM creds
  GROUP BY password
  HAVING COUNT(DISTINCT cred_user) >= :min_users
)
SELECT
  'Lateral movement' AS category,
  c.ts AS timestamp,
  c.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = c.host AND l.ts <= c.ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = c.host
                                AND o.ts > l.ts AND o.ts <= c.ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  'bash' AS process,
  'low' AS confidence,
  c.target AS evidence,
  (SELECT COUNT(DISTINCT cred_user) FROM creds x WHERE x.password = c.password) AS users_sharing_password
FROM creds c
WHERE c.password IN (SELECT password FROM shared)
