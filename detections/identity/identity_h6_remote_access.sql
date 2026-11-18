-- name: Remote access to new servers
-- role: Identity
-- category: multiple
-- param: rdp_window_minutes | int | 30 | Max minutes between xfreerdp CMD and matching RDP auth
-- param: min_probe_targets | int | 8 | Minimum distinct targets for slow probe
-- param: min_probe_minutes | int | 30 | Minimum slow-probe span in minutes
-- param: probe_processes | list | python3 | NET_CONNECT processes that count as probing tools
WITH user_at AS (
  SELECT a.rowid AS rid,
         COALESCE((SELECT l.user FROM host l
                   WHERE l.event = 'LOGIN' AND l.host = a.host AND l.ts <= a.ts
                     AND NOT EXISTS (SELECT 1 FROM host o
                                     WHERE o.event = 'LOGOUT' AND o.host = a.host
                                       AND o.ts > l.ts AND o.ts <= a.ts)
                   ORDER BY l.ts DESC LIMIT 1), 'none') AS login_user
  FROM host a WHERE a.event = 'CMD'
),
lateral AS (
  SELECT a.ts, a.host, ua.login_user,
         substr(a.target, 1, instr(a.target || ' ', ' ') - 1) AS tool,
         a.target
  FROM host a
  JOIN user_at ua ON ua.rid = a.rowid
  WHERE a.event = 'CMD'
    AND (
      (a.target LIKE 'smbclient%' AND a.target LIKE '%recurse%' AND a.target LIKE '%mget *%')
      OR a.target LIKE 'wmic%process call create%'
      OR a.target GLOB 'winrs *admin-*'
      OR (a.target LIKE 'winexe%' AND (a.target LIKE '%admin-%' OR a.target LIKE 'winexe -U %:%'))
      OR (a.target LIKE 'xfreerdp%' AND EXISTS (
        SELECT 1 FROM auth r
        JOIN assets s ON s.hostname = r.target
        WHERE r.service = 'rdp' AND r.result = 'success' AND r.mfa = 'no'
          AND r.user LIKE 'admin-%'
          AND s.ip = substr(substr(a.target, instr(a.target, '/v:') + 3),
                            1, instr(substr(a.target, instr(a.target, '/v:') + 3) || ' ', ' ') - 1)
          AND r.user = substr(substr(a.target, instr(a.target, '/u:') + 3),
                              1, instr(substr(a.target, instr(a.target, '/u:') + 3) || ' ', ' ') - 1)
          AND ABS(julianday(r.ts) - julianday(a.ts)) * 1440 <= :rdp_window_minutes
      ))
    )
),
lateral_rows AS (
  SELECT 'Lateral movement' AS category, ts AS timestamp, host,
         login_user AS user, 'bash' AS process, target AS evidence
  FROM lateral
),
probes AS (
  SELECT host, process, MIN(ts) AS ts, COUNT(DISTINCT target) AS targets
  FROM host
  WHERE event = 'NET_CONNECT'
    AND process IN (SELECT value FROM json_each(:probe_processes))
  GROUP BY host, process
  HAVING COUNT(DISTINCT target) >= :min_probe_targets
    AND (julianday(MAX(ts)) - julianday(MIN(ts))) * 1440 >= :min_probe_minutes
),
probe_rows AS (
  SELECT 'Reconnaissance' AS category, p.ts AS timestamp, p.host,
         COALESCE((SELECT l.user FROM host l
                   WHERE l.event = 'LOGIN' AND l.host = p.host AND l.ts <= p.ts
                     AND NOT EXISTS (SELECT 1 FROM host o
                                     WHERE o.event = 'LOGOUT' AND o.host = p.host
                                       AND o.ts > l.ts AND o.ts <= p.ts)
                   ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
         p.process,
         'Slow probe: ' || p.targets || ' distinct server targets' AS evidence
  FROM probes p
)
SELECT * FROM lateral_rows
UNION ALL
SELECT * FROM probe_rows
