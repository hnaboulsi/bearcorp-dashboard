-- name: Impossible travel and slow spraying
-- role: Identity
-- category: Credential abuse
-- param: travel_window_minutes | int | 60 | Max minutes between VPN logins in different networks
-- param: min_spray_users | int | 10 | Minimum distinct users failed per slow spray
-- param: slow_min_hours | float | 12 | Minimum slow-spray span (first fail to success) in hours
-- param: slow_max_per_hour | float | 3 | Maximum slow-spray rate in attempts per hour
WITH v1 AS (
  SELECT user, ts, src_ip,
         substr(src_ip, instr(src_ip, '.') + 1) AS rest1
  FROM vpn
),
v2 AS (
  SELECT user, ts, src_ip,
         substr(rest1, instr(rest1, '.') + 1) AS rest2,
         (length(src_ip) - length(rest1)) + (length(rest1) - length(substr(rest1, instr(rest1, '.') + 1))) AS cut
  FROM v1
),
vpref AS (
  SELECT user, ts, src_ip,
         substr(src_ip, 1, cut + instr(rest2, '.')) AS net24
  FROM v2
),
travel AS (
  SELECT a.user, MIN(a.ts) AS first_ts
  FROM vpref a
  JOIN vpref b ON b.user = a.user AND b.ts > a.ts
    AND b.net24 <> a.net24
    AND (julianday(b.ts) - julianday(a.ts)) * 1440 <= :travel_window_minutes
  GROUP BY a.user
),
travel_rows AS (
  SELECT 'Credential abuse' AS category, t.first_ts AS timestamp,
         u.workstation AS host, t.user, 'vpn' AS process,
         'Impossible travel: VPN logins from two networks within ' ||
           :travel_window_minutes || ' min' AS evidence
  FROM travel t
  JOIN users u ON u.user = t.user AND u.workstation LIKE 'WS-%'
),
slow AS (
  SELECT s.user AS got_in, s.src, MIN(f.ts) AS first_fail, s.ts AS success_ts,
         COUNT(*) AS attempts, COUNT(DISTINCT f.user) AS victims
  FROM auth s
  JOIN auth f ON f.service = 'sso' AND f.result = 'fail' AND f.src = s.src
    AND f.ts < s.ts
    AND f.ts > COALESCE((SELECT MAX(p.ts) FROM auth p
                         WHERE p.service = 'sso' AND p.result = 'success'
                           AND p.src = s.src AND p.ts < s.ts), '0000-01-01T00:00:00.000Z')
  WHERE s.service = 'sso' AND s.result = 'success'
    AND s.src NOT LIKE 'WS-%' AND s.src NOT LIKE 'SRV-%'
    AND s.src NOT LIKE 'LAB-%' AND s.src NOT LIKE '10.%'
  GROUP BY s.user, s.src, s.ts
  HAVING COUNT(DISTINCT f.user) >= :min_spray_users
    AND (julianday(s.ts) - julianday(MIN(f.ts))) * 24 >= :slow_min_hours
    AND COUNT(*) / MAX((julianday(s.ts) - julianday(MIN(f.ts))) * 24, 0.01) <= :slow_max_per_hour
),
slow_rows AS (
  SELECT 'Credential abuse' AS category, sp.first_fail AS timestamp,
         u.workstation AS host, sp.got_in AS user, 'sso' AS process,
         'Slow spray from ' || sp.src || ': ' || sp.attempts || ' attempts over days before ' ||
           sp.got_in || ' got in' AS evidence
  FROM slow sp
  JOIN users u ON u.user = sp.got_in AND u.workstation LIKE 'WS-%'
)
SELECT * FROM travel_rows
UNION ALL
SELECT * FROM slow_rows
