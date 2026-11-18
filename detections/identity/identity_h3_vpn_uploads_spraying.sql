-- name: VPN uploads and password spraying
-- role: Identity
-- category: multiple
-- param: upload_ratio | float | 3 | VPN upload/download ratio that counts as exfiltration
-- param: min_bytes_up | int | 100000000 | Minimum VPN bytes uploaded
-- param: min_spray_users | int | 10 | Minimum distinct users failed per spraying burst
-- param: burst_hours | float | 2 | Maximum burst length (first fail to success) in hours
WITH vpn_rows AS (
  SELECT 'Data theft' AS category, v.ts AS timestamp,
         u.workstation AS host, v.user, 'vpn' AS process,
         'VPN upload ' || CAST(v.bytes_up / 1048576 AS INTEGER) || ' MB vs download ' ||
           CAST(v.bytes_down / 1048576 AS INTEGER) || ' MB (ratio ' ||
           CAST(ROUND(CAST(v.bytes_up AS REAL) / MAX(v.bytes_down, 1), 1) AS TEXT) || ')' AS evidence
  FROM vpn v
  JOIN users u ON u.user = v.user AND u.workstation LIKE 'WS-%'
  WHERE v.bytes_up >= :upload_ratio * v.bytes_down
    AND v.bytes_up >= :min_bytes_up
),
spray AS (
  SELECT s.user AS got_in, s.src, MIN(f.ts) AS first_fail, s.ts AS success_ts,
         COUNT(DISTINCT f.user) AS victims
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
    AND (julianday(s.ts) - julianday(MIN(f.ts))) * 24 <= :burst_hours
),
spray_rows AS (
  SELECT 'Credential abuse' AS category, sp.first_fail AS timestamp,
         u.workstation AS host, sp.got_in AS user, 'sso' AS process,
         'Password spray from ' || sp.src || ': ' || sp.victims ||
           ' users failed before ' || sp.got_in || ' got in' AS evidence
  FROM spray sp
  JOIN users u ON u.user = sp.got_in AND u.workstation LIKE 'WS-%'
)
SELECT * FROM vpn_rows
UNION ALL
SELECT * FROM spray_rows
