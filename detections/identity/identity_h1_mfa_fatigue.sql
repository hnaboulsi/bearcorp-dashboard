-- name: MFA fatigue (SSO fail burst then success)
-- role: Identity
-- category: Credential abuse
-- param: min_fails | int | 10 | Minimum failed SSO logins in the burst
-- param: window_minutes | int | 30 | Burst window in minutes
WITH bursts AS (
  SELECT user, src, MIN(ts) AS first_fail, MAX(ts) AS last_fail, COUNT(*) AS n
  FROM auth
  WHERE service = 'sso' AND result = 'fail'
  GROUP BY user, src
  HAVING COUNT(*) >= :min_fails
    AND (julianday(MAX(ts)) - julianday(MIN(ts))) * 1440 <= :window_minutes
)
SELECT
  'Credential abuse' AS category,
  b.first_fail AS timestamp,
  u.workstation AS host,
  b.user,
  'sso' AS process,
  b.n || ' failed SSO logins from ' || b.src || ' in ' ||
    CAST(ROUND((julianday(b.last_fail) - julianday(b.first_fail)) * 1440) AS INTEGER) ||
    ' min, then success' AS evidence
FROM bursts b
JOIN users u ON u.user = b.user AND u.workstation LIKE 'WS-%'
WHERE EXISTS (
  SELECT 1 FROM auth s
  WHERE s.service = 'sso' AND s.result = 'success'
    AND s.user = b.user AND s.src = b.src
    AND s.ts >= b.last_fail
    AND (julianday(s.ts) - julianday(b.last_fail)) * 1440 <= 60
)
