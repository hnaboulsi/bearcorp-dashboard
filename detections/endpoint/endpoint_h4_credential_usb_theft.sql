-- name: Stolen credentials and USB theft
-- role: Endpoint
-- category: multiple
-- param: cred_needles | list | id_rsa,id_ed25519,.aws/credentials,gcloud,azure,/etc/shadow,/etc/gshadow,Cookies,Login Data,logins.json,key4.db | Substrings marking a sensitive credential file read, matched on the CMD target
-- param: cred_exclude_substrings | list | .pub | Substrings that disqualify a credential read, e.g. public keys
-- param: rarity_max_hosts | int | 10 | Exact command text seen on more distinct hosts than this counts as normal admin noise
-- param: archive_needles | list | tar,zip,7z | Archive creation tools, matched with a trailing space on the CMD target
-- param: usb_min_mb | int | 1000 | USB copy must be at least this many MB
-- param: usb_window_min | int | 60 | USB copy must start within this many minutes after the archive command
WITH cred_hits AS (
  SELECT h.ts, h.host, h.process, h.target
  FROM host h
  WHERE h.event = 'CMD'
    AND EXISTS (SELECT 1 FROM json_each(:cred_needles) j
                WHERE h.target LIKE '%' || j.value || '%')
),
cred_rare AS (
  SELECT target FROM cred_hits
  GROUP BY target
  HAVING COUNT(DISTINCT host) <= :rarity_max_hosts
),
cred AS (
  SELECT 'Host intrusion signs' AS category, ts, host, process, target AS evidence,
         CAST(NULL AS TEXT) AS usb_ts, CAST(NULL AS INTEGER) AS usb_mb
  FROM cred_hits
  WHERE target IN (SELECT target FROM cred_rare)
    AND NOT EXISTS (SELECT 1 FROM json_each(:cred_exclude_substrings) j
                    WHERE cred_hits.target LIKE '%' || j.value || '%')
),
archive_hits AS (
  SELECT h.ts, h.host, h.process, h.target
  FROM host h
  WHERE h.event = 'CMD'
    AND EXISTS (SELECT 1 FROM json_each(:archive_needles) j
                WHERE h.target LIKE '%' || j.value || ' %')
),
archive_rare AS (
  SELECT target FROM archive_hits
  GROUP BY target
  HAVING COUNT(DISTINCT host) <= :rarity_max_hosts
),
theft AS (
  SELECT 'Data theft' AS category, a.ts, a.host, a.process, a.target AS evidence,
         (SELECT u.ts FROM usb u
          WHERE u.host = a.host AND u.action = 'copy' AND u.mb >= :usb_min_mb
            AND u.ts >= a.ts
            AND (julianday(u.ts) - julianday(a.ts)) * 1440 <= :usb_window_min
          ORDER BY u.ts LIMIT 1) AS usb_ts,
         (SELECT u.mb FROM usb u
          WHERE u.host = a.host AND u.action = 'copy' AND u.mb >= :usb_min_mb
            AND u.ts >= a.ts
            AND (julianday(u.ts) - julianday(a.ts)) * 1440 <= :usb_window_min
          ORDER BY u.ts LIMIT 1) AS usb_mb
  FROM archive_hits a
  WHERE a.target IN (SELECT target FROM archive_rare)
    AND EXISTS (SELECT 1 FROM usb u
                WHERE u.host = a.host AND u.action = 'copy' AND u.mb >= :usb_min_mb
                  AND u.ts >= a.ts
                  AND (julianday(u.ts) - julianday(a.ts)) * 1440 <= :usb_window_min)
),
combined AS (
  SELECT category, ts, host, process, evidence, usb_ts, usb_mb FROM cred
  UNION ALL
  SELECT category, ts, host, process, evidence, usb_ts, usb_mb FROM theft
),
dedup AS (
  SELECT category, ts, host, process, evidence, usb_ts, usb_mb,
         LAG(ts) OVER (PARTITION BY category, host, lower(process) ORDER BY ts) AS prev_ts
  FROM combined
),
kept AS (
  SELECT category, ts, host, process, evidence, usb_ts, usb_mb
  FROM dedup
  WHERE prev_ts IS NULL OR (julianday(ts) - julianday(prev_ts)) * 1440 > 10
)
SELECT
  k.category,
  k.ts AS timestamp,
  k.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = k.host AND l.ts <= k.ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = k.host
                                AND o.ts > l.ts AND o.ts <= k.ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  k.process,
  k.evidence,
  k.usb_ts,
  k.usb_mb
FROM kept k
ORDER BY k.ts
