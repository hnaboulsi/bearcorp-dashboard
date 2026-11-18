-- name: Host intrusion signs (hands-on-keyboard)
-- role: Endpoint
-- category: Host intrusion signs
-- param: min_b64_len | int | 40 | Minimum length of encoded blob before base64 decode
-- param: max_pattern_hosts | int | 20 | Rarity guard: drop normalised pattern seen on more hosts than this
-- param: collapse_window_min | int | 10 | Collapse repeats per category/host/process within this many minutes
-- param: metadata_ip | text | 169.254.169.254 | Cloud metadata IP for credential theft
-- param: shell_helpers | list | dup2,subprocess,/bin/sh,/bin/bash | Markers that turn a Python socket connect into a reverse shell
WITH hits AS (
  SELECT ts, host, process, target, lower(target) AS low,
    CASE
      WHEN instr(lower(target), '/dev/tcp/') > 0 THEN 'dev_tcp'
      WHEN (instr(' ' || lower(target) || ' ', ' nc ') > 0
            OR instr(' ' || lower(target) || ' ', ' ncat ') > 0
            OR instr(' ' || lower(target) || ' ', ' netcat ') > 0)
           AND instr(lower(target), ' -e ') > 0 THEN 'nc_exec'
      WHEN instr(lower(target), 'python') > 0
           AND lower(target) LIKE '%socket%.connect(%'
           AND EXISTS (SELECT 1 FROM json_each(:shell_helpers) WHERE instr(lower(target), lower(value)) > 0)
        THEN 'python_socket'
      WHEN instr(lower(target), lower(:metadata_ip)) > 0 THEN 'metadata'
      WHEN (lower(target) LIKE 'find %' OR instr(' ' || lower(target), ' find ') > 0)
           AND lower(target) LIKE '%find /%'
           AND (lower(target) LIKE '%-perm -4000%' OR lower(target) LIKE '%-perm 4000%')
        THEN 'suid_find'
      WHEN (instr(lower(target), 'base64 -d') > 0
            OR instr(lower(target), 'base64 --decode') > 0)
           AND target GLOB ('*' || replace(hex(zeroblob(:min_b64_len)), '00', '[A-Za-z0-9+/=]') || '*')
           AND (lower(target) LIKE '%| bash%' OR lower(target) LIKE '%| sh%'
                OR lower(target) LIKE '%|bash%' OR lower(target) LIKE '%|sh%')
        THEN 'base64_decode'
    END AS rule
  FROM host
  WHERE event = 'CMD'
),
classified AS (
  SELECT ts, host, process, target, rule,
    substr(
      replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(low, '0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', ''),
      1, 160) AS norm_key
  FROM hits
  WHERE rule IS NOT NULL
),
rare AS (
  SELECT norm_key FROM classified
  GROUP BY norm_key
  HAVING COUNT(DISTINCT host) <= :max_pattern_hosts
),
filtered AS (
  SELECT c.ts, c.host, c.process, c.target, c.rule
  FROM classified c
  WHERE c.norm_key IN (SELECT norm_key FROM rare)
),
sequenced AS (
  SELECT f.*,
    LAG(f.ts) OVER (PARTITION BY 'Host intrusion signs', f.host, lower(f.process) ORDER BY f.ts) AS prev_ts
  FROM filtered f
),
collapsed AS (
  SELECT * FROM sequenced
  WHERE prev_ts IS NULL
     OR (julianday(ts) - julianday(prev_ts)) * 1440.0 > :collapse_window_min
)
SELECT
  'Host intrusion signs' AS category,
  c.ts AS timestamp,
  c.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = c.host AND l.ts <= c.ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = c.host
                                AND o.ts > l.ts AND o.ts <= c.ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  c.process,
  c.target AS evidence,
  c.rule AS rule
FROM collapsed c
ORDER BY c.ts
