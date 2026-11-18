-- name: Temp-folder programs, scanners and large-ping C2
-- role: Endpoint
-- category: multiple
-- param: rarity_max_hosts | int | 25 | Normalised command pattern seen on more distinct hosts than this is fleet-wide noise
-- param: tmp_dirs | list | /tmp/,/dev/shm/ | Temp directories treated as suspicious execution locations
-- param: tmp_benign_substrings | list | pip-install,setup.py | Substrings that make a temp-folder execution benign
-- param: scanner_tools | list | nmap,masscan | Scanner tool names at the start of a command
-- param: scanner_benign_patterns | list | nmap -sv test.bearcorp.com | Normalised scanner patterns to exclude as admin checks
-- param: ping_min_size | int | 1000 | Minimum ping -s packet size for the ICMP tunnel detection
-- param: proc_start_window_min | int | 120 | Minutes before a CMD that a matching PROC_START counts as the same action
WITH hits AS (
  SELECT ts, host, process, target,
         lower(trim(target)) AS low,
         replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
           lower(trim(target)), '0', 'N'), '1', 'N'), '2', 'N'), '3', 'N'), '4', 'N'),
           '5', 'N'), '6', 'N'), '7', 'N'), '8', 'N'), '9', 'N') AS pattern_key
  FROM host
  WHERE event = 'CMD'
    AND (
      EXISTS (SELECT 1 FROM json_each(:tmp_dirs) WHERE instr(lower(target), value) > 0)
      OR EXISTS (SELECT 1 FROM json_each(:scanner_tools) WHERE lower(target) LIKE value || '%')
      OR lower(target) LIKE 'ping%'
    )
),
rare AS (
  SELECT pattern_key FROM hits
  GROUP BY pattern_key
  HAVING COUNT(DISTINCT host) <= :rarity_max_hosts
),
classified AS (
  SELECT h.ts, h.host, h.process, h.target,
    CASE
      WHEN h.low LIKE 'ping %'
           AND instr(h.low, ' -s ') > 0
           AND CAST(substr(h.low, instr(h.low, ' -s ') + 4) AS INTEGER) >= :ping_min_size
           AND rtrim(h.low) GLOB '* [0-9]*.[0-9]*.[0-9]*.[0-9]*'
           AND rtrim(h.low) NOT LIKE '% 10.%'
        THEN 'Command and control'
      WHEN EXISTS (SELECT 1 FROM json_each(:scanner_tools) WHERE h.low LIKE value || ' %')
           AND h.pattern_key NOT IN (SELECT value FROM json_each(:scanner_benign_patterns))
        THEN 'Reconnaissance'
      WHEN (
             h.low LIKE '/tmp/%' OR h.low LIKE '/dev/shm/%'
             OR h.low LIKE '%&& /tmp/%' OR h.low LIKE '%&&/tmp/%'
             OR h.low LIKE '%&& /dev/shm/%' OR h.low LIKE '%&&/dev/shm/%'
             OR h.low LIKE '%; /tmp/%' OR h.low LIKE '%;/tmp/%'
             OR h.low LIKE '%; /dev/shm/%' OR h.low LIKE '%;/dev/shm/%'
             OR h.low LIKE '%| /tmp/%' OR h.low LIKE '%|/tmp/%'
             OR h.low LIKE '%| /dev/shm/%' OR h.low LIKE '%|/dev/shm/%'
             OR h.low LIKE '%nohup /tmp/%' OR h.low LIKE '%nohup /dev/shm/%'
             OR h.low LIKE '%python /tmp/%' OR h.low LIKE '%python3 /tmp/%'
             OR h.low LIKE '%python /dev/shm/%' OR h.low LIKE '%python3 /dev/shm/%'
           )
           AND NOT EXISTS (SELECT 1 FROM json_each(:tmp_benign_substrings) WHERE instr(h.low, value) > 0)
        THEN 'Malware delivery'
    END AS category
  FROM hits h
  WHERE h.pattern_key IN (SELECT pattern_key FROM rare)
),
shifted AS (
  SELECT category, host, process, target,
    CASE WHEN lower(process) IN ('masscan', 'ping', 'nmap') THEN
      COALESCE((SELECT p.ts FROM host p
                WHERE p.event = 'PROC_START' AND p.host = classified.host
                  AND lower(p.process) = lower(classified.process)
                  AND p.ts <= classified.ts
                  AND (julianday(classified.ts) - julianday(p.ts)) * 1440 <= :proc_start_window_min
                ORDER BY p.ts DESC LIMIT 1), ts)
    ELSE ts END AS timestamp,
    ts AS cmd_ts
  FROM classified
  WHERE category IS NOT NULL
),
with_user AS (
  SELECT s.category, s.timestamp, s.host,
    COALESCE((SELECT l.user FROM host l
              WHERE l.event = 'LOGIN' AND l.host = s.host AND l.ts <= s.timestamp
                AND NOT EXISTS (SELECT 1 FROM host o
                                WHERE o.event = 'LOGOUT' AND o.host = s.host
                                  AND o.ts > l.ts AND o.ts <= s.timestamp)
              ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
    s.process, s.target AS evidence, s.cmd_ts
  FROM shifted s
),
dedup AS (
  SELECT *, LAG(timestamp) OVER (PARTITION BY category, host, lower(process) ORDER BY timestamp) AS prev_ts
  FROM with_user
)
SELECT category, timestamp, host, user, process, evidence, cmd_ts
FROM dedup
WHERE prev_ts IS NULL OR (julianday(timestamp) - julianday(prev_ts)) * 1440 > 10
ORDER BY timestamp
