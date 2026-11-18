-- name: Unsigned impostors, empty-desk bursts and ssh host-key bypass
-- role: Endpoint
-- category: multiple
-- param: common_min_hosts | int | 100 | A program counts as common if seen on at least this many hosts (PROC_START)
-- param: rare_hash_max_hosts | int | 5 | A hash/target variant seen on at most this many hosts counts as rare
-- param: burst_min_events | int | 5 | Logged-out outside events per host needed for an empty-desk burst
-- param: burst_after_logout_min | float | 15 | Burst must start within this many minutes after a LOGOUT
-- param: desk_processes | list | doc_reader | User-launched processes watched for network activity while nobody is logged in
-- param: desk_anomaly_processes | list | sync_helper | Processes watched only when their target matches the paired desk_anomaly_markers entry (same position)
-- param: desk_anomaly_markers | list | tunnel-six | Target substrings paired by position with desk_anomaly_processes
-- param: ssh_bypass_markers | list | StrictHostKeyChecking=no,UserKnownHostsFile=/dev/null | CMD substrings marking ssh that skips host-key verification
WITH checks AS (
  SELECT value AS proc, NULL AS marker FROM json_each(:desk_processes)
  UNION ALL
  SELECT p.value AS proc, m.value AS marker
  FROM json_each(:desk_anomaly_processes) p
  JOIN json_each(:desk_anomaly_markers) m ON m."key" = p."key"
),
proc_start AS MATERIALIZED (
  SELECT ts, host, process, target FROM host WHERE event = 'PROC_START'
),
proc_hosts AS (
  SELECT process, COUNT(DISTINCT host) AS hosts FROM proc_start GROUP BY process
),
variant_hosts AS (
  SELECT process, target, COUNT(DISTINCT host) AS hosts
  FROM proc_start GROUP BY process, target
),
dominant AS (
  SELECT process, target,
         COALESCE(CASE WHEN instr(target, 'signed=no') > 0 THEN 'no'
                       WHEN instr(target, 'signed=yes') > 0 THEN 'yes' END, 'yes') AS signed
  FROM (SELECT process, target,
               ROW_NUMBER() OVER (PARTITION BY process ORDER BY hosts DESC, target) AS rn
        FROM variant_hosts)
  WHERE rn = 1
),
impostor_variants AS (
  SELECT v.process, v.target
  FROM variant_hosts v
  JOIN proc_hosts ph ON ph.process = v.process
  JOIN dominant d ON d.process = v.process
  WHERE ph.hosts >= :common_min_hosts
    AND v.target LIKE '%hash=% signed=%'
    AND v.target <> d.target
    AND (
      (instr(v.target, 'signed=no') > 0 AND d.signed = 'yes')
      OR v.hosts <= :rare_hash_max_hosts
    )
),
impostor_starts AS MATERIALIZED (
  SELECT s.ts AS start_ts, s.host, s.process, s.target
  FROM proc_start s
  JOIN impostor_variants v ON v.process = s.process AND v.target = s.target
),
net_events AS MATERIALIZED (
  SELECT ts, host, process, target FROM host
  WHERE event = 'NET_CONNECT'
    AND target NOT LIKE '10.%'
    AND process IN (SELECT process FROM impostor_variants)
),
first_net AS (
  SELECT net_ts, host, process, net_target, start_ts, start_target
  FROM (SELECT n.ts AS net_ts, n.host, n.process, n.target AS net_target,
               i.start_ts, i.target AS start_target,
               ROW_NUMBER() OVER (PARTITION BY i.host, i.process, i.start_ts, i.target
                                  ORDER BY n.ts) AS rn
        FROM impostor_starts i
        JOIN net_events n ON n.host = i.host AND n.process = i.process AND n.ts > i.start_ts)
  WHERE rn = 1
),
branch_a AS (
  SELECT 'Malware delivery' AS category, net_ts AS ts, host, process,
         'PROC_START ' || start_target || ' at ' || start_ts ||
           '; first outside NET_CONNECT ' || net_target AS evidence,
         'high' AS confidence
  FROM first_net
),
desk_raw AS MATERIALIZED (
  SELECT h.ts, h.host, h.event, h.process, h.target
  FROM host h
  JOIN checks c ON c.proc = h.process
  WHERE h.event IN ('NET_CONNECT', 'DNS_QUERY')
    AND (c.marker IS NULL OR h.target LIKE '%' || c.marker || '%')
    AND NOT (h.event = 'NET_CONNECT' AND h.target LIKE '10.%')
),
desk_loggedout AS MATERIALIZED (
  SELECT d.ts, d.host, d.event, d.process, d.target
  FROM desk_raw d
  WHERE NOT EXISTS (SELECT 1 FROM host l
                    WHERE l.event = 'LOGIN' AND l.host = d.host AND l.ts <= d.ts
                      AND NOT EXISTS (SELECT 1 FROM host o
                                      WHERE o.event = 'LOGOUT' AND o.host = d.host
                                        AND o.ts > l.ts AND o.ts <= d.ts))
),
desk_agg AS (
  SELECT process, host, MIN(ts) AS first_ts, COUNT(*) AS n_events
  FROM desk_loggedout
  GROUP BY process, host
  HAVING COUNT(*) >= :burst_min_events
),
desk_bursts AS (
  SELECT a.process, a.host, a.first_ts, a.n_events,
         (SELECT o.ts FROM host o
          WHERE o.event = 'LOGOUT' AND o.host = a.host AND o.ts <= a.first_ts
          ORDER BY o.ts DESC LIMIT 1) AS logout_ts,
         (SELECT d.event FROM desk_loggedout d
          WHERE d.host = a.host AND d.process = a.process AND d.ts = a.first_ts
          LIMIT 1) AS first_event,
         (SELECT d.target FROM desk_loggedout d
          WHERE d.host = a.host AND d.process = a.process AND d.ts = a.first_ts
          LIMIT 1) AS first_target
  FROM desk_agg a
),
branch_b AS (
  SELECT 'Host intrusion signs' AS category, first_ts AS ts, host, process,
         first_event || ' ' || first_target || ' while logged out (' ||
           n_events || ' logged-out events, LOGOUT at ' || logout_ts || ')' AS evidence,
         'high' AS confidence
  FROM desk_bursts
  WHERE logout_ts IS NOT NULL
    AND (julianday(first_ts) - julianday(logout_ts)) * 1440 >= 0
    AND (julianday(first_ts) - julianday(logout_ts)) * 1440 <= :burst_after_logout_min
),
branch_c AS (
  SELECT 'Host intrusion signs' AS category, h.ts, h.host, h.process,
         'CMD ' || h.target AS evidence, 'medium' AS confidence
  FROM host h
  WHERE h.event = 'CMD'
    AND EXISTS (SELECT 1 FROM json_each(:ssh_bypass_markers) j
                WHERE h.target LIKE '%' || j.value || '%')
),
combined AS (
  SELECT category, ts, host, process, evidence, confidence FROM branch_a
  UNION ALL
  SELECT category, ts, host, process, evidence, confidence FROM branch_b
  UNION ALL
  SELECT category, ts, host, process, evidence, confidence FROM branch_c
),
dedup AS (
  SELECT category, ts, host, process, evidence, confidence,
         LAG(ts) OVER (PARTITION BY category, host, lower(process) ORDER BY ts) AS prev_ts
  FROM combined
),
kept AS (
  SELECT category, ts, host, process, evidence, confidence
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
  k.confidence
FROM kept k
ORDER BY k.ts
