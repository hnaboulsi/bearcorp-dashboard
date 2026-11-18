-- name: Regular check-ins
-- role: Web
-- category: Command and control
-- param: check_in_paths | list | /api/v2/check,/sync,/beacon | Short proxy paths used by the observed check-in requests
-- param: max_request_bytes | int | 1000 | Maximum outbound bytes per check-in
-- param: max_response_bytes | int | 2000 | Maximum inbound bytes per check-in
-- param: min_interval_seconds | int | 120 | Minimum expected time between check-ins
-- param: max_interval_seconds | int | 2200 | Maximum active interval; longer gaps allow overnight or work-hours schedules
-- param: min_intervals | int | 39 | Minimum number of intervals in the expected range
-- param: min_active_fraction | float | 0.85 | Minimum fraction of active intervals at or above the minimum interval
-- param: max_relative_jitter | float | 0.35 | Maximum standard deviation divided by mean interval
-- param: nat_ips | list | 10.9.1.1,10.9.1.2,10.9.1.3,10.9.1.4 | Shared proxy source IPs requiring an active NAT mapping
WITH observations AS (
  SELECT ts, src_ip, domain, url, bytes_out, bytes_in,
         (julianday(ts) - LAG(julianday(ts)) OVER (
           PARTITION BY src_ip, domain, url ORDER BY ts
         )) * 86400 AS gap_seconds
  FROM proxy
  WHERE method = 'POST'
    AND url IN (SELECT value FROM json_each(:check_in_paths) WHERE length(value) <= 100)
    AND bytes_out BETWEEN 1 AND :max_request_bytes
    AND bytes_in BETWEEN 1 AND :max_response_bytes
),
intervals AS (
  SELECT *, CASE WHEN gap_seconds BETWEEN :min_interval_seconds AND :max_interval_seconds
                 THEN gap_seconds END AS cadence_gap
  FROM observations
),
streams AS (
  SELECT src_ip, domain, url, MIN(ts) AS first_ts, MAX(ts) AS last_ts,
         COUNT(*) AS requests, COUNT(DISTINCT date(ts)) AS active_days,
         MIN(bytes_out) AS min_request_bytes, MAX(bytes_out) AS max_request_bytes,
         COUNT(*) FILTER (WHERE gap_seconds <= :max_interval_seconds) AS active_intervals,
         COUNT(cadence_gap) AS cadence_intervals,
         AVG(cadence_gap) AS mean_gap,
         AVG(cadence_gap * cadence_gap) AS mean_squared_gap
  FROM intervals
  GROUP BY src_ip, domain, url
),
periodic AS MATERIALIZED (
  SELECT *
  FROM streams
  WHERE cadence_intervals >= :min_intervals
    AND cadence_intervals >= active_intervals * :min_active_fraction
    AND mean_squared_gap - mean_gap * mean_gap <=
        :max_relative_jitter * :max_relative_jitter * mean_gap * mean_gap
),
attributed AS (
  SELECT p.*, h.host, h.process
  FROM periodic p
  JOIN host h ON h.target = p.domain AND h.ts = p.first_ts AND h.event = 'DNS_QUERY'
  WHERE h.process IS NOT NULL AND h.process NOT IN ('', '-')
    AND (
      (p.src_ip NOT IN (SELECT value FROM json_each(:nat_ips))
       AND h.host = (
         SELECT a.host FROM host a
         WHERE a.event = 'IP_ASSIGNED' AND a.target = p.src_ip AND a.ts <= p.first_ts
         ORDER BY a.ts DESC, a.rowid DESC LIMIT 1
       ))
      OR EXISTS (
        SELECT 1 FROM nat n
        WHERE n.nat_ip = p.src_ip AND n.start <= p.first_ts AND p.first_ts < n.end
          AND h.host = (
            SELECT a.host FROM host a
            WHERE a.event = 'IP_ASSIGNED' AND a.target = n.internal_ip AND a.ts <= p.first_ts
            ORDER BY a.ts DESC, a.rowid DESC LIMIT 1
          )
      )
    )
),
ranked AS (
  SELECT *, ROW_NUMBER() OVER (
    PARTITION BY host, lower(process), domain, url ORDER BY first_ts, src_ip
  ) AS first_rank
  FROM attributed
)
SELECT 'Command and control' AS category, r.first_ts AS timestamp, r.host,
       COALESCE((
         SELECT l.user FROM host l
         WHERE l.event = 'LOGIN' AND l.host = r.host AND l.ts <= r.first_ts
           AND NOT EXISTS (
             SELECT 1 FROM host o
             WHERE o.event = 'LOGOUT' AND o.host = l.host AND l.ts < o.ts AND o.ts <= r.first_ts
           )
         ORDER BY l.ts DESC LIMIT 1
       ), 'none') AS user,
       r.process,
       'POST ' || r.domain || r.url || ' requests=' || r.requests
         || ' average_active_interval_sec=' || ROUND(r.mean_gap, 1)
         || ' bytes_out=' || r.min_request_bytes || '-' || r.max_request_bytes
         || ' src_ip=' || r.src_ip AS evidence,
       r.domain, r.requests, r.cadence_intervals, ROUND(r.mean_gap, 1) AS mean_interval_seconds,
       r.active_days, r.last_ts AS last_request
FROM ranked r
WHERE r.first_rank = 1
ORDER BY r.first_ts, r.host, r.process, r.domain
