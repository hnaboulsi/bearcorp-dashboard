-- name: Rotating check-ins
-- role: Web
-- category: Command and control
-- param: min_hosts | int | 5 | Minimum computers taking turns checking in to the same site
-- param: max_hosts | int | 30 | Maximum computers taking turns checking in to the same site
-- param: min_requests_per_host | int | 3 | Minimum check-ins in one computer's single burst
-- param: max_requests_per_host | int | 10 | Maximum check-ins per computer, so each computer looks quiet on its own
-- param: max_burst_span_minutes | float | 30 | Maximum minutes from a computer's first to last check-in (one short burst per computer)
-- param: max_request_bytes | int | 5000 | Maximum outbound bytes per check-in (small request)
-- param: max_response_bytes | int | 1000 | Maximum inbound bytes per check-in (small fixed reply)
-- param: min_turn_gap_minutes | float | 30 | Minimum minutes between successive computers' first check-ins to count as taking a turn
-- param: max_turn_gap_minutes | float | 180 | Maximum minutes between successive computers' first check-ins to count as taking a turn (about an hour apart)
-- param: min_turn_gaps | int | 3 | Minimum successive computer pairs about an hour apart for the site to count as rotating
-- param: nat_ips | list | 10.9.1.1,10.9.1.2,10.9.1.3,10.9.1.4 | NAT source IPs translated via the nat table before IP_ASSIGNED host lookup
-- param: collapse_minutes | int | 10 | Keep only the first row per category, host and process within this many minutes
WITH bursts AS (
  SELECT lower(domain) AS domain, url, method, src_ip,
         MIN(ts) AS first_ts, MAX(ts) AS last_ts, COUNT(*) AS requests,
         MIN(bytes_out) AS min_request_bytes, MAX(bytes_out) AS max_request_bytes,
         (julianday(MAX(ts)) - julianday(MIN(ts))) * 1440.0 AS burst_span_minutes
  FROM proxy
  WHERE bytes_out BETWEEN 1 AND :max_request_bytes
    AND bytes_in BETWEEN 1 AND :max_response_bytes
  GROUP BY lower(domain), url, method, src_ip
  HAVING COUNT(*) BETWEEN :min_requests_per_host AND :max_requests_per_host
     AND (julianday(MAX(ts)) - julianday(MIN(ts))) * 1440.0 <= :max_burst_span_minutes
),
host_firsts AS (
  SELECT b.*,
         (julianday(b.first_ts) - julianday(LAG(b.first_ts) OVER (
           PARTITION BY b.domain, b.url, b.method ORDER BY b.first_ts, b.src_ip
         ))) * 1440.0 AS turn_gap_minutes
  FROM bursts b
),
rotating AS (
  SELECT domain, url, method,
         COUNT(*) AS hosts, SUM(requests) AS requests,
         COUNT(*) FILTER (
           WHERE turn_gap_minutes BETWEEN :min_turn_gap_minutes AND :max_turn_gap_minutes
         ) AS turn_gaps
  FROM host_firsts
  GROUP BY domain, url, method
  HAVING COUNT(*) BETWEEN :min_hosts AND :max_hosts
     AND COUNT(*) FILTER (
           WHERE turn_gap_minutes BETWEEN :min_turn_gap_minutes AND :max_turn_gap_minutes
         ) >= :min_turn_gaps
),
cand AS (
  SELECT h.domain, h.url, h.method, h.src_ip, h.first_ts, h.last_ts, h.requests,
         h.min_request_bytes, h.max_request_bytes, h.burst_span_minutes,
         r.hosts AS rotation_hosts, r.turn_gaps
  FROM host_firsts h
  JOIN rotating r ON r.domain = h.domain AND r.url = h.url AND r.method = h.method
),
attributed AS (
  SELECT c.*, dns.host, dns.process
  FROM cand c
  JOIN host dns ON dns.target = c.domain AND dns.ts = c.first_ts AND dns.event = 'DNS_QUERY'
  WHERE dns.process IS NOT NULL AND dns.process NOT IN ('', '-')
    AND (
      (c.src_ip NOT IN (SELECT value FROM json_each(:nat_ips))
       AND dns.host = (
         SELECT a.host FROM host a
         WHERE a.event = 'IP_ASSIGNED' AND a.target = c.src_ip AND a.ts <= c.first_ts
         ORDER BY a.ts DESC, a.rowid DESC LIMIT 1
       ))
      OR EXISTS (
        SELECT 1 FROM nat n
        WHERE n.nat_ip = c.src_ip AND n.start <= c.first_ts AND c.first_ts < n.end
          AND dns.host = (
            SELECT a.host FROM host a
            WHERE a.event = 'IP_ASSIGNED' AND a.target = n.internal_ip AND a.ts <= c.first_ts
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
),
kept AS (
  SELECT * FROM ranked WHERE first_rank = 1
),
flagged AS (
  SELECT *,
    LAG(first_ts) OVER (
      PARTITION BY 'Command and control', host, lower(process)
      ORDER BY first_ts
    ) AS prev_ts
  FROM kept
)
SELECT
  'Command and control' AS category,
  f.first_ts AS timestamp,
  f.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = f.host AND l.ts <= f.first_ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = f.host
                                AND o.ts > l.ts AND o.ts <= f.first_ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  f.process,
  f.method || ' ' || f.domain || f.url || ' requests=' || f.requests
    || ' burst_span_min=' || ROUND(f.burst_span_minutes, 1)
    || ' hosts_in_rotation=' || f.rotation_hosts
    || ' turn_gaps_about_1h=' || f.turn_gaps
    || ' bytes_out=' || f.min_request_bytes || '-' || f.max_request_bytes
    || ' src_ip=' || f.src_ip AS evidence,
  'high' AS confidence,
  f.domain AS domain,
  f.requests AS requests,
  f.rotation_hosts AS hosts_in_rotation,
  f.turn_gaps AS turn_gaps
FROM flagged f
WHERE f.prev_ts IS NULL
   OR (julianday(f.first_ts) - julianday(f.prev_ts)) * 1440.0 > :collapse_minutes
ORDER BY f.first_ts
