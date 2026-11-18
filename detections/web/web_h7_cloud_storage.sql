-- name: Hiding in a popular cloud storage site
-- role: Web
-- category: multiple
-- param: storage_domain | text | vaultdrive.com | Popular cloud storage domain everyone uses; attacker traffic hides inside its normal proxy traffic
-- param: status_path | text | /drive/status | Status-check path polled hours apart (Command and control)
-- param: status_min_requests | int | 4 | Minimum status checks from one source IP
-- param: status_min_span_hours | int | 12 | Minimum first-to-last span in hours for status checks (they recur hours apart)
-- param: drop_prefix | text | /drive/shared/drop/ | Shared-drop path prefix for small hourly GET plus PUT file trades (Command and control)
-- param: drop_min_pairs | int | 10 | Minimum GET and PUT counts each from one source IP to the drop prefix
-- param: drop_min_span_hours | int | 24 | Minimum first-to-last span in hours for drop trades (they recur about hourly)
-- param: upload_prefix | text | /upload/chunk | Chunked-upload path prefix for one user uploading far more than usual (Data theft)
-- param: upload_min_chunks | int | 20 | Minimum uploaded chunks from one source IP
-- param: upload_min_total_mb | int | 500 | Minimum total uploaded megabytes from one source IP
-- param: upload_max_span_hours | int | 6 | Maximum first-to-last span in hours for chunk uploads (one burst, unlike normal photo uploads spread over days)
-- param: nat_ips | list | 10.9.1.1,10.9.1.2,10.9.1.3,10.9.1.4 | NAT source IPs translated via the nat table before IP_ASSIGNED host lookup
-- param: collapse_minutes | int | 10 | Keep only the first row per category, host and process within this many minutes
WITH per_ip AS (
  SELECT src_ip,
    SUM(CASE WHEN method = 'GET' AND url LIKE (:status_path || '%') THEN 1 ELSE 0 END) AS status_n,
    MIN(CASE WHEN method = 'GET' AND url LIKE (:status_path || '%') THEN ts END) AS status_first,
    MAX(CASE WHEN method = 'GET' AND url LIKE (:status_path || '%') THEN ts END) AS status_last,
    SUM(CASE WHEN url LIKE (:drop_prefix || '%') AND method = 'GET' THEN 1 ELSE 0 END) AS drop_gets,
    SUM(CASE WHEN url LIKE (:drop_prefix || '%') AND method = 'PUT' THEN 1 ELSE 0 END) AS drop_puts,
    MIN(CASE WHEN url LIKE (:drop_prefix || '%') THEN ts END) AS drop_first,
    MAX(CASE WHEN url LIKE (:drop_prefix || '%') THEN ts END) AS drop_last,
    SUM(CASE WHEN method IN ('PUT', 'POST') AND url LIKE (:upload_prefix || '%') THEN 1 ELSE 0 END) AS chunk_n,
    MIN(CASE WHEN method IN ('PUT', 'POST') AND url LIKE (:upload_prefix || '%') THEN ts END) AS chunk_first,
    MAX(CASE WHEN method IN ('PUT', 'POST') AND url LIKE (:upload_prefix || '%') THEN ts END) AS chunk_last,
    SUM(CASE WHEN method IN ('PUT', 'POST') AND url LIKE (:upload_prefix || '%') THEN bytes_out ELSE 0 END) AS chunk_bytes
  FROM proxy
  WHERE lower(domain) = lower(:storage_domain)
    AND (url LIKE (:status_path || '%')
         OR url LIKE (:drop_prefix || '%')
         OR (method IN ('PUT', 'POST') AND url LIKE (:upload_prefix || '%')))
  GROUP BY src_ip
),
cand AS (
  SELECT row_number() OVER (ORDER BY first_ts) AS pid, * FROM (
    SELECT 'Command and control' AS category, 'status_check' AS subtype,
           src_ip, status_first AS first_ts, status_n AS requests, 0 AS total_out,
           lower(:storage_domain) AS domain
    FROM per_ip
    WHERE status_n >= :status_min_requests
      AND (julianday(status_last) - julianday(status_first)) * 24.0 >= :status_min_span_hours
    UNION ALL
    SELECT 'Command and control' AS category, 'hourly_trade' AS subtype,
           src_ip, drop_first AS first_ts, drop_gets AS requests, 0 AS total_out,
           lower(:storage_domain) AS domain
    FROM per_ip
    WHERE drop_gets >= :drop_min_pairs
      AND drop_puts >= :drop_min_pairs
      AND (julianday(drop_last) - julianday(drop_first)) * 24.0 >= :drop_min_span_hours
    UNION ALL
    SELECT 'Data theft' AS category, 'big_upload' AS subtype,
           src_ip, chunk_first AS first_ts, chunk_n AS requests, chunk_bytes AS total_out,
           lower(:storage_domain) AS domain
    FROM per_ip
    WHERE chunk_n >= :upload_min_chunks
      AND chunk_bytes >= :upload_min_total_mb * 1000000
      AND (julianday(chunk_last) - julianday(chunk_first)) * 24.0 <= :upload_max_span_hours
  )
),
matched AS (
  SELECT c.pid, c.category, c.subtype, c.src_ip, c.first_ts, c.requests, c.total_out, c.domain,
         dns.host AS dns_host, dns.process AS dns_process, dns.ts AS dns_ts,
         ROW_NUMBER() OVER (
           PARTITION BY c.pid
           ORDER BY ABS(julianday(dns.ts) - julianday(c.first_ts))
         ) AS rn
  FROM cand c
  LEFT JOIN host dns
    ON dns.event = 'DNS_QUERY'
   AND dns.target = c.domain
   AND dns.ts = c.first_ts
),
resolved AS (
  SELECT
    category, subtype,
    COALESCE(dns_ts, first_ts) AS event_ts,
    first_ts AS proxy_ts,
    src_ip, domain, requests, total_out,
    COALESCE(dns_host, (
      SELECT h.host FROM host h
      WHERE h.event = 'IP_ASSIGNED'
        AND h.target = COALESCE((
              SELECT n.internal_ip FROM nat n
              WHERE n.nat_ip = matched.src_ip
                AND matched.src_ip IN (SELECT value FROM json_each(:nat_ips))
                AND n.start <= matched.first_ts AND n.end > matched.first_ts
              ORDER BY n.start DESC LIMIT 1), matched.src_ip)
        AND h.ts <= matched.first_ts
      ORDER BY h.ts DESC LIMIT 1)) AS host,
    dns_process AS process
  FROM matched
  WHERE rn = 1
),
kept AS (
  SELECT r.category, r.subtype, r.event_ts, r.proxy_ts, r.src_ip, r.domain,
         r.requests, r.total_out, r.host,
         COALESCE(r.process, (
           SELECT h.process FROM host h
           WHERE h.event = 'DNS_QUERY' AND h.target = r.domain
             AND h.host = r.host AND h.ts <= r.event_ts
           ORDER BY h.ts DESC LIMIT 1)) AS process
  FROM resolved r
  WHERE r.host IS NOT NULL
),
ranked AS (
  SELECT *,
    ROW_NUMBER() OVER (
      PARTITION BY category, host, lower(process)
      ORDER BY event_ts
    ) AS host_rank
  FROM kept
  WHERE process IS NOT NULL
),
first_per_host AS (
  SELECT * FROM ranked WHERE host_rank = 1
),
flagged AS (
  SELECT *,
    LAG(event_ts) OVER (
      PARTITION BY category, host, lower(process)
      ORDER BY event_ts
    ) AS prev_ts
  FROM first_per_host
)
SELECT
  f.category,
  f.event_ts AS timestamp,
  f.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = f.host AND l.ts <= f.event_ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = f.host
                                AND o.ts > l.ts AND o.ts <= f.event_ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  f.process,
  f.domain || ' ' || f.subtype || ' requests=' || f.requests
    || CASE WHEN f.total_out > 0 THEN ' bytes_out=' || f.total_out ELSE '' END
    || ' src_ip=' || f.src_ip AS evidence,
  f.domain AS domain,
  f.subtype AS subtype,
  f.requests AS requests
FROM flagged f
WHERE f.prev_ts IS NULL
   OR (julianday(f.event_ts) - julianday(f.prev_ts)) * 1440.0 > :collapse_minutes
ORDER BY f.event_ts
