-- name: Big uploads to rare sites
-- role: Web
-- category: Data theft
-- param: min_upload_bytes | int | 500000 | Minimum bytes sent in a single POST or PUT
-- param: max_site_hosts | int | 19 | Maximum computers observed querying the destination
-- param: max_upload_sources | int | 30 | Maximum proxy source IPs sending large uploads to the destination
-- param: nat_ips | list | 10.9.1.1,10.9.1.2,10.9.1.3,10.9.1.4 | Shared proxy source IPs requiring an active NAT mapping
WITH uploads AS MATERIALIZED (
  SELECT ts, src_ip, domain, url, method, bytes_out
  FROM proxy
  WHERE method IN ('POST', 'PUT')
    AND bytes_out >= :min_upload_bytes
),
limited_upload_sites AS (
  SELECT domain
  FROM uploads
  GROUP BY domain
  HAVING COUNT(DISTINCT src_ip) <= :max_upload_sources
),
rare_sites AS MATERIALIZED (
  SELECT h.target AS domain, COUNT(DISTINCT h.host) AS site_hosts
  FROM host h
  WHERE h.event = 'DNS_QUERY'
    AND h.target IN (SELECT domain FROM limited_upload_sites)
  GROUP BY h.target
  HAVING COUNT(DISTINCT h.host) <= :max_site_hosts
),
attributed AS (
  SELECT u.*, s.site_hosts, h.host, h.process
  FROM uploads u
  JOIN rare_sites s ON s.domain = u.domain
  JOIN host h ON h.target = u.domain AND h.ts = u.ts AND h.event = 'DNS_QUERY'
  WHERE h.process IS NOT NULL AND h.process NOT IN ('', '-')
    AND (
      (u.src_ip NOT IN (SELECT value FROM json_each(:nat_ips))
       AND h.host = (
         SELECT a.host FROM host a
         WHERE a.event = 'IP_ASSIGNED' AND a.target = u.src_ip AND a.ts <= u.ts
         ORDER BY a.ts DESC, a.rowid DESC LIMIT 1
       ))
      OR EXISTS (
        SELECT 1 FROM nat n
        WHERE n.nat_ip = u.src_ip AND n.start <= u.ts AND u.ts < n.end
          AND h.host = (
            SELECT a.host FROM host a
            WHERE a.event = 'IP_ASSIGNED' AND a.target = n.internal_ip AND a.ts <= u.ts
            ORDER BY a.ts DESC, a.rowid DESC LIMIT 1
          )
      )
    )
),
first_uploads AS (
  SELECT *, ROW_NUMBER() OVER (
    PARTITION BY host, lower(process), domain ORDER BY ts, src_ip, method, url
  ) AS first_rank
  FROM attributed
)
SELECT 'Data theft' AS category, f.ts AS timestamp, f.host,
       COALESCE((
         SELECT l.user FROM host l
         WHERE l.event = 'LOGIN' AND l.host = f.host AND l.ts <= f.ts
           AND NOT EXISTS (
             SELECT 1 FROM host o
             WHERE o.event = 'LOGOUT' AND o.host = l.host AND l.ts < o.ts AND o.ts <= f.ts
           )
         ORDER BY l.ts DESC LIMIT 1
       ), 'none') AS user,
       f.process,
       f.method || ' ' || f.domain || f.url || ' bytes_out=' || f.bytes_out
         || ' site_hosts=' || f.site_hosts || ' src_ip=' || f.src_ip AS evidence,
       f.domain, f.bytes_out, f.site_hosts
FROM first_uploads f
WHERE f.first_rank = 1
ORDER BY f.ts, f.host, f.process, f.domain
