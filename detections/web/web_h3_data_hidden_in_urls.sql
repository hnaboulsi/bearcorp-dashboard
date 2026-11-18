-- name: Data hidden in web addresses
-- role: Web
-- category: Data theft
-- param: min_query_len | int | 100 | Minimum length of the scrambled text after the ? in the url
-- param: min_requests | int | 10 | Minimum repeated long-url requests from one computer to one site
-- param: nat_ips | list | 10.9.1.1,10.9.1.2,10.9.1.3,10.9.1.4 | NAT source IPs translated via the nat table before IP_ASSIGNED host lookup
-- param: collapse_minutes | int | 10 | Keep only the first row per category, host and process within this many minutes
WITH groups_ AS (
  SELECT src_ip, lower(domain) AS domain,
         substr(url, 1, instr(url, '?') - 1) AS path,
         MIN(ts) AS first_ts, COUNT(*) AS requests,
         COUNT(DISTINCT url) AS distinct_urls,
         MAX(length(substr(url, instr(url, '?') + 1))) AS max_query_len
  FROM proxy
  WHERE instr(url, '?') > 0
    AND length(substr(url, instr(url, '?') + 1)) >= :min_query_len
  GROUP BY src_ip, domain, path
  HAVING COUNT(*) >= :min_requests
     AND COUNT(DISTINCT url) >= :min_requests
),
cand AS (
  SELECT row_number() OVER (ORDER BY first_ts) AS pid, * FROM groups_
),
matched AS (
  SELECT c.pid, c.first_ts, c.src_ip, c.domain, c.path, c.requests, c.max_query_len,
         dns.host AS dns_host, dns.process AS dns_process, dns.ts AS dns_ts,
         ROW_NUMBER() OVER (PARTITION BY c.pid ORDER BY ABS(julianday(dns.ts) - julianday(c.first_ts))) AS rn
  FROM cand c
  LEFT JOIN host dns
    ON dns.event = 'DNS_QUERY'
   AND dns.target = c.domain
   AND dns.ts = c.first_ts
),
resolved AS (
  SELECT
    COALESCE(dns_ts, first_ts) AS event_ts,
    first_ts AS proxy_ts,
    src_ip, domain, path, requests, max_query_len,
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
  SELECT * FROM resolved WHERE host IS NOT NULL AND process IS NOT NULL
),
flagged AS (
  SELECT *,
    LAG(event_ts) OVER (
      PARTITION BY 'Data theft', host, lower(process)
      ORDER BY event_ts
    ) AS prev_ts
  FROM kept
)
SELECT
  'Data theft' AS category,
  f.event_ts AS timestamp,
  f.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = f.host AND l.ts <= f.event_ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = f.host
                                AND o.ts > l.ts AND o.ts <= f.event_ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  f.process,
  f.domain || f.path || '?<long-scrambled> requests=' || f.requests || ' max_query_len=' || f.max_query_len || ' src_ip=' || f.src_ip AS evidence,
  f.domain AS domain,
  f.requests AS requests
FROM flagged f
WHERE f.prev_ts IS NULL
   OR (julianday(f.event_ts) - julianday(f.prev_ts)) * 1440.0 > :collapse_minutes
ORDER BY f.event_ts
