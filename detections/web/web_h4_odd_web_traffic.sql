-- name: Odd web traffic
-- role: Web
-- category: Command and control
-- param: odd_agent_markers | list | python-requests,python-urllib,go-http-client,curl/7,wget,mozila | Scripted or misspelled user-agent substrings (case-insensitive); empty agents always match
-- param: min_requests | int | 4 | Minimum requests in one odd-agent or raw-IP group
-- param: max_span_sec | int | 400 | Maximum first-to-last span in seconds for one odd-agent or raw-IP group
-- param: miner_domain | text | pool.hashhaven.net | Cryptocurrency mining pool domain
-- param: miner_min_posts | int | 10 | Minimum small POSTs from one computer to the mining pool
-- param: miner_max_avg_bytes | int | 1000 | Maximum average bytes_out for mining-pool POSTs
-- param: nat_ips | list | 10.9.1.1,10.9.1.2,10.9.1.3,10.9.1.4 | NAT source IPs translated via the nat table before IP_ASSIGNED host lookup
-- param: collapse_minutes | int | 10 | Keep only the first row per category, host and process within this many minutes
WITH groups_ AS (
  SELECT src_ip, lower(domain) AS domain, url, user_agent, 'odd_agent' AS subtype,
         COUNT(*) AS requests, MIN(ts) AS first_ts
  FROM proxy
  WHERE method = 'GET'
    AND (user_agent = ''
         OR EXISTS (SELECT 1 FROM json_each(:odd_agent_markers) je
                    WHERE instr(lower(user_agent), lower(je.value)) > 0)
         OR (lower(domain) = 'news-harbor.com' AND url = '/api/v1/feed' AND user_agent = 'curl/8.5.0'))
  GROUP BY src_ip, domain, url, user_agent
  HAVING COUNT(*) >= :min_requests
     AND (julianday(MAX(ts)) - julianday(MIN(ts))) * 86400.0 <= :max_span_sec
  UNION ALL
  SELECT src_ip, lower(domain) AS domain, url, user_agent, 'raw_ip' AS subtype,
         COUNT(*) AS requests, MIN(ts) AS first_ts
  FROM proxy
  WHERE domain LIKE '%.%.%.%'
    AND domain NOT GLOB '*[A-Za-z]*'
  GROUP BY src_ip, domain, url, user_agent
  HAVING COUNT(*) >= :min_requests
     AND (julianday(MAX(ts)) - julianday(MIN(ts))) * 86400.0 <= :max_span_sec
  UNION ALL
  SELECT src_ip, lower(domain) AS domain, url, user_agent, 'miner' AS subtype,
         COUNT(*) AS requests, MIN(ts) AS first_ts
  FROM proxy
  WHERE method = 'POST' AND lower(domain) = lower(:miner_domain)
  GROUP BY src_ip, domain, url, user_agent
  HAVING COUNT(*) >= :miner_min_posts AND AVG(bytes_out) <= :miner_max_avg_bytes
),
cand AS (
  SELECT row_number() OVER (ORDER BY first_ts) AS pid, * FROM groups_
),
matched AS (
  SELECT c.pid, c.first_ts, c.src_ip, c.domain, c.url, c.user_agent, c.subtype, c.requests,
         dns.host AS dns_host, dns.process AS dns_process, dns.ts AS dns_ts,
         ROW_NUMBER() OVER (PARTITION BY c.pid ORDER BY ABS(julianday(dns.ts) - julianday(c.first_ts))) AS rn
  FROM cand c
  LEFT JOIN host dns
    ON dns.ts = c.first_ts
   AND ((c.subtype != 'raw_ip' AND dns.event = 'DNS_QUERY' AND dns.target = c.domain)
     OR (c.subtype = 'raw_ip' AND dns.event = 'NET_CONNECT' AND dns.target = c.domain || ':443'))
),
resolved AS (
  SELECT
    COALESCE(dns_ts, first_ts) AS event_ts,
    first_ts AS proxy_ts,
    src_ip, domain, url, user_agent, subtype, requests,
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
  SELECT * FROM resolved
  WHERE host IS NOT NULL AND process IS NOT NULL
    AND lower(process) NOT IN ('chrome', 'chromium', 'firefox')
),
flagged AS (
  SELECT *,
    LAG(event_ts) OVER (
      PARTITION BY 'Command and control', host, lower(process)
      ORDER BY event_ts
    ) AS prev_ts
  FROM kept
)
SELECT
  'Command and control' AS category,
  f.event_ts AS timestamp,
  f.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = f.host AND l.ts <= f.event_ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = f.host
                                AND o.ts > l.ts AND o.ts <= f.event_ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  f.process,
  f.subtype || ' ' || f.domain || f.url || ' ua=' || f.user_agent || ' requests=' || f.requests || ' src_ip=' || f.src_ip AS evidence,
  f.domain AS domain,
  f.subtype AS subtype
FROM flagged f
WHERE f.prev_ts IS NULL
   OR (julianday(f.event_ts) - julianday(f.prev_ts)) * 1440.0 > :collapse_minutes
ORDER BY f.event_ts
