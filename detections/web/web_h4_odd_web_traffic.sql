-- name: Odd web traffic
-- role: Web
-- category: Command and control
-- param: odd_agent_markers | list | python-requests,python-urllib,go-http-client,curl/7,wget,mozila | Scripted or misspelled user-agent substrings (case-insensitive); empty agents always match
-- param: min_requests | int | 4 | Minimum requests in one odd-agent or raw-IP group
-- param: max_span_sec | int | 400 | Maximum first-to-last span in seconds for one odd-agent or raw-IP group
-- param: miner_domain | text | pool.hashhaven.net | Cryptocurrency mining pool domain
-- param: miner_min_posts | int | 10 | Minimum small POSTs from one computer to the mining pool
-- param: miner_max_avg_bytes | int | 1000 | Maximum average bytes_out for mining-pool POSTs
-- param: nat_ips | list | 10.9.1.1,10.9.1.2,10.9.1.3,10.9.1.4 | Shared proxy source IPs requiring an active NAT mapping
-- param: collapse_minutes | int | 10 | Keep only the first row per category, host and process within this many minutes
WITH odd_agent_domains AS MATERIALIZED (
  SELECT DISTINCT target
  FROM host
  WHERE event = 'DNS_QUERY' AND lower(process) NOT IN ('chrome', 'chromium', 'firefox', '', '-')
),
tagged AS (
  SELECT p.ts, p.src_ip, lower(p.domain) AS domain, p.url, COALESCE(p.user_agent, '') AS user_agent,
         p.bytes_out, CASE
           WHEN p.method = 'POST' AND p.domain = :miner_domain COLLATE NOCASE THEN 'miner'
           WHEN p.domain GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
             AND p.domain NOT GLOB '*[^0-9.]*'
             AND length(p.domain) - length(replace(p.domain, '.', '')) = 3 THEN 'raw_ip'
           WHEN p.method = 'GET' AND lower(p.domain) IN (SELECT target FROM odd_agent_domains)
             AND (COALESCE(p.user_agent, '') = ''
               OR EXISTS (
                 SELECT 1 FROM json_each(:odd_agent_markers)
                 WHERE instr(lower(p.user_agent), lower(value)) > 0
               )
               OR (p.domain = 'news-harbor.com' AND p.url = '/api/v1/feed'
                   AND p.user_agent = 'curl/8.5.0')) THEN 'odd_agent'
         END AS subtype
  FROM proxy p
),
groups_ AS MATERIALIZED (
  SELECT src_ip, domain, url, user_agent, subtype, COUNT(*) AS requests, MIN(ts) AS event_ts
  FROM tagged
  WHERE subtype IS NOT NULL
  GROUP BY src_ip, domain, url, user_agent, subtype
  HAVING CASE subtype
    WHEN 'miner' THEN COUNT(*) >= :miner_min_posts AND AVG(bytes_out) <= :miner_max_avg_bytes
    ELSE COUNT(*) >= :min_requests
      AND ROUND((julianday(MAX(ts)) - julianday(MIN(ts))) * 86400.0, 3) <= :max_span_sec
  END
),
kept AS (
  SELECT g.*, h.host, h.process
  FROM groups_ g
  JOIN host h
    ON h.target = CASE g.subtype WHEN 'raw_ip' THEN g.domain || ':443' ELSE g.domain END
   AND h.event = CASE g.subtype WHEN 'raw_ip' THEN 'NET_CONNECT' ELSE 'DNS_QUERY' END
   AND h.ts = g.event_ts
  WHERE lower(h.process) NOT IN ('chrome', 'chromium', 'firefox', '', '-')
    AND (
      (g.src_ip NOT IN (SELECT value FROM json_each(:nat_ips))
       AND h.host = (
         SELECT a.host FROM host a
         WHERE a.event = 'IP_ASSIGNED' AND a.target = g.src_ip AND a.ts <= g.event_ts
         ORDER BY a.ts DESC, a.rowid DESC LIMIT 1
       ))
      OR EXISTS (
        SELECT 1 FROM nat n
        WHERE n.nat_ip = g.src_ip AND n.start <= g.event_ts AND g.event_ts < n.end
          AND h.host = (
            SELECT a.host FROM host a
            WHERE a.event = 'IP_ASSIGNED' AND a.target = n.internal_ip AND a.ts <= g.event_ts
            ORDER BY a.ts DESC, a.rowid DESC LIMIT 1
          )
      )
    )
),
flagged AS (
  SELECT *,
    LAG(event_ts) OVER (
      PARTITION BY host, lower(process)
      ORDER BY event_ts, domain, url, subtype
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
