-- name: Risky downloads / malware delivery
-- role: Endpoint
-- category: Malware delivery
-- param: extensions | list | .exe,.dll,.scr,.hta | Dangerous download file extensions matched at the end of the URL path (query stripped)
-- param: trusted_domains | list | updates.nexusos.com,telemetry.nexusos.com,license.nexusos.com,inventory.nexusos.com,staging-downloads.nexusos.com | Normal software/update infrastructure domains, never flagged
-- param: lookalike_domains | list | updates.nexusos-patch.com | Look-alike update domains, always candidates regardless of extension or rarity
-- param: max_distinct_ips | int | 20 | Rarity gate: drop non-look-alike domains seen from more than this many distinct source IPs
-- param: dns_window_min | int | 10 | Window in minutes to match a host DNS_QUERY to a proxy row
-- param: nat_ips | list | 10.9.1.1,10.9.1.2,10.9.1.3,10.9.1.4 | NAT source IPs translated via the nat table before IP_ASSIGNED host lookup
-- param: collapse_minutes | int | 10 | Keep only the first row per category, host and process within this many minutes
WITH cand AS MATERIALIZED (
  SELECT rowid AS pid, ts, src_ip, lower(domain) AS domain, url,
    substr(url, 1, CASE WHEN instr(url, '?') > 0 THEN instr(url, '?') - 1 ELSE length(url) END) AS path
  FROM proxy
  WHERE lower(domain) IN (SELECT lower(value) FROM json_each(:lookalike_domains))
     OR EXISTS (SELECT 1 FROM json_each(:extensions) je
                WHERE proxy.url LIKE '%' || je.value || '%')
),
filtered AS MATERIALIZED (
  SELECT * FROM cand
  WHERE domain IN (SELECT lower(value) FROM json_each(:lookalike_domains))
     OR (
       domain NOT IN (SELECT lower(value) FROM json_each(:trusted_domains))
       AND EXISTS (SELECT 1 FROM json_each(:extensions) je
                   WHERE cand.path LIKE '%' || je.value)
     )
),
rare AS (
  SELECT domain FROM filtered
  WHERE domain NOT IN (SELECT lower(value) FROM json_each(:lookalike_domains))
  GROUP BY domain
  HAVING COUNT(DISTINCT src_ip) <= :max_distinct_ips
),
kept_cand AS MATERIALIZED (
  SELECT * FROM filtered
  WHERE domain IN (SELECT lower(value) FROM json_each(:lookalike_domains))
     OR domain IN (SELECT domain FROM rare)
),
matched AS (
  SELECT c.pid, c.ts, c.src_ip, c.domain, c.url,
         dns.host AS dns_host, dns.process AS dns_process, dns.ts AS dns_ts,
         ROW_NUMBER() OVER (
           PARTITION BY c.pid
           ORDER BY ABS(julianday(dns.ts) - julianday(c.ts))
         ) AS rn
  FROM kept_cand c
  LEFT JOIN host dns
    ON dns.event = 'DNS_QUERY'
   AND dns.target = c.domain
   AND ABS(julianday(dns.ts) - julianday(c.ts)) * 1440.0 <= :dns_window_min
),
resolved AS (
  SELECT
    COALESCE(dns_ts, ts) AS event_ts,
    ts AS proxy_ts,
    src_ip, domain, url,
    COALESCE(dns_host, (
      SELECT h.host FROM host h
      WHERE h.event = 'IP_ASSIGNED'
        AND h.target = COALESCE((
              SELECT n.internal_ip FROM nat n
              WHERE n.nat_ip = matched.src_ip
                AND matched.src_ip IN (SELECT value FROM json_each(:nat_ips))
                AND n.start <= matched.ts AND n.end > matched.ts
              ORDER BY n.start DESC LIMIT 1), matched.src_ip)
        AND h.ts <= matched.ts
      ORDER BY h.ts DESC LIMIT 1)) AS host,
    COALESCE(dns_process, 'chrome') AS process
  FROM matched
  WHERE rn = 1
),
actions AS (
  SELECT *,
         ROW_NUMBER() OVER (PARTITION BY host, domain ORDER BY proxy_ts) AS rn2
  FROM resolved
  WHERE host IS NOT NULL
),
first_action AS (
  SELECT * FROM actions WHERE rn2 = 1
),
flagged AS (
  SELECT *,
    LAG(event_ts) OVER (
      PARTITION BY 'Malware delivery', host, lower(process)
      ORDER BY event_ts
    ) AS prev_ts
  FROM first_action
)
SELECT
  'Malware delivery' AS category,
  f.event_ts AS timestamp,
  f.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = f.host AND l.ts <= f.event_ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = f.host
                                AND o.ts > l.ts AND o.ts <= f.event_ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  f.process,
  f.domain || f.url || ' src_ip=' || f.src_ip AS evidence,
  f.domain AS domain
FROM flagged f
WHERE f.prev_ts IS NULL
   OR (julianday(f.event_ts) - julianday(f.prev_ts)) * 1440.0 > :collapse_minutes
ORDER BY f.event_ts
