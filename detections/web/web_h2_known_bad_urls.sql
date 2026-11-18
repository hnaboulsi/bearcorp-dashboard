-- name: Known-bad URLs
-- role: Web
-- category: Known-bad indicators
-- param: known_bad_urls | list | http://news-harbor.com/wp-content/uploads/2026/10/invoice.doc?token=7f3a9c,http://docs.paperstack.io/shared/x.php?id=90210,http://shop.quickmart.com/checkout/x.php?debug=1 | Full URLs (http:// + domain + path) listed as known-bad in the iocs table; the sites themselves are normal, only these pages are bad
-- param: nat_ips | list | 10.9.1.1,10.9.1.2,10.9.1.3,10.9.1.4 | NAT source IPs translated via the nat table before IP_ASSIGNED host lookup
-- param: collapse_minutes | int | 10 | Keep only the first row per category, host and process within this many minutes
WITH cand AS MATERIALIZED (
  SELECT rowid AS pid, ts, src_ip, lower(domain) AS domain, url
  FROM proxy
  WHERE lower(domain) IN (
          SELECT lower(substr(value, 8, instr(substr(value, 8), '/') - 1))
          FROM json_each(:known_bad_urls))
    AND ('http://' || lower(domain) || url) IN (SELECT lower(value) FROM json_each(:known_bad_urls))
),
matched AS (
  SELECT c.pid, c.ts, c.src_ip, c.domain, c.url,
         dns.host AS dns_host, dns.process AS dns_process, dns.ts AS dns_ts,
         ROW_NUMBER() OVER (
           PARTITION BY c.pid
           ORDER BY ABS(julianday(dns.ts) - julianday(c.ts))
         ) AS rn
  FROM cand c
  LEFT JOIN host dns
    ON dns.event = 'DNS_QUERY'
   AND dns.target = c.domain
   AND dns.ts = c.ts
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
kept AS (
  SELECT * FROM resolved WHERE host IS NOT NULL
),
flagged AS (
  SELECT *,
    LAG(event_ts) OVER (
      PARTITION BY 'Known-bad indicators', host, lower(process)
      ORDER BY event_ts
    ) AS prev_ts
  FROM kept
)
SELECT
  'Known-bad indicators' AS category,
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
