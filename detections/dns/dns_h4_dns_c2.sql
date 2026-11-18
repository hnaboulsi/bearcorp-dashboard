-- name: DNS C2 (long queries, repeated TXT, long answers)
-- role: DNS
-- category: Command and control
-- param: min_query_len | int | 60 | Minimum A query length for the tunnel signal
-- param: min_unique | int | 10 | Minimum distinct long names per source and domain
-- param: min_txt_repeats | int | 20 | Minimum repeats of one TXT name from one source
-- param: min_answer_len | int | 300 | Minimum answer length in characters
-- param: excluded_domains | list | threatstop.net, shieldops.net, vaultcdn.net | Domains that are known-good lookup services
WITH named AS MATERIALIZED (
  SELECT ts, src_ip, query, qtype, answer,
         replace(query, rtrim(query, replace(query, '.', '')), '') AS tld,
         substr(query, 1, length(query) - length(replace(query, rtrim(query, replace(query, '.', '')), '')) - 1) AS rest
  FROM dns
  WHERE (qtype = 'A' AND length(query) >= :min_query_len)
     OR qtype = 'TXT'
     OR length(answer) >= :min_answer_len
),
d AS MATERIALIZED (
  SELECT ts, src_ip, query, qtype, answer,
         replace(rest, rtrim(rest, replace(rest, '.', '')), '') || '.' || tld AS domain
  FROM named
),
long_a AS (
  SELECT src_ip, domain, COUNT(DISTINCT query) AS n
  FROM d
  WHERE qtype = 'A' AND length(query) >= :min_query_len
    AND domain NOT IN (SELECT value FROM json_each(:excluded_domains))
  GROUP BY src_ip, domain
  HAVING COUNT(DISTINCT query) >= :min_unique
),
sig_a AS (
  SELECT h.host, h.process, MIN(h.ts) AS ts,
         'Long A queries under ' || f.domain || ': ' || MAX(f.n) || ' distinct from ' || f.src_ip AS evidence
  FROM d
  JOIN long_a f ON f.src_ip = d.src_ip AND f.domain = d.domain
  JOIN host h ON h.target = d.query AND h.ts = d.ts AND h.event = 'DNS_QUERY'
  WHERE d.qtype = 'A' AND length(d.query) >= :min_query_len
  GROUP BY h.host, h.process, f.domain
),
txt_rep AS (
  SELECT src_ip, query, COUNT(*) AS n
  FROM d
  WHERE qtype = 'TXT'
  GROUP BY src_ip, query
  HAVING COUNT(*) >= :min_txt_repeats
    AND SUM(CASE WHEN answer LIKE 'v=spf1%' OR answer LIKE 'v=DKIM1%' THEN 1 ELSE 0 END) = 0
),
sig_b AS (
  SELECT h.host, h.process, MIN(h.ts) AS ts,
         'Repeated TXT ' || f.query || ': ' || MAX(f.n) || ' lookups from ' || f.src_ip AS evidence
  FROM d
  JOIN txt_rep f ON f.src_ip = d.src_ip AND f.query = d.query
  JOIN host h ON h.target = d.query AND h.ts = d.ts AND h.event = 'DNS_QUERY'
  WHERE d.qtype = 'TXT'
  GROUP BY h.host, h.process, f.query
),
sig_c AS (
  SELECT h.host, h.process, MIN(h.ts) AS ts,
         'Long answers (' || MAX(length(d.answer)) || ' chars) under ' || d.domain AS evidence
  FROM d
  JOIN host h ON h.target = d.query AND h.ts = d.ts AND h.event = 'DNS_QUERY'
  WHERE length(d.answer) >= :min_answer_len
    AND d.answer NOT LIKE 'v=spf1%'
    AND d.answer NOT LIKE 'v=DKIM1%'
  GROUP BY h.host, h.process, d.domain
),
all_sigs AS (
  SELECT * FROM sig_a
  UNION ALL
  SELECT * FROM sig_b
  UNION ALL
  SELECT * FROM sig_c
)
SELECT
  'Command and control' AS category,
  a.ts AS timestamp,
  a.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = a.host AND l.ts <= a.ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = a.host
                                AND o.ts > l.ts AND o.ts <= a.ts)
            ORDER BY l.ts DESC LIMIT 1),
           (SELECT u.user FROM users u WHERE u.workstation = a.host LIMIT 1),
           'none') AS user,
  a.process,
  a.evidence
FROM all_sigs a
