-- name: Lookalike (typosquat) domains
-- role: DNS
-- category: Deceptive domains
-- param: extra_domains | list |  | Extra analyst-supplied lookalike domains (exact match)
SELECT
  'Deceptive domains' AS category,
  a.ts AS timestamp,
  a.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = a.host AND l.ts <= a.ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = a.host
                                AND o.ts > l.ts AND o.ts <= a.ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  a.process,
  'Lookalike domain ' || a.target AS evidence
FROM host a
WHERE a.event = 'DNS_QUERY'
  AND a.target <> 'bearcorp.com'
  AND a.target NOT LIKE '%.bearcorp.com'
  AND a.target <> 'victim-corp.net'
  AND a.target NOT LIKE '%.victim-corp.net'
  AND (
    a.target LIKE 'xn--%'
    OR a.target LIKE '%bearcorp%'
    OR a.target LIKE '%bear-corp%'
    OR a.target LIKE '_earcorp.%'
    OR a.target LIKE 'b_arcorp.%'
    OR a.target LIKE 'be_rcorp.%'
    OR a.target LIKE 'bea_corp.%'
    OR a.target LIKE 'bear_orp.%'
    OR a.target LIKE 'bearc_rp.%'
    OR a.target LIKE 'bearco_p.%'
    OR a.target LIKE 'bearcor_.%'
    OR a.target IN (SELECT value FROM json_each(:extra_domains))
  )
