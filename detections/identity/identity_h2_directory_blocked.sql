-- name: Directory dumps and blocked connections
-- role: Identity
-- category: multiple
-- param: min_searches | int | 10 | Minimum wildcard/dump LDAP searches per host
-- param: dump_filters | list | (uid=*), (memberOf=*), (servicePrincipalName=*), (adminCount=1), (objectClass=user), (objectClass=computer) | LDAP dump filters to flag
WITH ldap_hits AS (
  SELECT host, user, MIN(ts) AS ts, COUNT(*) AS n
  FROM ldap
  WHERE filter IN (SELECT value FROM json_each(:dump_filters))
  GROUP BY host, user
  HAVING COUNT(*) >= :min_searches
),
fw_hits AS (
  SELECT h.host, h.process, MIN(f.ts) AS ts, MIN(f.dst_ip) AS dst
  FROM fw f
  JOIN host h ON h.event = 'NET_CONNECT' AND h.ts = f.ts
    AND h.target = f.dst_ip || ':' || f.dst_port
  WHERE f.rule = 'threat-intel-block'
  GROUP BY h.host, h.process
),
ldap_rows AS (
  SELECT 'Reconnaissance' AS category, ts AS timestamp, host, user,
         'ldapsearch' AS process,
         n || ' directory dump searches (wildcard/dump filters)' AS evidence
  FROM ldap_hits
),
fw_rows AS (
  SELECT 'Command and control' AS category, a.ts AS timestamp, a.host,
         COALESCE((SELECT l.user FROM host l
                   WHERE l.event = 'LOGIN' AND l.host = a.host AND l.ts <= a.ts
                     AND NOT EXISTS (SELECT 1 FROM host o
                                     WHERE o.event = 'LOGOUT' AND o.host = a.host
                                       AND o.ts > l.ts AND o.ts <= a.ts)
                   ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
         a.process,
         'Repeated threat-intel-block denials to ' || a.dst AS evidence
  FROM fw_hits a
)
SELECT * FROM ldap_rows
UNION ALL
SELECT * FROM fw_rows
