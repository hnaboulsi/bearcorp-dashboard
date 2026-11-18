-- name: Downloads piped into a shell
-- role: Endpoint
-- category: multiple
-- param: max_distinct_hosts_per_url | int | 50 | A URL run on more distinct hosts than this counts as benign setup noise
-- param: benign_domains | list | ctf-tools.hackedu.io | Domains never reported even if rare
-- param: plugin_process_markers | list | plugin | Process name substrings treated as browser-plugin processes
-- param: category_bash | text | Malware delivery | Category when the piping process is a shell
-- param: category_plugin | text | Host intrusion signs | Category when the piping process matches a plugin marker
-- param: collapse_window_minutes | int | 10 | Keep only the first row per category host process within this many minutes
WITH raw AS (
  SELECT ts, host, COALESCE(process, 'bash') AS process, target, LOWER(target) AS lt
  FROM host
  WHERE event = 'CMD'
    AND (LOWER(target) LIKE '%curl%' OR LOWER(target) LIKE '%wget%')
    AND target LIKE '%|%'
),
piped AS (
  SELECT
    ts, host, process, target, lt,
    INSTR(lt, '|') AS pipe_pos,
    LTRIM(SUBSTR(lt, INSTR(lt, '|') + 1)) AS after_pipe
  FROM raw
  WHERE INSTR(lt, '|') > 0
    AND (SUBSTR(lt, 1, INSTR(lt, '|') - 1) LIKE '%curl%'
      OR SUBSTR(lt, 1, INSTR(lt, '|') - 1) LIKE '%wget%')
),
shell_piped AS (
  SELECT
    ts, host, process, target, lt,
    CASE
      WHEN after_pipe LIKE 'sudo %' THEN LTRIM(SUBSTR(after_pipe, 6))
      ELSE after_pipe
    END AS shell_cmd
  FROM piped
),
matched AS (
  SELECT ts, host, process, target,
    CASE
      WHEN INSTR(lt, 'https://') > 0 THEN INSTR(lt, 'https://')
      WHEN INSTR(lt, 'http://') > 0 THEN INSTR(lt, 'http://')
      ELSE 0
    END AS url_start
  FROM shell_piped
  WHERE shell_cmd = 'sh' OR shell_cmd LIKE 'sh %' OR shell_cmd LIKE 'sh;%' OR shell_cmd LIKE 'sh&%' OR shell_cmd LIKE 'sh)%' OR shell_cmd LIKE 'sh' || CHAR(9) || '%'
     OR shell_cmd = 'bash' OR shell_cmd LIKE 'bash %' OR shell_cmd LIKE 'bash;%' OR shell_cmd LIKE 'bash&%' OR shell_cmd LIKE 'bash)%' OR shell_cmd LIKE 'bash' || CHAR(9) || '%'
),
with_url AS (
  SELECT ts, host, process, target, url_start,
    CASE WHEN url_start > 0 THEN SUBSTR(LOWER(target), url_start) ELSE LOWER(target) END AS url_rest
  FROM matched
),
url_cut1 AS (
  SELECT ts, host, process, target, url_start,
    SUBSTR(url_rest, 1, INSTR(url_rest || '|', '|') - 1) AS u
  FROM with_url
),
url_cut2 AS (
  SELECT ts, host, process, target, url_start,
    SUBSTR(u, 1, INSTR(u || ' ', ' ') - 1) AS u
  FROM url_cut1
),
url_cut3 AS (
  SELECT ts, host, process, target, url_start,
    SUBSTR(u, 1, INSTR(u || '''', '''') - 1) AS u
  FROM url_cut2
),
url_cut4 AS (
  SELECT ts, host, process, target, url_start,
    SUBSTR(u, 1, INSTR(u || '"', '"') - 1) AS u
  FROM url_cut3
),
extracted AS (
  SELECT ts, host, process, target,
    CASE WHEN url_start > 0 THEN SUBSTR(u, 1, INSTR(u || CHAR(9), CHAR(9)) - 1) ELSE target END AS url
  FROM url_cut4
),
domain_rest AS (
  SELECT ts, host, process, target, url,
    CASE WHEN INSTR(url, '://') > 0 THEN SUBSTR(url, INSTR(url, '://') + 3) ELSE '' END AS d
  FROM extracted
),
domain_cut AS (
  SELECT ts, host, process, target, url,
    SUBSTR(d, 1, INSTR(d || '/', '/') - 1) AS d
  FROM domain_rest
),
with_domain AS (
  SELECT ts, host, process, target, url,
    SUBSTR(d, 1, INSTR(d || ':', ':') - 1) AS domain
  FROM domain_cut
),
rare AS (
  SELECT url FROM with_domain
  GROUP BY url
  HAVING COUNT(DISTINCT host) <= :max_distinct_hosts_per_url
),
filtered AS (
  SELECT w.ts, w.host, w.process, w.target, w.url, w.domain
  FROM with_domain w
  WHERE w.url IN (SELECT url FROM rare)
    AND w.domain NOT IN (SELECT LOWER(value) FROM json_each(:benign_domains))
),
categorised AS (
  SELECT
    CASE WHEN EXISTS (SELECT 1 FROM json_each(:plugin_process_markers) WHERE INSTR(LOWER(f.process), LOWER(value)) > 0)
         THEN :category_plugin ELSE :category_bash END AS category,
    f.ts AS timestamp,
    f.host,
    f.process,
    f.target AS evidence,
    f.url,
    f.domain
  FROM filtered f
),
deduped AS (
  SELECT *,
    LAG(timestamp) OVER (PARTITION BY category, host, LOWER(process) ORDER BY timestamp) AS prev_ts
  FROM categorised
)
SELECT
  d.category,
  d.timestamp,
  d.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = d.host AND l.ts <= d.timestamp
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = d.host
                                AND o.ts > l.ts AND o.ts <= d.timestamp)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  d.process,
  d.evidence,
  d.url,
  d.domain
FROM deduped d
WHERE d.prev_ts IS NULL
   OR (julianday(d.timestamp) - julianday(d.prev_ts)) * 1440 > :collapse_window_minutes
ORDER BY d.timestamp
