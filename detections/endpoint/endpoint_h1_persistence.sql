-- name: Persistence and cleanup commands
-- role: Endpoint
-- category: Host intrusion signs
-- param: max_hosts | int | 10 | Normalised-pattern rarity gate: keep patterns seen on at most this many distinct hosts
-- param: prefilter | list | authorized_keys,crontab,/etc/cron,useradd,adduser,.bashrc,history -c,bash_history,HISTFILE,/var/log | Cheap any-of substrings pre-filtering CMD targets (case-insensitive)
-- param: collapse_minutes | int | 10 | Keep only the first row per category, host and process within this many minutes
WITH hits AS MATERIALIZED (
  SELECT ts, host, process, target, lower(target) AS lt
  FROM host
  WHERE event = 'CMD'
    AND EXISTS (
      SELECT 1 FROM json_each(:prefilter) je
      WHERE instr(lower(host.target), lower(je.value)) > 0
    )
    AND (
      -- ssh_key: authorized_keys with a write verb (>>, tee, > ~, > /, cp, echo, cat >)
      (instr(lower(target), 'authorized_keys') > 0 AND (
        instr(lower(target), '>>') > 0
        OR instr(lower(target), 'tee') > 0
        OR instr(lower(target), '> ~') > 0
        OR instr(lower(target), '>~') > 0
        OR instr(lower(target), '> /') > 0
        OR instr(lower(target), '>/') > 0
        OR instr(lower(target), 'cp ') > 0
        OR instr(lower(target), 'echo') > 0
        OR instr(lower(target), 'cat >') > 0
        OR instr(lower(target), 'cat>') > 0))
      -- cron: crontab or /etc/cron with install/write verb
      OR ((instr(lower(target), 'crontab') > 0 OR instr(lower(target), '/etc/cron') > 0) AND (
        instr(lower(target), '>>') > 0
        OR instr(lower(target), 'echo') > 0
        OR instr(lower(target), '| crontab') > 0
        OR instr(lower(target), '|crontab') > 0
        OR instr(lower(target), 'crontab -') > 0
        OR instr(lower(target), 'crontab /') > 0))
      -- useradd / adduser account creation
      OR instr(lower(target), 'useradd') > 0
      OR instr(lower(target), 'adduser') > 0
      -- bashrc: .bashrc with a write verb
      OR (instr(lower(target), '.bashrc') > 0 AND (
        instr(lower(target), '>>') > 0
        OR instr(lower(target), 'tee') > 0
        OR instr(lower(target), '> ~') > 0
        OR instr(lower(target), '>~') > 0))
      -- history_clear: history -c/-w, unset HISTFILE, or rm of .bash_history
      OR instr(lower(target), 'history -c') > 0
      OR instr(lower(target), 'history -w') > 0
      OR instr(lower(target), 'unset histfile') > 0
      OR (instr(lower(target), 'rm') > 0
          AND instr(lower(target), '.bash_history') > instr(lower(target), 'rm'))
      -- varlog_delete: rm/shred/truncate on /var/log, or redirect onto /var/log
      OR (instr(lower(target), '/var/log') > 0 AND (
        (instr(lower(target), 'rm') > 0 AND instr(lower(target), 'rm') < instr(lower(target), '/var/log'))
        OR (instr(lower(target), 'shred') > 0 AND instr(lower(target), 'shred') < instr(lower(target), '/var/log'))
        OR (instr(lower(target), 'truncate') > 0 AND instr(lower(target), 'truncate') < instr(lower(target), '/var/log'))
        OR instr(lower(target), '> /var/log') > 0
        OR instr(lower(target), '>/var/log') > 0))
    )
),
normed AS (
  SELECT *,
    replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
      lt, '0', ''), '1', ''), '2', ''), '3', ''), '4', ''),
      '5', ''), '6', ''), '7', ''), '8', ''), '9', '') AS pattern_key,
    CASE
      WHEN instr(lt, 'authorized_keys') > 0 THEN 'ssh_key'
      WHEN instr(lt, 'crontab') > 0 OR instr(lt, '/etc/cron') > 0 THEN 'cron'
      WHEN instr(lt, 'useradd') > 0 OR instr(lt, 'adduser') > 0 THEN 'useradd'
      WHEN instr(lt, '.bashrc') > 0 AND instr(lt, 'history') = 0 THEN 'bashrc'
      WHEN instr(lt, 'history -c') > 0 OR instr(lt, 'history -w') > 0
        OR instr(lt, 'unset histfile') > 0 OR instr(lt, '.bash_history') > 0 THEN 'history_clear'
      WHEN instr(lt, '/var/log') > 0 THEN 'varlog_delete'
      ELSE 'other'
    END AS subtype
  FROM hits
),
rare AS (
  SELECT pattern_key FROM normed
  GROUP BY pattern_key
  HAVING COUNT(DISTINCT host) <= :max_hosts
),
kept AS (
  SELECT n.ts, n.host, n.process, n.target, n.subtype
  FROM normed n
  WHERE n.pattern_key IN (SELECT pattern_key FROM rare)
),
flagged AS (
  SELECT *,
    LAG(ts) OVER (
      PARTITION BY 'Host intrusion signs', host, lower(process)
      ORDER BY ts
    ) AS prev_ts
  FROM kept
)
SELECT
  'Host intrusion signs' AS category,
  f.ts AS timestamp,
  f.host,
  COALESCE((SELECT l.user FROM host l
            WHERE l.event = 'LOGIN' AND l.host = f.host AND l.ts <= f.ts
              AND NOT EXISTS (SELECT 1 FROM host o
                              WHERE o.event = 'LOGOUT' AND o.host = f.host
                                AND o.ts > l.ts AND o.ts <= f.ts)
            ORDER BY l.ts DESC LIMIT 1), 'none') AS user,
  f.process,
  f.target AS evidence,
  f.subtype
FROM flagged f
WHERE f.prev_ts IS NULL
   OR (julianday(f.ts) - julianday(f.prev_ts)) * 1440.0 > :collapse_minutes
ORDER BY f.ts
