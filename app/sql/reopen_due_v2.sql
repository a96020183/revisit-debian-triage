-- Post-hoc fixes: QA round 1, the sealed watch (reopen_due.sql) never checked whether bookworm had already resolved the wait;
-- QA round 4, a linked commit counts as the fix only when it qualifies (Fixed-by note, names the CVE, or dated after the deferral);
-- QA round 5, a signal reopens a deferral only if it appeared AFTER the deferral (it was not there when Debian decided to wait),
-- and an unstable fixed version only if it is on bookworm's version line and newer than bookworm (same epoch, Debian order).
SELECT w.wait_id, w.cve, w.pkg, w.deferred_at, w.condition_at_deferral, w.condition_now, c.via, c.tpl, ev.kind, ev.detail, ev.signal_date
FROM (SELECT wait_id, 'original' AS via, tpl_deferral AS tpl, branch_deferral AS br FROM revisit_pg.rv3_waits
      UNION ALL
      SELECT wait_id, 'latest' AS via, tpl_now AS tpl, branch_now AS br FROM revisit_pg.rv3_waits) c
JOIN revisit_pg.rv3_waits w ON w.wait_id = c.wait_id
JOIN (SELECT wait_id, 'unstable' AS kind, concat('unstable ships ', version, ' (in the archive since ', since, ')') AS detail, since AS signal_date
        FROM revisit_pg.rv3_tracker_now
        WHERE release = 'sid' AND status = 'fixed' AND version <> '0' AND same_line = '1' AND fix_newer = '1' AND since <> ''
      UNION ALL
      SELECT wait_id, 'release_tag' AS kind, concat('fix commit first released ', tag_date, ': ', url) AS detail, tag_date AS signal_date
        FROM revisit_pg.rv3_upstream
        WHERE kind = 'gh_commit' AND release_tags <> '' AND qualifies = '1' AND tag_date <> ''
      UNION ALL
      SELECT wait_id, 'commit' AS kind, concat('fix commit authored ', commit_date, ': ', url) AS detail, commit_date AS signal_date
        FROM revisit_pg.rv3_upstream
        WHERE kind = 'gh_commit' AND commit_exists = '1' AND qualifies = '1' AND commit_date <> ''
      UNION ALL
      SELECT wait_id, 'pr_merged' AS kind, concat('PR merged ', merged_at, ': ', url) AS detail, merged_at AS signal_date
        FROM revisit_pg.rv3_upstream
        WHERE kind = 'gh_pull' AND merged_at <> ''
      UNION ALL
      SELECT wait_id, 'branch' AS kind, concat('fix on release/', branch, ': ', tags, ' (first tag ', tag_date, ')') AS detail, tag_date AS signal_date
        FROM revisit_pg.rv3_branch_fix
        WHERE met = '1' AND tag_date <> '') ev ON ev.wait_id = c.wait_id
WHERE w.wait_id NOT IN (SELECT r.wait_id FROM revisit_pg.rv3_resolved r)
  AND ev.signal_date > w.deferred_at
  AND ((c.tpl = 'upstream_fix' AND ev.kind IN ('unstable', 'release_tag'))
   OR (c.tpl = 'patch_available' AND ev.kind IN ('unstable', 'release_tag', 'commit', 'pr_merged'))
   OR (c.tpl = 'branch_fix' AND ev.kind = 'branch' AND ev.detail LIKE concat('fix on release/', c.br, ':%')))
