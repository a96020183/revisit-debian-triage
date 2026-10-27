SELECT w.wait_id, w.cve, w.pkg, w.deferred_at, w.condition_at_deferral, w.condition_now, c.via, c.tpl, ev.kind, ev.detail
FROM (SELECT wait_id, 'original' AS via, tpl_deferral AS tpl, branch_deferral AS br FROM revisit_pg.rv3_waits
      UNION ALL
      SELECT wait_id, 'latest' AS via, tpl_now AS tpl, branch_now AS br FROM revisit_pg.rv3_waits) c
JOIN revisit_pg.rv3_waits w ON w.wait_id = c.wait_id
JOIN (SELECT wait_id, 'unstable' AS kind, concat('unstable ships ', version) AS detail FROM revisit_pg.rv3_tracker_now
        WHERE release = 'sid' AND status = 'fixed' AND version <> '0'
      UNION ALL
      SELECT wait_id, 'release_tag' AS kind, concat('fix commit in release tag ', split(release_tags, ',')[0], ': ', url) AS detail FROM revisit_pg.rv3_upstream
        WHERE kind = 'gh_commit' AND release_tags <> ''
      UNION ALL
      SELECT wait_id, 'commit' AS kind, concat('fix commit exists: ', url) AS detail FROM revisit_pg.rv3_upstream
        WHERE kind = 'gh_commit' AND commit_exists = '1'
      UNION ALL
      SELECT wait_id, 'pr_merged' AS kind, concat('PR merged ', merged_at, ': ', url) AS detail FROM revisit_pg.rv3_upstream
        WHERE kind = 'gh_pull' AND merged_at <> ''
      UNION ALL
      SELECT wait_id, 'branch' AS kind, concat('fix on release/', branch, ': ', tags) AS detail FROM revisit_pg.rv3_branch_fix
        WHERE met = '1') ev ON ev.wait_id = c.wait_id
WHERE (c.tpl = 'upstream_fix' AND ev.kind IN ('unstable', 'release_tag'))
   OR (c.tpl = 'patch_available' AND ev.kind IN ('unstable', 'release_tag', 'commit', 'pr_merged'))
   OR (c.tpl = 'branch_fix' AND ev.kind = 'branch' AND ev.detail LIKE concat('fix on release/', c.br, ':%'))
