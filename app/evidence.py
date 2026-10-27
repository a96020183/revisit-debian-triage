"""Zetaris is the only way Revisit reads evidence. Every read below is one SQL statement sent to Zetaris
(app/zetaris.py), logged, and recorded for SAMPLE_MODE replay. Rows come back with ids (E1, E2, ...) so the Verifier can
check that every claim an agent makes points at a row that was actually returned."""
import json, re, os
import zetaris as z

WALLS = ['2026-06-01', '2026-07-01', '2026-08-01', '2026-09-01', '2026-10-01', '2026-10-26']   # monthly snapshots + today's tracker
TODAY = '2026-10-26'
q = lambda s: "'" + str(s).replace("'", "''") + "'"
safe = lambda s: re.sub(r'[^a-z0-9]+', '_', s.lower()).strip('_')
_RT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'evidence', 'rest_tables.json')
REST = json.load(open(_RT, encoding='utf-8')) if os.path.exists(_RT) else dict(osv=[], rm=[])   # REST tables app/zetaris_setup.py created


class ZetarisError(RuntimeError):
    pass


# Each agent role reads Zetaris as its own non-admin user (scripts/setup_governance.py); Zetaris refuses anything not granted.
EXECUTOR, WATCHER = 'executor', 'watcher'


def sql(text, tag, limit=5000, identity=EXECUTOR):
    ok, out, rec = z.run(text, tag=tag, limit=limit, identity=identity)
    if not ok: raise ZetarisError(f'{tag}: {rec.get("error")}')
    return z.rows(out), dict(tag=tag, identity=identity, sql=re.sub(r'\s+', ' ', text.strip()), replayed=bool(rec.get('replayed')), secs=rec.get('secs'))


def wall_of(cve, pkg):
    """the wall keeper (setup identity) looks up which wall an item belongs to, before the executor may read anything"""
    rows, meta = sql(f"SELECT wall, queue FROM revisit_pg.rv3_cve_facts WHERE cve = {q(cve)} AND pkg = {q(pkg)}", 'wall_of', identity='admin')
    return (rows[0]['wall'] if rows else None), meta


def wall_access(wall, open_=True):
    """Per-item time wall, enforced by Zetaris: the triage executor holds no grant on any walled view by default. Before an item
    runs, the wall keeper (admin identity, setup role) grants SELECT on exactly that wall's three views; afterwards it revokes them.
    Returns the statements' metas for the trace."""
    w = wall.replace('-', '_'); metas = []
    objs = [f'VIEW TABLE rv3.{v}_{w}' for v in ('decisions', 'advisories', 'kev') + (('cve_tracker',) if wall == TODAY else ())] + ['DATASOURCE TABLE revisit_pg.rv3_cve_facts']
    for o in objs:
        q_ = (f"GRANT SELECT ON {o} TO ROLE 'RV3_EXECUTOR'" if open_ else f"REVOKE SELECT ON {o} FROM ROLE 'RV3_EXECUTOR'")
        ok, out, rec = z.run(q_, tag=f"wall_{'grant' if open_ else 'revoke'}:{w}", identity='admin', record_ddl=True)
        if not ok and not re.search(r'already been granted|not been granted|does not have', rec.get('error') or ''):
            raise ZetarisError(f"wall keeper: {rec.get('error')}")
        metas.append(dict(sql=q_, ok=ok, replayed=bool(rec.get('replayed'))))
    return metas


def facts(cve, pkg):
    rows, meta = sql(f"SELECT * FROM revisit_pg.rv3_cve_facts WHERE cve = {q(cve)} AND pkg = {q(pkg)}", 'facts')
    if not rows: return None, meta
    r = rows[0]
    return dict(cve=r['cve'], pkg=r['pkg'], queue=r['queue'], desc=json.loads(r['descr_json']), scope=r['scope'], bw_version=r['bw_version'], bw_version_walled=r['bw_version_walled'],
                limited_support=r['limited_support'] == '1', first_seen=r['first_seen'], wall=r['wall'], drop_own_cve_history=r['drop_own'] == '1'), meta


def packages(queue):
    """packages H-MEM loads: the exam's own set for exam replays (so the replay is byte-identical to the sealed run), today's set for today"""
    rows, meta = sql(f"SELECT DISTINCT pkg FROM revisit_pg.rv3_cve_facts WHERE queue = {q(queue)}", f'packages:{queue}')
    return {r['pkg'] for r in rows}, meta


def today_queue(limit=50):
    rows, meta = sql(f"SELECT cve, pkg, first_seen FROM revisit_pg.rv3_cve_facts WHERE queue = 'today' "
                     f"ORDER BY first_seen DESC, cast(cve_year AS int) DESC, cast(cve_num AS int) DESC, pkg LIMIT {int(limit)}", 'today_queue', identity='admin')   # newest first; the queue builder runs as the setup identity
    return rows, meta


def history(wall):
    """the whole decision history up to the wall, read through the per-wall schema-store view the executor role is granted"""
    assert wall in WALLS
    rows, meta = sql(f"SELECT * FROM rv3.decisions_{wall.replace('-', '_')}", f'history:{wall}', limit=100000)
    ev = {}
    for r in sorted(rows, key=lambda r: (r['pkg'], int(r['seq']))):
        ev.setdefault(r['pkg'], []).append(dict(snap=r['snap'], cve=r['cve'], cls=r['cls'], prev=r['prev'] or None, bw=r['bw_line'], sid=r['sid_line'],
                                                notes=json.loads(r['notes_json']), desc=json.loads(r['descr_json'])))
    return ev, meta


# ---------------------------------------------------------------- triage evidence pack (one federated SQL)
TRIAGE_SOURCES = {
    'package_history': "SELECT 'package_history' AS source, d.cve AS ref, d.snap AS at, d.cls AS label, concat(d.bw_line, ' | ', d.sid_line) AS detail "
                       "FROM rv3.decisions_{w} d WHERE d.pkg = {p} AND d.cve <> {own}",
    'advisories': "SELECT 'advisories' AS source, a.adv_id AS ref, a.adv_date AS at, a.release AS label, concat(a.pkg, ' ', a.version, ' fixes ', a.cve) AS detail "
                  "FROM rv3.advisories_{w} a WHERE a.pkg = {p} AND a.cve <> {own}",
    'same_cve_other_packages': "SELECT 'same_cve_other_packages' AS source, d.pkg AS ref, d.snap AS at, d.cls AS label, concat(d.bw_line, ' | ', d.sid_line) AS detail "
                               "FROM rv3.decisions_{w} d WHERE d.cve = {c} AND d.pkg <> {p}",
    'kev': "SELECT 'kev' AS source, k.cve AS ref, k.date_added AS at, 'known exploited' AS label, concat(k.vendor, ' ', k.product, ': ', k.name) AS detail "
           "FROM rv3.kev_{w} k WHERE k.cve = {c}",
    'cve_tracker': "SELECT 'cve_tracker' AS source, t.pkg AS ref, t.snap AS at, t.release AS label, "
                   "concat(t.release, ' ', t.pkg, ' ', t.status, CASE WHEN t.note <> '' THEN concat(' ', t.note) ELSE '' END) AS detail "
                   "FROM rv3.cve_tracker_{w} t WHERE t.cve = {c}",
    'cve_facts': "SELECT 'cve_facts' AS source, f.cve AS ref, f.first_seen AS at, '' AS label, "
                 "concat('bookworm ships ', f.bw_version_walled, '; limited security support: ', f.limited_support) AS detail "
                 "FROM revisit_pg.rv3_cve_facts f WHERE f.cve = {c} AND f.pkg = {p}",
}


def triage_pack(cve, pkg, wall, sources, start=1):
    """One Zetaris statement over the chosen sources, all cut at the time wall. Returns rows with ids."""
    own = q(cve)   # the CVE under review never appears as its own precedent
    fmt = dict(w=wall.replace('-', '_'), p=q(pkg), c=q(cve), wq=q(wall), own=own)
    hist = [s for s in ('package_history', 'same_cve_other_packages') if s in sources]
    if wall != TODAY: sources = [s for s in sources if s != 'cve_tracker']   # the CVE's own record exists only for today's queue
    parts = [TRIAGE_SOURCES[s].format(**fmt) for s in sources if s in TRIAGE_SOURCES and s not in hist]
    if len(hist) == 1: parts.insert(0, TRIAGE_SOURCES[hist[0]].format(**fmt))
    elif hist:   # one scan of the wall view for both (the engine cannot union a view with itself)
        parts.insert(0, ("SELECT CASE WHEN d.pkg = {p} THEN 'package_history' ELSE 'same_cve_other_packages' END AS source, "
                         "CASE WHEN d.pkg = {p} THEN d.cve ELSE d.pkg END AS ref, d.snap AS at, d.cls AS label, concat(d.bw_line, ' | ', d.sid_line) AS detail "
                         "FROM rv3.decisions_{w} d WHERE (d.pkg = {p} AND d.cve <> {own}) OR (d.cve = {c} AND d.pkg <> {p})").format(**fmt))
    text = '\nUNION ALL\n'.join(parts) + '\nORDER BY source, at DESC'
    rows, meta = sql(text, f'triage_pack:{cve}|{pkg}')
    per = {}; kept = []
    for r in rows:   # keep the newest 12 rows per source so prompts stay short; counts are reported
        per[r['source']] = per.get(r['source'], 0) + 1
        if per[r['source']] <= 12: kept.append(r)
    for i, r in enumerate(kept, start): r['id'] = f'E{i}'
    meta['counts'] = per
    return kept, meta


# ---------------------------------------------------------------- reopen
def reopen_due(view='reopen_due_v2'):
    """reopen_due = the watch as sealed; reopen_due_v2 = the same minus waits bookworm had already resolved (post-hoc fix, QA round 1)"""
    rows, meta = sql(f'SELECT * FROM rv3.{view}', view, identity=WATCHER)
    return rows, meta


def resolved():
    rows, meta = sql('SELECT * FROM revisit_pg.rv3_resolved', 'resolved', identity=WATCHER)
    return {r['wait_id']: r for r in rows}, meta


def waits(keys):
    rows, meta = sql('SELECT * FROM revisit_pg.rv3_waits WHERE wait_id IN (' + ', '.join(q(k) for k in keys) + ')', 'waits', identity=WATCHER)
    return {r['wait_id']: r for r in rows}, meta


def reopen_pack(wait, rm_name, start=1):
    """One federated statement: Debian tracker (Postgres) + upstream links (Postgres) + release-monitoring.org (REST)
    + OSV (REST) + the deferral record (Postgres)."""
    k, cve, pkg = wait['wait_id'], wait['cve'], wait['pkg']
    rm_part = f"""
UNION ALL
SELECT 'upstream_releases' AS source, concat('latest stable release ', it.stable_versions[0], ' [no release date: context only]') AS fact,
       concat('recent: ', concat_ws(', ', slice(it.stable_versions, 1, 6))) AS detail, '' AS signal_date, '' AS versions
FROM rv3_up.rm_{safe(pkg)} LATERAL VIEW explode(items) i AS it WHERE lower(it.name) = {q(rm_name.lower())}""" if pkg in REST['rm'] else ''
    osv_part = f"""
UNION ALL
SELECT 'osv' AS source, concat(o.id, ' modified ', substr(o.modified, 1, 10), ' [no date for when the fix appeared: context only]') AS fact,
       substr(to_json(o.affected), 1, 700) AS detail, '' AS signal_date, '' AS versions
FROM rv3_up.osv_{safe(cve)} o""" if cve in REST['osv'] else ''
    # QA round 5: every row says when its signal appeared relative to the deferral, and an unstable fix says whether it is on
    # bookworm's version line. Only a row that appeared after the deferral can meet a condition (the Verifier checks the dates itself).
    when = lambda d: (f"CASE WHEN {d} = '' THEN ' [date unknown: does not count as new]' WHEN {d} > w.deferred_at THEN concat(' [new since the deferral: ', {d}, ']') "
                      f"ELSE concat(' [already there when Debian deferred: ', {d}, ']') END")
    usd = "CASE WHEN u.kind = 'gh_pull' THEN u.merged_at WHEN u.tag_date <> '' THEN u.tag_date ELSE u.commit_date END"
    text = f"""SELECT 'debian_tracker' AS source, concat(t.release, ' ', t.status, CASE WHEN t.version <> '' THEN concat(' ', t.version) ELSE '' END,
       CASE WHEN t.release = 'sid' AND t.status = 'fixed' THEN concat({when('t.since')},
            CASE WHEN t.same_line = '0' THEN concat(' [not on the bookworm version line: ', t.line_note, ']')
                 WHEN t.fix_newer = '0' THEN concat(' [not newer than bookworm ', t.bw_versions, ']')
                 ELSE concat(' [same version line, newer than bookworm ', t.bw_versions, ']') END) ELSE '' END) AS fact,
       t.note AS detail, t.since AS signal_date, CASE WHEN t.bw_versions <> '' THEN concat('fixed ', t.version, ' vs bookworm ', t.bw_versions) ELSE '' END AS versions
FROM revisit_pg.rv3_tracker_now t JOIN revisit_pg.rv3_waits w ON w.wait_id = t.wait_id WHERE t.wait_id = {q(k)}
UNION ALL
SELECT 'upstream_link' AS source, concat(u.kind, CASE WHEN u.release_tags <> '' THEN concat(' contained in ', size(split(u.release_tags, ',')), ' release tags (latest listed ', split(u.release_tags, ',')[0], ')') ELSE '' END,
       CASE WHEN u.merged_at <> '' THEN concat(' merged ', u.merged_at) ELSE '' END,
       CASE WHEN u.commit_date <> '' AND u.kind = 'gh_commit' THEN concat(' authored ', u.commit_date) ELSE '' END,
       CASE WHEN u.tag_date = '' THEN '' WHEN u.tag_bound = 'at_most' THEN concat(' already released by ', u.tag_date, ' (the oldest of the newest tags listed)') ELSE concat(' first released ', u.tag_date) END,
       CASE WHEN u.qualifies = '1' THEN concat(' [counts as the fix: ', u.why, ']') ELSE concat(' [NOT the fix by the rule: ', u.why, ']') END,
       {when(usd)}) AS fact, u.url AS detail, {usd} AS signal_date, '' AS versions
FROM revisit_pg.rv3_upstream u JOIN revisit_pg.rv3_waits w ON w.wait_id = u.wait_id WHERE u.wait_id = {q(k)}
UNION ALL
SELECT 'upstream_branch' AS source, concat('fix on upstream release/', b.branch, CASE WHEN b.met = '1' THEN ' branch: yes' ELSE ' branch: no' END,
       CASE WHEN b.met = '1' THEN {when('b.tag_date')} ELSE '' END) AS fact,
       concat('release tags: ', b.tags) AS detail, b.tag_date AS signal_date, '' AS versions
FROM revisit_pg.rv3_branch_fix b JOIN revisit_pg.rv3_waits w ON w.wait_id = b.wait_id WHERE b.wait_id = {q(k)}{rm_part}{osv_part}
UNION ALL
SELECT 'deferral_record' AS source, concat('deferred ', w.deferred_at) AS fact, concat('condition at deferral: ', w.condition_at_deferral, ' || condition now: ', w.condition_now) AS detail,
       w.deferred_at AS signal_date, '' AS versions
FROM revisit_pg.rv3_waits w WHERE w.wait_id = {q(k)}"""
    rows, meta = sql(text, f'reopen_pack:{k}', identity=WATCHER)
    for i, r in enumerate(rows, start): r['id'] = f'E{i}'
    return rows, meta
