"""Zetaris is the only way Revisit reads evidence. Every read below is one SQL statement sent to Zetaris
(app/zetaris.py), logged, and recorded for SAMPLE_MODE replay. Rows come back with ids (E1, E2, ...) so the Verifier can
check that every claim an agent makes points at a row that was actually returned."""
import json, re, os
import zetaris as z

WALLS = ['2026-06-01', '2026-07-01', '2026-08-01', '2026-09-01', '2026-10-01']
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


def facts(cve, pkg):
    rows, meta = sql(f"SELECT * FROM revisit_pg.rv3_cve_facts WHERE cve = {q(cve)} AND pkg = {q(pkg)}", 'facts')
    if not rows: return None, meta
    r = rows[0]
    return dict(cve=r['cve'], pkg=r['pkg'], desc=json.loads(r['descr_json']), scope=r['scope'], bw_version=r['bw_version'],
                limited_support=r['limited_support'] == '1', first_seen=r['first_seen'], wall=r['wall'], drop_own_cve_history=r['drop_own'] == '1'), meta


def packages():
    rows, meta = sql("SELECT DISTINCT pkg FROM revisit_pg.rv3_cve_facts", 'packages')
    return {r['pkg'] for r in rows}, meta


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
                  "FROM revisit_pg.rv3_advisories a WHERE a.pkg = {p} AND a.adv_date <= {wq} AND a.cve <> {own}",
    'same_cve_other_packages': "SELECT 'same_cve_other_packages' AS source, d.pkg AS ref, d.snap AS at, d.cls AS label, concat(d.bw_line, ' | ', d.sid_line) AS detail "
                               "FROM rv3.decisions_{w} d WHERE d.cve = {c} AND d.pkg <> {p}",
    'kev': "SELECT 'kev' AS source, k.cve AS ref, k.date_added AS at, 'known exploited' AS label, concat(k.vendor, ' ', k.product, ': ', k.name) AS detail "
           "FROM revisit_pg.rv3_kev k WHERE k.cve = {c} AND k.date_added <= {wq}",
    'cve_facts': "SELECT 'cve_facts' AS source, f.cve AS ref, f.first_seen AS at, f.scope AS label, "
                 "concat('bookworm ships ', f.bw_version, '; limited security support: ', f.limited_support) AS detail "
                 "FROM revisit_pg.rv3_cve_facts f WHERE f.cve = {c} AND f.pkg = {p}",
}


def triage_pack(cve, pkg, wall, sources, start=1):
    """One Zetaris statement over the chosen sources, all cut at the time wall. Returns rows with ids."""
    own = q(cve)   # the CVE under review never appears as its own precedent
    fmt = dict(w=wall.replace('-', '_'), p=q(pkg), c=q(cve), wq=q(wall), own=own)
    hist = [s for s in ('package_history', 'same_cve_other_packages') if s in sources]
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
def reopen_due():
    rows, meta = sql('SELECT * FROM rv3.reopen_due', 'reopen_due', identity=WATCHER)
    return rows, meta


def waits(keys):
    rows, meta = sql('SELECT * FROM revisit_pg.rv3_waits WHERE wait_id IN (' + ', '.join(q(k) for k in keys) + ')', 'waits', identity=WATCHER)
    return {r['wait_id']: r for r in rows}, meta


def reopen_pack(wait, rm_name, start=1):
    """One federated statement: Debian tracker (Postgres) + upstream links (Postgres) + release-monitoring.org (REST)
    + OSV (REST) + the deferral record (Postgres)."""
    k, cve, pkg = wait['wait_id'], wait['cve'], wait['pkg']
    rm_part = f"""
UNION ALL
SELECT 'upstream_releases' AS source, concat('latest stable release ', it.stable_versions[0]) AS fact, concat('recent: ', concat_ws(', ', slice(it.stable_versions, 1, 6))) AS detail
FROM rv3_up.rm_{safe(pkg)} LATERAL VIEW explode(items) i AS it WHERE lower(it.name) = {q(rm_name.lower())}""" if pkg in REST['rm'] else ''
    osv_part = f"""
UNION ALL
SELECT 'osv' AS source, concat(o.id, ' modified ', substr(o.modified, 1, 10)) AS fact, substr(to_json(o.affected), 1, 700) AS detail
FROM rv3_up.osv_{safe(cve)} o""" if cve in REST['osv'] else ''
    text = f"""SELECT 'debian_tracker' AS source, concat(t.release, ' ', t.status, CASE WHEN t.version <> '' THEN concat(' ', t.version) ELSE '' END) AS fact, t.note AS detail
FROM revisit_pg.rv3_tracker_now t WHERE t.wait_id = {q(k)}
UNION ALL
SELECT 'upstream_link' AS source, concat(u.kind, CASE WHEN u.release_tags <> '' THEN concat(' contained in release tag ', u.release_tags) ELSE '' END,
       CASE WHEN u.merged_at <> '' THEN concat(' merged ', u.merged_at) ELSE '' END) AS fact, u.url AS detail
FROM revisit_pg.rv3_upstream u WHERE u.wait_id = {q(k)}{rm_part}{osv_part}
UNION ALL
SELECT 'deferral_record' AS source, concat('deferred ', w.deferred_at) AS fact, concat('condition at deferral: ', w.condition_at_deferral, ' || condition now: ', w.condition_now) AS detail
FROM revisit_pg.rv3_waits w WHERE w.wait_id = {q(k)}"""
    rows, meta = sql(text, f'reopen_pack:{k}', identity=WATCHER)
    for i, r in enumerate(rows, start): r['id'] = f'E{i}'
    return rows, meta
