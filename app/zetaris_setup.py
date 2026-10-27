"""Put every evidence source Revisit uses behind Zetaris (local Zetaris 2.4 in Docker). Re-runnable.

Postgres (container revisit-pg on the zetaris_default network, registered in Zetaris as datasource revisit_pg):
  rv3_cve_facts     the CVEs to triage: the 570 sealed-exam items (queue 'exam', replayed behind their time wall) and the
                    1,290 bookworm CVEs still undecided on 2026-10-26 (queue 'today', wall = the 2026-10-26 tracker)
  rv3_decisions     package decision history (labelled from the Debian tracker snapshots: data/news_events.json, data/today_events.json)
  rv3_advisories    DSA/DLA lines (advisory id, date, release, package, CVE) for those packages
  rv3_kev           CISA Known Exploited Vulnerabilities catalog
  rv3_waits         the 286 conditional bookworm deferrals: condition at deferral (original commitment) and condition now
  rv3_tracker_now   Debian tracker lines (unstable / trixie / bookworm) of those waits on the watch date 2026-10-23; a fixed
                    unstable line also carries the day that version reached the archive (since), bookworm's versions, and
                    whether it is on bookworm's line and newer (QA round 5; data/reopen_signal_dates.json, app/debver.py)
  rv3_upstream      upstream links of those waits: GitHub fix commits (+ commit date, the earliest release tag that contains
                    them and its date), PR merges (+ merge date)
  rv3_branch_fix    fix on a named upstream branch (ffmpeg release/5.1) + the date of the first release tag with it
  rv3_resolved      waits bookworm had already resolved by the watch date (DSA/DLA or fixed +deb12u line; data/reopen_resolved.json)
Zetaris REST tables (Lightning database rv3_up): OSV records and release-monitoring.org projects for the demo set.
Schema-store views (container rv3): reopen_due (the watch as sealed), reopen_due_v2 (same, minus resolved waits; post-hoc fix),
decisions_<wall>, advisories_<wall>, kev_<wall> (strictly before the wall for advisories and KEV).
Roles and users: scripts/setup_governance.py.
Usage: python -I app/zetaris_setup.py NEW_DL_DIR"""
import sys, os, json, re, csv, io, subprocess, datetime, collections
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE); sys.path.insert(0, HERE)
import zetaris as z
NEW = sys.argv[1]
D = lambda p: os.path.join(ROOT, p)
SAMPLE = json.load(open(D('sample/sample_cases.json'), encoding='utf-8'))
LOG = []


def psql(sql, stdin=None):
    p = subprocess.run(['docker', 'exec', '-i', 'revisit-pg', 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'revisit', '-d', 'revisit', '-c', sql],
                       input=stdin, capture_output=True, text=True, encoding='utf-8')
    if p.returncode: raise SystemExit(p.stderr[:800])
    return p.stdout


def copy(table, cols, rows):
    psql(f'DROP TABLE IF EXISTS {table}; CREATE TABLE {table} ({", ".join(c + " text" for c in cols)});')
    buf = io.StringIO(); w = csv.writer(buf, lineterminator='\n', quoting=csv.QUOTE_ALL)
    for r in rows: w.writerow(['' if r.get(c) is None else re.sub(r'[\r\n]+', ' ', str(r.get(c))) for c in cols])
    psql(f"COPY {table} FROM STDIN WITH (FORMAT csv)", buf.getvalue())
    print(f'{table}: {len(rows)} rows', flush=True)


def step(name, sql, ok_if_exists=True):
    ok, out, rec = z.run(sql, tag='setup:' + name, record=False)
    if not ok and ok_if_exists and re.search(r'already (exists|been granted)', rec['error'] or ''): ok = True
    LOG.append(dict(step=name, ok=ok, error=(rec['error'] or '')[:300]))
    print(('PASS ' if ok else 'FAIL ') + name + ('' if ok else ' ' + (rec['error'] or '')[:300]), flush=True)
    return ok, out


# ---------------------------------------------------------------- Postgres tables
items = [dict(i, queue='exam') for i in json.load(open(D('data/news_items.json'), encoding='utf-8'))] +         [dict(i, queue='today') for i in json.load(open(D('data/today_items.json'), encoding='utf-8'))]
for i in items:
    y, n = re.match(r'CVE-(\d+)-(\d+)', i['cve']).groups(); i['cve_year'], i['cve_num'] = int(y), int(n)
WALLED = {(x['cve'], x['pkg']): x['bw_version'] for x in json.load(open(D('data/news_items_facts_walled.json'), encoding='utf-8'))}
for i in items:   # today: the tracker's 'scope' is a default ('local' for most CVEs), not an attack vector, so it is not shown; versions are today's
    if i['queue'] == 'today': i['scope'] = ''
    i['bw_version_walled'] = WALLED.get((i['cve'], i['pkg']), i['bw_version']) if i['queue'] == 'exam' else i['bw_version']
copy('rv3_cve_facts', ['cve', 'pkg', 'queue', 'cve_year', 'cve_num', 'descr_json', 'scope', 'bw_version', 'bw_version_walled', 'limited_support', 'first_seen', 'wall', 'drop_own'],
     [dict(cve=i['cve'], pkg=i['pkg'], queue=i['queue'], cve_year=i['cve_year'], cve_num=i['cve_num'], bw_version_walled=i['bw_version_walled'], descr_json=json.dumps(i['desc'], ensure_ascii=False), scope=i['scope'], bw_version=i['bw_version'], limited_support=int(bool(i['limited_support'])),
           first_seen=i['first_seen'], wall=i['wall'], drop_own=int(i['drop_own_cve_history'])) for i in items])
ev = json.load(open(D('data/news_events.json'), encoding='utf-8'))
ev.update(json.load(open(D('data/today_events.json'), encoding='utf-8')))   # same labelling; for shared packages the 06-01..10-01 part is identical (test/test_data.py)
copy('rv3_decisions', ['pkg', 'seq', 'cve', 'snap', 'cls', 'prev', 'bw_line', 'sid_line', 'notes_json', 'descr_json'],
     [dict(pkg=p, seq=n, cve=e['cve'], snap=e['snap'], cls=e['cls'], prev=e['prev'], bw_line=e['bw'], sid_line=e['sid'], notes_json=json.dumps(e['notes'], ensure_ascii=False), descr_json=json.dumps(e['desc'], ensure_ascii=False))
      for p, es in ev.items() for n, e in enumerate(es)])
pk = {i['pkg'] for i in items}; adv = []
for fn in ('dsa.txt', 'dla.txt'):
    cur = None; cves = []
    for ln in open(os.path.join(NEW, fn), encoding='utf-8'):
        m = re.match(r'^\[(\d+ \w+ \d{4})\]\s+(D[SL]A-\S+)\s+(\S+)', ln)
        if m: cur = (datetime.datetime.strptime(m.group(1), '%d %b %Y').date().isoformat(), m.group(2)); cves = []; continue
        if cur is None: continue
        s = ln.strip()
        if s.startswith('{'): cves = re.findall(r'CVE-\d{4}-\d+', s); continue
        mm = re.match(r'^\[(\w+)\]\s+-\s+(\S+)\s*(\S*)', s)
        if mm and mm.group(2) in pk:
            for c in cves: adv.append(dict(adv_id=cur[1], adv_date=cur[0], release=mm.group(1), pkg=mm.group(2), version=mm.group(3), cve=c))
copy('rv3_advisories', ['adv_id', 'adv_date', 'release', 'pkg', 'version', 'cve'], adv)
kev = json.load(open(os.path.join(NEW, 'kev.json'), encoding='utf-8'))['vulnerabilities']
copy('rv3_kev', ['cve', 'date_added', 'vendor', 'product', 'name', 'ransomware'],
     [dict(cve=v['cveID'], date_added=v['dateAdded'], vendor=v['vendorProject'], product=v['product'], name=v['vulnerabilityName'], ransomware=v.get('knownRansomwareCampaignUse')) for v in kev])

B = json.load(open(D('data/reopen_bundle.json'), encoding='utf-8'))
NOTES = json.load(open(D('data/reopen_notes.json'), encoding='utf-8'))   # the tracker NOTE lines of each wait (revisit2 volume B)


def fix_rule(link, b, notes):
    """QA round 4: a linked commit is not automatically the fix. It counts only if the tracker note in front of it says 'Fixed by',
    or the commit message names the CVE, or the commit is dated after the deferral. (Tracker / OSV fixed versions count separately.)"""
    from email.utils import parsedate_to_datetime
    d = ''
    try: d = parsedate_to_datetime(link['date']).date().isoformat() if link.get('date') else (link.get('merged_at') or '')[:10]
    except Exception: d = ''
    line = next((n for n in notes if link['url'].rstrip('/') in n), '')
    if re.search(r'\bfixed by\b', line, re.I): return dict(ok=True, date=d, why='tracker note says Fixed by')
    if b['cve'] in (link.get('subject') or '') or b['cve'] in (link.get('title') or ''): return dict(ok=True, date=d, why='commit names the CVE')
    if d and d > b['deferred_at']: return dict(ok=True, date=d, why=f'authored {d}, after the deferral')
    return dict(ok=False, date=d, why=(f'authored {d}, before the deferral' if d else 'undated') + '; no Fixed-by note; does not name the CVE')   # revisit2's evidence bundle of the 286 waits
SIG = json.load(open(D('data/reopen_signal_dates.json'), encoding='utf-8'))   # QA round 5: when each signal appeared; version line
TPL = json.load(open(D('data/reopen_compiled.json'), encoding='utf-8'))   # Nemotron-compiled condition templates (revisit2)
waits, now_lines, up, br = [], [], [], []
for k, b in B.items():
    hist = [h for h in b['cond_history'] if h['status'] in ('postponed', 'no-dsa') and h['note']]
    cnow = hist[-1]['note'] if hist else b['condition_at_deferral']
    t0, t1 = TPL.get(b['condition_at_deferral'], {}), TPL.get(cnow, {})
    waits.append(dict(wait_id=k, cve=b['cve'], pkg=b['pkg'], deferred_at=b['deferred_at'], condition_at_deferral=b['condition_at_deferral'], condition_now=cnow,
                      tpl_deferral=t0.get('template', 'needs_human'), branch_deferral=t0.get('branch'), tpl_now=t1.get('template', 'needs_human'), branch_now=t1.get('branch')))
    for rel in ('sid', 'trixie', 'bookworm'):
        e = b.get(f'{rel}_now')
        sg = SIG.get(k, {}).get('sid') if rel == 'sid' else None
        if e: now_lines.append(dict(snap='2026-10-23', wait_id=k, cve=b['cve'], pkg=b['pkg'], release=rel, status='fixed' if e[2].startswith('fixed:') else e[2],
                                    version=e[2][6:] if e[2].startswith('fixed:') else '', note=(e[3] or '')[:200],
                                    since=(sg or {}).get('since') or '', bw_versions=','.join((sg or {}).get('bookworm') or []),
                                    same_line=int(bool((sg or {}).get('same_line'))), fix_newer=int(bool((sg or {}).get('fix_newer'))), line_note=(sg or {}).get('line_note') or ''))
    for l in b['links']:
        if l.get('kind') in ('gh_commit', 'gh_pull'):
            q = fix_rule(l, b, NOTES.get(k, [])); tg = SIG.get(k, {}).get('tags', {}).get(l['url']) or {}
            tag_date = tg.get('date') or ''   # the first release with the fix (scripts/build_signal_dates.py); '' = unknown, never counts as new
            up.append(dict(wait_id=k, url=l['url'], kind=l['kind'], commit_exists=int(bool(l.get('exists'))), release_tags=','.join(l.get('tags') or []),
                           merged_at=(l.get('merged_at') or '')[:10], commit_date=q['date'], qualifies=int(q['ok']), why=q['why'],
                           first_tag=tg.get('tag') or '', tag_date=tag_date, tag_bound=tg.get('bound') or ''))
    if b.get('ffmpeg51'): br.append(dict(wait_id=k, branch='5.1', met=int(bool(b['ffmpeg51']['met_51'])), tags=','.join(b['ffmpeg51']['tags'][:5]),
                                         tag_date=(SIG.get(k, {}).get('branch') or {}).get('date') or ''))
copy('rv3_waits', ['wait_id', 'cve', 'pkg', 'deferred_at', 'condition_at_deferral', 'condition_now', 'tpl_deferral', 'branch_deferral', 'tpl_now', 'branch_now'], waits)
copy('rv3_tracker_now', ['snap', 'wait_id', 'cve', 'pkg', 'release', 'status', 'version', 'note', 'since', 'bw_versions', 'same_line', 'fix_newer', 'line_note'], now_lines)
copy('rv3_upstream', ['wait_id', 'url', 'kind', 'commit_exists', 'release_tags', 'merged_at', 'commit_date', 'qualifies', 'why', 'first_tag', 'tag_date', 'tag_bound'], up)
copy('rv3_branch_fix', ['wait_id', 'branch', 'met', 'tags', 'tag_date'], br)
copy('rv3_cve_tracker', ['cve', 'snap', 'release', 'pkg', 'status', 'note'], json.load(open(D('data/today_cve_tracker.json'), encoding='utf-8')))
RES = json.load(open(D('data/reopen_resolved.json'), encoding='utf-8'))
copy('rv3_resolved', ['wait_id', 'how', 'ref', 'date', 'version'], [dict(wait_id=k, **v) for k, v in RES.items()])

# ---------------------------------------------------------------- Zetaris: datasource, REST tables, views, roles
step('register revisit_pg tables', 'REGISTER DATASOURCE TABLES FROM revisit_pg')
for t in ('rv3_cve_facts', 'rv3_decisions', 'rv3_advisories', 'rv3_kev', 'rv3_waits', 'rv3_tracker_now', 'rv3_upstream', 'rv3_branch_fix', 'rv3_resolved', 'rv3_cve_tracker'):
    step(f'count {t}', f'SELECT count(*) AS n FROM revisit_pg.{t}')
step('lightning db rv3_up', 'CREATE LIGHTNING DATABASE rv3_up DESCRIBE BY "Revisit 3 upstream and OSV REST tables"')
REST = '''CREATE LIGHTNING REST TABLE {t} FROM rv3_up REQUEST (
  endpoint "{u}", method "GET", http_encoding "URLENCODED", response_type "JSON", insecure_ssl "false") HEADER () BODY ()'''
safe = lambda s: re.sub(r'[^a-z0-9]+', '_', s.lower()).strip('_')
step('container rv3', 'CREATE SCHEMASTORE CONTAINER rv3')
WATCH = open(os.path.join(HERE, 'sql', 'reopen_due.sql'), encoding='utf-8').read()
z.run('DROP SCHEMASTORE VIEW reopen_due FROM rv3', tag='setup:drop', record=False)
step('view rv3.reopen_due (daily watch)', 'CREATE SCHEMASTORE VIEW reopen_due WITH CONTAINER rv3 AS ' + WATCH)
V2 = open(os.path.join(HERE, 'sql', 'reopen_due_v2.sql'), encoding='utf-8').read()
z.run('DROP SCHEMASTORE VIEW reopen_due_v2 FROM rv3', tag='setup:drop', record=False)
step('view rv3.reopen_due_v2 (watch minus resolved waits)', 'CREATE SCHEMASTORE VIEW reopen_due_v2 WITH CONTAINER rv3 AS ' + V2)
WALLS = ('2026-06-01', '2026-07-01', '2026-08-01', '2026-09-01', '2026-10-01', '2026-10-26')
for w in WALLS:
    wv = w.replace('-', '_')
    for v, q in ((f'decisions_{wv}', f"SELECT * FROM revisit_pg.rv3_decisions WHERE snap <= '{w}'"),        # the snapshot taken on the wall date
                 (f'advisories_{wv}', f"SELECT * FROM revisit_pg.rv3_advisories WHERE adv_date < '{w}'"),   # strictly before the wall
                 (f'kev_{wv}', f"SELECT * FROM revisit_pg.rv3_kev WHERE date_added < '{w}'")):
        z.run(f'DROP SCHEMASTORE VIEW {v} FROM rv3', tag='setup:drop', record=False)
        step(f'wall view rv3.{v}', f"CREATE SCHEMASTORE VIEW {v} WITH CONTAINER rv3 AS {q}")
# today's tracker record of each undecided CVE: exists only for today's wall (an exam replay must not see its CVE's own record)
z.run('DROP SCHEMASTORE VIEW cve_tracker_2026_10_26 FROM rv3', tag='setup:drop', record=False)
step('wall view rv3.cve_tracker_2026_10_26', "CREATE SCHEMASTORE VIEW cve_tracker_2026_10_26 WITH CONTAINER rv3 AS SELECT * FROM revisit_pg.rv3_cve_tracker WHERE snap <= '2026-10-26'")
for role in ('rv3_planner', 'rv3_executor', 'rv3_watcher'):
    step(f'role {role}', f"CREATE ROLE '{role}'")
step('count reopen_due', 'SELECT count(*) AS n FROM rv3.reopen_due')
# REST tables for every wait the watch flags today + the demo set (OSV is read only for reopen: today's facts; triage replays
# stay behind their time wall and never read OSV)
ok, out = step('flagged waits', 'SELECT DISTINCT wait_id FROM rv3.reopen_due')
keys = sorted({r['wait_id'] for r in z.rows(out)} | set(SAMPLE['reopen']))
made = dict(osv=[], rm=[])
for c in sorted({k.split('|')[0] for k in keys}):
    t = 'osv_' + safe(c)
    z.run(f'DROP LIGHTNING DATABASE TABLE {t} FROM rv3_up', tag='setup:drop', record=False)
    if step(f'REST {t}', REST.format(t=t, u=f'https://api.osv.dev/v1/vulns/{c}'))[0]:
        usable, _o, _r = z.run(f'SELECT substr(to_json(o.affected), 1, 10) FROM rv3_up.{t} o LIMIT 1', tag='setup:probe', record=False)
        if usable: made['osv'].append(c)   # some OSV records carry no 'affected' list
for p in sorted({k.split('|')[1] for k in keys}):
    t = 'rm_' + safe(p)
    z.run(f'DROP LIGHTNING DATABASE TABLE {t} FROM rv3_up', tag='setup:drop', record=False)
    if step(f'REST {t}', REST.format(t=t, u=f'https://release-monitoring.org/api/v2/projects/?name={SAMPLE["rm_names"].get(p, p)}'))[0]:
        usable, _o, _r = z.run(f'SELECT it.name FROM rv3_up.{t} LATERAL VIEW explode(items) i AS it LIMIT 1', tag='setup:probe', record=False)
        if usable: made['rm'].append(p)   # an unknown project comes back with an empty, untyped item list: not joinable
json.dump(made, open(D('evidence/rest_tables.json'), 'w', encoding='utf-8'), indent=1)
json.dump(LOG, open(D('evidence/zetaris_setup.json'), 'w', encoding='utf-8'), indent=1)
print('done', sum(s['ok'] for s in LOG), '/', len(LOG))
