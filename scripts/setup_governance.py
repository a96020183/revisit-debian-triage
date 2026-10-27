"""Zetaris governance for Revisit's agents: each agent role reads Zetaris as its own non-admin user, and Zetaris itself
refuses what that role may not read.
  triage executor  user executor@revisit3.local, role RV3_EXECUTOR: CVE records, and decision history, advisories and KEV ONLY
                   through the per-time-wall views rv3.{decisions,advisories,kev}_<wall> (the raw tables are not granted, so the
                   triage agent cannot read past its time wall: the full advisory table would hold the answers)
  reopen watcher   user watcher@revisit3.local, role RV3_WATCHER: the daily view rv3.reopen_due, the deferral tables and the
                   upstream / OSV REST tables; nothing about new CVEs
  admin            setup only
Passwords and API keys are generated locally into data/private/*_PRIVATE.txt (git-ignored), never printed.
Writes evidence/zetaris_governance.txt (allowed and refused queries per identity).
Usage: python -I scripts/setup_governance.py"""
import os, sys, re, json, uuid, secrets, datetime, urllib.request, urllib.error
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'app'))
import zetaris as z
PRIV = os.path.join(ROOT, 'data', 'private'); os.makedirs(PRIV, exist_ok=True)
BASE = z.E['ZETARIS_REST_URL'].rstrip('/')
WALLS = ['2026_06_01', '2026_07_01', '2026_08_01', '2026_09_01', '2026_10_01', '2026_10_26']
REST = json.load(open(os.path.join(ROOT, 'evidence', 'rest_tables.json'), encoding='utf-8'))
safe = lambda s: __import__('re').sub(r'[^a-z0-9]+', '_', s.lower()).strip('_')
USERS = {
    'executor': dict(email='executor@revisit3.local', role='RV3_EXECUTOR', name='Revisit triage executor',
                     grants=[],   # nothing standing: the item's CVE record and wall views are granted per item by the wall keeper (app/evidence.py wall_access)
                     revoke=['DATASOURCE TABLE revisit_pg.rv3_advisories', 'DATASOURCE TABLE revisit_pg.rv3_kev', 'DATASOURCE TABLE revisit_pg.rv3_decisions', 'DATASOURCE TABLE revisit_pg.rv3_cve_facts']
                            + [f'VIEW TABLE rv3.{v}_{w}' for w in WALLS for v in ('decisions', 'advisories', 'kev')]),
    'watcher': dict(email='watcher@revisit3.local', role='RV3_WATCHER', name='Revisit reopen watcher',
                    revoke=[],
                    grants=['VIEW TABLE rv3.reopen_due', 'VIEW TABLE rv3.reopen_due_v2'] + [f'DATASOURCE TABLE revisit_pg.{t}' for t in ('rv3_waits', 'rv3_tracker_now', 'rv3_upstream', 'rv3_branch_fix', 'rv3_resolved')]
                           + [f'LIGHTNING DATABASE TABLE rv3_up.osv_{safe(c)}' for c in REST['osv']] + [f'LIGHTNING DATABASE TABLE rv3_up.rm_{safe(p)}' for p in REST['rm']]),
}
OUT = []


def api(method, path, body=None, token=None, base=BASE):
    h = {'X-Org-ID': z.E.get('ZETARIS_ORG_ID', '1'), 'X-Request-ID': str(uuid.uuid4()), 'Content-Type': 'application/json',
         'Authorization': 'Bearer ' + (token or z.E['ZETARIS_API_KEY'])}
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            t = r.read().decode('utf-8', 'replace'); return r.status, (json.loads(t) if t.strip().startswith(('{', '[')) else t)
    except urllib.error.HTTPError as e:
        return e.code, z.scrub(e.read().decode('utf-8', 'replace')[:400])


def sql(q, ident='admin'):
    ok, out, rec = z.run(q, tag='governance', record=False, identity=ident)
    exists = not ok and re.search(r'already (exists|been assigned|been granted)|has already', rec['error'] or '')
    label = 'ALLOWED' if ok else ('ALREADY SET' if exists else 'REFUSED')   # a rerun of setup: the role, user or grant is already there, not a refusal
    OUT.append(f"{label:<11}  [{ident}]  {q[:150]}" + ('' if ok else f"  -> {(rec['error'] or '')[:160]}"))
    print(OUT[-1], flush=True)
    return ok


def setup():
    for who, u in USERS.items():
        pwf = os.path.join(PRIV, f'zetaris_{who}_password_PRIVATE.txt'); keyf = os.path.join(PRIV, f'zetaris_{who}_key_PRIVATE.txt')
        if not os.path.exists(pwf):
            open(pwf, 'w').write('Aa1!' + ''.join(secrets.choice('abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(20)))
        pw = open(pwf).read().strip(); z.SECRETS.append(pw)
        sql(f"CREATE ROLE '{u['role']}'")
        st, out = api('POST', '/users', {'email': u['email'], 'name': u['name'], 'level': 'GENERAL', 'password': pw, 'isLdap': False, 'status': 'Active'})
        print('create user', who, st, '' if st < 300 or 'exist' in str(out).lower() else str(out)[:200])
        sql(f"ASSIGN USER '{u['email']}' TO ROLE '{u['role']}'")
        sql(f"ASSIGN DATASOURCE revisit_pg TO ROLE '{u['role']}'")
        if who == 'watcher': sql(f"ASSIGN LIGHTNING DATABASE rv3_up TO ROLE '{u['role']}'")
        for g in u['revoke']: sql(f"REVOKE SELECT ON {g} FROM ROLE '{u['role']}'")
        for g in u['grants']: sql(f"GRANT SELECT ON {g} TO ROLE '{u['role']}'")
        if not os.path.exists(keyf):
            req = urllib.request.Request('http://localhost:3000/api/auth/login', data=json.dumps({'username': u['email'], 'password': pw}).encode(), method='POST',
                                         headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=60) as r: tok = json.loads(r.read().decode())
            token = next((tok[k] for k in ('idToken', 'token', 'accessToken', 'access_token') if isinstance(tok.get(k), str)), None)
            exp = (datetime.datetime.utcnow() + datetime.timedelta(days=30)).replace(microsecond=0).isoformat() + '.000Z'
            st, k = api('POST', '/auth/api-key', {'name': f'revisit3-{who}', 'expiryDate': exp}, token=token)
            key = next((k[x] for x in ('apiKey', 'key', 'token', 'value') if isinstance(k, dict) and isinstance(k.get(x), str)), None)
            if not key: raise SystemExit(f'no API key for {who}: HTTP {st}')
            open(keyf, 'w').write(key)
        print('identity ready:', who, flush=True)


def check():
    import evidence as EV
    OUT.append('== what each identity may read (Zetaris enforces; same SQL, different API key)')
    OUT.append('-- no item running: the executor holds no grant on any walled view')
    sql("SELECT count(*) FROM rv3.decisions_2026_10_01", 'executor')
    sql("SELECT * FROM rv3.advisories_2026_10_26 WHERE cve = 'CVE-2026-109618'", 'executor')
    sql("SELECT count(*) FROM revisit_pg.rv3_cve_facts", 'executor')                     # even the CVE records: only while an item runs
    OUT.append('-- wall keeper opens wall 2026-10-01 (as for an item whose wall is 2026-10-01)')
    EV.wall_access('2026-10-01', True)
    sql("SELECT count(*) FROM rv3.decisions_2026_10_01", 'executor')            # the open wall's history view: allowed
    sql("SELECT count(*) FROM revisit_pg.rv3_cve_facts", 'executor')               # the CVE records: allowed while the item runs
    OUT.append('   (note: the CVE-record grant is the whole table, so while an item runs the executor could also read the records of other items:'
               ' descriptions and versions, never answers; the product reads only its own item, see the SQL in each trace)')
    sql("SELECT count(*) FROM revisit_pg.rv3_decisions", 'executor')            # raw history = beyond the time wall: must be refused
    sql("SELECT count(*) FROM rv3.advisories_2026_10_01", 'executor')
    sql("SELECT count(*) FROM rv3.kev_2026_10_01", 'executor')
    sql("SELECT * FROM revisit_pg.rv3_advisories WHERE cve = 'CVE-2026-109618'", 'executor')   # the full advisory table holds the answers: must be refused
    sql("SELECT count(*) FROM revisit_pg.rv3_kev", 'executor')                                 # raw KEV: refused, only the walled view
    sql("SELECT * FROM rv3.advisories_2026_10_26 WHERE cve = 'CVE-2026-109618'", 'executor')   # a later wall: still refused
    sql("SELECT count(*) FROM revisit_pg.rv3_waits", 'executor')                # reopen data: not the triage agent's
    sql("GRANT SELECT ON DATASOURCE TABLE revisit_pg.rv3_decisions TO ROLE 'RV3_EXECUTOR'", 'executor')   # cannot grant itself
    EV.wall_access('2026-10-01', False)
    OUT.append('-- wall keeper revoked wall 2026-10-01')
    sql("SELECT count(*) FROM rv3.decisions_2026_10_01", 'executor')
    sql("SELECT count(*) FROM rv3.reopen_due", 'watcher')
    sql("SELECT count(*) FROM revisit_pg.rv3_cve_facts", 'watcher')             # new CVEs: not the watcher's
    sql("SELECT count(*) FROM rv3.decisions_2026_10_01", 'watcher')


if __name__ == '__main__':
    if '--check' not in sys.argv: setup()
    check()
    open(os.path.join(ROOT, 'evidence', 'zetaris_governance.txt'), 'w', encoding='utf-8').write(
        f"Zetaris governance check {datetime.datetime.now().isoformat(timespec='seconds')} (local Zetaris, non-admin users per agent role)\n\n" + '\n'.join(OUT) + '\n')
