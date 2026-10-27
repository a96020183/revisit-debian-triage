"""Zetaris REST client: POST {ZETARIS_REST_URL}/sql-editor/sqls/run (Bearer API key, X-Org-ID, fresh X-Request-ID).
Every query is logged (scrubbed) to runs/zetaris_sql_log.jsonl and its result recorded to runs/zetaris_cassette.jsonl
(key = SHA-256 of the SQL). REVISIT_SAMPLE_MODE=1 replays recorded results without a Zetaris server; an unrecorded SQL raises.
Secrets come from ../.env (outside the repo) and are never printed or logged."""
import json, time, uuid, os, re, hashlib, urllib.request, urllib.error, pathlib, threading
ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV = pathlib.Path(os.environ.get('REVISIT_ENV', str(ROOT.parent / '.env')))
LOG = pathlib.Path(os.environ.get('REVISIT_SQL_LOG', str(ROOT / 'runs' / 'zetaris_sql_log.jsonl')))
CASSETTE = pathlib.Path(os.environ.get('REVISIT_SQL_CASSETTE', str(ROOT / 'runs' / 'zetaris_cassette.jsonl')))
SAMPLE_MODE = os.environ.get('REVISIT_SAMPLE_MODE', '') in ('1', 'true', 'yes')
_lock = threading.Lock()


def _env():
    d = {}
    if ENV.exists():
        for ln in open(ENV, encoding='utf-8'):
            ln = ln.strip()
            if ln and not ln.startswith('#') and '=' in ln:
                k, v = ln.split('=', 1); d[k.strip()] = v.strip().strip('"').strip("'")
    return d


E = {} if SAMPLE_MODE else _env()
_PRIV = ROOT / 'data' / 'private' / 'revisit_pg_password_PRIVATE.txt'   # only used to scrub logs
PGPW = _PRIV.read_text().strip() if (not SAMPLE_MODE and _PRIV.exists()) else ''
SECRETS = [v for k, v in E.items() if any(x in k for x in ('KEY', 'TOKEN', 'PASSWORD')) and len(v) > 4] + ([PGPW] if PGPW else [])


def scrub(s):
    s = str(s)
    for v in SECRETS: s = s.replace(v, '<redacted>')
    return s


def key_of(sql, identity='admin'):
    return hashlib.sha256((identity + '|' + re.sub(r'\s+', ' ', sql.strip())).encode('utf-8')).hexdigest()


_KEYS = {}


def api_key(identity):
    """admin = the key in ../.env (setup only). Agent identities use their own non-admin Zetaris users
    (scripts/setup_governance.py, keys in data/private/*_PRIVATE.txt)."""
    if identity == 'admin': return E['ZETARIS_API_KEY']
    if identity not in _KEYS:
        p = ROOT / 'data' / 'private' / f'zetaris_{identity}_key_PRIVATE.txt'
        if not p.exists(): raise RuntimeError(f'no Zetaris API key for identity {identity}: run scripts/setup_governance.py')
        _KEYS[identity] = p.read_text().strip(); SECRETS.append(_KEYS[identity])
    return _KEYS[identity]


_CASS = None


def _cassette():
    global _CASS
    if _CASS is None:
        _CASS = {}
        if CASSETTE.exists():
            for ln in open(CASSETTE, encoding='utf-8'):
                try: r = json.loads(ln); _CASS[r['key']] = r
                except Exception: pass
    return _CASS


def rows(out):
    """Zetaris returns {'columns'/'header': [...], 'data': [[...]]}; normalise to a list of dicts."""
    if not out: return []
    cols = out.get('headers') or out.get('columns') or out.get('header') or []
    cols = [c.get('name') if isinstance(c, dict) else c for c in cols]
    data = out.get('data') or []
    if cols and data and isinstance(data[0], list): return [dict(zip(cols, r)) for r in data]
    return data


def run(sql, limit=1000, timeout=600, tag='', record=True, identity='admin', record_ddl=False):
    """returns (ok, out, rec). out is the raw JSON reply. identity = which Zetaris user sends it."""
    k = key_of(sql, identity)
    if os.environ.get('REVISIT_USED_LOG') and record:
        with _lock, open(os.environ['REVISIT_USED_LOG'], 'a', encoding='utf-8') as f: f.write(json.dumps(dict(kind='zetaris', key=k, tag=tag)) + chr(10))
    if SAMPLE_MODE:
        r = _cassette().get(k)
        if r is None: raise RuntimeError(f'SAMPLE_MODE: no recorded Zetaris result for {tag} (key {k[:12]})')
        return r['ok'], r['out'], dict(tag=tag, sql=r['sql'], ok=r['ok'], replayed=True, secs=0, error=r.get('error'), identity=identity)
    body = {'queryId': str(uuid.uuid4()), 'sql': sql, 'source': 'SqlEditor', 'limit': limit}
    req = urllib.request.Request(E['ZETARIS_REST_URL'].rstrip('/') + '/sql-editor/sqls/run', data=json.dumps(body).encode(), method='POST',
                                 headers={'Authorization': 'Bearer ' + api_key(identity), 'X-Org-ID': E.get('ZETARIS_ORG_ID', '1'),
                                          'X-Request-ID': str(uuid.uuid4()), 'Content-Type': 'application/json'})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: out = json.loads(r.read().decode('utf-8')); ok, err = True, None
    except urllib.error.HTTPError as e:
        out, ok, err = None, False, f'HTTP {e.code} ' + e.read().decode('utf-8', 'replace')[:1500]
    except Exception as e:
        out, ok, err = None, False, f'{type(e).__name__}: {e}'
    rec = dict(ts=time.strftime('%Y-%m-%dT%H:%M:%S'), tag=tag, identity=identity, sql=scrub(sql), ok=ok, secs=round(time.time() - t0, 1), error=scrub(err) if err else None,
               preview=scrub(json.dumps(out, ensure_ascii=False)[:800]) if out is not None else None)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        with open(LOG, 'a', encoding='utf-8') as f: f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        if record and (record_ddl or not re.match(r'\s*(CREATE|DROP|GRANT|REVOKE|REGISTER|CACHE)\b', sql, re.I)):
            with open(CASSETTE, 'a', encoding='utf-8') as f:
                f.write(scrub(json.dumps(dict(key=k, tag=tag, identity=identity, sql=sql, ok=ok, out=out, error=err), ensure_ascii=False)) + '\n')
    return ok, out, rec
