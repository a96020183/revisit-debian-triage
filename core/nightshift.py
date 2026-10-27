"""Nightshift (Meterless) client for Revisit 3. Based on ../revisit2/nightshift2.py (same transport: stream, tier-split off,
long content in one system message + a one-line user message, backoff 15/30/60/120/180 s).

Scope: the product default follows the Power contract (meterless-scope: user). Scored and recorded runs set
REVISIT_SCOPE=iso, which sends a fresh iso-<uuid4> per request: with 'user', Nightshift injects up to 3 earlier answers
into the system prompt, so the evidence path and the memory path would stop being independent (measured by the L1 team,
see README "Sponsor tech"). One request in flight per process (the box is shared with two other projects).

Recording: every successful call is appended to runs/cassette.jsonl (key = SHA-256 of the exact request messages + model;
the answer text and the served model). REVISIT_SAMPLE_MODE=1 replays answers from a cassette and never opens a socket;
a request that is not in the cassette raises (no silent fallback).
Secrets: URL and runtime token come from ../.env (outside the repo); never printed or logged (scrubbed to <redacted>)."""
import json, os, re, time, threading, urllib.request, urllib.error, uuid, pathlib, hashlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV = pathlib.Path(os.environ.get('REVISIT_ENV', str(ROOT.parent / '.env')))
LOG = pathlib.Path(os.environ.get('REVISIT_CALL_LOG', str(ROOT / 'runs' / 'calls.jsonl')))
CASSETTE = pathlib.Path(os.environ.get('REVISIT_CASSETTE', str(ROOT / 'runs' / 'cassette.jsonl')))
SAMPLE_MODE = os.environ.get('REVISIT_SAMPLE_MODE', '') in ('1', 'true', 'yes')
SCOPE_MODE = os.environ.get('REVISIT_SCOPE', 'user')   # 'user' = Power contract default; 'iso' for scored / recorded runs
APP = 'revisit3'
_lock = threading.Lock()
_sem = threading.BoundedSemaphore(1)


def _env():
    d = {}
    if not ENV.exists(): return d
    for ln in open(ENV, encoding='utf-8'):
        ln = ln.strip()
        if ln and not ln.startswith('#') and '=' in ln:
            k, v = ln.split('=', 1); d[k.strip()] = v.strip().strip('"').strip("'")
    return d


_E = {} if SAMPLE_MODE else _env()
BASE = (os.environ.get('METERLESS_BASE_URL') or _E.get('METERLESS_BASE_URL') or 'http://127.0.0.1:8088/v1').rstrip('/')
_TOKEN = os.environ.get('METERLESS_RUNTIME_TOKEN') or _E.get('METERLESS_RUNTIME_TOKEN') or ''
SECRET_PAT = re.compile(re.escape(_TOKEN)) if _TOKEN else None


def _hdr(extra=None):
    scope = ('iso-' + str(uuid.uuid4())) if SCOPE_MODE == 'iso' else 'user'
    h = {'Authorization': 'Bearer ' + _TOKEN, 'Content-Type': 'application/json', 'meterless-app': APP, 'meterless-scope': scope}
    if extra: h.update(extra)
    return h


def _scrub(s):
    s = str(s)
    if SECRET_PAT: s = SECRET_PAT.sub('<redacted>', s)
    return re.sub(r'(?i)(bearer\s+)\S+', r'\1<redacted>', s)


THINK = re.compile(r'<think>.*?</think>', re.S)


def strip_reasoning(text):
    if text is None: return ''
    t = THINK.sub('', text)
    if '</think>' in t: t = t.rsplit('</think>', 1)[1]
    return t.strip()


ASK = 'Answer now: follow the instructions above.'


def to_system(messages):
    sys_txt = (chr(10) * 2).join(m['content'] for m in messages)
    return [{'role': 'system', 'content': sys_txt}, {'role': 'user', 'content': ASK}]


def key_of(messages, model):
    return hashlib.sha256(json.dumps([to_system(messages), model], ensure_ascii=False, sort_keys=True).encode('utf-8')).hexdigest()


_CASS = None


def _cassette():
    global _CASS
    if _CASS is None:
        _CASS = {}
        paths = [CASSETTE] + [pathlib.Path(p) for p in os.environ.get('REVISIT_EXTRA_CASSETTES', '').split(os.pathsep) if p]
        for p in paths:
            if p.exists():
                for ln in open(p, encoding='utf-8'):
                    try: r = json.loads(ln); _CASS.setdefault(r['key'], r)
                    except Exception: pass
    return _CASS


BACKOFF = [15, 30, 60, 120, 180, 180, 180, 180]


def chat(messages, model, max_tokens=1200, temperature=0.0, tag='', timeout=600, retries=8, extra_headers=None, extra_body=None):
    k = key_of(messages, model)
    if SAMPLE_MODE:
        r = _cassette().get(k)
        if r is None: raise RuntimeError(f'SAMPLE_MODE: no recorded Nightshift answer for {tag} (key {k[:12]})')
        return dict(text=r['text'], served=r['served'], usage=r.get('usage'), headers={}, raw=r['text'], replayed=True, key=k)
    msgs = to_system(messages)
    body = dict(model=model, messages=msgs, max_tokens=max_tokens, temperature=temperature, stream=True)
    if extra_body: body.update(extra_body)
    data = json.dumps(body).encode('utf-8')
    hx = {'meterless-tier-split': 'off'}
    if extra_headers: hx.update(extra_headers)
    last = None
    for attempt in range(retries):
        t0 = time.time()
        try:
            with _sem:
                req = urllib.request.Request(BASE + '/chat/completions', data=data, headers=_hdr(hx), method='POST')
                raw = ''; served = None; reasoning = False; ttfb = None
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    hdrs = dict(r.headers)
                    for bl in r:
                        line = bl.decode('utf-8', 'replace').strip()
                        if not line.startswith('data:') or line == 'data: [DONE]': continue
                        try: j = json.loads(line[5:])
                        except ValueError: continue
                        if j.get('error'): raise RuntimeError('stream error ' + str(j['error'])[:200])
                        if ttfb is None: ttfb = round(time.time() - t0, 2)
                        served = (j.get('meterless') or {}).get('routed_model') or j.get('model') or served
                        if j.get('choices'):
                            d = j['choices'][0].get('delta') or {}
                            raw += d.get('content') or ''
                            if d.get('reasoning_content') or d.get('reasoning'): reasoning = True
            if not raw.strip(): raise RuntimeError('empty answer')
            sys_chars = len(msgs[0]['content'])
            usage = dict(prompt_tokens=round((sys_chars + len(ASK)) / 4), completion_tokens=round(len(raw) / 4), estimated=True)
            rec = dict(ts=time.strftime('%Y-%m-%dT%H:%M:%S'), tag=tag, scope_mode=SCOPE_MODE, stream=True, tier_split='off', requested=model, served=served,
                       latency=round(time.time() - t0, 2), ttfb=ttfb, usage=usage, attempt=attempt, system_chars=sys_chars, user_chars=len(ASK),
                       had_think='</think>' in raw or reasoning, key=k,
                       route_headers={kk: v for kk, v in hdrs.items() if re.search(r'meterless|model|route|provider|lane|x-', kk, re.I)})
            _log(LOG, rec)
            text = strip_reasoning(raw)
            _log(CASSETTE, dict(key=k, tag=tag, ts=rec['ts'], served=served, text=text, usage=usage, scope_mode=SCOPE_MODE))
            return dict(text=text, served=served, usage=usage, headers=rec['route_headers'], raw=raw, key=k)
        except urllib.error.HTTPError as e:
            body_txt = ''
            try: body_txt = e.read().decode('utf-8', 'replace')[:300]
            except Exception: pass
            last = f'HTTP {e.code} {body_txt}'
        except Exception as e:
            last = f'{type(e).__name__}: {e}'
        _log(LOG, dict(ts=time.strftime('%Y-%m-%dT%H:%M:%S'), tag=tag, requested=model, error=_scrub(last), attempt=attempt))
        time.sleep(BACKOFF[min(attempt, len(BACKOFF) - 1)])
    raise RuntimeError(_scrub(last))


def _log(path, rec):
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock, open(path, 'a', encoding='utf-8') as f:
        f.write(_scrub(json.dumps(rec, ensure_ascii=False)) + '\n')
