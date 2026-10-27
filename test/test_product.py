"""Product checks that need no network (run after `python -I app/run.py demo --sample`):
  1. the SAMPLE_MODE replay reaches the same results as the recorded live run (runs/traces_sample vs runs/traces)
  2. for sealed-exam items, both decision paths were answered by the sealed exam's own recording, and the product's path answers
     equal the answers the sealed scorer used (last answer per item)
  3. the reopen watch closes every wait bookworm had already fixed and reopens none of them; the waits it fires on are the
     sealed watch's flags minus those (evidence/watch_equivalence.txt has the live Zetaris check)
  4. the reopen Verifier (QA round 5) rejects a "met" that rests on a signal already there at the deferral or on an unstable
     version from another epoch, and every reopened card passes it
  5. every page number is recomputed from the traces (app/stats.py) and matches ui/data.js
Usage: python -I test/test_product.py"""
import os, sys, json, glob
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'app'))
from stats import trace_stats
L = lambda d: {os.path.basename(p): json.load(open(p, encoding='utf-8')) for p in sorted(glob.glob(os.path.join(ROOT, 'runs', d, '*.json')))}
J = lambda p: json.load(open(os.path.join(ROOT, p), encoding='utf-8'))
if not glob.glob(os.path.join(ROOT, 'runs', 'traces_sample', '*.json')):   # prepare the replay if it has not been run yet
    import subprocess
    print('runs/traces_sample is empty: running `python -I app/run.py demo --sample` first')
    subprocess.run([sys.executable, '-I', os.path.join(ROOT, 'app', 'run.py'), 'demo', '--sample'], cwd=ROOT, check=True, capture_output=True)
live, rep = L('traces'), L('traces_sample')
fails = []
def check(name, ok, info=''):
    print(('PASS ' if ok else 'FAIL ') + name + (f'  ({info})' if info else '')); ok or fails.append(name)

check('recorded live traces exist', bool(live), f'{len(live)} traces')
check('sample replay traces exist (run: python -I app/run.py demo --sample)', bool(rep), f'{len(rep)} traces')
scored = {}
for arm in ('S', 'OURS'):
    for ln in open(os.path.join(ROOT, 'runs', f'news_preds_{arm}.jsonl'), encoding='utf-8'):
        r = json.loads(ln); scored.setdefault(f"{r['cve']}|{r['pkg']}", {})[arm] = r['pred']   # last answer per item = the sealed scorer's rule
res = J('data/reopen_resolved.json')
flags = {k for k, v in J('evidence/from_revisit2/reopen_OURS_deferral_condition.json')['flags'].items() if v}
for n, t in live.items():
    r = rep.get(n)
    if t['kind'] == 'triage':
        a, b = t['result'], (r or {}).get('result') or {}
        same = all(a.get(k) == b.get(k) for k in ('decision', 'status', 'gate_rule', 'evidence_path', 'memory_path', 'evaluator'))
        check(f'replay == live: {n}', same, f"{a.get('decision')}/{a.get('status')} vs {b.get('decision')}/{b.get('status')}")
        k = t['subject']
        if k in scored:
            check(f'product paths == scored exam answers: {n}', (a.get('evidence_path'), a.get('memory_path')) == (scored[k].get('S'), scored[k].get('OURS')))
            paths = [e for e in t['events'] if e['kind'] == 'path']
            check(f'paths answered from the sealed exam recording: {n}', bool(paths) and all(e['detail'].get('from_sealed_exam') for e in paths))
    else:
        cards = {c['wait']: c['status'] for c in t['result']['cards']}
        sb = {c['wait']: c['status'] for c in ((r or {}).get('result') or {}).get('cards', [])}
        check(f'replay == live: {n}', cards == sb, json.dumps(cards))
        check('no wait bookworm had already fixed is reopened; each is closed', all(cards[w] == 'resolved' for w in cards if w in res))
        fired = {e['detail']['wait'] for e in t['events'] if e['kind'] == 'fired'}
        v2 = set(J('sample/sample_cases.json')['v2_flags'])   # rv3.reopen_due_v2 as read from Zetaris (scripts/check_watch.py checks it live)
        check('the watch fires exactly where rv3.reopen_due_v2 does', all((w in fired) == (w in v2) for w in cards) and t['result']['watch_fired'] == len(v2), f"{t['result']['watch_fired']} vs {len(v2)}")
        check('the fixed watch only drops waits from the sealed watch (already fixed, not the fix, another version line, or already there at the deferral)', v2 <= flags - set(res))
        from pipeline import verify_reopen
        packs = {e['detail']['wait']: e['detail']['rows'] for e in t['events'] if e['kind'] == 'zetaris' and e['detail'].get('wait') and e['detail'].get('rows')}
        W = {c['wait']: c for c in t['result']['cards']}
        dates = {k: next((r['signal_date'] for r in rows if r['source'] == 'deferral_record'), '') for k, rows in packs.items()}
        for c in t['result']['cards']:
            if c['status'] == 'reopen':
                ok, why = verify_reopen(c['judge'], packs[c['wait']], dict(deferred_at=dates[c['wait']]))
                check(f"reopened {c['wait']}: the judge cites a fix row dated after the deferral, on bookworm's line", ok, '; '.join(why))
from pipeline import verify_reopen
_w = dict(deferred_at='2026-06-01')
_rows = [dict(id='E1', source='debian_tracker', fact='sid fixed 1:1.8.7-1', signal_date='2026-03-12', versions='fixed 1:1.8.7-1 vs bookworm 1.10.3-3'),
         dict(id='E2', source='debian_tracker', fact='sid fixed 1:1.8.7-1', signal_date='2026-07-12', versions='fixed 1:1.8.7-1 vs bookworm 1.10.3-3'),
         dict(id='E3', source='debian_tracker', fact='sid fixed 1.10.3-3', signal_date='2026-07-12', versions='fixed 1.10.3-3 vs bookworm 1.10.3-3+deb12u1'),
         dict(id='E4', source='upstream_link', fact='gh_commit [counts as the fix: x]', signal_date='2025-01-09', versions=''),
         dict(id='E5', source='osv', fact='osv', signal_date='', versions=''),
         dict(id='E6', source='debian_tracker', fact='sid fixed 1:4.10.1-1', signal_date='2026-07-10', versions='fixed 1:4.10.1-1 vs bookworm 1:4.9.0-3')]
_v = lambda c: verify_reopen(dict(met='yes', cites=c, parsed=True), _rows, _w)[0]
check('Verifier: a signal already there at the deferral, another epoch, not newer than bookworm, an old commit or a context-only row cannot carry "met"',
      not any(_v([c]) for c in ('E1', 'E2', 'E3', 'E4', 'E5')) and _v(['E6']) and _v(['E1', 'E6']))
exam_items = {f"{i['cve']}|{i['pkg']}" for i in J('data/news_items.json')}
for d, ts in (('traces', live), ('traces_sample', rep)):
    for n, t in ts.items():
        if t['kind'] == 'triage' and t['subject'] not in exam_items:
            srcs = [e['detail'].get('sources') or {} for e in t['events'] if e['kind'] == 'path']
            check(f'{d}/{n}: not an exam item, so no answer is labelled as reused from the exam', all('exam' not in x and not e_flag for x, e_flag in
                  zip(srcs, [e['detail'].get('from_sealed_exam') for e in t['events'] if e['kind'] == 'path'])), json.dumps(srcs))
sl, ss = trace_stats(list(live.values())), trace_stats(list(rep.values()))
check('replay marks each answer with its recorded source (live in the run / reused from the sealed exam), same counts as the recording',
      all(sl.get(k) == ss.get(k) for k in ('nemotron_live', 'nemotron_reused', 'zetaris_queries')),
      f"live {ss.get('nemotron_live')} / reused {ss.get('nemotron_reused')} vs recorded {sl.get('nemotron_live')} / {sl.get('nemotron_reused')}")
dpath = os.path.join(ROOT, 'ui', 'data.js')
if os.path.exists(dpath):
    d = open(dpath, encoding='utf-8').read(); data = json.loads(d[d.index('=') + 1:].rstrip().rstrip(';'))
    check('ui/data.js stats recomputed from its traces', trace_stats(data['traces']) == data['stats'])
print('ALL PASS' if not fails else f'{len(fails)} FAILED'); sys.exit(1 if fails else 0)
