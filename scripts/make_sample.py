"""Cut the SAMPLE_MODE cassettes to exactly what the recorded demo run used.
Input: runs/used_keys.jsonl (written during `REVISIT_USED_LOG=runs/used_keys.jsonl python -I app/run.py demo --record`),
runs/cassette.jsonl (every Nemotron answer recorded through Nightshift) and runs/zetaris_cassette.jsonl (every Zetaris result).
The same request can have been answered more than once (the sealed exam's two runner copies; a later product run). The answer
the demo actually used is picked: by the answer's SHA-256 when the used-key log has it; otherwise exam answers by the sealed
scorer's rule (last answer before the exam ended) and live answers as the first one recorded inside the demo's time window
(--window START END, ISO times). Each Nemotron entry keeps its source ('exam' / 'live').
Output: sample/cassette_nightshift.jsonl, sample/cassette_zetaris.jsonl.
Usage: python -I scripts/make_sample.py [--window START END]"""
import os, sys, json, hashlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'app'))
R = lambda p: os.path.join(ROOT, p)
EXAM_END = '2026-10-27T02:12:00'
win = sys.argv[sys.argv.index('--window') + 1:sys.argv.index('--window') + 3] if '--window' in sys.argv else None
used = [json.loads(l) for l in open(R('runs/used_keys.jsonl'), encoding='utf-8')]
sha = lambda t: hashlib.sha256((t or '').encode('utf-8')).hexdigest()
# Nemotron
want = {}
for u in used:
    if u['kind'] == 'nightshift': want.setdefault(u['key'], u)
cands = {}
for l in open(R('runs/cassette.jsonl'), encoding='utf-8'):
    r = json.loads(l)
    if r['key'] in want: cands.setdefault(r['key'], []).append(r)
got, missing = {}, []
for k, u in want.items():
    rs = cands.get(k, []); src = {'sealed_exam': 'exam'}.get(u.get('source'), u.get('source') or 'live'); pick = None
    if u.get('text_sha'): pick = next((r for r in rs if sha(r['text']) == u['text_sha']), None)
    if pick is None and src == 'exam': pick = ([r for r in rs if r.get('ts', '9999') <= EXAM_END] or [None])[-1]
    if pick is None and win: pick = next((r for r in rs if win[0] <= r.get('ts', '') <= win[1]), None)
    if pick is None and rs: pick = rs[-1]
    if pick is None: missing.append(k); continue
    got[k] = json.dumps(dict(pick, source=src), ensure_ascii=False) + chr(10)
with open(R('sample/cassette_nightshift.jsonl'), 'w', encoding='utf-8', newline=chr(10)) as f: f.writelines(got[k] for k in sorted(got))
print('sample/cassette_nightshift.jsonl', len(got), 'entries; missing', len(missing))
# Zetaris (results are deterministic per SQL and identity; the last successful one is kept)
wantz = {u['key'] for u in used if u['kind'] == 'zetaris'}; gz = {}
for l in open(R('runs/zetaris_cassette.jsonl'), encoding='utf-8'):
    r = json.loads(l)
    if r['key'] in wantz and r.get('ok', True): gz[r['key']] = l if l.endswith(chr(10)) else l + chr(10)
with open(R('sample/cassette_zetaris.jsonl'), 'w', encoding='utf-8', newline=chr(10)) as f: f.writelines(gz[k] for k in sorted(gz))
print('sample/cassette_zetaris.jsonl', len(gz), 'entries; missing', len(wantz - set(gz)))
