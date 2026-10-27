"""How often does the review loop actually loop? (QA round 1: the recorded demo never showed a send-back.)
Draws 30 sealed-exam items with random.Random(20261027).sample over the sorted item keys (fixed before running), runs the full
product triage on each in --record mode (iso scope; the two decision paths reuse the sealed exam's own answers; Planner,
Evaluator and Verifier run live through Nightshift, one request at a time), and counts what the loop did. Nothing is forced:
the prompts and loop are the product's. Writes runs/review_rate/*.json and runs/review_rate.json.
Usage: python -I exam/run_review_rate.py"""
import os, sys, json, random, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ['REVISIT_SCOPE'] = 'iso'; os.environ['REVISIT_REUSE_RECORDED'] = '1'
sys.path.insert(0, os.path.join(ROOT, 'app'))
import pipeline as P
items = json.load(open(os.path.join(ROOT, 'data/news_items.json'), encoding='utf-8'))
keys = random.Random(20261027).sample(sorted(f"{i['cve']}|{i['pkg']}" for i in items), 30)
OUT = os.path.join(ROOT, 'runs', 'review_rate'); os.makedirs(OUT, exist_ok=True)
R = P.Revisit()
try:
    for n, k in enumerate(keys, 1):
        p = os.path.join(OUT, k.replace('|', '__') + '.json')
        if os.path.exists(p): continue
        tr = R.triage(*k.split('|')); json.dump(tr.d, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print(n, k, tr.d['result'].get('status'), flush=True)
finally:
    R.close()
c = collections.Counter(); per = []
for k in keys:
    t = json.load(open(os.path.join(OUT, k.replace('|', '__') + '.json'), encoding='utf-8')); ev = t['events']
    sb = sum(e['kind'] == 'send_back' for e in ev); vb = sum(e['agent'] == 'verifier' and not e['detail'].get('ok', True) for e in ev)
    pl = sum(e['agent'] == 'planner' for e in ev); r = t['result']
    c['items'] += 1; c['evaluator_send_back_items'] += sb > 0; c['evaluator_send_backs'] += sb; c['verifier_send_back_items'] += vb > 0; c['verifier_send_backs'] += vb
    c['planner_rounds'] += pl; c[f"status_{r['status']}"] += 1; c[f"evaluator_{r['evaluator']}"] += 1
    per.append(dict(key=k, status=r['status'], evaluator=r['evaluator'], send_backs=sb, verifier_send_backs=vb, planner_rounds=pl, reason=(r.get('reason') or '')[:200]))
out = dict(rule=__doc__.split('Usage')[0].strip(), keys=keys, counts=dict(c), items=per)
json.dump(out, open(os.path.join(ROOT, 'runs', 'review_rate.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print(json.dumps(dict(c)))
