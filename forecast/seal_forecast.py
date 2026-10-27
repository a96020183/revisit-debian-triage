"""Live forecast, step 3: seal the predictions. K = the longest prefix of the registered sample order in which every item has
all registered predictions (runs/forecast_preds.jsonl); items after the first gap are not sealed. Writes forecast_sealed.json
(per item: CVE, package, each arm's prediction, the gate rule and short reasons) and forecast_sealed.sha256.
Usage: python -I forecast/seal_forecast.py"""
import os, json, hashlib, datetime
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda p: os.path.join(ROOT, p)
P = json.loads(open(R('prereg_forecast.json'), 'rb').read().replace(b'\r\n', b'\n'))
pre = hashlib.sha256(open(R('prereg_forecast.json'), 'rb').read().replace(b'\r\n', b'\n')).hexdigest()
assert pre == open(R('prereg_forecast.sha256')).read().split()[0]
recs = {}
for ln in open(R('runs/forecast_preds.jsonl'), encoding='utf-8'):
    r = json.loads(ln); recs.setdefault(r['key'], r)   # first complete answer per item (the runner never repeats an item)
items = []
for k in P['sample']['order']:
    r = recs.get(k)
    if not r: break
    items.append(dict(n=len(items) + 1, cve=r['cve'], pkg=r['pkg'], predictions={a: r[a] for a in ('GATED', 'pkg_mode', 'S', 'OURS')}, gate_rule=r['gate_rule'],
                      reason_evidence_path=r['S_reason'][:240], reason_memory_path=r['OURS_reason'][:240], predicted_at=r['ts']))
out = dict(title='Revisit live forecast: sealed predictions', prereg_sha256=pre, snapshot=P['snapshot'], N_registered=P['sample']['N'], K_sealed=len(items),
           sealed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
           arms=P['arms'], outcome=P['outcome']['rule_short'], items=items)
open(R('forecast_sealed.json'), 'w', encoding='utf-8', newline='\n').write(json.dumps(out, ensure_ascii=False, indent=1) + '\n')
h = hashlib.sha256(open(R('forecast_sealed.json'), 'rb').read()).hexdigest()
open(R('forecast_sealed.sha256'), 'w', encoding='utf-8', newline='\n').write(f'{h}  forecast_sealed.json\n')
print('sealed', len(items), 'of', P['sample']['N'], 'sha256', h)
