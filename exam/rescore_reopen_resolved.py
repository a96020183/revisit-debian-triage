"""Re-score the reopen task with the QA round-1 correction (POST-HOC; not part of any sealed procedure).
Correction: a wait that bookworm had already resolved by 2026-10-23 (data/reopen_resolved.json: a DSA/DLA for the CVE and
package, or a fixed +deb12u bookworm line) must NOT be reopened. The original truth counted these as "condition met",
so every arm that flagged them got credit. Corrected truth = met AND not resolved.

Arms (flags exactly as recorded; nothing re-run):
  watch_sealed        Revisit's watch as measured (rv3.reopen_due = revisit2 original-or-latest watcher, 85 flags)
  watch_fixed         the same watch with resolved waits removed (rv3.reopen_due_v2; the fix is POST-HOC)
  judge_sealed        watch + Nemotron judge as sealed in prereg_reopen_judge.json
  judge_fixed         judge_sealed with resolved waits removed (POST-HOC)
  latest_only, R0, R1, R2   revisit2's arms
Each arm is scored against both the original and the corrected truth. Paired bootstrap 2,000, seed 11.
Usage: python -I exam/rescore_reopen_resolved.py"""
import os, json, random
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E = lambda p: json.load(open(os.path.join(ROOT, p), encoding='utf-8'))
T = E('evidence/from_revisit2/reopen_truth.json'); RES = E('data/reopen_resolved.json')
base = E('evidence/from_revisit2/reopen_base.json')
r2 = {r['key']: bool(r['met']) for r in map(json.loads, open(os.path.join(ROOT, 'evidence/from_revisit2/reopen_R2.jsonl'), encoding='utf-8'))}
watch = E('evidence/from_revisit2/reopen_OURS_deferral_condition.json')['flags']
latest = E('evidence/from_revisit2/reopen_OURS.json')['flags']
jt = E('runs/reopen_judge_trace.json'); jcards = {c['wait']: c['status'] for c in jt['result']['cards']}
judge = {k: jcards.get(k) == 'reopen' for k in T}
keys = sorted(T)
ARMS = dict(watch_sealed=watch, watch_fixed={k: watch[k] and k not in RES for k in keys}, judge_sealed=judge,
            judge_fixed={k: judge[k] and k not in RES for k in keys}, latest_only=latest,
            R0={k: base[k]['R0'] for k in keys}, R1={k: base[k]['R1'] for k in keys}, R2={k: r2.get(k, False) for k in keys})
TRUTH = dict(original={k: T[k]['met'] for k in keys}, corrected={k: T[k]['met'] and k not in RES for k in keys})


def f1(p, g):
    tp = sum(a and b for a, b in zip(p, g)); fp = sum(a and not b for a, b in zip(p, g)); fn = sum(b and not a for a, b in zip(p, g))
    pr = tp / (tp + fp) if tp + fp else 0; rc = tp / (tp + fn) if tp + fn else 0
    return (2 * pr * rc / (pr + rc) if pr + rc else 0), dict(tp=tp, fp=fp, fn=fn, flagged=tp + fp)


out = dict(note=__doc__.split('Usage')[0].strip(), resolved=RES, resolved_flagged_by_watch=sorted(k for k in RES if watch.get(k)))
for tn, truth in TRUTH.items():
    g = [truth[k] for k in keys]; res = {}
    for a, fl in ARMS.items():
        v, d = f1([fl[k] for k in keys], g); res[a] = dict(F1=round(v, 4), **d)
    rnd = random.Random(11); n = len(keys); diffs = {b: [] for b in ('R2', 'R0', 'watch_sealed')}
    for _ in range(2000):
        ii = [rnd.randrange(n) for _ in range(n)]; gg = [g[i] for i in ii]
        fo = f1([ARMS['watch_fixed'][keys[i]] for i in ii], gg)[0]
        for b in diffs: diffs[b].append(fo - f1([ARMS[b][keys[i]] for i in ii], gg)[0])
    for b, d in diffs.items():
        d.sort(); res[f'watch_fixed_minus_{b}'] = dict(point=round(res['watch_fixed']['F1'] - res[b]['F1'], 4), ci95=[round(d[50], 4), round(d[1949], 4)])
    rnd = random.Random(11); d = []
    for _ in range(2000):
        ii = [rnd.randrange(n) for _ in range(n)]; gg = [g[i] for i in ii]
        d.append(f1([ARMS['watch_sealed'][keys[i]] for i in ii], gg)[0] - f1([ARMS['R2'][keys[i]] for i in ii], gg)[0])
    d.sort(); res['watch_sealed_minus_R2'] = dict(point=round(res['watch_sealed']['F1'] - res['R2']['F1'], 4), ci95=[round(d[50], 4), round(d[1949], 4)])
    out[tn] = res
json.dump(out, open(os.path.join(ROOT, 'runs', 'reopen_rescore_resolved.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
for tn in TRUTH: print(tn, {a: (v['F1'], v['fp'], v['fn']) for a, v in out[tn].items() if 'F1' in v}, {a: v for a, v in out[tn].items() if 'minus' in a})
print('resolved & flagged by the watch:', out['resolved_flagged_by_watch'])
