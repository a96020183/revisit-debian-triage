"""Measure the reopen judge (pre-registered in prereg_reopen_judge.json before any judge call).
Runs the product's own reopen loop (app/pipeline.py Revisit.reopen) over every wait the daily Zetaris watch flags, then scores
"reopened" against the objective truth of the 286 waits (evidence/from_revisit2/reopen_truth.json, computed 2026-10-24 from
Debian unstable, upstream release tags and OSV; no labels by people or models).
Usage: REVISIT_SCOPE=iso python -I exam/run_reopen_judge.py"""
import os, sys, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'app'))
assert os.environ.get('REVISIT_SCOPE') == 'iso'
import pipeline as P
import evidence as EV


def f1(flags, truth):
    tp = sum(flags[k] and truth[k]['met'] for k in truth); fp = sum(flags[k] and not truth[k]['met'] for k in truth); fn = sum(truth[k]['met'] and not flags[k] for k in truth)
    pr = tp / (tp + fp) if tp + fp else 0; rc = tp / (tp + fn) if tp + fn else 0
    return dict(F1=round(2 * pr * rc / (pr + rc) if pr + rc else 0, 4), tp=tp, fp=fp, fn=fn, flagged=tp + fp)


def main():
    truth = json.load(open(os.path.join(ROOT, 'evidence/from_revisit2/reopen_truth.json'), encoding='utf-8'))
    due, _ = EV.reopen_due(); keys = sorted({r['wait_id'] for r in due})
    R = P.Revisit()
    try: tr = R.reopen(keys, {})
    finally: R.close()
    cards = {c['wait']: c for c in tr.d['result']['cards']}
    watch = {k: k in cards for k in truth}
    judged = {k: (k in cards and cards[k]['status'] == 'reopen') for k in truth}
    out = dict(n=len(truth), flagged_by_watch=len(keys), watch_only=f1(watch, truth), watch_plus_judge=f1(judged, truth),
               judge=dict(yes=sum(c['status'] == 'reopen' for c in cards.values()), no=sum(c['status'] == 'waiting' for c in cards.values()),
                          needs_lead=sum(c['status'] == 'needs_lead' for c in cards.values())),
               dropped_true=[k for k in keys if truth[k]['met'] and not judged[k]],
               verifier_send_backs=sum(1 for e in tr.d['events'] if e['agent'] == 'verifier' and not e['detail'].get('ok', True)))
    json.dump(tr.d, open(os.path.join(ROOT, 'runs', 'reopen_judge_trace.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=0)
    json.dump(out, open(os.path.join(ROOT, 'runs', 'reopen_judge_score.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
