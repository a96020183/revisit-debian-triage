"""Post-hoc sensitivity (NOT part of the sealed procedure; written 2026-10-27 after scoring).
What happened: two copies of exam/run_news.py ran at the same time from the start (a launch that looked failed had in fact
started), so almost every item got two independent answers per arm, appended to the same file, and two requests were in
flight instead of one. The sealed scorer (exam/score_news.py, hash in prereg_news.json) keeps the LAST answer per item.
This script re-scores with the FIRST answer per item, and with each item's two answers treated as replicate A / B,
so the reader can see whether the verdict depends on which copy is used. Output: runs/news_score_duplicates.json."""
import os, sys, json, io, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'exam')); sys.path.insert(0, os.path.join(ROOT, 'core'))
import score_news as SN   # it wraps stdout once
K = lambda r: f"{r['cve']}|{r['pkg']}"
lines = {a: [json.loads(l) for l in open(os.path.join(ROOT, 'runs', f'news_preds_{a}.jsonl'), encoding='utf-8')] for a in ('S', 'OURS')}
out = dict(lines={a: len(v) for a, v in lines.items()}, distinct={a: len({K(r) for r in v}) for a, v in lines.items()},
           items_with_two_answers={a: sum(1 for c in collections.Counter(K(r) for r in v).values() if c > 1) for a, v in lines.items()},
           )
dis = {}
for a, v in lines.items():
    g = collections.defaultdict(list)
    for r in v: g[K(r)].append(r['pred'])
    dis[a] = sum(1 for p in g.values() if len(p) > 1 and len(set(p)) > 1)
out['two_answers_disagree'] = dis


def pick(which):
    sel = {}
    for a, v in lines.items():
        d = {}
        for r in v:
            k = K(r)
            if which == 'first': d.setdefault(k, r)
            elif which == 'last': d[k] = r
            elif which in ('second_or_only',): d.setdefault(k, []).append(r)
        if which == 'second_or_only': d = {k: rs[1] if len(rs) > 1 else rs[0] for k, rs in d.items()}
        sel[a] = d
    return sel


res = {}
for which in ('last', 'first', 'second_or_only'):
    sel = pick(which)
    SN.loadp = lambda a, sel=sel: sel[a]
    SN.R = lambda p, which=which: os.path.join(ROOT, p.replace('news_score.json', f'news_score_{which}.json'))
    SN.main()
    s = json.load(open(os.path.join(ROOT, 'runs', f'news_score_{which}.json'), encoding='utf-8'))
    res[which] = dict(n_pairs=s['n_pairs'], gate=s['gate'], URGENT_F1={a: s['arms'][a]['URGENT_F1'] for a in ('GATED', 'S', 'OURS', 'NN', 'R1')},
                      URGENT_recall={a: s['arms'][a]['URGENT_recall'] for a in ('GATED', 'S', 'OURS')})
out['scoring'] = res
json.dump(out, open(os.path.join(ROOT, 'runs', 'news_score_duplicates.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print(json.dumps(out, ensure_ascii=False, indent=1))
