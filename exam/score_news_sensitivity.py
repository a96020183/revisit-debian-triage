"""Post-hoc sensitivity analyses of the sealed news exam (NOT part of the sealed procedure; QA round 1). Same scorer
(exam/score_news.py), restricted item sets; results in runs/news_score_<name>.json and runs/news_sensitivity.json.
  excl_postwall  drop every pair whose inputs carried data from after the time wall: the items whose shown bookworm version first
                 appeared in any Debian archive after the item's wall (snapshot.debian.org; runs/leak_check_versions.json; for jq
                 CVE-2026-32316 that version is the CVE's own fix) and the 6 wall-2026-10-01 items of nodejs (4) and expat (2) whose
                 history holds URGENT labels resting on a DLA dated the wall day itself. Both decision paths saw the same facts; the history reached both (raw for S, via H-MEM for OURS).
  same_period    keep only pairs whose news item has wall 2026-09-01 or 2026-10-01, the walls where mix items exist (the mix pool
                 was drawn from CVEs first seen after 2026-09-01, the news set from any wall)
Usage: python -I exam/score_news_sensitivity.py"""
import os, sys, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'exam')); sys.path.insert(0, os.path.join(ROOT, 'core'))
import score_news as SN
ALL = json.load(open(os.path.join(ROOT, 'data/news_items.json'), encoding='utf-8'))
LV = json.load(open(os.path.join(ROOT, 'runs/leak_check_versions.json'), encoding='utf-8'))   # scripts/check_version_leaks.py
leak = {(x['cve'], x['pkg']) for x in LV['sealed_leaks']}
bad_pairs = {i['pair'] for i in ALL if (i['cve'], i['pkg']) in leak or (i['wall'] == '2026-10-01' and i['pkg'] in ('nodejs', 'expat'))}
news_wall = {i['pair']: i['wall'] for i in ALL if i['set'] == 'news'}
SETS = dict(excl_postwall=lambda i: i['pair'] not in bad_pairs, same_period=lambda i: news_wall[i['pair']] in ('2026-09-01', '2026-10-01'))
res = {}
for name, keep in SETS.items():
    SN.ITEMS = [i for i in ALL if keep(i)]
    SN.R = lambda p, name=name: os.path.join(ROOT, p.replace('news_score.json', f'news_score_{name}.json'))
    SN.main()
    s = json.load(open(os.path.join(ROOT, 'runs', f'news_score_{name}.json'), encoding='utf-8'))
    res[name] = dict(n_pairs=s['n_pairs'], gold=s['gold'], gate=s['gate'], URGENT_F1={a: s['arms'][a]['URGENT_F1'] for a in ('GATED', 'S', 'OURS', 'NN', 'pkg_mode')},
                     GATED_minus_S=s['diffs_URGENT_F1']['GATED-S'], GATED_minus_OURS=s['diffs_URGENT_F1']['GATED-OURS'])
json.dump(dict(note=__doc__.split('Usage')[0].strip(), bad_pairs=sorted(bad_pairs), results=res), open(os.path.join(ROOT, 'runs', 'news_sensitivity.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
