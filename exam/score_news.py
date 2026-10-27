"""Score the sealed news exam exactly as prereg_news.json says. Writes runs/news_score.json.
Scored set = every pair whose two items both have an S and an OURS answer (pairs are run in sealed random order, so the
completed pairs are a random subset). The gate needs at least MIN_PAIRS complete pairs.
Usage: python -I exam/score_news.py"""
import sys, os, json, collections, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'core'))
import eval_core as E
import gate as G
MIN_PAIRS = 50
R = lambda p: os.path.join(ROOT, p)
ITEMS = json.load(open(R('data/news_items.json'), encoding='utf-8'))
FEAT = json.load(open(R('data/news_feat.json'), encoding='utf-8'))
K = lambda r: f"{r['cve']}|{r['pkg']}"


def loadp(a):
    p = R(f'runs/news_preds_{a}.jsonl'); d = {}
    if os.path.exists(p):
        for ln in open(p, encoding='utf-8'): r = json.loads(ln); d[K(r)] = r
    return d


def stats(p, g):
    m, per = E.mf1(p, g)
    return dict(URGENT_F1=round(E.cf1(p, g), 4), URGENT_recall=round(E.crec(p, g), 4), URGENT_precision=per['URGENT']['precision'],
                macroF1=round(m, 4), acc=round(sum(a == b for a, b in zip(p, g)) / max(1, len(g)), 4), per_class=per)


def cost(rs):
    calls = [c for r in rs for c in r.get('calls', [])]
    return dict(calls_per_item=round(len(calls) / max(1, len(rs)), 3),
                prompt_tokens_per_item_estimated=round(sum((c.get('usage') or {}).get('prompt_tokens', 0) for c in calls) / max(1, len(rs))),
                served=dict(collections.Counter(c['served'] for c in calls)))


def main():
    S, O = loadp('S'), loadp('OURS')
    by = collections.defaultdict(list)
    for i in ITEMS: by[i['pair']].append(i)
    pairs = [p for p, its in by.items() if all(K(i) in S and K(i) in O for i in its)]
    common = [i for p in sorted(pairs) for i in sorted(by[p], key=lambda i: i['set'] != 'news')]
    out = dict(n_pairs=len(pairs), n_items=len(common), gold=dict(collections.Counter(i['cls'] for i in common)),
               coverage=dict(S=len(S), OURS=len(O), total_items=len(ITEMS)))
    if not common:
        json.dump(out, open(R('runs/news_score.json'), 'w', encoding='utf-8'), indent=1); print(out); return
    ks = [K(i) for i in common]; g = [i['cls'] for i in common]
    ps = [S[k]['pred'] for k in ks]; po = [O[k]['pred'] for k in ks]
    dec = [G.decide(FEAT[k], S[k]['pred'], O[k]['pred']) for k in ks]; pg = [d[0] for d in dec]
    nn, mode, r1 = E.base_preds(common)
    def no_hmem_rule(f, s, o): return o if s == o else (s if s in G.CLASS_UNRELIABLE else o)
    pa = [no_hmem_rule(FEAT[k], S[k]['pred'], O[k]['pred']) for k in ks]
    arms = dict(S=ps, OURS=po, GATED=pg, NN=nn, R1=r1, pkg_mode=mode, ablation_gate_without_HMEM_rule=pa)
    out['arms'] = {a: stats(p, g) for a, p in arms.items()}
    pkgs = [i['pkg'] for i in common]
    out['diffs_URGENT_F1'] = {f'GATED-{b}': dict(point=round(E.cf1(pg, g) - E.cf1(arms[b], g), 4), ci95=E.boot_diff(pg, arms[b], g, E.cf1),
                                                 ci95_package_clusters=E.boot_diff(pg, arms[b], g, E.cf1, clusters=pkgs))
                              for b in ('S', 'OURS', 'NN', 'R1', 'pkg_mode', 'ablation_gate_without_HMEM_rule')}
    out['diffs_URGENT_recall'] = {f'GATED-{b}': dict(point=round(E.crec(pg, g) - E.crec(arms[b], g), 4), ci95=E.boot_diff(pg, arms[b], g, E.crec))
                                  for b in ('S', 'OURS', 'NN', 'R1')}
    out['diffs_macroF1'] = {f'GATED-{b}': dict(point=round(E.mf1(pg, g)[0] - E.mf1(arms[b], g)[0], 4), ci95=E.boot_diff(pg, arms[b], g, lambda p, gg: E.mf1(p, gg)[0]))
                            for b in ('S', 'OURS', 'NN')}
    news = [j for j, i in enumerate(common) if i['set'] == 'news']
    out['news_half_only'] = {a: stats([p[j] for j in news], [g[j] for j in news]) for a, p in arms.items() if a in ('S', 'OURS', 'GATED', 'NN', 'R1')}
    out['gate_rules'] = {r: dict(n=sum(1 for d in dec if d[1] == r), chosen_right=sum(1 for d, gg in zip(dec, g) if d[1] == r and d[0] == gg),
                                 OURS_right=sum(1 for d, gg, o in zip(dec, g, po) if d[1] == r and o == gg),
                                 S_right=sum(1 for d, gg, s in zip(dec, g, ps) if d[1] == r and s == gg)) for r in sorted(set(d[1] for d in dec))}
    cS, cO = cost([S[k] for k in ks]), cost([O[k] for k in ks])
    out['cost'] = dict(S=cS, OURS=cO, GATED_calls_per_item=round(cS['calls_per_item'] + cO['calls_per_item'], 3))
    ok = len(pairs) >= MIN_PAIRS; ci = out['diffs_URGENT_F1']['GATED-S']['ci95']
    out['gate'] = dict(rule=f'GATED - S URGENT F1, paired bootstrap 2,000 (seed 11) lower 95% bound > 0, with >= {MIN_PAIRS} complete pairs',
                       ci95=ci, n_pairs=len(pairs), evaluable=ok, pass_=bool(ok and ci[0] > 0))
    out['php2shell'] = [dict(cve=i['cve'], pkg=i['pkg'], gold=i['cls'], S=S[K(i)]['pred'], OURS=O[K(i)]['pred'], GATED=pg[ks.index(K(i))], rule=dec[ks.index(K(i))][1])
                        for i in common if i['cve'] in ('CVE-2026-109618', 'CVE-2026-109619')]
    out['blocked'] = [dict(cve=i['cve'], pkg=i['pkg'], gold=i['cls'], OURS=O[k]['pred'], S=S[k]['pred'], GATED=d[0], rule=d[1])
                      for i, k, d in zip(common, ks, dec) if d[1] not in ('agree', 'trust_memory')]
    json.dump(out, open(R('runs/news_score.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps(dict(n_pairs=out['n_pairs'], gate=out['gate'], URGENT_F1={a: v['URGENT_F1'] for a, v in out['arms'].items()},
                          URGENT_recall={a: v['URGENT_recall'] for a, v in out['arms'].items()}), ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
