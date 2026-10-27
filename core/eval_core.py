"""Scoring helpers. mf1 / boot / TF-IDF nearest neighbour are copied from ../revisit/eval_gates.py (unchanged maths);
revisit3 adds: per-class F1 bootstrap (URGENT), the own-CVE history filter, and the R1 rule baseline."""
import json, os, re, math, random, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
C = ['URGENT', 'NEXT', 'WONTFIX', 'NOTAFF']
EVENTS = json.load(open(os.path.join(ROOT, 'data/news_events.json'), encoding='utf-8'))


def per_class(pred, gold):
    per = {}
    for c in C:
        tp = sum(p == c and g == c for p, g in zip(pred, gold)); pp = sum(p == c for p in pred); ap = sum(g == c for g in gold)
        pr = tp / pp if pp else 0; rc = tp / ap if ap else 0
        per[c] = dict(tp=tp, pred=pp, gold=ap, precision=round(pr, 4), recall=round(rc, 4), f1=round(2 * pr * rc / (pr + rc) if pr + rc else 0, 4))
    return per


def mf1(pred, gold):
    per = per_class(pred, gold); return sum(per[c]['f1'] for c in C) / 4, per


def cf1(pred, gold, c='URGENT'):
    tp = sum(p == c and g == c for p, g in zip(pred, gold)); pp = sum(p == c for p in pred); ap = sum(g == c for g in gold)
    pr = tp / pp if pp else 0; rc = tp / ap if ap else 0
    return 2 * pr * rc / (pr + rc) if pr + rc else 0


def crec(pred, gold, c='URGENT'):
    ap = sum(g == c for g in gold); return sum(p == c and g == c for p, g in zip(pred, gold)) / ap if ap else 0


def boot_diff(a, b, gold, metric, B=2000, seed=11, clusters=None):
    """paired bootstrap of metric(a) - metric(b); resample items (or whole clusters when clusters is given).
    95% interval = sorted[int(0.025B)], sorted[int(0.975B)-1] as in ../revisit/eval_gates.py"""
    rnd = random.Random(seed); n = len(gold); d = []
    if clusters:
        groups = collections.defaultdict(list)
        for i, c in enumerate(clusters): groups[c].append(i)
        keys = sorted(groups)
    for _ in range(B):
        if clusters: ii = [i for _k in range(len(keys)) for i in groups[keys[rnd.randrange(len(keys))]]]
        else: ii = [rnd.randrange(n) for _ in range(n)]
        g = [gold[i] for i in ii]
        d.append(metric([a[i] for i in ii], g) - metric([b[i] for i in ii], g))
    d.sort()
    return round(d[int(0.025 * B)], 4), round(d[int(0.975 * B) - 1], 4)


def walled_history(it):
    cur = {}
    drop = it['cve'] if it.get('drop_own_cve_history') else None
    for e in EVENTS.get(it['pkg'], []):
        if e['snap'] <= it['wall'] and e['cve'] != drop: cur[e['cve']] = e
    return list(cur.values())


TOK = lambda s: set(re.findall(r'[a-z]{3,}', s.lower()))
ALL_DESC = [e['desc'] for v in EVENTS.values() for e in v]
DF = collections.Counter(); [DF.update(TOK(d)) for d in ALL_DESC]; N = len(ALL_DESC)
def vec(s): return {w: math.log(N / (1 + DF[w])) for w in TOK(s)}
def cos(a, b):
    s = sum(a[w] * b.get(w, 0) for w in a); return s / (math.sqrt(sum(v * v for v in a.values())) * math.sqrt(sum(v * v for v in b.values())) + 1e-9)


def cve_num(c):
    m = re.match(r'CVE-(\d+)-(\d+)', c); return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def base_preds(items):
    """NN (time-walled TF-IDF nearest past decision in the package), package mode, and R1 (repeat the package's most recent
    recorded decision). All fall back to NEXT when the package has no history."""
    nn, mode, r1 = [], [], []
    for it in items:
        h = walled_history(it)
        if not h: nn.append('NEXT'); mode.append('NEXT'); r1.append('NEXT'); continue
        mode.append(collections.Counter(e['cls'] for e in h).most_common(1)[0][0])
        v = vec(it['desc']); nn.append(max(h, key=lambda e: cos(v, vec(e['desc'])))['cls'])
        r1.append(max(h, key=lambda e: (e['snap'], cve_num(e['cve'])))['cls'])
    return nn, mode, r1
