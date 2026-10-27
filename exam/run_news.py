"""Run the sealed news exam: evidence path (S) and memory path (OURS) for every item, through Nightshift only.
Order: the 285 (news item, matched mix item) pairs in the sealed random order (random.Random(20261027).shuffle of the pairs
sorted by news key). Inside a pair: news item then mix item; inside an item: S then OURS. One request in flight in total.
H-MEM: one memory per time wall, loaded chronologically up to that wall (never later snapshots).
Stops starting new pairs at STOP (2026-10-27 05:30 +08:00). Resumable: runs/news_preds_<arm>.jsonl.
GATED needs no extra call: it is the frozen gatekeeper (core/gate.py) over the two answers + H-MEM features.
Usage: REVISIT_SCOPE=iso python -I exam/run_news.py"""
import sys, os, json, time, io, random, datetime
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'core'))
assert os.environ.get('REVISIT_SCOPE') == 'iso', 'scored runs use REVISIT_SCOPE=iso'
import triage_agent as T
ITEMS = T.ITEMS
STOP = datetime.datetime(2026, 10, 27, 5, 30, tzinfo=datetime.timezone(datetime.timedelta(hours=8)))
K = lambda r: f"{r['cve']}|{r['pkg']}"


def pair_order():
    pairs = sorted({i['pair'] for i in ITEMS})
    random.Random(20261027).shuffle(pairs)
    by = {}
    for i in ITEMS: by.setdefault(i['pair'], []).append(i)
    return [(p, sorted(by[p], key=lambda i: i['set'] != 'news')) for p in pairs]


def done(arm):
    p = os.path.join(ROOT, 'runs', f'news_preds_{arm}.jsonl'); s = set()
    if os.path.exists(p):
        for ln in open(p, encoding='utf-8'): s.add(K(json.loads(ln)))
    return s


def main():
    D = {a: done(a) for a in ('S', 'OURS')}; mems = {}; t0 = time.time(); n = 0
    order = pair_order()
    for pi, (pair, its) in enumerate(order, 1):
        if all(K(i) in D[a] for i in its for a in D): continue
        if datetime.datetime.now(datetime.timezone.utc) > STOP: print('STOP time reached; no new pairs'); break
        for it in its:
            for arm in ('S', 'OURS'):
                if K(it) in D[arm]: continue
                mem = None
                if arm == 'OURS':
                    if it['wall'] not in mems: mems[it['wall']] = T.Memory({i['pkg'] for i in ITEMS}); mems[it['wall']].advance_to(it['wall'])
                    mem = mems[it['wall']]
                try: res = T.ARMS[arm](it, mem)
                except Exception as e: res = dict(pred=None, error=str(e)[:300])
                rec = dict(cve=it['cve'], pkg=it['pkg'], gold=it['cls'], set=it['set'], pair=pair, wall=it['wall'], **res)
                if rec['pred'] is not None:
                    with open(os.path.join(ROOT, 'runs', f'news_preds_{arm}.jsonl'), 'a', encoding='utf-8') as f: f.write(json.dumps(rec, ensure_ascii=False) + chr(10))
                    D[arm].add(K(it))
                n += 1
                print(f"[pair {pi}/{len(order)} {time.time()-t0:.0f}s] {arm} {it['pkg']} {it['cve']} pred={rec['pred']} {rec.get('error','')}", flush=True)
    for m in mems.values(): m.e.close()


if __name__ == '__main__':
    main()
