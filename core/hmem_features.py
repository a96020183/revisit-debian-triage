"""Memory gatekeeper features, computed from H-MEM only (no model call, never the answer).
Replays the tracker decision events into H-MEM wall by wall (same Memory class as the OURS arm), and for each item reads:
  - the package's current stances (superseded decisions excluded by H-MEM supersession) and their counts
  - the stance changes H-MEM recorded (supersedes / supersededBy chains)
  - H-MEM relevance recall (top hits and their decisions)
  - memory self-reliability: walking the package's current records in time order, how often "the package's dominant
    stance so far" would have predicted the next recorded decision (overall and per predicted class). This is the
    package's own track record of being predictable from memory.
Usage: python -I hmem_features.py OUT.json   (revisit3 copy of ../revisit2/hmem_features.py; own-CVE filter added)"""
import sys, os, json, re, collections, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)   # revisit3 copy: core/triage_agent.py
CWD0 = os.getcwd()
import triage_agent as T

C = T.C


def cve_num(c):
    m = re.match(r'CVE-(\d+)-(\d+)', c or ''); return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def self_reliability(cur):
    """cur: current records (dict with meta.snap, meta.cve, claimValue). Chronological 'dominant stance so far' predictor."""
    recs = sorted(cur, key=lambda m: (m['meta']['snap'], cve_num(m['meta']['cve'])))
    cnt = collections.Counter(); tot = ok = 0; per = collections.Counter(); per_ok = collections.Counter()
    for m in recs:
        if sum(cnt.values()) >= 2:
            p = cnt.most_common(1)[0][0]; tot += 1; per[p] += 1
            if p == m['claimValue']: ok += 1; per_ok[p] += 1
        cnt[m['claimValue']] += 1
    return dict(n=tot, acc=(ok / tot if tot else None), per={c: (per_ok[c] / per[c] if per[c] else None) for c in C}, per_n=dict(per))


def item_features(mem, it):
    with mem.lock:
        recs = mem.e.call('domain_records', domain=it['pkg'])
        hits = mem.e.call('query', q=f"{it['pkg']} {it['desc'][:600]}", opts=dict(domain=it['pkg'], topN=8, threshold=0.2, entities=[it['pkg']], touch=False), currentOnly=True)['hits']
    if T.own(it):   # revisit3: hide the item's own CVE (same filter as triage_agent.Memory.context)
        recs = [m for m in recs if (m.get('meta') or {}).get('cve') != it['cve']]; hits = [h for h in hits if (h.get('meta') or {}).get('cve') != it['cve']]
    cur = [m for m in recs if not m.get('supersededBy')]; sup = [m for m in recs if m.get('supersededBy')]
    cnt = collections.Counter(m['claimValue'] for m in cur)
    dom = cnt.most_common(1)[0] if cur else (None, 0)
    call = collections.Counter(m['claimValue'] for m in recs); doma = call.most_common(1)[0][0] if recs else None   # ablation: no supersession
    return dict(n=len(cur), n_superseded=len(sup), cnt=dict(cnt), dom=dom[0], dom_share=(dom[1] / len(cur) if cur else 0), n_all=len(recs), dom_all=doma,
                hits=[dict(v=h['claimValue'], s=round(h['score'], 3)) for h in hits], rel=self_reliability(cur))


def run(items):
    items = sorted(items, key=lambda i: (T.SNAPS.index(i['wall']), i['pkg'], i['cve']))
    mem = T.Memory({i['pkg'] for i in T.ITEMS} | {i['pkg'] for i in items}); out = {}
    for w in T.SNAPS:
        b = [i for i in items if i['wall'] == w]
        if not b: continue
        mem.advance_to(w)
        for it in b: out[f"{it['cve']}|{it['pkg']}"] = item_features(mem, it)
    mem.e.close(); return out


if __name__ == '__main__':
    outp = os.path.join(CWD0, sys.argv[1]); items = T.ITEMS   # revisit3: news exam items
    F = run(items)
    json.dump(F, open(outp, 'w', encoding='utf-8'), ensure_ascii=False, indent=0); print('news', len(F))
