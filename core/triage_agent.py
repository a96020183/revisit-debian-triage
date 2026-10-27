"""[revisit3 copy of ../revisit/triage_agent.py. Changes, all marked REVISIT3: data files are the news exam's
 (data/news_items.json, data/news_events.json); when an item has drop_own_cve_history (its CVE was already in the earliest
 snapshot) every record of that CVE is removed from what S and OURS see; Nightshift client = core/nightshift.py. Prompts,
 arms, Planner/Executor/Evaluator logic are unchanged.]
Revisit decision two (new CVE -> one of four decisions) for the day-one gates.
Arms (all via Nightshift, same requested Nemotron model, same item facts, same policy text):
  L0   : policy + item facts, no past decisions
  S    : + the package's 20 most recent tracker decision events (raw lines, superseded ones included)  [strong baseline]
  OURS : Planner reads H-MEM (current stances, superseded excluded/penalised, relevance-ranked recall, stance changes)
         -> Executor decides -> Evaluator checks (cited past decision? deviation explained? not-affected evidence?)
Time wall: each item only sees tracker snapshots up to the snapshot before its CVE first appeared.
Predictions are cached in runs/preds_<arm>.jsonl so a crash/restart resumes.
Usage: python -I triage_agent.py ARM SUBSET [--limit N]     SUBSET in dev|s300|sub|gate (= s300 ∪ sub)"""
import sys, os, json, re, time, collections, threading, datetime
from concurrent.futures import ThreadPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import nightshift as ns   # REVISIT3: core/nightshift.py
from engines_client import Engines

MODEL = 'nvidia/nemotron-3-super-120b-a12b'   # requested lane; Nightshift reroutes, served model is logged per call
C = ['URGENT', 'NEXT', 'WONTFIX', 'NOTAFF']
SNAPS = ['2026-06-01', '2026-07-01', '2026-08-01', '2026-09-01', '2026-10-01']
ROOT = os.path.dirname(HERE)   # REVISIT3
ITEMS = json.load(open(os.path.join(ROOT, 'data/news_items.json'), encoding='utf-8'))
EVENTS = json.load(open(os.path.join(ROOT, 'data/news_events.json'), encoding='utf-8'))

POLICY = """You triage a newly published CVE for Debian 12 "bookworm", which is now maintained by the Debian LTS team.
Pick exactly one decision for this (CVE, source package) in bookworm:
- URGENT: fix now. The LTS team ships a security update (DLA) for bookworm.
- NEXT: affected but deferred. Marked <no-dsa> or <postponed> ("Minor issue", "revisit when fixed upstream"); may be fixed later in a batch or point release.
- WONTFIX: will not be fixed. Marked <ignored> (too intrusive to backport, unsupported or limited-support package) or "unimportant" (crosses no security boundary, only affects tools/tests/examples, not a real issue in Debian's build).
- NOTAFF: bookworm is not affected. The vulnerable code is not in the bookworm version (introduced later), or the affected feature is not built or shipped in Debian.
LTS deliberately batches minor issues and spends DLAs on issues with real impact. A package's own past decisions are the best guide to how this team treats it."""

ANSWER = 'Reply with one JSON object only: {"decision": "URGENT|NEXT|WONTFIX|NOTAFF", "reason": "<one or two sentences>", "cites": ["<CVE ids of past decisions you relied on>"]}'


def facts(it):
    return (f"Package: {it['pkg']}\nBookworm ships version: {it['bw_version'] or 'unknown'}\nAttack scope (tracker): {it['scope'] or 'unknown'}\n"
            f"On Debian's limited-security-support list: {'yes' if it['limited_support'] else 'no'}\n"
            f"CVE: {it['cve']}\nDescription: {it['desc'][:1200]}")


def visible_events(pkg, wall, drop=None):
    return [e for e in EVENTS.get(pkg, []) if e['snap'] <= wall and e['cve'] != drop]   # REVISIT3: drop own CVE


def cve_num(c):
    m = re.match(r'CVE-(\d+)-(\d+)', c); return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def recent_events(pkg, wall, k=20, drop=None):
    ev = visible_events(pkg, wall, drop)
    ev.sort(key=lambda e: (e['snap'], cve_num(e['cve'])), reverse=True)
    return ev[:k]


def parse_decision(text):
    m = re.search(r'\{.*\}', text, re.S)
    if m:
        try:
            d = json.loads(m.group(0)); dec = str(d.get('decision', '')).upper().strip()
            if dec in C: return dec, d
        except Exception: pass
    m = re.search(r'"?decision"?\s*[:=]\s*"?(URGENT|NEXT|WONTFIX|NOTAFF)', text, re.I)
    if m: return m.group(1).upper(), {'reason': text[-300:]}
    hits = [c for c in C if re.search(r'\b' + c + r'\b', text)]
    return (hits[-1] if hits else 'NEXT'), {'reason': 'unparsed: ' + text[-200:], 'parse_fail': True}


def ask(messages, tag, max_tokens=6000):
    r = ns.chat(messages, MODEL, max_tokens=max_tokens, temperature=0.0, tag=tag, timeout=300)
    return r


# ---------------------------------------------------------------- arms
def run_L0(it, ctx):
    r = ask([{'role': 'system', 'content': POLICY}, {'role': 'user', 'content': facts(it) + '\n\n' + ANSWER}], f'L0:{it["cve"]}:{it["pkg"]}')
    dec, d = parse_decision(r['text']); return dict(pred=dec, reason=d.get('reason'), calls=[call_meta(r)])


def fmt_event(e):
    return f"[{e['snap']}] {e['cve']}: {e['bw'] or '(no bookworm line)'} | {e['sid'] or ''} | {e['desc'][:160]}"


def run_S(it, ctx):
    ev = recent_events(it['pkg'], it['wall'], drop=own(it))   # REVISIT3
    hist = '\n'.join(fmt_event(e) for e in ev) if ev else '(no past decisions recorded for this package)'
    msg = (facts(it) + f"\n\nThe package's {len(ev)} most recent decision events in the Debian security tracker (newest first; raw tracker lines, later changes appear as new events):\n"
           + hist + '\n\n' + ANSWER)
    r = ask([{'role': 'system', 'content': POLICY}, {'role': 'user', 'content': msg}], f'S:{it["cve"]}:{it["pkg"]}')
    dec, d = parse_decision(r['text']); return dict(pred=dec, reason=d.get('reason'), cites=d.get('cites'), calls=[call_meta(r)])


def own(it):
    """REVISIT3: the CVE whose own records must be hidden from this item (None for almost every item)"""
    return it['cve'] if it.get('drop_own_cve_history') else None


def call_meta(r):
    return dict(served=r['served'], usage=r['usage'])


class Memory:
    """Loads tracker decision events into H-MEM chronologically (time wall per snapshot)."""
    def __init__(self, pkgs):
        self.e = Engines(); self.loaded = None; self.pkgs = pkgs; self.lock = threading.Lock()

    def advance_to(self, wall):
        with self.lock:
            start = 0 if self.loaded is None else SNAPS.index(self.loaded) + 1
            for s in SNAPS[start:SNAPS.index(wall) + 1]:
                self.e.call('set_clock', t=s + 'T00:00:00Z')
                batch = []
                for p in sorted(self.pkgs):
                    for ev in EVENTS.get(p, []):
                        if ev['snap'] != s: continue
                        note = re.sub(r'\s+', ' ', ' '.join(ev['notes']))[:160]
                        batch.append(dict(content=f"{p} {ev['cve']}: bookworm decision {ev['cls']}. Tracker: {ev['bw'] or ev['sid']}. {ev['desc'][:220]} {note}",
                                          source='lts_tracker', confidence=0.9, layer='long_term', domain=p, type='factual',
                                          claimKey=f"{p}|{ev['cve']}", claimValue=ev['cls'], supersedeCurrent=True,
                                          entities=[{'name': p, 'type': 'package'}, {'name': ev['cve'].lower(), 'type': 'cve'}],
                                          tags=[f"decision:{ev['cls']}", f"snap:{s}"], meta={'snap': s, 'cve': ev['cve'], 'prev': ev['prev']},
                                          timestamp=int(datetime.datetime.fromisoformat(s).replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)))
                for i in range(0, len(batch), 500): self.e.call('add_many', inputs=batch[i:i + 500])
                self.loaded = s

    def context(self, it):
        with self.lock:
            recs = self.e.call('domain_records', domain=it['pkg'])
            hits = self.e.call('query', q=f"{it['pkg']} {it['desc'][:600]}", opts=dict(domain=it['pkg'], topN=8, threshold=0.2, entities=[it['pkg']], touch=False), currentOnly=True)['hits']
        if own(it):   # REVISIT3: hide the item's own CVE
            recs = [m for m in recs if (m.get('meta') or {}).get('cve') != it['cve']]; hits = [h for h in hits if (h.get('meta') or {}).get('cve') != it['cve']]
        cur = [m for m in recs if not m.get('supersededBy')]
        sup = [m for m in recs if m.get('supersededBy')]
        byid = {m['id']: m for m in recs}
        changes = []
        for m in sup:
            nm = byid.get(m['supersededBy'])
            if nm: changes.append((nm['meta']['snap'], m['meta']['cve'], m['claimValue'], nm['claimValue']))
        changes.sort(reverse=True)
        cnt = collections.Counter(m['claimValue'] for m in cur)
        recent = [m for m in cur if m['meta']['snap'] >= '2026-07-01']
        rcnt = collections.Counter(m['claimValue'] for m in recent)
        return dict(n=len(cur), cnt=cnt, rcnt=rcnt, changes=changes, hits=hits)


def stance_line(c):
    return ', '.join(f'{k} {c[k]}' for k in C if c.get(k)) or 'none'


def run_OURS(it, mem):
    mc = mem.context(it)
    # Planner: route by what H-MEM holds
    route = 'deep' if mc['n'] == 0 else ('verify' if mc['changes'] else 'cheap')
    if mc['n'] == 0:
        memtxt = 'H-MEM has no past bookworm decision for this package. Decide from the policy and the facts.'
    else:
        lines = [f"Current stance of this package in H-MEM (superseded decisions excluded): {mc['n']} decisions: {stance_line(mc['cnt'])}.",
                 f"Since LTS took over (decisions recorded 2026-07-01 or later): {stance_line(mc['rcnt'])}."]
        if mc['changes']:
            lines.append('The team changed its mind on these (old -> current); prefer the current stance:')
            lines += [f"  [{s}] {c}: {a} -> {b}" for s, c, a, b in mc['changes'][:6]]
        lines.append('Most relevant current decisions recalled by H-MEM (relevance-ranked):')
        lines += [f"  - (score {h['score']:.2f}) {h['content'][:330]}" for h in mc['hits']] or ['  (none above threshold)']
        memtxt = '\n'.join(lines)
    msg = facts(it) + '\n\n' + memtxt + '\n\n' + ANSWER
    r1 = ask([{'role': 'system', 'content': POLICY}, {'role': 'user', 'content': msg}], f'OURS-exec:{it["cve"]}:{it["pkg"]}')
    dec, d = parse_decision(r1['text']); calls = [call_meta(r1)]
    dom = mc['cnt'].most_common(1)[0] if mc['n'] else None
    deviates = bool(dom and mc['n'] >= 4 and dom[1] / mc['n'] >= 0.5 and dec != dom[0])
    need_eval = deviates or dec == 'NOTAFF' or d.get('parse_fail')
    final, ev = dec, None
    if need_eval:
        emsg = (facts(it) + '\n\n' + memtxt + f"\n\nA triager proposed: {dec}. Reason: {d.get('reason')}. Cited: {d.get('cites')}\n\n"
                "You are the evaluator. Check: (1) Is the decision consistent with this package's current stance in H-MEM? "
                "(2) If it deviates, does the reason explain why this CVE is different? (3) For NOTAFF, is there concrete evidence that the bookworm version lacks the vulnerable code or feature (e.g. version ranges in the description vs the shipped version)? "
                "If the proposal passes, keep it; otherwise give the corrected decision.\n"
                'Reply with one JSON object only: {"verdict": "accept|revise", "decision": "URGENT|NEXT|WONTFIX|NOTAFF", "reason": "<one sentence>"}')
        r2 = ask([{'role': 'system', 'content': POLICY}, {'role': 'user', 'content': emsg}], f'OURS-eval:{it["cve"]}:{it["pkg"]}')
        calls.append(call_meta(r2)); dec2, d2 = parse_decision(r2['text'])
        ev = dict(verdict=d2.get('verdict'), decision=dec2, reason=d2.get('reason'))
        if str(d2.get('verdict', '')).lower() == 'revise': final = dec2
    return dict(pred=final, exec_pred=dec, route=route, evaluator=ev, reason=d.get('reason'), cites=d.get('cites'), calls=calls,
                mem=dict(n=mc['n'], changes=len(mc['changes']), hits=len(mc['hits'])))


ARMS = {'L0': run_L0, 'S': run_S, 'OURS': run_OURS}


def select(subset):
    if subset == 'dev': return [i for i in ITEMS if i['in_dev']]
    if subset == 's300': return [i for i in ITEMS if i['in_s300']]
    if subset == 'sub': return [i for i in ITEMS if i['in_sub']]
    if subset == 'gate': return [i for i in ITEMS if i['in_s300'] or i['in_sub']]
    raise SystemExit('bad subset')


def main():
    arms, subset = sys.argv[1].split(','), sys.argv[2]
    lim = int(sys.argv[sys.argv.index('--limit') + 1]) if '--limit' in sys.argv else None
    pc = int(sys.argv[sys.argv.index('--per-class') + 1]) if '--per-class' in sys.argv else None
    items = select(subset)
    items.sort(key=lambda i: (SNAPS.index(i['wall']), i['pkg'], i['cve']))   # chronological replay
    if pc:
        cnt = collections.Counter(); keep = []
        for i in items:
            if cnt[i['cls']] < pc: keep.append(i); cnt[i['cls']] += 1
        items = keep
    if lim: items = items[:lim]
    tasks = []
    for arm in arms:
        out = os.path.join(HERE, 'runs', f'preds_{arm}.jsonl'); done = set()
        if os.path.exists(out):
            for ln in open(out, encoding='utf-8'):
                r = json.loads(ln); done.add((r['cve'], r['pkg']))
        tasks += [(arm, i) for i in items if (i['cve'], i['pkg']) not in done]
    # interleave arms item by item so every arm covers the same items at any moment
    order = {(i['cve'], i['pkg']): k for k, i in enumerate(items)}
    tasks.sort(key=lambda t: (SNAPS.index(t[1]['wall']), order[(t[1]['cve'], t[1]['pkg'])], arms.index(t[0])))
    print(f'{arms} {subset}: {len(items)} items, {len(tasks)} tasks to run', flush=True)
    mem = Memory({i['pkg'] for i in ITEMS}) if 'OURS' in arms else None
    wlock = threading.Lock(); t0 = time.time(); n = [0]

    def one(task):
        arm, it = task
        try:
            res = ARMS[arm](it, mem)
        except Exception as e:
            res = dict(pred=None, error=str(e)[:300])
        rec = dict(cve=it['cve'], pkg=it['pkg'], gold=it['cls'], wall=it['wall'], **res)
        with wlock:
            if rec['pred'] is not None:
                with open(os.path.join(HERE, 'runs', f'preds_{arm}.jsonl'), 'a', encoding='utf-8') as f: f.write(json.dumps(rec, ensure_ascii=False) + chr(10))
            n[0] += 1
            print(f"[{n[0]}/{len(tasks)} {time.time()-t0:.0f}s] {arm} {it['pkg']} {it['cve']} gold={it['cls']} pred={rec['pred']} {rec.get('error','')}", flush=True)

    # replay wall by wall so H-MEM never holds snapshots after the item's wall
    for w in SNAPS:
        batch = [t for t in tasks if t[1]['wall'] == w]
        if not batch: continue
        if mem: mem.advance_to(w)
        with ThreadPoolExecutor(3) as ex: list(ex.map(one, batch))   # Nightshift client caps in-flight requests at 2
    if mem: mem.e.close()


if __name__ == '__main__':
    main()
