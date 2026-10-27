"""Pick the demo cases by fixed rules. Written 2026-10-27 after the sealed exam was scored (03:06 first version; this version
after QA round 1). "first" always means first in sorted (CVE, package) order unless stated. No package is named in a rule;
PHP2Shell is named because the brief asked for that replay.

Triage (sealed-exam items; the paths' answers are the exam's own):
  1. both PHP2Shell items (CVE-2026-109618, CVE-2026-109619, php8.2)
  2. Scout overruled memory and was right (first)
  3. Scout overruled memory and was wrong (first)
  4. an urgent news item Revisit missed (first)
  5. a routine deferral both paths agreed on, answer NEXT (first mix item)
  6. from the 30-item review-rate sample (exam/run_review_rate.py): the first item, in sample order, whose loop had an Evaluator
     send-back; if none had one, the first with a Verifier send-back; if neither, nothing is added and README says so
Today (undecided in the 2026-10-26 tracker; nobody knows the answer yet): the first 4 rows of evidence.today_queue order (newest
first: first tracker snapshot listing the CVE, then CVE number).
Reopen (the 286 waits; watch date 2026-10-23; the watch is rv3.reopen_due_v2):
  a. a wait the watch fires on only through the original commitment (its note was rewritten later) (first)
  b. a wait the watch fires on through the latest note too (first)
  c. a wait bookworm had already fixed that the sealed watch flagged: it must be closed, not reopened (first)
  d. a wait the sealed watch flagged only through a linked commit that is not the fix by the rule (first)
  g. a wait the sealed watch flagged only through signals already there when Debian deferred (first; QA round 5)
  h. a wait the sealed watch flagged through an unstable fix on another version line (first; QA round 5)
  e. a wait the watch does not fire on although the plain-table LLM baseline said met (first)
  f. a wait the watch does not fire on although OSV lists a fixed version (the watch does not read OSV) (first)
The QA round 5 sets (d, g, h) come from evidence/watch_drops.json (scripts/check_watch.py).
Writes sample/sample_cases.json. Usage: python -I scripts/pick_demo.py"""
import os, sys, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'core'))
import gate as G
R = lambda p: os.path.join(ROOT, p)
J = lambda p: json.load(open(R(p), encoding='utf-8'))
K = lambda r: f"{r['cve']}|{r['pkg']}"
items = {K(i): i for i in J('data/news_items.json')}
F = J('data/news_feat.json')
S, O = {}, {}
for arm, d in (('S', S), ('OURS', O)):
    for ln in open(R(f'runs/news_preds_{arm}.jsonl'), encoding='utf-8'): r = json.loads(ln); d[K(r)] = r   # last answer = sealed scorer's rule
rows = []
for k in sorted(k for k in items if k in S and k in O):
    g, rule = G.decide(F[k], S[k]['pred'], O[k]['pred'])
    rows.append(dict(key=k, gold=items[k]['cls'], set=items[k]['set'], S=S[k]['pred'], O=O[k]['pred'], G=g, rule=rule))
BLOCK = ('class_unreliable', 'memory_disagrees_with_itself')
pick, why = [], {}
def add(k, w):
    if k and k not in pick: pick.append(k); why[k] = w
first = lambda f: next((r['key'] for r in rows if f(r)), None)
add('CVE-2026-109618|php8.2', 'PHP2Shell'); add('CVE-2026-109619|php8.2', 'PHP2Shell')
add(first(lambda r: r['rule'] in BLOCK and r['G'] == r['gold'] and r['O'] != r['gold']), 'Scout overruled memory and was right')
add(first(lambda r: r['rule'] in BLOCK and r['G'] != r['gold'] and r['O'] == r['gold']), 'Scout overruled memory and was wrong')
add(first(lambda r: r['set'] == 'news' and r['gold'] == 'URGENT' and r['G'] != 'URGENT'), 'an urgent CVE Revisit missed')
add(first(lambda r: r['set'] == 'mix' and r['S'] == r['O'] == r['gold'] == 'NEXT'), 'a routine deferral')
loop_note = 'review-rate run not found'
if os.path.exists(R('runs/review_rate.json')):
    its = J('runs/review_rate.json')['items']
    hit = next((x for x in its if x['send_backs'] > 0), None) or next((x for x in its if x['verifier_send_backs'] > 0), None)
    if hit: add(hit['key'], 'the review loop sent work back (first such item of the 30-item review-rate sample)'); loop_note = hit['key']
    else: loop_note = 'no send-back in the 30-item sample'
sys.path.insert(0, R('app'))
old = J('sample/sample_cases.json')
try:
    import evidence as EV
    tq, _ = EV.today_queue(4); today = [K(r) for r in tq]
    v2 = {r['wait_id'] for r in EV.reopen_due('reopen_due_v2')[0]}
except Exception:
    today = old.get('today', []); v2 = None   # offline: keep the recorded pick
truth = J('evidence/from_revisit2/reopen_truth.json'); res = J('data/reopen_resolved.json')
watch = J('evidence/from_revisit2/reopen_OURS_deferral_condition.json')['flags']; latest = J('evidence/from_revisit2/reopen_OURS.json')['flags']
r2 = {x['key']: bool(x['met']) for x in map(json.loads, open(R('evidence/from_revisit2/reopen_R2.jsonl'), encoding='utf-8'))}
wk = sorted(truth)
firstw = lambda f: next((k for k in wk if f(k)), None)
v2 = v2 if v2 is not None else set(old.get('v2_flags', []))
drops = J('evidence/watch_drops.json')
reo = [firstw(lambda k: k in v2 and not latest[k]),
       firstw(lambda k: k in v2 and latest[k]),
       firstw(lambda k: k in res and watch[k]),
       firstw(lambda k: k in drops['not_the_fix']),
       firstw(lambda k: k in drops['already_there']),
       firstw(lambda k: k in drops['other_line']),
       firstw(lambda k: k not in v2 and k not in res and r2.get(k)),
       firstw(lambda k: k not in v2 and k not in res and any(x.startswith('(c)') for x in truth[k]['sources']))]
s = dict(old)
RW = ['the watch fires only through the original commitment (the note was rewritten later)', 'the watch fires through the latest note too',
      'bookworm had already fixed it: close, do not reopen', 'the sealed watch flagged it through a linked commit that is not the fix',
      'the sealed watch flagged it through signals that were already there when Debian deferred',
      'the sealed watch flagged it through an unstable fix on another version line',
      'the plain-table LLM baseline said met; the watch does not fire', 'OSV lists a fixed version; the watch does not read OSV']
if reo[-1]:   # say under which OSV ecosystem the fixed version is listed (QA round 5: openbabel's is a PyPI alias, not Debian)
    osv = [x.split() for x in truth[reo[-1]]['sources'] if x.startswith('(c)')]
    eco = sorted({x[2].split(':')[0] for x in osv if len(x) > 2 and ':' in x[2]})
    ids = ', '.join(x[1] for x in osv if len(x) > 1)
    if eco and 'Debian' not in eco:
        RW[-1] = f"OSV lists a fixed version only under {', '.join(eco)} ({ids}); OSV's Debian ranges list none, and the watch does not read OSV"
reopen_why = {}
for k, w in zip(reo, RW):
    if k and k not in reopen_why: reopen_why[k] = w
s['reopen_why'] = reopen_why
s.update(triage=pick, triage_why=why, today=today, reopen=list(dict.fromkeys(k for k in reo if k)), review_loop_case=loop_note, rule=__doc__.split('Writes')[0].strip(), v2_flags=sorted(v2))
s['rm_names'] = dict(old.get('rm_names', {}), **{k.split('|')[1]: old.get('rm_names', {}).get(k.split('|')[1], k.split('|')[1]) for k in s['reopen']})
json.dump(s, open(R('sample/sample_cases.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print(json.dumps(dict(triage=why, today=today, reopen=s['reopen'], loop=loop_note), ensure_ascii=False, indent=1))
