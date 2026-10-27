"""Score the reopen watch against Debian's own later action, exactly as prereg_reopen_action.json says.
Usage: python -I exam/score_reopen_action.py OUTCOME_DIR   (data/CVE/list, data/DSA/list, data/DLA/list fetched after sealing)"""
import os, sys, re, json, hashlib, datetime, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'core'))
from debparse import parse
D = sys.argv[1]; WATCH, CUT = '2026-10-23', '2026-10-27'
J = lambda p: json.load(open(os.path.join(ROOT, p), encoding='utf-8'))
B = J('data/reopen_bundle.json'); RES = J('data/reopen_resolved.json')
adv = collections.defaultdict(list)
for f in ('dsa.txt', 'dla.txt'):
    cur, cves = None, []
    for ln in open(os.path.join(D, f), encoding='utf-8'):
        m = re.match(r'^\[(\d+ \w+ \d{4})\]\s+(D[SL]A-\S+)\s+(\S+)', ln)
        if m: cur = (datetime.datetime.strptime(m.group(1), '%d %b %Y').date().isoformat(), m.group(2)); cves = []; continue
        if cur is None: continue
        s = ln.strip()
        if s.startswith('{'): cves = re.findall(r'CVE-\d{4}-\d+', s); continue
        mm = re.match(r'^\[bookworm\]\s+-\s+(\S+)', s)
        if mm:
            for c in cves: adv[(c, mm.group(1))].append(cur)
NOW = parse(os.path.join(D, 'list.txt'))
truth, why = {}, {}
for k, b in B.items():
    if k in RES: continue   # already fixed on or before the watch date: excluded
    a = [x for x in adv.get((b['cve'], b['pkg']), []) if WATCH < x[0] <= CUT]
    rec = NOW.get(b['cve']); ent = {e[0]: e for e in (rec or {}).get('entries', []) if e[1] == b['pkg']}
    bw = ent.get('bookworm'); fixed_line = bool(bw and bw[2].startswith('fixed:') and 'deb12u' in bw[2])
    truth[k] = bool(a or fixed_line)
    if truth[k]: why[k] = dict(advisories=a, bookworm_line=bw[2] if bw else None)
pos = sum(truth.values())
out = dict(prereg_sha256=hashlib.sha256(open(os.path.join(ROOT, 'prereg_reopen_action.json'), 'rb').read()).hexdigest(),
           outcome_files_sha256={f: hashlib.sha256(open(os.path.join(D, f), 'rb').read()).hexdigest() for f in ('list.txt', 'dsa.txt', 'dla.txt')},
           waits_scored=len(truth), positives=pos, positives_detail=why, threshold=10,
           verdict=('no F1 reported: fewer than 10 waits had a Debian action in the window; the reopen feature is shown as cases only' if pos < 10 else 'F1 reported'))
json.dump(out, open(os.path.join(ROOT, 'runs', 'reopen_action_score.json'), 'w', encoding='utf-8', newline=chr(10)), ensure_ascii=False, indent=1)
print(json.dumps({k: v for k, v in out.items() if k != 'positives_detail'}, indent=1)); print(why)
