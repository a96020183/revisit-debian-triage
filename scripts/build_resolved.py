"""Which of the 286 waits were already resolved in bookworm on the watch date (2026-10-23)?
A wait is resolved if Debian published a DSA or DLA for (CVE, package, bookworm) dated on or before the watch date,
or the bookworm line of the 2026-10-23 tracker is a fixed +deb12u version. Such a wait must not be reopened: the right
action is to close it. (Found by QA round 1: the sealed watch never checked this.) Writes data/reopen_resolved.json.
Usage: python -I scripts/build_resolved.py NEW_DL_DIR   (data/DSA/list and data/DLA/list fetched 2026-10-26)"""
import sys, os, re, json, datetime, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCH = '2026-10-23'
B = json.load(open(os.path.join(ROOT, 'data', 'reopen_bundle.json'), encoding='utf-8'))
A = collections.defaultdict(list)
for f in ('dsa.txt', 'dla.txt'):
    cur, cves = None, []
    for ln in open(os.path.join(sys.argv[1], f), encoding='utf-8'):
        m = re.match(r'^\[(\d+ \w+ \d{4})\]\s+(D[SL]A-\S+)\s+(\S+)', ln)
        if m: cur = (datetime.datetime.strptime(m.group(1), '%d %b %Y').date().isoformat(), m.group(2)); cves = []; continue
        if cur is None: continue
        s = ln.strip()
        if s.startswith('{'): cves = re.findall(r'CVE-\d{4}-\d+', s); continue
        mm = re.match(r'^\[bookworm\]\s+-\s+(\S+)\s*(\S*)', s)
        if mm:
            for c in cves: A[(c, mm.group(1))].append(dict(adv=cur[1], date=cur[0], version=mm.group(2)))
out = {}
for k, b in B.items():
    ds = [d for d in A.get((b['cve'], b['pkg']), []) if d['date'] <= WATCH]
    bw = b.get('bookworm_now')
    if ds: out[k] = dict(how='advisory', ref=ds[0]['adv'], date=ds[0]['date'], version=ds[0]['version'])
    elif bw and bw[2].startswith('fixed:') and 'deb12u' in bw[2]: out[k] = dict(how='bookworm_fixed_line', ref='tracker 2026-10-23', date='', version=bw[2][6:])
json.dump(out, open(os.path.join(ROOT, 'data', 'reopen_resolved.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print(len(out), 'resolved waits'); [print(' ', k, v) for k, v in out.items()]
