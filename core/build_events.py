"""Per-package decision history for the news exam packages, from the monthly tracker snapshots (2026-06-01 .. 2026-10-01).
Same labelling code as ../revisit/prep_data.py (snap_label: snapshot text + advisories dated on/before the snapshot, so no
future leakage), restricted to the packages that appear in data/news_items.json. Writes data/news_events.json.
Usage: python -I build_events.py OLD_DEB_DIR NEW_DL_DIR"""
import sys, os, json, re, collections, datetime, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE); sys.path.insert(0, HERE)
from debparse import parse
OLD, NEW = sys.argv[1], sys.argv[2]
SNAPS = ['2026-06-01', '2026-07-01', '2026-08-01', '2026-09-01', '2026-10-01']


def advisories(path):
    out = collections.defaultdict(list); cur = None; cves = []
    for ln in open(path, encoding='utf-8'):
        m = re.match(r'^\[(\d+ \w+ \d{4})\]\s+(D[SL]A-\S+)\s+(\S+)', ln)
        if m: cur = (datetime.datetime.strptime(m.group(1), '%d %b %Y').date().isoformat(), m.group(2)); cves = []; continue
        if cur is None: continue
        s = ln.strip()
        if s.startswith('{'): cves = re.findall(r'CVE-\d{4}-\d+', s); continue
        mm = re.match(r'^\[(\w+)\]\s+-\s+(\S+)', s)
        if mm:
            for c in cves: out[(c, mm.group(2), mm.group(1))].append(cur)
    return out


ADV = advisories(NEW + '/dsa.txt')
for k, v in advisories(NEW + '/dla.txt').items(): ADV[k] += v
tj = json.load(open(NEW + '/tracker.json', encoding='utf-8'))


def snap_label(cid, p, rec, snapdate):
    """verbatim from ../revisit/prep_data.py"""
    ent = {e[0]: e for e in rec['entries'] if e[1] == p}
    bw = ent.get('bookworm'); sid = ent.get('sid')
    sid_unimp = sid is not None and (sid[2] == 'unimportant' or sid[3].strip() == 'unimportant')
    if bw and bw[2] == 'not-affected': return 'NOTAFF'
    if not bw and sid and sid[2] == 'not-affected': return 'NOTAFF'
    if any(d[0] <= snapdate for d in ADV.get((cid, p, 'bookworm'), [])): return 'URGENT'
    if sid_unimp: return 'WONTFIX'
    if bw and bw[2] in ('ignored', 'end-of-life'): return 'WONTFIX'
    if bw and bw[2] in ('no-dsa', 'postponed'): return 'NEXT'
    if bw and bw[2].startswith('fixed:') and 'deb12u' in bw[2]: return 'NEXT'
    if bw and bw[2].startswith('fixed:'): return None
    if not bw and sid and sid[2].startswith('fixed:'): return None
    return 'OPEN'


def line_text(e):
    if e is None: return ''
    st = e[2]
    s = (st[6:] if st.startswith('fixed:') else f'<{st}>')
    return f"[{e[0]}] - {e[1]} {s}" + (f" ({e[3]})" if e[3] else '')


items = json.load(open(os.path.join(ROOT, 'data/news_items.json'), encoding='utf-8'))
pkgs = {i['pkg'] for i in items}
prev_lab = {}; events = collections.defaultdict(list)
for s in SNAPS:
    P = parse(OLD + f'/list_{s}.txt')
    for cid, rec in P.items():
        if rec['nfu'] or '#' in cid or not cid.startswith('CVE-'): continue
        for p in set(e[1] for e in rec['entries']) & pkgs:
            lab = snap_label(cid, p, rec, s)
            if lab in (None, 'OPEN') or prev_lab.get((cid, p)) == lab: continue
            ent = {e[0]: e for e in rec['entries'] if e[1] == p}
            events[p].append(dict(snap=s, cve=cid, cls=lab, prev=prev_lab.get((cid, p)), bw=line_text(ent.get('bookworm')), sid=line_text(ent.get('sid')),
                                  notes=[n for n in rec['notes'] if not n.startswith('http')][:2],
                                  desc=(tj.get(p, {}).get(cid, {}).get('description') or rec['desc'])[:300]))
            prev_lab[(cid, p)] = lab
    print('snapshot', s, 'events so far', sum(len(v) for v in events.values()), flush=True)
    del P
json.dump(events, open(os.path.join(ROOT, 'data/news_events.json'), 'w', encoding='utf-8'), ensure_ascii=False)
print('pkgs with events', len(events), 'of', len(pkgs))
