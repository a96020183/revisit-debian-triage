"""Today's queue: every (CVE, source package) that is still undecided for bookworm in the Debian tracker fetched on
2026-10-26 (gold rule = 'OPEN': no DSA/DLA, no <no-dsa>/<postponed>/<ignored>/<not-affected>, not fixed), same package
exclusions as the exam. These are the CVEs a triager has to decide this morning; nobody knows the answer yet.
Also rebuilds the decision history of their packages over the six snapshots (2026-06-01 .. 2026-10-01 + 2026-10-26), with the
same labelling as core/build_events.py, so today's time wall is the 2026-10-26 snapshot.
Writes data/today_items.json and data/today_events.json. Usage: python -I scripts/build_today.py OLD_DEB_DIR NEW_DL_DIR"""
import sys, os, json, re, collections, datetime, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'core'))
from debparse import parse
OLD, NEW = sys.argv[1], sys.argv[2]
TODAY = '2026-10-26'
SNAPS = ['2026-06-01', '2026-07-01', '2026-08-01', '2026-09-01', '2026-10-01', TODAY]
EXCL = {'linux', 'chromium', 'firefox-esr', 'thunderbird', 'webkit2gtk', 'wpewebkit'}
is_excl = lambda p: p in EXCL or p.startswith('linux-')


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


def snap_label(cid, p, rec, snapdate):   # verbatim from core/build_events.py
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
    st = e[2]; s = (st[6:] if st.startswith('fixed:') else f'<{st}>')
    return f"[{e[0]}] - {e[1]} {s}" + (f" ({e[3]})" if e[3] else '')


NOW = parse(NEW + '/list.txt')
ss13 = [l.split()[0] for l in open(OLD + '/ss13.txt', encoding='utf-8') if l.strip() and not l.startswith('#')]


def bw_version(p):
    for cid, v in tj.get(p, {}).items():
        r = v.get('releases', {}).get('bookworm', {}).get('repositories', {})
        if 'bookworm' in r: return r['bookworm']
    return ''


items = []
for c, rec in NOW.items():
    if not c.startswith('CVE-2') or '#' in c or rec['nfu']: continue
    for p in sorted(set(e[1] for e in rec['entries'])):
        if is_excl(p): continue
        t = tj.get(p, {}).get(c, {}); bw = t.get('releases', {}).get('bookworm')
        if not bw or bw.get('status') != 'open' or 'nodsa' in bw: continue
        if snap_label(c, p, rec, TODAY) != 'OPEN': continue
        items.append(dict(cve=c, pkg=p, desc=t.get('description', ''), scope=t.get('scope', ''), bw_version=bw_version(p),
                          limited_support=any(re.fullmatch(x, p) for x in ss13), first_seen=TODAY, wall=TODAY, drop_own_cve_history=False,
                          urgency=bw.get('urgency', '')))
print('today: undecided bookworm items', len(items), 'packages', len({i['pkg'] for i in items}))
pkgs = {i['pkg'] for i in items}
prev_lab = {}; events = collections.defaultdict(list); FIRST = {}; today_cves = {i['cve'] for i in items}
for s in SNAPS:
    P = NOW if s == TODAY else parse(OLD + f'/list_{s}.txt')
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
    if s != TODAY:
        for c in today_cves:
            if c not in FIRST and c in P: FIRST[c] = s
    print('snapshot', s, 'events', sum(len(v) for v in events.values()), flush=True)
    if s != TODAY: del P
# the CVE's own tracker record today (all source packages it lists, their status per release, the NOTE lines): evidence a triager
# sees this morning for an undecided CVE (QA round 3: the description alone can name the wrong product)
lines = []
for c in sorted({i['cve'] for i in items}):
    rec = NOW[c]
    for e in rec['entries']:
        lines.append(dict(cve=c, snap=TODAY, release=e[0], pkg=e[1], status=e[2], note=(e[3] or '')[:200]))
    for n in rec['notes'][:6]:
        lines.append(dict(cve=c, snap=TODAY, release='NOTE', pkg='', status='', note=n[:300]))
json.dump(lines, open(os.path.join(ROOT, 'data/today_cve_tracker.json'), 'w', encoding='utf-8', newline=chr(10)), ensure_ascii=False, indent=0)
# first snapshot that lists each CVE (newest first is the queue order); CVE year and number for numeric ordering
for i in items:
    i['first_seen'] = next((s_ for s_ in SNAPS[:-1] if FIRST.get(i['cve']) == s_), TODAY)
    y, n = re.match(r'CVE-(\d+)-(\d+)', i['cve']).groups(); i['cve_year'], i['cve_num'] = int(y), int(n)
json.dump(items, open(os.path.join(ROOT, 'data/today_items.json'), 'w', encoding='utf-8', newline=chr(10)), ensure_ascii=False, indent=0)
json.dump(events, open(os.path.join(ROOT, 'data/today_events.json'), 'w', encoding='utf-8'), ensure_ascii=False)
