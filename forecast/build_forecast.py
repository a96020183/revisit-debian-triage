"""Live forecast, step 1 (no model call): population, sample and inputs, all from one fresh Debian tracker snapshot.
Population: every (CVE, source package) still undecided for bookworm in the snapshot, by the same rule as today's queue
(scripts/build_today.py): bookworm status open with no <no-dsa>/<postponed>/<ignored> mark, no bookworm DSA/DLA, label OPEN;
same package exclusions as the exam (linux*, chromium, firefox-esr, thunderbird, webkit2gtk, wpewebkit).
Sample: the population sorted by (CVE, package), shuffled with random.Random(SEED); the first N in that order.
Item facts (time wall = the snapshot): the tracker's description, bookworm's version from the snapshot, limited support from
debian-security-support's security-support.deb12, no scope (as in every exam built after 2026-10-27).
Package history: the recorded history of revisit3 (data/today_events.json, 2026-06-01 .. 2026-10-26; data/news_events.json for
packages only there, 2026-06-01 .. 2026-10-01), plus the label changes the fresh snapshot shows, dated with the snapshot day;
a package with no recorded history gets the snapshot's labels only. Labels are core/build_events.py's.
Writes data/forecast_population.json, data/forecast_items.json, data/forecast_events.json.
Usage: python -I forecast/build_forecast.py SNAPSHOT_DIR   (list.txt, dsa.txt, dla.txt, tracker.json, ss13.txt, fetched_at.txt)"""
import sys, os, json, re, collections, datetime, io, random
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'core'))
from debparse import parse
DL = sys.argv[1]
SEED, N = 20261027, 150
FETCHED = open(os.path.join(DL, 'fetched_at.txt')).read().split()[0]
WALL = FETCHED[:10]
EXCL = {'linux', 'chromium', 'firefox-esr', 'thunderbird', 'webkit2gtk', 'wpewebkit'}
is_excl = lambda p: p in EXCL or p.startswith('linux-')
J = lambda p: json.load(open(os.path.join(ROOT, p), encoding='utf-8'))


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


ADV = advisories(os.path.join(DL, 'dsa.txt'))
for k, v in advisories(os.path.join(DL, 'dla.txt')).items(): ADV[k] += v
tj = json.load(open(os.path.join(DL, 'tracker.json'), encoding='utf-8'))


def snap_label(cid, p, rec, snapdate):   # verbatim from core/build_events.py (as in scripts/build_today.py)
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


def bw_version(p):
    best = ''
    for cid, v in tj.get(p, {}).items():
        r = v.get('releases', {}).get('bookworm', {}).get('repositories', {})
        if 'bookworm-security' in r: return r['bookworm-security']
        if 'bookworm' in r: best = best or r['bookworm']
    return best


NOW = parse(os.path.join(DL, 'list.txt'))
ss = [l.split()[0] for l in open(os.path.join(DL, 'ss13.txt'), encoding='utf-8') if l.strip() and not l.startswith('#')]
pop = []
for c, rec in NOW.items():
    if not c.startswith('CVE-2') or '#' in c or rec['nfu']: continue
    for p in sorted(set(e[1] for e in rec['entries'])):
        if is_excl(p): continue
        t = tj.get(p, {}).get(c, {}); bw = t.get('releases', {}).get('bookworm')
        if not bw or bw.get('status') != 'open' or 'nodsa' in bw: continue
        if snap_label(c, p, rec, WALL) != 'OPEN': continue
        pop.append((c, p))
pop.sort()
order = list(pop); random.Random(SEED).shuffle(order)
sample = order[:N]
print('fetched', FETCHED, 'population', len(pop), 'packages', len({p for _, p in pop}), 'sample', len(sample))
items = []
for c, p in sample:
    t = tj.get(p, {}).get(c, {})
    items.append(dict(cve=c, pkg=p, desc=t.get('description', '') or NOW[c]['desc'], scope='', bw_version=bw_version(p), bw_version_walled=bw_version(p),
                      limited_support=any(re.fullmatch(x, p) for x in ss), first_seen=WALL, wall=WALL, drop_own_cve_history=False, cls=None, set='forecast', pair=None))
pkgs = {i['pkg'] for i in items}
today, news = J('data/today_events.json'), J('data/news_events.json')
events = {p: list(today.get(p) or news.get(p) or []) for p in pkgs}
base = {p: ('today_events' if today.get(p) else 'news_events' if news.get(p) else 'none') for p in pkgs}
prev = {}
for p, es in events.items():
    for e in es: prev[(e['cve'], p)] = e['cls']
added = 0
for cid, rec in NOW.items():
    if rec['nfu'] or '#' in cid or not cid.startswith('CVE-'): continue
    for p in set(e[1] for e in rec['entries']) & pkgs:
        lab = snap_label(cid, p, rec, WALL)
        if lab in (None, 'OPEN') or prev.get((cid, p)) == lab: continue
        ent = {e[0]: e for e in rec['entries'] if e[1] == p}
        events[p].append(dict(snap=WALL, cve=cid, cls=lab, prev=prev.get((cid, p)), bw=line_text(ent.get('bookworm')), sid=line_text(ent.get('sid')),
                              notes=[n for n in rec['notes'] if not n.startswith('http')][:2], desc=(tj.get(p, {}).get(cid, {}).get('description') or rec['desc'])[:300]))
        prev[(cid, p)] = lab; added += 1
print('history: base', dict(collections.Counter(base.values())), 'events', sum(len(v) for v in events.values()), 'added from the snapshot', added)
W = lambda name, obj: json.dump(obj, open(os.path.join(ROOT, 'data', name), 'w', encoding='utf-8', newline='\n'), ensure_ascii=False, indent=0)
W('forecast_population.json', dict(fetched_at=FETCHED, wall=WALL, n=len(pop), seed=SEED, order=[f'{c}|{p}' for c, p in order]))
W('forecast_items.json', items)
W('forecast_events.json', events)
