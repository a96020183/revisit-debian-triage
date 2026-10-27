"""Revisit 3 news exam (sealed before any model call). Objective selection rules only; answers are Debian's own records.

News set N (every item that matches, nothing hand-picked):
  A. every CVE named in a Debian DSA or DLA dated 2026-10-01 .. CUTOFF (data/DSA/list, data/DLA/list of the fetch);
  B. every CVE that CISA KEV added with dateAdded in 2026-10 (catalog fetched at the same time).
  An item is (CVE, Debian source package) for every source package the tracker lists for that CVE, kept only if
  Debian has made a bookworm decision (gold rule = ../revisit/prep_data.py gold_label, unchanged) and the package is not
  a whole-version bulk-update package (EXCL, same list as every earlier exam, plus the linux-* backport kernels).
Mix set M (same size as N): non-urgent items of the same period, drawn at random per package type.
  pool = (CVE, pkg) whose CVE first appears in the tracker after the 2026-09-01 snapshot (September-October), CVE not in A or B, pkg not in
  EXCL, and whose bookworm record is a deferral or not-affected (bookworm line <no-dsa>, <postponed> or <not-affected>,
  or no bookworm line and the unstable line <not-affected>); gold must be NEXT or NOTAFF.
  package type = Section field of the package in Debian bookworm main Sources (component prefix removed; 'unknown' if absent).
  For each N item in (cve, pkg) order: draw one pool item of the same type (random.Random(SEED)); if none is left in that
  type, draw from the whole remaining pool.
Time wall per item: the latest monthly snapshot strictly before the snapshot in which the CVE first appears. If the CVE is
already in the earliest snapshot (2026-06-01), the wall is 2026-06-01 and every record of that same CVE is removed from the
item's history (S raw lines, H-MEM, NN).
Usage: python -I make_news_exam.py OLD_DEB_DIR NEW_DL_DIR"""
import sys, os, json, re, collections, random, io, lzma, datetime, hashlib
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'core'))
from debparse import parse
OLD, NEW = sys.argv[1], sys.argv[2]
CUTOFF = '2026-10-26'
SEED = 20261026
C = ['URGENT', 'NEXT', 'WONTFIX', 'NOTAFF']
SNAPS = ['2026-06-01', '2026-07-01', '2026-08-01', '2026-09-01', '2026-10-01']
EXCL = {'linux', 'chromium', 'firefox-esr', 'thunderbird', 'webkit2gtk', 'wpewebkit'}
is_excl = lambda p: p in EXCL or p.startswith('linux-')


def advisories(path):
    """(cve, pkg, release) -> [(date, advisory id)]; also advisory id -> (date, cves)"""
    out = collections.defaultdict(list); adv = {}; cur = None; cves = []
    for ln in open(path, encoding='utf-8'):
        m = re.match(r'^\[(\d+ \w+ \d{4})\]\s+(D[SL]A-\S+)\s+(\S+)', ln)
        if m:
            cur = (datetime.datetime.strptime(m.group(1), '%d %b %Y').date().isoformat(), m.group(2)); cves = []
            adv[cur[1]] = dict(date=cur[0], pkg=m.group(3), cves=[]); continue
        if cur is None: continue
        s = ln.strip()
        if s.startswith('{'): cves = re.findall(r'CVE-\d{4}-\d+', s); adv[cur[1]]['cves'] = cves; continue
        mm = re.match(r'^\[(\w+)\]\s+-\s+(\S+)', s)
        if mm:
            for c in cves: out[(c, mm.group(2), mm.group(1))].append(cur)
    return out, adv


ADV, ADVS = advisories(NEW + '/dsa.txt')
a2, adv2 = advisories(NEW + '/dla.txt')
for k, v in a2.items(): ADV[k] += v
ADVS.update(adv2)
tj = json.load(open(NEW + '/tracker.json', encoding='utf-8'))
NOW = parse(NEW + '/list.txt')


def gold_label(cid, p, rec, rel='bookworm', deb='deb12u'):
    """identical rules to ../revisit/prep_data.py gold_label (copied verbatim)"""
    t = tj.get(p, {}).get(cid, {}).get('releases', {}).get(rel)
    if not t: return None
    ent = {e[0]: e for e in rec['entries'] if e[1] == p}
    tr = ent.get(rel); sid = ent.get('sid')
    if tr and tr[2] == 'not-affected': return 'NOTAFF'
    if sid and sid[2] == 'not-affected': return 'NOTAFF'
    if (cid, p, rel) in ADV: return 'URGENT'
    if t.get('urgency') == 'unimportant' or (sid and sid[2] == 'unimportant'): return 'WONTFIX'
    if t.get('nodsa_reason') == 'ignored' or (tr and tr[2] in ('ignored', 'end-of-life')): return 'WONTFIX'
    if 'nodsa' in t or (tr and tr[2] in ('no-dsa', 'postponed')): return 'NEXT'
    if t['status'] == 'resolved':
        if deb in t.get('fixed_version', ''): return 'NEXT'
        return None
    return 'OPEN'


# ---- A, B
octo = {aid: a for aid, a in ADVS.items() if '2026-10-01' <= a['date'] <= CUTOFF}
A = {}
for aid, a in sorted(octo.items(), key=lambda x: (x[1]['date'], x[0])):
    for c in a['cves']: A.setdefault(c, []).append(f"{aid} ({a['date']})")
kev = json.load(open(NEW + '/kev.json', encoding='utf-8'))
B = {v['cveID']: f"CISA KEV added {v['dateAdded']} ({v['vendorProject']} {v['product']})" for v in kev['vulnerabilities'] if v['dateAdded'].startswith('2026-10')}
print('October advisories', len(octo), 'CVEs in A', len(A), 'KEV Oct CVEs', len(B))

N = []; skipped = collections.Counter()
for c in sorted(set(A) | set(B)):
    rec = NOW.get(c)
    if rec is None: skipped['not in tracker'] += 1; continue
    if rec['nfu']: skipped['NOT-FOR-US'] += 1; continue
    for p in sorted(set(e[1] for e in rec['entries'])):
        if is_excl(p): skipped['excluded package'] += 1; continue
        g = gold_label(c, p, rec)
        if g in C: N.append(dict(cve=c, pkg=p, cls=g, why=(A.get(c, []) + ([B[c]] if c in B else []))))
        else: skipped[f'no bookworm decision ({g})'] += 1
print('N', len(N), collections.Counter(i['cls'] for i in N), dict(skipped))

# ---- package types
SEC = {}
with lzma.open(NEW + '/Sources_bookworm.xz', 'rt', encoding='utf-8', errors='replace') as f:
    pk = None
    for ln in f:
        if ln.startswith('Package: '): pk = ln[9:].strip()
        elif ln.startswith('Section: ') and pk: SEC.setdefault(pk, ln[9:].strip().split('/')[-1])
sec = lambda p: SEC.get(p, 'unknown')

# ---- M
print('loading 2026-09-01 snapshot'); OCT1 = parse(OLD + '/list_2026-09-01.txt')
AB = set(A) | set(B); pool = []
for c, rec in NOW.items():
    if not c.startswith('CVE-2') or '#' in c or rec['nfu'] or c in OCT1 or c in AB: continue
    for p in sorted(set(e[1] for e in rec['entries'])):
        if is_excl(p): continue
        ent = {e[0]: e for e in rec['entries'] if e[1] == p}; bw = ent.get('bookworm'); sid = ent.get('sid')
        ok = (bw and bw[2] in ('no-dsa', 'postponed', 'not-affected')) or (not bw and sid and sid[2] == 'not-affected')
        if not ok: continue
        g = gold_label(c, p, rec)
        if g in ('NEXT', 'NOTAFF'): pool.append(dict(cve=c, pkg=p, cls=g, why=['mix: same-period non-urgent, type ' + sec(p)]))
pool.sort(key=lambda r: (r['cve'], r['pkg']))
print('mix pool', len(pool), collections.Counter(r['cls'] for r in pool))
rnd = random.Random(SEED); left = list(pool); M = []
for it in sorted(N, key=lambda r: (r['cve'], r['pkg'])):
    same = [r for r in left if sec(r['pkg']) == sec(it['pkg'])]
    pick = rnd.choice(same) if same else rnd.choice(left)
    left.remove(pick); M.append(dict(pick, matched_type=sec(it['pkg']), type_fallback=not same, pair=f"{it['cve']}|{it['pkg']}"))
print('M', len(M), collections.Counter(i['cls'] for i in M), 'type fallbacks', sum(m['type_fallback'] for m in M))
del OCT1

# ---- time walls, facts
ALL = [dict(i, set='news', pair=f"{i['cve']}|{i['pkg']}") for i in N] + [dict(i, set='mix') for i in M]
cves = {i['cve'] for i in ALL}; first = {}
for s in SNAPS:
    P = parse(OLD + f'/list_{s}.txt')
    for c in cves:
        if c not in first and c in P: first[c] = s
    del P


def bw_version(p):
    for cid, v in tj.get(p, {}).items():
        r = v.get('releases', {}).get('bookworm', {}).get('repositories', {})
        if 'bookworm' in r: return r['bookworm']
    return ''


ss13 = [l.split()[0] for l in open(OLD + '/ss13.txt', encoding='utf-8') if l.strip() and not l.startswith('#')]
items = []
for r in sorted(ALL, key=lambda r: (r['cve'], r['pkg'])):
    c, p = r['cve'], r['pkg']; t = tj.get(p, {}).get(c, {}); f = first.get(c, 'after-2026-10-01')
    if f == 'after-2026-10-01': wall = SNAPS[-1]; own = False
    elif f == SNAPS[0]: wall = SNAPS[0]; own = True
    else: wall = SNAPS[SNAPS.index(f) - 1]; own = False
    items.append(dict(cve=c, pkg=p, cls=r['cls'], set=r['set'], pair=r['pair'], why=r['why'], pkg_type=sec(p), desc=t.get('description', ''), scope=t.get('scope', ''),
                      bw_version=bw_version(p), limited_support=any(re.fullmatch(x, p) for x in ss13), first_seen=f, wall=wall,
                      drop_own_cve_history=own))
json.dump(items, open(os.path.join(ROOT, 'data/news_items.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=0)
print('items', len(items), collections.Counter(i['cls'] for i in items), 'walls', collections.Counter(i['wall'] for i in items),
      'own-history dropped', sum(i['drop_own_cve_history'] for i in items), 'pkgs', len({i['pkg'] for i in items}))
for i in items:
    if i['cve'] in ('CVE-2026-109618', 'CVE-2026-109619'): print('PHP2Shell', i['cve'], i['pkg'], i['cls'], i['set'], i['why'], i['wall'])
src = {k: hashlib.sha256(open(os.path.join(NEW, k), 'rb').read()).hexdigest() for k in ('list.txt', 'dsa.txt', 'dla.txt', 'tracker.json', 'kev.json', 'Sources_bookworm.xz')}
json.dump(dict(cutoff=CUTOFF, seed=SEED, fetched_files_sha256=src, kev_catalog=kev.get('catalogVersion'), n_news=len(N), n_mix=len(M),
               skipped=dict(skipped), mix_pool=len(pool)), open(os.path.join(ROOT, 'data/news_build_meta.json'), 'w'), indent=1)
