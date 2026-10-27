"""Item facts that respect the time wall (QA rounds 1-2). Used by every exam built after 2026-10-27; the sealed news exam is NOT
rebuilt or re-run (its facts came from the 2026-10-26 tracker; README lists what that exposed).

For each (CVE, package, wall):
  bw_version  the newest version of the package in bookworm on the wall date: the higher (Debian version order) of
              bookworm main and bookworm-security in snapshot.debian.org at <wall>T000000Z
              (archive/debian/.../dists/bookworm/main/source/Sources.xz and archive/debian-security/.../dists/bookworm-security/main/source/Sources.xz)
  desc        the CVE's description as the Debian tracker listed it in the first monthly snapshot that contains the CVE
              (a CVE's own text cannot predate the CVE; this is the text a triager saw when it first appeared)
  scope       '' (the attack-scope field is not in the dated snapshots, so it is not shown at all)
Usage: python -I exam/build_item_facts.py OLD_DEB_DIR SOURCES_DIR ITEMS.json OUT.json
  SOURCES_DIR holds Sources_<yyyymmdd>.xz (main) and SecSources_<yyyymmdd>.xz (security) for each wall date."""
import sys, os, json, lzma, re, functools
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'core'))
from debparse import parse
SNAPS = ['2026-06-01', '2026-07-01', '2026-08-01', '2026-09-01', '2026-10-01']


def _order(c):
    return 0 if c.isdigit() else (ord(c) if c.isalpha() else (-1 if c == '~' else ord(c) + 256))


def _cmp_part(a, b):
    """Debian policy 5.6.12: alternate non-digit and digit runs; '~' sorts before everything, letters before non-letters"""
    while a or b:
        na = re.match(r'^[^\d]*', a).group(0); nb = re.match(r'^[^\d]*', b).group(0)
        for i in range(max(len(na), len(nb))):
            x = _order(na[i]) if i < len(na) else 0; y = _order(nb[i]) if i < len(nb) else 0
            if x != y: return -1 if x < y else 1
        a, b = a[len(na):], b[len(nb):]
        da = re.match(r'^\d*', a).group(0); db = re.match(r'^\d*', b).group(0)
        if int(da or 0) != int(db or 0): return -1 if int(da or 0) < int(db or 0) else 1
        a, b = a[len(da):], b[len(db):]
    return 0


def vcmp(a, b):
    ea, ra = (a.split(':', 1) if ':' in a else ('0', a)); eb, rb = (b.split(':', 1) if ':' in b else ('0', b))
    if int(ea) != int(eb): return -1 if int(ea) < int(eb) else 1
    ua, da = (ra.rsplit('-', 1) if '-' in ra else (ra, '0')); ub, db = (rb.rsplit('-', 1) if '-' in rb else (rb, '0'))
    return _cmp_part(ua, ub) or _cmp_part(da, db)


def sources_versions(path):
    v, pk = {}, None
    if not os.path.exists(path): return v
    with lzma.open(path, 'rt', encoding='utf-8', errors='replace') as f:
        for ln in f:
            if ln.startswith('Package: '): pk = ln[9:].strip()
            elif ln.startswith('Version: ') and pk:
                ver = ln[9:].strip()
                if pk not in v or vcmp(ver, v[pk]) > 0: v[pk] = ver
    return v


def build(old_dir, sources_dir, items, list_now=None):
    vers = {}
    for w in sorted({i['wall'] for i in items}):
        d = w.replace('-', '')
        main, sec = sources_versions(os.path.join(sources_dir, f'Sources_{d}.xz')), sources_versions(os.path.join(sources_dir, f'SecSources_{d}.xz'))
        vers[w] = {p: max([x for x in (main.get(p), sec.get(p)) if x], key=functools.cmp_to_key(vcmp)) for p in set(main) | set(sec)}
    need = {i['cve'] for i in items}; first_desc = {}
    for s in SNAPS + (['now'] if list_now else []):
        P = parse(list_now if s == 'now' else os.path.join(old_dir, f'list_{s}.txt'))
        for c in need - set(first_desc):
            if c in P: first_desc[c] = (s, re.sub(r'^\(|\)$', '', P[c]['desc'].strip()))
        del P
    out = []
    for i in items:
        s, d = first_desc.get(i['cve'], (None, ''))
        out.append(dict(cve=i['cve'], pkg=i['pkg'], wall=i['wall'], bw_version=vers[i['wall']].get(i['pkg'], ''), desc=d, desc_from_snapshot=s, scope=''))
    return out


if __name__ == '__main__':
    assert vcmp('1.0~rc1', '1.0') < 0 and vcmp('2:1.0', '1:9') > 0 and vcmp('1.2-1+deb12u2', '1.2-1+deb12u10') < 0 and vcmp('7.88.1-10+deb12u15', '7.88.1-10+deb12u9') > 0
    old, src, inp, outp = sys.argv[1:5]
    items = json.load(open(inp, encoding='utf-8'))
    res = build(old, src, items, list_now=os.environ.get('LIST_NOW'))
    json.dump(res, open(outp, 'w', encoding='utf-8', newline=chr(10)), ensure_ascii=False, indent=0)
    changed = sum(1 for a, b in zip(items, res) if a.get('bw_version') != b['bw_version'])
    print(len(res), 'items;', changed, 'bookworm versions differ from the sealed exam facts')
