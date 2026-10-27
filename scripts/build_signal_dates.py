"""When did each reopen signal appear, and is it on bookworm's version line? (QA round 5)
A deferral is reopened only by a signal that appeared AFTER the deferral and, for a fixed version, one on bookworm's line.
For the 286 waits this writes data/reopen_signal_dates.json:
  sid      Debian unstable fixed on the watch date: the fixed version, the day it first appeared in the Debian archive
           (snapshot.debian.org /mr/package/<src>/<version>/srcfiles first_seen), bookworm's versions (tracker download,
           bookworm + bookworm-security), same_line and fix_newer (app/debver.py: same epoch, Debian version order)
  tags     upstream fix commits that sit in release tags: the date of the earliest
           version-like tag listed (GitHub API: tagger date, or the commit date of a lightweight tag). A list of 15 tags
           may be cut short: then an earliest listed tag dated on or before the deferral still proves 'before' (the true first
           tag is no later), but one dated after it proves nothing and the date is left unknown.
  branch   ffmpeg release/5.1: the date of the first release tag on the branch that contains the fix
Commit and PR dates are already in data/reopen_bundle.json. Unknown dates never count as new.
Network answers are cached in data/version_first_seen.json and data/tag_dates.json, so a rerun is offline.
Usage: python -I scripts/build_signal_dates.py TRACKER_JSON"""
import os, sys, json, re, subprocess, urllib.request, urllib.error, urllib.parse, time, functools
from email.utils import parsedate_to_datetime
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'app'))
from debver import vcmp, same_line, fix_newer, epoch
J = lambda p: json.load(open(os.path.join(ROOT, p), encoding='utf-8'))
B = J('data/reopen_bundle.json'); RES = J('data/reopen_resolved.json'); tj = json.load(open(sys.argv[1], encoding='utf-8'))
CACHE = os.path.join(ROOT, 'data', 'version_first_seen.json'); cache = J('data/version_first_seen.json') if os.path.exists(CACHE) else {}
TCACHE = os.path.join(ROOT, 'data', 'tag_dates.json'); tcache = J('data/tag_dates.json') if os.path.exists(TCACHE) else {}


def get(url):
    for a in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'revisit3'}), timeout=60) as r: return json.loads(r.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            if e.code in (403, 404, 429): return None
            time.sleep(3 * (a + 1))
        except Exception: time.sleep(3 * (a + 1))
    try:   # some hosts fail Python's certificate check on this machine; curl uses the system store
        p = subprocess.run(['curl', '-sf', '-A', 'revisit3', url], capture_output=True, text=True, encoding='utf-8', timeout=60)
        return json.loads(p.stdout) if p.returncode == 0 and p.stdout else None
    except Exception: return None


def first_seen(pkg, ver):
    k = f'{pkg} {ver}'
    if k not in cache:
        d = get(f"https://snapshot.debian.org/mr/package/{urllib.parse.quote(pkg)}/{urllib.parse.quote(ver)}/srcfiles?fileinfo=1")
        dsc = re.sub(r'^\d+:', '', ver) + '.dsc'
        seen = [f['first_seen'] for fs in (d or {}).get('fileinfo', {}).values() for f in fs if f['name'].endswith(dsc) and f['archive_name'] in ('debian', 'debian-security')]
        cache[k] = dict(first_seen=min(seen) if seen else None)
    fs = cache[k].get('first_seen')
    return f'{fs[:4]}-{fs[4:6]}-{fs[6:8]}' if fs else None


def tag_date(repo, tag):
    k = f'{repo} {tag}'
    if tcache.get(k) is None:
        r = get(f'https://api.github.com/repos/{repo}/git/ref/tags/{urllib.parse.quote(tag)}'); d = None
        typ = ((r or {}).get('object') or {}).get('type')
        if typ == 'tag': d = ((get(r['object']['url']) or {}).get('tagger') or {}).get('date')
        elif typ == 'commit': d = ((get(r['object']['url']) or {}).get('committer') or {}).get('date')
        tcache[k] = d[:10] if d else None
    return tcache[k]


VERSIONISH = re.compile(r'^(?:v|n|release-)?\d+(?:[._-]\d+)*$')
NORM = lambda x: re.sub(r'^(?:v|n|release-)', '', x).replace('_', '.')


def earliest_tag(tags):
    t = [x for x in tags or [] if VERSIONISH.match(x)]
    return min(t, key=functools.cmp_to_key(lambda a, b: vcmp(NORM(a), NORM(b)))) if t else None


def cdate(link):
    try: return parsedate_to_datetime(link['date']).date().isoformat() if link.get('date') else ''
    except Exception: return ''


out = {}
for k, b in B.items():
    o = {}
    sid = b.get('sid_now')
    if sid and sid[2].startswith('fixed:') and sid[2] != 'fixed:0':
        v = sid[2][6:]
        rel = (tj.get(b['pkg'], {}).get(b['cve'], {}) or {}).get('releases', {}).get('bookworm', {}).get('repositories', {})
        bw = sorted(set(rel.values()))
        o['sid'] = dict(fixed=v, since=first_seen(b['pkg'], v), bookworm=bw, same_line=same_line(v, bw), fix_newer=fix_newer(v, bw),
                        line_note='' if same_line(v, bw) else
                        f"unstable {v} (epoch {epoch(v)}) is not on bookworm's line ({', '.join(bw) or '?'}, epoch {', '.join(sorted({str(epoch(x)) for x in bw}))})")
    if k not in RES:   # resolved waits close without a model call, so their tags are not looked up
        for l in b['links']:
            if l.get('kind') == 'gh_commit' and l.get('tags'):
                m = re.match(r'https://github\.com/([^/]+/[^/]+)/commit/', l['url']); t = earliest_tag(l['tags'])
                if m and t:
                    d = tag_date(m.group(1), t); unsure = len(l['tags']) >= 15 and d and d > b['deferred_at']
                    o.setdefault('tags', {})[l['url']] = dict(tag=t, date=None if unsure else d, listed=len(l['tags']),
                                                               bound='at_most' if len(l['tags']) >= 15 and not unsure else '',
                                                               note='tag list may be cut short; earliest tag unknown' if unsure else
                                                               ('tag list may be cut short; released on or before this date' if len(l['tags']) >= 15 else ''))
        if b.get('ffmpeg51') and b['ffmpeg51']['met_51'] and b['ffmpeg51']['tags']:
            t = earliest_tag(b['ffmpeg51']['tags']); o['branch'] = dict(tag=t, date=tag_date('FFmpeg/FFmpeg', t) if t else None)
    if o: out[k] = o
json.dump(cache, open(CACHE, 'w', encoding='utf-8', newline=chr(10)), indent=0, sort_keys=True)
json.dump(tcache, open(TCACHE, 'w', encoding='utf-8', newline=chr(10)), indent=0, sort_keys=True)
json.dump(out, open(os.path.join(ROOT, 'data', 'reopen_signal_dates.json'), 'w', encoding='utf-8', newline=chr(10)), ensure_ascii=False, indent=1)
S = [(k, x['sid']) for k, x in out.items() if 'sid' in x]
print(len(S), 'waits fixed in unstable;', sum(1 for _, x in S if not x['same_line']), 'on another line;',
      sum(1 for k, x in S if x['since'] and x['since'] <= B[k]['deferred_at']), 'already in the archive on or before the deferral;',
      sum(1 for _, x in S if not x['since']), 'undated')
T = [(k, u, t) for k, x in out.items() for u, t in x.get('tags', {}).items()]
print(len(T), 'fix commits in tags;', sum(1 for _, _, t in T if t['date'] is None), 'tag date unknown;',
      sum(1 for k, _, t in T if t['date'] and t['date'] > B[k]['deferred_at']), 'first tagged after the deferral')
print({k: x['branch'] for k, x in out.items() if 'branch' in x})
print(out.get('CVE-2022-29977|libsixel'))
