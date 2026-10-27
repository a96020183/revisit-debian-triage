"""Which exam items showed a bookworm version that did not exist yet at their time wall? (QA round 2, H3)
For every (package, version) the sealed facts showed, ask snapshot.debian.org when that source version first appeared in any
Debian archive (debian or debian-security): /mr/package/<pkg>/<version>/srcfiles?fileinfo=1, the first_seen time of its .dsc.
An item leaks if that first appearance is after the item's wall (walls are snapshot dates, 00:00 UTC).
Writes data/version_first_seen.json (cache of the API answers) and runs/leak_check_versions.json.
Also checks data/news_items_facts_walled.json (the facts later exam builds use) the same way.
Usage: python -I scripts/check_version_leaks.py"""
import os, json, re, time, urllib.request, urllib.parse
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda p: os.path.join(ROOT, p)
CACHE = R('data/version_first_seen.json')
cache = json.load(open(CACHE, encoding='utf-8')) if os.path.exists(CACHE) else {}


def first_seen(pkg, ver):
    k = f'{pkg} {ver}'
    if k in cache: return cache[k]
    url = f"https://snapshot.debian.org/mr/package/{urllib.parse.quote(pkg)}/{urllib.parse.quote(ver)}/srcfiles?fileinfo=1"
    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=60) as r: d = json.loads(r.read().decode('utf-8'))
            break
        except Exception as e:
            d = None; err = str(e); time.sleep(3 * (attempt + 1))
    if d is None: cache[k] = dict(error=err[:120]); return cache[k]
    dsc = re.sub(r'^\d+:', '', ver) + '.dsc'
    seen = [f['first_seen'] for fs in d.get('fileinfo', {}).values() for f in fs if f['name'].endswith(dsc) and f['archive_name'] in ('debian', 'debian-security')]
    cache[k] = dict(first_seen=min(seen) if seen else None, archives=sorted({f['archive_name'] for fs in d.get('fileinfo', {}).values() for f in fs if f['name'].endswith(dsc)}))
    return cache[k]


def check(items):
    out = []
    for i in items:
        if not i.get('bw_version'): continue
        fs = first_seen(i['pkg'], i['bw_version']).get('first_seen')
        day = f"{fs[:4]}-{fs[4:6]}-{fs[6:8]}" if fs else None
        if fs and fs > i['wall'].replace('-', '') + 'T000000Z':
            out.append(dict(cve=i['cve'], pkg=i['pkg'], wall=i['wall'], bw_version=i['bw_version'], first_seen=day))
    return out


sealed = json.load(open(R('data/news_items.json'), encoding='utf-8'))
walled = json.load(open(R('data/news_items_facts_walled.json'), encoding='utf-8'))
ls, lw = check(sealed), check(walled)
json.dump(cache, open(CACHE, 'w', encoding='utf-8'), indent=0, sort_keys=True)
unknown = sorted({f'{i["pkg"]} {i["bw_version"]}' for i in sealed if i.get('bw_version') and not cache.get(f'{i["pkg"]} {i["bw_version"]}', {}).get('first_seen')})
res = dict(note=__doc__.split('Writes')[0].strip(), sealed_items_checked=sum(1 for i in sealed if i.get('bw_version')), sealed_leaks=ls,
           walled_facts_leaks=lw, versions_without_answer=unknown)
json.dump(res, open(R('runs/leak_check_versions.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print('sealed facts: items checked', res['sealed_items_checked'], 'leaking', len(ls), sorted({(x['pkg'], x['bw_version']) for x in ls}))
print('walled facts leaking', len(lw), '; versions snapshot.debian.org could not date:', len(unknown), unknown[:10])
