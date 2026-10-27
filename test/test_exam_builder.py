"""Time-wall checks for exam item facts (QA round 1). Run: python -I test/test_exam_builder.py
  1. the facts built by exam/build_item_facts.py (data/news_items_facts_walled.json) never show a bookworm version that first
     appeared in a Debian archive after the item's wall (snapshot.debian.org dates), show no scope, and take the description from
     a dated tracker snapshot;
  2. the same check run on the sealed exam's facts (data/news_items.json, built from the 2026-10-26 tracker) finds exactly the
     leaks README lists, which shows the check can catch them."""
import os, sys, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
J = lambda p: json.load(open(os.path.join(ROOT, p), encoding='utf-8'))
FS = J('data/version_first_seen.json')   # snapshot.debian.org first appearance of each (package, version), scripts/check_version_leaks.py
def leaks(items):
    out = []
    for i in items:
        fs = (FS.get(f"{i['pkg']} {i['bw_version']}") or {}).get('first_seen')
        if i['bw_version'] and (fs is None or fs > i['wall'].replace('-', '') + 'T000000Z'): out.append((i['cve'], i['pkg']))
    return sorted(out)
fails = []
def check(name, ok, info=''):
    print(('PASS ' if ok else 'FAIL ') + name + (f'  ({info})' if info else '')); ok or fails.append(name)
walled = J('data/news_items_facts_walled.json')
check('walled facts: no post-wall bookworm version', not leaks(walled), str(leaks(walled)))
check('walled facts: no scope shown', all(i['scope'] == '' for i in walled))
check('walled facts: description taken from a dated snapshot', all(i['desc_from_snapshot'] for i in walled))
check('walled facts: one row per sealed item, same order', [(i['cve'], i['pkg']) for i in walled] == [(i['cve'], i['pkg']) for i in J('data/news_items.json')])
sealed = leaks(J('data/news_items.json'))
known = sorted((x['cve'], x['pkg']) for x in J('runs/leak_check_versions.json')['sealed_leaks'])
check(f'the check finds the {len(known)} leaks README lists in the sealed facts', sealed == known and len(known) > 0, str(sealed))
print('ALL PASS' if not fails else f'{len(fails)} FAILED'); sys.exit(1 if fails else 0)
