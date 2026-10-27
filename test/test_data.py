"""Data consistency checks. Usage: python -I test/test_data.py
  1. today's history (data/today_events.json) and the exam's (data/news_events.json) agree, event for event, on every package they
     share up to the 2026-10-01 snapshot, so loading both into one Zetaris table leaves the exam replay byte-identical
  2. no today item is a sealed-exam item (today = still undecided; exam items all have a Debian decision)
  3. resolved waits (data/reopen_resolved.json) each carry an advisory dated on/before the watch date or a fixed +deb12u line"""
import os, sys, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
J = lambda p: json.load(open(os.path.join(ROOT, p), encoding='utf-8'))
fails = []
def check(name, ok, info=''):
    print(('PASS ' if ok else 'FAIL ') + name + (f'  ({info})' if info else '')); ok or fails.append(name)
ev, tv = J('data/news_events.json'), J('data/today_events.json')
both = set(ev) & set(tv)
check('shared packages: identical history up to 2026-10-01', all([e for e in tv[p] if e['snap'] <= '2026-10-01'] == ev[p] for p in both), f'{len(both)} packages')
ex = {(i['cve'], i['pkg']) for i in J('data/news_items.json')}; td = {(i['cve'], i['pkg']) for i in J('data/today_items.json')}
check('today queue and sealed exam do not overlap', not (ex & td), f'{len(td)} today items')
res = J('data/reopen_resolved.json')
check('every resolved wait has dated evidence', all((v['how'] == 'advisory' and v['date'] <= '2026-10-23') or (v['how'] == 'bookworm_fixed_line' and 'deb12u' in v['version']) for v in res.values()), f'{len(res)} waits')
print('ALL PASS' if not fails else f'{len(fails)} FAILED'); sys.exit(1 if fails else 0)
