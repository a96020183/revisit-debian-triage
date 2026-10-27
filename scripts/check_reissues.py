"""Which urgent news items already had a bookworm DSA/DLA for the same (CVE, package) before 2026-10-01? (QA round 3)
Those are fixes re-issued or regressions fixed again in October, not newly tracked CVEs. Writes runs/exam_reissues.json.
Usage: python -I scripts/check_reissues.py DOWNLOADS   (data/DSA/list and data/DLA/list fetched 2026-10-26)"""
import os, sys, re, json, datetime, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = collections.defaultdict(list)
for f in ('dsa.txt', 'dla.txt'):
    cur, cves = None, []
    for ln in open(os.path.join(sys.argv[1], f), encoding='utf-8'):
        m = re.match(r'^\[(\d+ \w+ \d{4})\]\s+(D[SL]A-\S+)\s+(\S+)', ln)
        if m: cur = (datetime.datetime.strptime(m.group(1), '%d %b %Y').date().isoformat(), m.group(2)); cves = []; continue
        if cur is None: continue
        s = ln.strip()
        if s.startswith('{'): cves = re.findall(r'CVE-\d{4}-\d+', s); continue
        mm = re.match(r'^\[bookworm\]\s+-\s+(\S+)', s)
        if mm:
            for c in cves: A[(c, mm.group(1))].append(dict(adv=cur[1], date=cur[0]))
items = json.load(open(os.path.join(ROOT, 'data', 'news_items.json'), encoding='utf-8'))
out = [dict(cve=i['cve'], pkg=i['pkg'], wall=i['wall'], earlier=[a for a in A.get((i['cve'], i['pkg']), []) if a['date'] < '2026-10-01'])
       for i in items if i['set'] == 'news' and i['cls'] == 'URGENT']
out = [o for o in out if o['earlier']]
json.dump(dict(note=__doc__.split('Writes')[0].strip(), n=len(out), items=out), open(os.path.join(ROOT, 'runs', 'exam_reissues.json'), 'w', encoding='utf-8', newline=chr(10)), ensure_ascii=False, indent=1)
print(len(out), [(o['cve'], o['pkg'], o['earlier'][0]['adv']) for o in out])
