"""Which KEV catalog the exam used, and what changed since (QA round 6). The exam was built from KEV catalog 2026.10.23
(data/news_build_meta.json, prereg_news.json); CISA kept adding entries afterwards. This compares the October additions of
that catalog with the live catalog and lists exam items that were added to KEV later. Writes evidence/kev_check.json.
Usage: python -I scripts/check_kev.py EXAM_KEV_JSON   (the kev.json the exam was built from; its SHA-256 is in prereg_news.json)"""
import os, sys, json, hashlib, subprocess, datetime
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
J = lambda p: json.load(open(os.path.join(ROOT, p), encoding='utf-8'))
URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
raw = open(sys.argv[1], 'rb').read()
P = J('prereg_news.json')
want = json.dumps(P).split('"kev.json": "')[1][:64]
assert hashlib.sha256(raw).hexdigest() == want or hashlib.sha256(raw.replace(b'\r\n', b'\n')).hexdigest() == want, 'not the kev.json the exam was built from'
old = json.loads(raw.decode('utf-8'))
p = subprocess.run(['curl', '-sf', '-A', 'revisit3', URL], capture_output=True, timeout=120)
new = json.loads(p.stdout.decode('utf-8'))
octo = lambda k: {v['cveID']: v['dateAdded'] for v in k['vulnerabilities'] if v['dateAdded'].startswith('2026-10')}
o, n = octo(old), octo(new)
items = {i['cve'] for i in J('data/news_items.json')}
later = sorted((c, d) for c, d in n.items() if c not in o)
out = dict(checked=datetime.date.today().isoformat(), exam_catalog=old['catalogVersion'], exam_october_additions=len(o),
           live_catalog=new['catalogVersion'], live_october_additions=len(n),
           added_after_exam_catalog=[dict(cve=c, date_added=d, in_exam=c in items) for c, d in later],
           exam_items_in_exam_catalog_october=sorted(c for c in o if c in items))
json.dump(out, open(os.path.join(ROOT, 'evidence', 'kev_check.json'), 'w', encoding='utf-8', newline='\n'), indent=1)
print(json.dumps(out, indent=1))
