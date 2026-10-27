"""Revisit command line.
  python -I app/run.py demo [--sample|--record]      triage the demo CVEs + run the reopen watch, then rebuild ui/data.js
  python -I app/run.py triage CVE PKG [--record]     one CVE (a sealed-exam item, or one still undecided in the 2026-10-26 tracker)
  python -I app/run.py today [N] [--record]          the first N CVEs of this morning's undecided queue (default 3)
  python -I app/run.py reopen [--record]             the daily reopen watch over the demo waits

Modes
  default    live, as the Power contract asks: every Nightshift request carries meterless-app: revisit3 and meterless-scope: user.
  --record   the mode used for every recorded and scored run: a fresh meterless-scope iso-<uuid> per request, because with 'user'
             Nightshift inserts up to three earlier answers into the prompt (README, Sponsor technology), which would make the two
             decision paths stop being independent and make recordings unreplayable. Exam items reuse the sealed exam's own answers
             for the two decision paths (REVISIT_REUSE_RECORDED); Planner, Evaluator and judge are called live.
  --sample   no Nightshift, no Zetaris: every Nemotron answer and Zetaris result is replayed from sample/cassette_*.jsonl.
             Scout, H-MEM, World Model, the Verifier and all control flow run for real. Writes runs/traces_sample/ and ui/data.js
             (both git-ignored)."""
import os, sys, json, datetime
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if '--sample' in sys.argv or os.environ.get('REVISIT_SAMPLE_MODE') == '1':
    os.environ['REVISIT_SAMPLE_MODE'] = '1'
    os.environ['REVISIT_CASSETTE'] = os.path.join(ROOT, 'sample', 'cassette_nightshift.jsonl')
    os.environ['REVISIT_SQL_CASSETTE'] = os.path.join(ROOT, 'sample', 'cassette_zetaris.jsonl')
    OUT = os.path.join(ROOT, 'runs', 'traces_sample')
elif '--record' in sys.argv:
    os.environ['REVISIT_SCOPE'] = 'iso'
    os.environ.setdefault('REVISIT_REUSE_RECORDED', '1')
    OUT = os.path.join(ROOT, 'runs', 'traces')
else:
    os.environ['REVISIT_SCOPE'] = 'user'   # Power contract default
    OUT = os.path.join(ROOT, 'runs', 'traces_scope_user')   # product mode; kept in git as evidence of Power-contract calls
sys.path.insert(0, os.path.join(ROOT, 'app'))
import pipeline as P
import evidence as EV

SAMPLE = json.load(open(os.path.join(ROOT, 'sample', 'sample_cases.json'), encoding='utf-8'))
safe = lambda s: s.replace('|', '__').replace('/', '_')


def save(tr, name):
    os.makedirs(OUT, exist_ok=True)
    tr.d['finished'] = datetime.datetime.now().isoformat(timespec='seconds')
    tr.d['scope_mode'] = os.environ.get('REVISIT_SCOPE', 'replay') if os.environ.get('REVISIT_SAMPLE_MODE') != '1' else 'replay'
    p = os.path.join(OUT, name + '.json')
    json.dump(tr.d, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('trace', os.path.relpath(p, ROOT), json.dumps(tr.d.get('result'), ensure_ascii=False)[:300], flush=True)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    cmd = args[0] if args else 'demo'
    R = P.Revisit()
    try:
        if cmd == 'triage':
            save(R.triage(args[1], args[2]), 'triage__' + safe(f'{args[1]}|{args[2]}'))
        if cmd == 'today':
            rows, _ = EV.today_queue(int(args[1]) if len(args) > 1 else 3)
            for r in rows: save(R.triage(r['cve'], r['pkg']), 'today__' + safe(f"{r['cve']}|{r['pkg']}"))
        if cmd == 'demo':
            for k in SAMPLE['triage'] + SAMPLE.get('today', []):
                cve, pkg = k.split('|'); save(R.triage(cve, pkg), ('today__' if k in SAMPLE.get('today', []) else 'triage__') + safe(k))
        if cmd in ('demo', 'reopen'):
            save(R.reopen(SAMPLE['reopen'], SAMPLE['rm_names']), 'reopen__daily')
    finally:
        R.close()
    if cmd == 'demo':
        import build_ui_data
        build_ui_data.build(OUT)


if __name__ == '__main__':
    main()
