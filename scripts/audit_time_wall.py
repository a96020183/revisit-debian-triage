"""Audit every recorded triage trace for time-wall violations (runs/traces, runs/review_rate, runs/traces_sample if present):
  - every Zetaris row an agent saw is dated before the item's wall (history rows: snapshot on or before the wall, the wall being
    that snapshot; advisory and KEV rows: strictly before the wall);
  - every walled view the executor queried (decisions_, advisories_, kev_, cve_tracker_<wall>) belongs to the item's own wall;
  - a row from a dated source that carries no date counts as a violation;
  - where the trace has wall-keeper events (recordings made after 2026-10-27 05:00), Zetaris granted exactly that wall and revoked it.
Exit 1 on any violation. Usage: python -I scripts/audit_time_wall.py"""
import os, sys, json, glob, re
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
bad, n_tr, n_rows, n_sql, n_keep = [], 0, 0, 0, 0
for d in ('traces', 'review_rate', 'traces_sample'):
    for p in sorted(glob.glob(os.path.join(ROOT, 'runs', d, '*.json'))):
        t = json.load(open(p, encoding='utf-8'))
        if t.get('kind') != 'triage' or 'wall' not in (t.get('result') or {}): continue
        n_tr += 1; wall = t['result']['wall']; w = wall.replace('-', '_'); name = f'{d}/{os.path.basename(p)}'
        for e in t['events']:
            det = e['detail']
            for r in det.get('rows') or []:
                n_rows += 1; at = r.get('at') or ''
                if r.get('source') in ('advisories', 'kev', 'package_history', 'same_cve_other_packages', 'cve_tracker') and not at:
                    bad.append((name, r['source'], r.get('ref'), 'row has no date'))   # an undated row cannot be shown to sit behind the wall
                elif r.get('source') in ('advisories', 'kev') and not at < wall: bad.append((name, r['source'], r.get('ref'), at))
                elif r.get('source') in ('package_history', 'same_cve_other_packages', 'cve_tracker') and not at <= wall: bad.append((name, r['source'], r.get('ref'), at))
            if det.get('sql') and e['agent'] == 'executor':
                n_sql += 1
                for v in re.findall(r'rv3\.(?:decisions|advisories|kev|cve_tracker)_(\d{4}_\d{2}_\d{2})', det['sql']):
                    if v != w: bad.append((name, 'view of another wall', v, wall))
            if e['agent'] == 'wallkeeper':
                n_keep += 1
                if det.get('wall') != wall: bad.append((name, 'wall keeper wall', det.get('wall'), wall))
        kinds = [e['kind'] for e in t['events'] if e['agent'] == 'wallkeeper']
        if kinds and kinds not in (['grant', 'revoke'], ['lookup', 'grant', 'revoke']): bad.append((name, 'wall keeper sequence', kinds, wall))
print(f'{n_tr} triage traces, {n_rows} evidence rows, {n_sql} executor SQL statements, {n_keep} wall-keeper events checked')
print('NO TIME-WALL VIOLATIONS' if not bad else f'{len(bad)} VIOLATIONS: {bad[:10]}'); sys.exit(1 if bad else 0)
