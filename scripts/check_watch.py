"""Live check of the two Zetaris watch views against the recorded flags (writes evidence/watch_equivalence.txt):
  rv3.reopen_due     (the watch as sealed)  == revisit2's original-or-latest watcher flags (85 waits)
  rv3.reopen_due_v2  (post-hoc fixes)       a subset of those flags minus the waits bookworm had already resolved (data/reopen_resolved.json)
Each dropped wait is attributed to the rule that drops it, by running app/sql/reopen_due_v2.sql with the QA round 5 conditions taken out.
Usage: python -I scripts/check_watch.py"""
import os, sys, json, datetime
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'app'))
import evidence as EV
J = lambda p: json.load(open(os.path.join(ROOT, p), encoding='utf-8'))
flags = {k for k, v in J('evidence/from_revisit2/reopen_OURS_deferral_condition.json')['flags'].items() if v}
res = set(J('data/reopen_resolved.json'))
v1 = {r['wait_id'] for r in EV.reopen_due('reopen_due')[0]}; v2 = {r['wait_id'] for r in EV.reopen_due('reopen_due_v2')[0]}
V2 = open(os.path.join(ROOT, 'app', 'sql', 'reopen_due_v2.sql'), encoding='utf-8').read()
run = lambda t, tag: {r['wait_id'] for r in EV.sql(t, tag, identity=EV.WATCHER)[0]}
no_date = V2.replace('  AND ev.signal_date > w.deferred_at', '')
no_r5 = no_date.replace("AND same_line = '1' AND fix_newer = '1' AND since <> ''", '').replace(" AND tag_date <> ''", '').replace("AND tag_date <> ''", '')
assert no_date != V2 and no_r5 != no_date
r4, r5_line = run(no_r5, 'watch_without_round5'), run(no_date, 'watch_without_date_rule')
lines = [f'watch equivalence check {datetime.datetime.now().isoformat(timespec="seconds")} (Zetaris, identity watcher)',
         f'rv3.reopen_due: {len(v1)} waits; equal to revisit2 original-or-latest flags ({len(flags)}): {v1 == flags}',
         f'rv3.reopen_due_v2: {len(v2)} waits; a subset of those flags minus resolved ({len(flags - res)}): {v2 <= flags - res}',
         f'dropped because their only firing evidence was a commit that is not the fix by the rule (QA round 4): {len(flags - res - r4)}: {sorted(flags - res - r4)}',
         f'dropped because the unstable fix is not on the bookworm version line or not newer (QA round 5): {len(r4 - r5_line)}: {sorted(r4 - r5_line)}',
         f'dropped because every firing signal was already there when Debian deferred (QA round 5): {len(r5_line - v2)}: {sorted(r5_line - v2)}',
         f'still flagged by rv3.reopen_due_v2: {sorted(v2)}',
         f'resolved waits the sealed watch had flagged: {len(flags & res)}: {sorted(flags & res)}']
open(os.path.join(ROOT, 'evidence', 'watch_equivalence.txt'), 'w', encoding='utf-8', newline='\n').write('\n'.join(lines) + '\n'); print('\n'.join(lines))
json.dump(dict(sealed=sorted(v1), v2=sorted(v2), resolved=sorted(flags & res), not_the_fix=sorted(flags - res - r4), other_line=sorted(r4 - r5_line),
               already_there=sorted(r5_line - v2)), open(os.path.join(ROOT, 'evidence', 'watch_drops.json'), 'w', encoding='utf-8', newline='\n'), indent=1)
sys.exit(0 if v1 == flags and v2 <= flags - res else 1)
