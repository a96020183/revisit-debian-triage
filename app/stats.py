"""Numbers computed from traces only (the UI header and the README use these; nothing is typed by hand).
ui/app.js recomputes the per-trace counts in the browser from the same events.
  nemotron_live        answers produced by a Nightshift call during the run (Planner, Evaluator, judge, and decision paths of
                       CVEs the sealed exam never saw)
  nemotron_reused      decision-path answers taken from the sealed exam's recording (exam items only; same request, byte for byte)
  nemotron_earlier_product_run  answers taken from an earlier product recording (only in recordings made before 2026-10-27 05:10)
  zetaris_queries      SQL statements sent to Zetaris (a decision history already loaded for the same wall is not re-queried)"""
import collections

MODEL_AGENTS = {'planner', 'evaluator', 'judge'}


def trace_stats(traces):
    s = collections.Counter(); served = collections.Counter()
    for t in traces:
        for e in t['events']:
            d = e['detail']
            if e['agent'] in MODEL_AGENTS and e['kind'] in ('plan', 'verdict'):
                s['nemotron_live'] += 1; s[f"calls_{e['agent']}"] += 1
                if d.get('served'): served[d['served']] += 1
            if e['kind'] == 'path':
                src = d.get('sources') or ({'exam': len(d.get('served') or [])} if d.get('from_sealed_exam') else {'live': len(d.get('served') or [])})
                s['nemotron_reused'] += src.get('exam', 0); s['nemotron_live'] += src.get('live', 0)
                s['nemotron_earlier_product_run'] += src.get('earlier_product_run', 0)
                if src.get('live'):
                    for x in d.get('served') or []: served[x] += 1
            if e['kind'] == 'zetaris' and d.get('sql'): s['zetaris_queries'] += 1
            if e['kind'] == 'send_back': s['evaluator_send_backs'] += 1
            if e['agent'] == 'verifier' and not d.get('ok', True): s['verifier_send_backs'] += 1
            if e['agent'] == 'scout' and e['kind'] == 'guard' and d.get('blocked'): s['scout_blocked_memory'] += 1
            if e['agent'] == 'scout' and e['kind'] == 'replan': s['scout_replans'] += 1
            if e['agent'] == 'scout' and e['kind'] == 'refused': s['scout_refusals'] += 1
            if e['agent'] == 'watcher' and e['kind'] in ('quiet', 'resolved'): s['waits_without_model_call'] += 1
        r = t.get('result') or {}
        if t['kind'] == 'triage':
            s['triage_cases'] += 1; s[f"triage_{r.get('status')}"] += 1
        if t['kind'] == 'reopen':
            for c in r.get('cards', []): s[f"reopen_{c['status']}"] += 1
    out = dict(s); out['served_models_live'] = dict(served)
    out['modes'] = sorted({t.get('mode') for t in traces})
    return out


def exam_inputs(root):
    """What each decision path was given on the sealed exam (QA round 5): the evidence path sees the package's 20 most recent
    tracker lines, so for items whose package history is longer it sees only part of it; the memory path sees H-MEM's stances
    over the whole history and makes one extra self-check call when it departs from memory (last answer per item)."""
    import os, json
    J = lambda p: json.load(open(os.path.join(root, p), encoding='utf-8'))
    items, ev = J('data/news_items.json'), J('data/news_events.json')
    n = [len([e for e in ev.get(i['pkg'], []) if e['snap'] <= i['wall'] and not (i.get('drop_own_cve_history') and e['cve'] == i['cve'])]) for i in items]
    last = {}
    for ln in open(os.path.join(root, 'runs', 'news_preds_OURS.jsonl'), encoding='utf-8'):
        r = json.loads(ln); last[(r['cve'], r['pkg'])] = r
    return dict(items=len(items), history_cut=sum(x > 20 for x in n), history_max=max(n), self_check=sum(1 for r in last.values() if len(r.get('calls') or []) > 1))
