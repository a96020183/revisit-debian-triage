"""Build ui/data.js from the traces and the scored exam files. Every number the UI shows comes from these files.
Usage: python -I app/build_ui_data.py [TRACE_DIR]"""
import os, sys, json, glob, hashlib, datetime
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE); sys.path.insert(0, HERE)
from stats import trace_stats, exam_inputs

J = lambda p: json.load(open(os.path.join(ROOT, p), encoding='utf-8')) if os.path.exists(os.path.join(ROOT, p)) else None


def build(trace_dir=None):
    trace_dir = trace_dir or os.path.join(ROOT, 'runs', 'traces')
    traces = [json.load(open(p, encoding='utf-8')) for p in sorted(glob.glob(os.path.join(trace_dir, '*.json')))]
    score = J('runs/news_score.json') or {}
    r2 = J('evidence/from_revisit2/score.json') or {}
    cases = J('sample/sample_cases.json') or {}
    items = {f"{i['cve']}|{i['pkg']}": i for i in (J('data/news_items.json') or [])}
    exam = None
    if score.get('arms'):
        exam = dict(n_pairs=score['n_pairs'], n_items=score['n_items'], gold=score['gold'], gate=score['gate'],
                    arms={a: {k: v for k, v in s.items() if k != 'per_class'} for a, s in score['arms'].items()},
                    diffs=score['diffs_URGENT_F1'], diffs_recall=score['diffs_URGENT_recall'], gate_rules=score['gate_rules'],
                    news_half=score.get('news_half_only'), cost=score['cost'], php2shell=score.get('php2shell'),
                    prereg_sha256=open(os.path.join(ROOT, 'prereg_news.sha256')).read().split()[0], inputs=exam_inputs(ROOT))
    reopen = None
    if r2.get('reopen'):
        p = r2['reopen']['primary']
        reopen = dict(n=p['n'], positives=p['positives'], ours_current=p['OURS'], ours_original_or_latest=p['OURS_deferral_condition'], R0=p['R0'], R1=p['R1'], R2=p['R2'],
                      minus_R2=p['OURS_minus_R2'], source='revisit2 commit ' + open(os.path.join(ROOT, 'evidence/from_revisit2/SOURCE_COMMIT.txt')).read().split()[0][:7])
    facts = {}
    for t in traces:
        if t['kind'] == 'triage':
            k = t['subject']; i = items.get(k, {})
            # in October 2026 bookworm is in LTS, so its advisories are DLAs; the item's 'why' also lists
            # advisories for other releases (a DSA naming the same CVE for trixie), which the page does not present as bookworm's
            w = i.get('why') or []
            facts[k] = dict(desc=i.get('desc', '')[:400], answer=i.get('cls'), why=[x for x in w if x.startswith('DLA')], why_other_releases=[x for x in w if not x.startswith('DLA')],
                            first_seen=i.get('first_seen'), wall=i.get('wall'), set=i.get('set')) if i else dict(answer=None, set='today')
    truth = J('evidence/from_revisit2/reopen_truth.json') or {}
    keep = {c['wait'] for t in traces if t['kind'] == 'reopen' for c in t['result']['cards']}
    sens = J('runs/news_sensitivity.json'); rres = J('runs/reopen_rescore_resolved.json')
    lv = J('runs/leak_check_versions.json')
    ra = J('runs/reopen_action_score.json')
    fs = J('forecast_sealed.json')
    forecast = dict(K=fs['K_sealed'], N=fs['N_registered'], fetched_at=fs['snapshot']['fetched_at'], sealed_at=fs['sealed_at'],
                    prereg_sha=open(os.path.join(ROOT, 'prereg_forecast.sha256')).read().split()[0],
                    sealed_sha=open(os.path.join(ROOT, 'forecast_sealed.sha256')).read().split()[0]) if fs else None
    data = dict(forecast=forecast, kev=J('evidence/kev_check.json'), reopen_action=(dict(positives=ra['positives'], waits=ra['waits_scored'], window='2026-10-23 and 2026-10-27') if ra else None), leaks=(dict(n=len(lv['sealed_leaks']), checked=lv['sealed_items_checked']) if lv else None), sensitivity=(sens or {}).get('results'), reopen_rescored=({k: rres[k] for k in ('original', 'corrected')} if rres else None), reopen_truth={k: dict(met=truth[k]['met'], sources=truth[k]['sources'][:2]) for k in keep if k in truth}, generated=datetime.datetime.now().isoformat(timespec='seconds'), trace_dir=os.path.relpath(trace_dir, ROOT).replace('\\', '/'),
                stats=trace_stats(traces), exam=exam, reopen_measured=reopen, cases=cases, answers=facts, traces=traces)
    os.makedirs(os.path.join(ROOT, 'ui'), exist_ok=True)
    txt = 'window.REVISIT = ' + json.dumps(data, ensure_ascii=False) + ';\n'
    open(os.path.join(ROOT, 'ui', 'data.js'), 'w', encoding='utf-8').write(txt)
    print('ui/data.js', len(txt), 'bytes;', len(traces), 'traces; stats', json.dumps(data['stats'])[:300])
    return data


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else None)
