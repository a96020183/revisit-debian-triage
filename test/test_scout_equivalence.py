"""Equivalence: Scout's memory-reliability Guard check == the frozen core/gate.py decide().

For every feature record in data/news_feat.json (570) and every (evidence proposal, memory proposal) pair over
URGENT/NEXT/WONTFIX/NOTAFF (16), ask the Scout bridge (engines/scout_bridge.ts, op scout_decide) to commit the decision
for intent triage.commit_decision, and check it picks exactly what gate.decide(f, s_pred, o_pred) picks, with the same
rule name, routed to the matching tool (decision.adopt_memory / decision.adopt_evidence) in a signed contract.
A few synthetic records cover the Python-truthiness branches (n = 0 / None, empty or missing hits, dom None).

Run from the repo root:  python -I test/test_scout_equivalence.py
Reads data/ and core/gate.py only; writes nothing (bytecode writing is disabled so core/ stays untouched).
"""
import sys, os, json, time, itertools, collections
sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'core'))
import gate                                  # frozen reference (read-only import)
from scout_client import ScoutBridge

CLASSES = ['URGENT', 'NEXT', 'WONTFIX', 'NOTAFF']
SYNTHETIC = {
    'CVE-2099-0001|pkg-a': {'n': 0, 'dom': 'URGENT', 'hits': [{'v': 'URGENT', 's': 0.9}]},
    'CVE-2099-0002|pkg-b': {'n': None, 'dom': 'NEXT', 'hits': [{'v': 'NEXT', 's': 0.5}]},
    'CVE-2099-0003|pkg-c': {'n': 3, 'dom': None},
    'CVE-2099-0004|pkg-d': {'n': 2, 'dom': 'NOTAFF', 'hits': []},
    'CVE-2099-0005|pkg-e': {'n': 4, 'dom': 'NOTAFF', 'hits': [{'v': 'URGENT', 's': 0.7}, {'v': 'NOTAFF', 's': 0.6}]},
    'CVE-2099-0006|pkg-f': {},
}


def main():
    feat = json.load(open(os.path.join(ROOT, 'data', 'news_feat.json'), encoding='utf-8'))
    print(f'reference: core/gate.py decide()  |  records: {len(feat)} real + {len(SYNTHETIC)} synthetic  |  pairs per record: 16')
    br = ScoutBridge()
    info = br.call('scout_info')
    print(f"scout: registryVersion={info['registryVersion']} digest={info['registryDigest']} selfTest={info['selfTest']} secret={info['secretSource']}")
    t0 = time.time()
    fails, n, rules, paths, verified = [], 0, collections.Counter(), collections.Counter(), 0
    for src, records in (('real', feat), ('synthetic', SYNTHETIC)):
        for i, (key, f) in enumerate(records.items()):
            cve, pkg = key.split('|')
            for s, o in itertools.product(CLASSES, CLASSES):
                want, want_rule = gate.decide(f, s, o)
                r = br.decide(f'Commit the triage decision for {cve} in {pkg}', user={'id': f'eq-{src}-{i}-{s}-{o}', 'role': 'lts_triager'},
                              surface='api', context={'features': f, 'evidence': {'decision': s}, 'memory': {'decision': o}})
                n += 1
                c = r['contract'] or {}
                step = next((x for x in r['toolPlan'] if x['capability'] == 'decision.commit'), None)
                flag = next((x for x in r['risk']['flags'] if x['kind'] == 'memory-reliability'), None)
                want_tool = 'decision.adopt_memory' if want_rule in ('agree', 'trust_memory') else 'decision.adopt_evidence'
                got = dict(intent=r['intent'], level=r['risk']['level'], decision=(r['outcome'] or {}).get('decision'),
                           rule=(r['outcome'] or {}).get('rule'), tool=step and step['tool'], step_decision=step and step['input'].get('decision'),
                           flag_rule=flag and flag['rule'], signed=bool(c.get('signature')),
                           contract_tool=next((x['tool'] for x in c.get('toolPlan', []) if x['capability'] == 'decision.commit'), None))
                ok = (got['intent'] == 'triage.commit_decision' and got['level'] != 'block' and got['decision'] == want
                      and got['rule'] == want_rule and got['tool'] == want_tool and got['step_decision'] == want
                      and got['flag_rule'] == want_rule and got['signed'] and got['contract_tool'] == want_tool)
                if not ok:
                    fails.append((key, s, o, (want, want_rule), got))
                rules[want_rule] += 1; paths[want_tool] += 1
                if n % 97 == 1 and c:   # spot-check the signed contract at a downstream boundary
                    v = br.verify(c, engine='equivalence-test', capability='decision.commit', tool=want_tool, requireApprovals=False)
                    pending = br.verify(c, engine='equivalence-test')
                    if not v['ok'] or pending.get('code') != 'approval-missing':
                        fails.append((key, s, o, 'verify', (v, pending)))
                    verified += 1
    br.close()
    dt = time.time() - t0
    print(f'decisions compared: {n}  ({dt:.1f} s, {1000 * dt / n:.2f} ms each over the bridge)')
    print('by rule:', dict(rules))
    print('by tool:', dict(paths))
    print(f'contracts spot-verified at a boundary: {verified} (signature + scope ok; execution refused until user-confirm approval)')
    if fails:
        print(f'MISMATCHES: {len(fails)}')
        for x in fails[:20]: print('  ', x)
        sys.exit(1)
    print(f'RESULT: PASS - Scout picked exactly what core/gate.py decide() picks, with the same rule name, on all {n} inputs.')


if __name__ == '__main__':
    main()
