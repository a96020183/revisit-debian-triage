"""Revisit's two jobs, as loops between agents. Everything an agent does is appended to a trace (runs/traces/*.json).

TRIAGE (a newly tracked CVE)
  Scout     recognises the request, guards it, routes it, signs a contract (Meterless Scout Intent)
  Executor  reads facts + history from Zetaris; loads H-MEM up to the time wall; runs both decision paths on Nemotron
  Scout     memory-reliability check (Guard stage of triage.commit_decision): trust the memory path or the evidence path
  Planner   (Nemotron) chooses which evidence the review needs and how deep
  Executor  one federated Zetaris query for those sources
  Evaluator (Nemotron) accept / need_evidence (-> back to the Planner) / escalate (-> LTS lead)
  Verifier  (code) every cited row id exists, every CVE / advisory id in the reason appears in a returned row,
            the contract covers each tool; a failed check sends the answer back to the Evaluator once, then escalates
REOPEN (daily)
  Watcher   the daily Zetaris view rv3.reopen_due (original commitment OR latest note, compiled to SQL)
  Memory    H-MEM keeps each deferral's original commitment (never superseded) and the latest note (superseded)
  Executor  one federated Zetaris query per candidate (tracker + upstream links + release-monitoring REST + OSV REST)
  Judge     (Nemotron) is the team's condition met today?
  Verifier  (code) cited rows exist and include release-level evidence when the judge says "met"
"""
import os, sys, json, time, re, collections, datetime
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(ROOT, 'core'))
import evidence as EV
import agents as A
import llm
import triage_agent as T
T.ns = llm   # the two decision paths call Nemotron through the product wrapper
import hmem_features as HF
from scout_client import ScoutBridge
from engines_client import Engines

TRIAGER = dict(id='triager-1', role='lts_triager')
WATCHER = dict(id='watcher-bot', role='lts_triager')
MAX_ROUNDS = 2


class Trace:
    def __init__(self, kind, subject):
        self.d = dict(kind=kind, subject=subject, started=datetime.datetime.now().isoformat(timespec='seconds'),
                      mode='sample-replay' if os.environ.get('REVISIT_SAMPLE_MODE') == '1' else 'live', events=[])

    def add(self, agent, kind, title, **detail):
        self.d['events'].append(dict(seq=len(self.d['events']) + 1, t=datetime.datetime.now().isoformat(timespec='seconds'), agent=agent, kind=kind, title=title, detail=detail))

    def save(self, name):
        p = os.path.join(ROOT, 'runs', 'traces', name + '.json'); os.makedirs(os.path.dirname(p), exist_ok=True)
        self.d['finished'] = datetime.datetime.now().isoformat(timespec='seconds')
        json.dump(self.d, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        return p


class Revisit:
    def __init__(self):
        self.scout = ScoutBridge(); self.mems = {}; self.events_by_wall = {}
        pk, _ = EV.packages(); self.pkgs = pk

    def close(self):
        for m in self.mems.values(): m.e.close()
        self.scout.close()

    # ---------------------------------------------------------- Scout contract helpers
    def ensure(self, tr, contract, capability, tool):
        """verify the contract at the executor boundary; an expired contract is re-issued through Scout replan (lineage kept)"""
        v = self.scout.verify(contract, engine='revisit-executor', capability=capability, tool=tool)
        if v.get('ok'):
            tr.add('scout', 'verified', f'Executor boundary: contract allows {tool}', tool=tool, capability=capability, contract=contract['contractId'])
            return contract
        reason = v.get('reason') or v.get('code') or str(v)[:120]
        if 'expire' in json.dumps(v):
            r = self.scout.call('scout_replan', parent=contract['contractId'], reason='contract expired during a long model call')
            tr.add('scout', 'replan', f'Contract expired; Scout re-issued it (parent {contract["contractId"][-6:]})', parent=contract['contractId'], new=r['contract']['contractId'])
            return r['contract']
        tr.add('scout', 'refused', f'Executor refused {tool}: {reason}', verify=v)
        raise PermissionError(f'{tool}: {reason}')

    def memory(self, wall):
        if wall not in self.mems:
            if wall not in self.events_by_wall:
                self.events_by_wall[wall], _ = EV.history(wall)
            T.EVENTS = self.events_by_wall[wall]
            m = T.Memory(self.pkgs); m.advance_to(wall); self.mems[wall] = m
        T.EVENTS = self.events_by_wall[wall]
        return self.mems[wall]

    # ---------------------------------------------------------- TRIAGE
    def triage(self, cve, pkg):
        tr = Trace('triage', f'{cve}|{pkg}')
        d = self.scout.decide(f'Triage {cve} in {pkg} for bookworm', TRIAGER, 'api')
        tr.add('scout', 'route', f"Scout: intent {d['intent']} ({d['band']} band, {d['confidence']:.2f}); risk {d['risk']['level']}",
               intent=d['intent'], band=d['band'], confidence=d['confidence'], toolPlan=[s['tool'] for s in d['toolPlan']],
               layers=d['risk']['layers'], contract=d['contract']['contractId'] if d.get('contract') else None)
        if not d.get('contract'): tr.add('scout', 'blocked', 'Scout issued no contract', risk=d['risk']); return tr
        contract = d['contract']
        contract = self.ensure(tr, contract, 'evidence.query', 'zetaris.sql')
        it, meta = EV.facts(cve, pkg)
        tr.add('executor', 'zetaris', f'Zetaris: CVE record ({meta["tag"]})', sql=meta['sql'], identity=meta.get('identity'), replayed=meta['replayed'])
        mem = self.memory(it['wall'])
        tr.add('executor', 'zetaris', f'Zetaris: decision history up to the time wall {it["wall"]} via view rv3.decisions_{it["wall"].replace("-", "_")}',
               sql=f'SELECT * FROM rv3.decisions_{it["wall"].replace("-", "_")}', packages=len(self.events_by_wall[it['wall']]))
        contract = self.ensure(tr, contract, 'memory.recall', 'hmem.query')
        f = HF.item_features(mem, it)
        tr.add('memory', 'recall', f"H-MEM: {f['n']} current decisions for {pkg} ({', '.join(f'{k} {v}' for k, v in f['cnt'].items()) or 'none'})",
               n=f['n'], counts=f['cnt'], dominant=f['dom'], top_hits=[h['v'] for h in f['hits'][:3]], superseded=f['n_superseded'])
        contract = self.ensure(tr, contract, 'reason.llm', 'nightshift.chat')
        c0 = llm.COUNT['recorded']; S = T.run_S(it, None); recS = llm.COUNT['recorded'] - c0
        tr.add('executor', 'path', f"Evidence path (Nemotron, raw tracker lines, no memory): {S['pred']}" + (' [answer recorded in the sealed exam run]' if recS else ''),
               path='evidence', pred=S['pred'], reason=S.get('reason'), served=[c['served'] for c in S['calls']], from_sealed_exam=bool(recS))
        c0 = llm.COUNT['recorded']; O = T.run_OURS(it, mem); recO = llm.COUNT['recorded'] - c0
        tr.add('executor', 'path', f"Memory path (Nemotron + H-MEM, Planner/Executor/Evaluator): {O['pred']}" + (' [answers recorded in the sealed exam run]' if recO else ''),
               path='memory', pred=O['pred'], exec_pred=O.get('exec_pred'), reason=O.get('reason'), inner_evaluator=O.get('evaluator'),
               served=[c['served'] for c in O['calls']], from_sealed_exam=bool(recO))
        g = self.scout.decide(f'Commit the triage decision for {cve} in {pkg}', TRIAGER, 'api',
                              context=dict(features=f, evidence=S['pred'], memory=O['pred']))
        oc = g.get('outcome') or {}
        gate = dict(rule=oc.get('rule'), decision=oc.get('decision'), path=oc.get('path'), reason=oc.get('reason'))
        blocked = gate['rule'] in ('class_unreliable', 'memory_disagrees_with_itself')
        tr.add('scout', 'guard', ('Scout blocked the memory path: ' if blocked else 'Scout memory-reliability check: ') + f"{gate['rule']} -> {gate['decision']}",
               blocked=blocked, approvalsRequired=g['risk']['approvalsRequired'], tool=[s['tool'] for s in g['toolPlan']][:1], **gate)
        props = dict(S=S, OURS=O)
        # ------------- review loop: Planner -> Executor -> Evaluator -> Verifier
        counts_hint = {}
        _, cm = EV.triage_pack(cve, pkg, it['wall'], list(A.MENU))   # counts only (rows are not shown to the Planner)
        counts_hint = cm['counts']
        tr.add('executor', 'zetaris', 'Zetaris: availability of each evidence source (counts only)', counts=counts_hint, sql=cm['sql'], identity=cm.get('identity'))
        have, rows, request, verdict, vnote = [], [], None, None, None
        for rnd in range(1, MAX_ROUNDS + 2):
            p = A.planner(it, props, gate, f"{f['n']} current decisions; counts {f['cnt']}; top recall {[h['v'] for h in f['hits'][:3]]}", counts_hint, rnd, request, have)
            tr.add('planner', 'plan', f"Planner (round {rnd}): {p['depth']} review, fetch {', '.join(p['fetch']) or 'nothing new'}", round=rnd, **p)
            if p['fetch']:
                new, pm = EV.triage_pack(cve, pkg, it['wall'], p['fetch'], start=len(rows) + 1)
                rows += new; have += p['fetch']
                tr.add('executor', 'zetaris', f"Zetaris federated query: {len(new)} rows from {', '.join(p['fetch'])}", round=rnd, sql=pm['sql'], identity=pm.get('identity'), rows=new, replayed=pm['replayed'])
            for attempt in (1, 2):
                ev = A.evaluator(it, props, gate, rows, p['focus'], rnd, vnote)
                tr.add('evaluator', 'verdict', f"Evaluator (round {rnd}): {ev['verdict']}" + (f" -> suggests {ev['suggested']}" if ev['verdict'] == 'escalate' else ''), round=rnd, **ev)
                ok, problems = verify_claims(ev, rows, it)
                tr.add('verifier', 'check', 'Verifier: claims supported' if ok else f'Verifier: sent back ({"; ".join(problems)[:160]})', ok=ok, problems=problems, round=rnd)
                if ok: vnote = None; break
                vnote = '; '.join(problems)
            if vnote:   # still unsupported after one send-back
                verdict = dict(ev, verdict='escalate', reason=f'Verifier could not confirm the Evaluator\'s claims: {vnote}'); break
            verdict = ev
            if ev['verdict'] != 'need_evidence': break
            request = ', '.join(ev['need']) or ev['reason']
            if rnd > MAX_ROUNDS or not [s for s in ev['need'] if s not in have]:
                verdict = dict(ev, verdict='escalate', reason='Evaluator still lacks evidence after re-planning: ' + ev['reason']); break
            tr.add('evaluator', 'send_back', f'Evaluator sent the plan back to the Planner: needs {request}', round=rnd)
        status = 'proposed' if verdict['verdict'] == 'accept' else 'escalated'
        tr.d['result'] = dict(cve=cve, pkg=pkg, wall=it['wall'], decision=gate['decision'], status=status, gate_rule=gate['rule'], gate_path=gate['path'],
                              evidence_path=S['pred'], memory_path=O['pred'], evaluator=verdict['verdict'], suggested=verdict.get('suggested'),
                              reason=verdict.get('reason'), needs_confirmation=bool(g['risk']['approvalsRequired']), cites=verdict.get('cites'))
        tr.add('scout', 'final', f"{'Proposed' if status == 'proposed' else 'Escalated to LTS lead'}: {gate['decision']}"
               + (' (needs a human confirm before commit)' if g['risk']['approvalsRequired'] else ''), **tr.d['result'])
        return tr

    # ---------------------------------------------------------- REOPEN
    def reopen(self, keys, rm_names):
        tr = Trace('reopen', 'daily watch 2026-10-23')
        d = self.scout.decide('Run the daily watch over deferred CVEs', WATCHER, 'scheduled')
        tr.add('scout', 'route', f"Scout: intent {d['intent']} ({d['band']} band); risk {d['risk']['level']}", intent=d['intent'], toolPlan=[s['tool'] for s in d['toolPlan']],
               contract=d['contract']['contractId'] if d.get('contract') else None)
        contract = self.ensure(tr, d['contract'], 'evidence.query', 'zetaris.sql')
        due, meta = EV.reopen_due()
        fired = collections.defaultdict(list)
        for r in due: fired[r['wait_id']].append(r)
        tr.add('watcher', 'zetaris', f'Zetaris daily view rv3.reopen_due: {len(fired)} of 286 waits have a condition row today', sql=meta['sql'], identity=meta.get('identity'), n_waits=len(fired))
        W, wm = EV.waits(keys)
        e = Engines(); e.call('wm_reset'); e.call('set_clock', t='2026-10-23T00:00:00Z')
        # H-MEM: original commitment (own claim key, never superseded) + latest note (superseded by later notes)
        for k in keys:
            w = W[k]
            e.call('add', input=dict(content=f"{k}: deferred {w['deferred_at']}; original commitment: {w['condition_at_deferral']}", source='lts_tracker', confidence=0.9,
                                     layer='long_term', domain=w['pkg'], claimKey=f'commitment|{k}', claimValue=w['condition_at_deferral'], tags=['commitment'],
                                     meta=dict(snap=w['deferred_at'])))
            e.call('add', input=dict(content=f"{k}: deferral note {w['condition_at_deferral']}", source='lts_tracker', confidence=0.9, layer='long_term', domain=w['pkg'],
                                     claimKey=f'note|{k}', claimValue=w['condition_at_deferral'], tags=['note'], meta=dict(snap=w['deferred_at'])))
            if w['condition_now'] != w['condition_at_deferral']:
                e.call('add', input=dict(content=f"{k}: deferral note {w['condition_now']}", source='lts_tracker', confidence=0.9, layer='long_term', domain=w['pkg'],
                                         claimKey=f'note|{k}', claimValue=w['condition_now'], supersedeCurrent=True, tags=['note'], meta=dict(snap='2026-10-23')))
            e.call('wm_upsert', input=dict(type='wait', externalKey=dict(system='revisit', id=k), attrs=dict(commitment=w['condition_at_deferral'], latest=w['condition_now']),
                                           source=dict(kind='debian_tracker', at='2026-10-23T00:00:00.000Z', by='revisit-watcher')))
        cards = []
        for k in keys:
            w = W[k]
            com = e.call('current_claim', key=f'commitment|{k}'); note = e.call('current_claim', key=f'note|{k}')
            rewritten = note['claimValue'] != com['claimValue']
            tr.add('memory', 'recall', f"H-MEM {k}: original commitment \"{com['claimValue']}\"" + (f"; latest note \"{note['claimValue']}\" (rewritten since deferral)" if rewritten else ''),
                   wait=k, commitment=com['claimValue'], latest=note['claimValue'], rewritten=rewritten)
            hit = fired.get(k, [])
            if not hit:
                tr.add('watcher', 'quiet', f'{k}: no condition row today; keeps waiting (no model call)', wait=k)
                cards.append(dict(wait=k, cve=w['cve'], pkg=w['pkg'], status='waiting', commitment=com['claimValue'], latest=note['claimValue'], watch_rows=[]))
                continue
            tr.add('watcher', 'fired', f"{k}: watch query fired via the {'/'.join(sorted({h['via'] for h in hit}))} condition ({hit[0]['detail'][:80]})", wait=k, rows=hit)
            e.call('wm_fact', input=dict(about=f'wait:revisit:{k}', predicate='condition_row', value=True, source=dict(kind='condition_query', at='2026-10-23T00:00:00.000Z', by='revisit-watcher', ref=hit[0]['detail'][:200])))
            rows, pm = EV.reopen_pack(w, rm_names.get(w['pkg'], w['pkg']))
            tr.add('executor', 'zetaris', f'Zetaris federated query for {k}: {len(rows)} rows (tracker, upstream links, release-monitoring REST, OSV REST, deferral record)', wait=k, sql=pm['sql'], identity=pm.get('identity'), rows=rows)
            vnote = None
            for attempt in (1, 2):
                j = A.reopen_judge(w, com['claimValue'], note['claimValue'], rows, vnote)
                tr.add('judge', 'verdict', f"Reopen judge (Nemotron) {k}: met = {j['met']} ({j['which']})", wait=k, **j)
                ok, problems = verify_reopen(j, rows)
                tr.add('verifier', 'check', 'Verifier: claims supported' if ok else f'Verifier: sent back ({"; ".join(problems)[:160]})', ok=ok, problems=problems, wait=k)
                if ok: vnote = None; break
                vnote = '; '.join(problems)
            status = 'needs_lead' if vnote or j['met'] == 'unclear' else ('reopen' if j['met'] == 'yes' else 'waiting')
            if status == 'reopen':
                r = self.scout.decide(f'Bring back the deferred decision for {w["cve"]}', TRIAGER, 'api')
                tr.add('scout', 'route', f"Scout: intent {r['intent']} -> {', '.join(s['tool'] for s in r['toolPlan'])}", intent=r['intent'])
                e.call('add', input=dict(content=f"re-review {k}: {j['reason'][:200]}", source='reopen_judge', confidence=0.8, layer='working', domain=w['pkg'],
                                         claimKey=f'review|{k}', claimValue='to_review', tags=['to_review']))
                e.call('wm_fact', input=dict(about=f'wait:revisit:{k}', predicate='reopened', value=True, source=dict(kind='reopen_judge', at='2026-10-23T00:00:00.000Z', by='revisit-judge', ref=j['reason'][:200])))
            cards.append(dict(wait=k, cve=w['cve'], pkg=w['pkg'], status=status, commitment=com['claimValue'], latest=note['claimValue'], rewritten=rewritten,
                              watch_rows=[h['detail'] for h in hit], judge=j))
        tr.d['result'] = dict(cards=cards, watch_fired=len(fired), audit=e.call('wm_audit_n')['n'])
        tr.add('scout', 'final', f"Reopen today: {sum(c['status'] == 'reopen' for c in cards)}; keep waiting: {sum(c['status'] == 'waiting' for c in cards)}; needs lead: {sum(c['status'] == 'needs_lead' for c in cards)}")
        e.close()
        return tr


ID_PAT = re.compile(r'\b(CVE-\d{4}-\d+|D[SL]A-\d+-\d+)\b')


def verify_claims(ev, rows, it):
    ids = {r['id'] for r in rows}; problems = []
    if ev['verdict'] in ('accept', 'escalate') and not ev['cites'] and rows: problems.append('no row cited')
    bad = [c for c in ev['cites'] if c not in ids]
    if bad: problems.append('cited rows that do not exist: ' + ', '.join(bad[:5]))
    text_ids = set(re.findall(r'\bE\d+\b', ev['reason'] or ''))
    if text_ids - ids: problems.append('reason mentions rows that do not exist: ' + ', '.join(sorted(text_ids - ids)[:5]))
    blob = json.dumps(rows) + it['desc'] + it['cve']
    unk = [x for x in set(ID_PAT.findall(ev['reason'] or '')) if x not in blob]
    if unk: problems.append('reason names ids not in any row: ' + ', '.join(sorted(unk)[:5]))
    if not ev['parsed']: problems.append('reply was not valid JSON')
    return not problems, problems


RELEASE_KINDS = ('debian_tracker', 'upstream_link', 'upstream_releases', 'osv')


def verify_reopen(j, rows):
    ids = {r['id']: r for r in rows}; problems = []
    bad = [c for c in j['cites'] if c not in ids]
    if bad: problems.append('cited rows that do not exist: ' + ', '.join(bad[:5]))
    if j['met'] == 'yes' and not any(ids[c]['source'] in RELEASE_KINDS for c in j['cites'] if c in ids):
        problems.append('"met" without citing a tracker, upstream release or OSV row')
    if not j['parsed']: problems.append('reply was not valid JSON')
    return not problems, problems
