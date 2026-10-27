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
import debver as DV
import agents as A
import llm
import triage_agent as T
T.ns = llm   # the two decision paths call Nemotron through the product wrapper
if EV.TODAY not in T.SNAPS: T.SNAPS = T.SNAPS + [EV.TODAY]   # today's tracker is the newest snapshot H-MEM can load (exam walls unchanged)
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
        self.scout = ScoutBridge(); self.mems = {}; self.events_by_wall = {}; self.pkgs = {}

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

    def memory(self, wall, queue):
        """H-MEM loaded up to the wall. Returns (memory, meta of the Zetaris read or None when this wall was already loaded)."""
        meta = None
        if wall not in self.events_by_wall:
            self.events_by_wall[wall], meta = EV.history(wall)
        if queue not in self.pkgs: self.pkgs[queue], _ = EV.packages(queue)
        T.EVENTS = self.events_by_wall[wall]
        if (wall, queue) not in self.mems:
            m = T.Memory(self.pkgs[queue]); m.advance_to(wall); self.mems[(wall, queue)] = m
        return self.mems[(wall, queue)], meta

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
        wall, wm = EV.wall_of(cve, pkg)
        tr.add('wallkeeper', 'lookup', f"Wall keeper: this item's time wall is {wall}" if wall else 'Wall keeper: no CVE record in Zetaris for this package',
               sql=wm['sql'], identity=wm.get('identity'), replayed=wm['replayed'], wall=wall)
        if not wall:
            tr.d['result'] = dict(cve=cve, pkg=pkg, status='unknown', reason='This (CVE, package) is not in rv3_cve_facts: neither a sealed-exam item nor undecided for bookworm in the 2026-10-26 tracker.')
            tr.add('scout', 'final', 'Stopped: no CVE record in Zetaris for this package', **tr.d['result']); return tr
        tr.add('wallkeeper', 'grant', f"Wall keeper: Zetaris grants the executor this item's record and wall only ({wall}): CVE record, decisions, advisories, KEV views",
               statements=EV.wall_access(wall, True), wall=wall)
        try:
            it, meta = EV.facts(cve, pkg)
            tr.add('executor', 'zetaris', f'Zetaris: CVE record (queue {it["queue"]})', sql=meta['sql'], identity=meta.get('identity'), replayed=meta['replayed'])
            return self._triage_walled(tr, d, g_contract=contract, it=it, cve=cve, pkg=pkg)
        finally:
            tr.add('wallkeeper', 'revoke', f"Wall keeper: grants for {wall} revoked", statements=EV.wall_access(wall, False), wall=wall)

    def _triage_walled(self, tr, d, g_contract, it, cve, pkg):
        contract = g_contract
        mem, hm = self.memory(it['wall'], it['queue'])
        hv = f'rv3.decisions_{it["wall"].replace("-", "_")}'
        if hm: tr.add('executor', 'zetaris', f'Zetaris: decision history up to the time wall {it["wall"]} via view {hv}', sql=hm['sql'], identity=hm.get('identity'), replayed=hm['replayed'], packages=len(self.events_by_wall[it['wall']]))
        else: tr.add('executor', 'cache', f'Decision history up to {it["wall"]} already loaded from {hv} earlier in this run (no new query)', view=hv)
        contract = self.ensure(tr, contract, 'memory.recall', 'hmem.query')
        f = HF.item_features(mem, it)
        tr.add('memory', 'recall', f"H-MEM: {f['n']} current decisions for {pkg} ({', '.join(f'{k} {v}' for k, v in f['cnt'].items()) or 'none'})",
               n=f['n'], counts=f['cnt'], dominant=f['dom'], top_hits=[h['v'] for h in f['hits'][:3]], superseded=f['n_superseded'])
        contract = self.ensure(tr, contract, 'reason.llm', 'nightshift.chat')
        def sources(before):   # where each answer of this path came from: exam / live / earlier_product_run (SAMPLE replay keeps the recorded label)
            return {k: llm.COUNT[k] - before.get(k, 0) for k in ('exam', 'live', 'earlier_product_run') if llm.COUNT[k] - before.get(k, 0)}
        LABEL = {'exam': 'reused from the sealed exam', 'live': 'live Nightshift call', 'earlier_product_run': 'from an earlier product run'}
        tag = lambda src: ' [' + ', '.join(f'{n} {LABEL[k]}' for k, n in src.items()) + ']' + (' (replayed)' if os.environ.get('REVISIT_SAMPLE_MODE') == '1' else '')
        b0 = dict(llm.COUNT); S = T.run_S(it, None); srcS = sources(b0)
        tr.add('executor', 'path', f"Evidence path (Nemotron, raw tracker lines, no memory): {S['pred']}" + tag(srcS),
               path='evidence', pred=S['pred'], reason=S.get('reason'), served=[c['served'] for c in S['calls']], sources=srcS, from_sealed_exam=set(srcS) == {'exam'})
        b0 = dict(llm.COUNT); O = T.run_OURS(it, mem); srcO = sources(b0)
        tr.add('executor', 'path', f"Memory path (Nemotron + H-MEM; a rule-triggered self-check when it departs from memory): {O['pred']}" + tag(srcO),
               path='memory', pred=O['pred'], exec_pred=O.get('exec_pred'), reason=O.get('reason'), inner_evaluator=O.get('evaluator'),
               served=[c['served'] for c in O['calls']], sources=srcO, from_sealed_exam=set(srcO) == {'exam'})
        g = self.scout.decide(f'Commit the triage decision for {cve} in {pkg}', TRIAGER, 'api',
                              context=dict(features=f, evidence=S['pred'], memory=O['pred']))
        oc = g.get('outcome') or {}
        if not oc.get('decision'):   # Scout refused the commit (e.g. its rate limit for high-risk commits); stop, nothing is proposed
            reason = (g.get('risk') or {}).get('reason') or 'no outcome'
            tr.d['result'] = dict(cve=cve, pkg=pkg, wall=it['wall'], status='blocked', decision=None, reason=f'Scout did not allow the commit: {reason}',
                                  evidence_path=S['pred'], memory_path=O['pred'])
            tr.add('scout', 'blocked', f'Scout blocked triage.commit_decision: {reason}', risk=g.get('risk')); return tr
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
            if rnd > MAX_ROUNDS:
                verdict = dict(ev, verdict='escalate', reason=f'Evaluator still lacks evidence after {rnd - 1} re-plan(s): ' + ev['reason']); break
            if not [s for s in ev['need'] if s not in have]:
                verdict = dict(ev, verdict='escalate', reason='Evaluator asked only for sources already read; Zetaris holds nothing more for this CVE before its time wall: ' + ev['reason']); break
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
        res, rm = EV.resolved()
        tr.add('watcher', 'zetaris', f'Zetaris: {len(res)} of 286 waits were already resolved in bookworm (a DSA/DLA or a fixed +deb12u line): close them, do not reopen',
               sql=rm['sql'], identity=rm.get('identity'), rows=list(res.values()))
        due, meta = EV.reopen_due('reopen_due_v2')
        fired = collections.defaultdict(list)
        for r in due: fired[r['wait_id']].append(r)
        tr.add('watcher', 'zetaris', f'Zetaris daily view rv3.reopen_due_v2: {len(fired)} of the open waits have a condition row today', sql=meta['sql'], identity=meta.get('identity'), n_waits=len(fired))
        sealed, sm = EV.reopen_due('reopen_due'); sealed = {r['wait_id'] for r in sealed}
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
            if k in res:
                r = res[k]
                tr.add('watcher', 'resolved', f"{k}: already resolved in bookworm ({r['ref']} {r['date']}); close the wait, no model call", wait=k, **r)
                cards.append(dict(wait=k, cve=w['cve'], pkg=w['pkg'], status='resolved', commitment=com['claimValue'], latest=note['claimValue'], resolved_by=r))
                continue
            hit = fired.get(k, [])
            if not hit:
                why_quiet = []
                if k in sealed:   # the sealed watch fired here; show from Zetaris why the corrected watch does not (no model call)
                    rows, pm = EV.reopen_pack(w, rm_names.get(w['pkg'], w['pkg']))
                    why_quiet = [r['fact'] for r in rows if re.search(r'already there when Debian deferred|not on the bookworm version line|not newer than bookworm|NOT the fix by the rule|date unknown', r.get('fact') or '')]
                    tr.add('executor', 'zetaris', f'Zetaris rows for {k}: the sealed watch fired here; {len(why_quiet)} of {len(rows)} rows say why the corrected watch does not',
                           wait=k, sql=pm['sql'], identity=pm.get('identity'), rows=rows)
                tr.add('watcher', 'quiet', f'{k}: no condition row today; keeps waiting (no model call)', wait=k, why_quiet=why_quiet)
                cards.append(dict(wait=k, cve=w['cve'], pkg=w['pkg'], status='waiting', commitment=com['claimValue'], latest=note['claimValue'], watch_rows=[], why_quiet=why_quiet))
                continue
            tr.add('watcher', 'fired', f"{k}: watch query fired via the {'/'.join(sorted({h['via'] for h in hit}))} condition ({hit[0]['detail'][:80]})", wait=k, rows=hit)
            e.call('wm_fact', input=dict(about=f'wait:revisit:{k}', predicate='condition_row', value=True, source=dict(kind='condition_query', at='2026-10-23T00:00:00.000Z', by='revisit-watcher', ref=hit[0]['detail'][:200])))
            rows, pm = EV.reopen_pack(w, rm_names.get(w['pkg'], w['pkg']))
            tr.add('executor', 'zetaris', f'Zetaris federated query for {k}: {len(rows)} rows (tracker, upstream links, release-monitoring REST, OSV REST, deferral record)', wait=k, sql=pm['sql'], identity=pm.get('identity'), rows=rows)
            vnote = None
            for attempt in (1, 2):
                j = A.reopen_judge(w, com['claimValue'], note['claimValue'], rows, vnote)
                tr.add('judge', 'verdict', f"Reopen judge (Nemotron) {k}: met = {j['met']} ({j['which']})", wait=k, **j)
                ok, problems = verify_reopen(j, rows, w)
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
                              watch_rows=list(dict.fromkeys(h['detail'] for h in hit)), judge=j))
        tr.d['result'] = dict(cards=cards, watch_fired=len(fired), resolved=len(res), watch_date='2026-10-23', audit=e.call('wm_audit_n')['n'])
        tr.add('scout', 'final', f"Reopen today: {sum(c['status'] == 'reopen' for c in cards)}; close (already resolved): {sum(c['status'] == 'resolved' for c in cards)}; keep waiting: {sum(c['status'] == 'waiting' for c in cards)}; needs lead: {sum(c['status'] == 'needs_lead' for c in cards)}")
        e.close()
        return tr


ID_PAT = re.compile(r'\b(CVE-\d{4}-\d+|D[SL]A-\d+-\d+)\b')


def base_name(s):
    """'ruby3.1' -> 'ruby', 'php8.2' -> 'php', 'gst-plugins-bad1.0' -> 'gst-plugins-bad', 'ImageMagick' -> 'imagemagick'"""
    return re.sub(r'[\d.]+$', '', s.lower()).strip('-')


def evidence_packages(rows, it):
    """source packages the evidence attributes this CVE to: the item's package, packages named in the CVE's own tracker record,
    advisories and same-CVE rows"""
    pk = {it['pkg']}
    for r in rows:
        if r.get('source') in ('cve_tracker', 'same_cve_other_packages') and r.get('ref'): pk.add(r['ref'])
        if r.get('source') == 'advisories' and r.get('detail'): pk.add(r['detail'].split()[0])
    return {p for p in pk if p}


AFFIX = re.compile(r'^(node-|python3?-|ruby-|golang-|php-|r-cran-|lua-|lib)|(-perl|-java|-js|-python)$')


def names_of(pkg):
    """the names a source package goes by: 'node-undici' -> {'node-undici', 'undici'}, 'libsoup3' -> {'libsoup', 'soup'}"""
    b = base_name(pkg); out = {b}
    for _ in range(2): b = AFFIX.sub('', b); out.add(b)
    return {x for x in out if x}


def component_matches(component, packages):
    c = re.sub(r'[^a-z0-9+.\- ]', ' ', component.lower()); toks = {base_name(t) for t in c.split() if t}
    return any((n in c if len(n) >= 3 else n in toks) for p in packages for n in names_of(p))   # short names must match a whole word


def verify_claims(ev, rows, it):
    ids = {r['id'] for r in rows}; problems = []
    # the component the Evaluator says the flaw is in must be a source package the evidence attributes this CVE to (generic rule,
    # QA round 3: a description written by another vendor can name the wrong product)
    pk = evidence_packages(rows, it)
    if not ev.get('component'): problems.append('no affected component stated')
    elif not component_matches(ev['component'], pk):
        problems.append(f"claimed component '{ev['component']}' is not a source package the evidence attributes this CVE to ({', '.join(sorted(pk))})")
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


RELEASE_KINDS = ('debian_tracker', 'upstream_link', 'upstream_branch', 'upstream_releases', 'osv')


def verify_reopen(j, rows, wait):
    """Code checks the judge (QA rounds 4-5). "met = yes" must cite a fix row that (1) is a fix by the rules: an unstable fixed version,
    a commit or PR that counts as the fix, or the fixed branch; (2) appeared after the deferral: its own date, read from the row,
    later than wait['deferred_at'] (a signal that was already there when Debian chose to wait cannot trigger the wait); and (3) for an
    unstable version, is on bookworm's version line and newer than bookworm, recomputed here with Debian's version order (app/debver.py)."""
    ids = {r['id']: r for r in rows}; problems = []
    bad = [c for c in j['cites'] if c not in ids]
    if bad: problems.append('cited rows that do not exist: ' + ', '.join(bad[:5]))

    def why_not(r):
        f, sd = r.get('fact') or '', r.get('signal_date') or ''
        if not ((r['source'] == 'debian_tracker' and f.startswith('sid fixed')) or (r['source'] == 'upstream_link' and 'counts as the fix' in f)
                or (r['source'] == 'upstream_branch' and 'branch: yes' in f)):
            return 'is not a fix row'
        if not sd: return 'has no date, so it is not shown to be new'
        if sd <= wait['deferred_at']: return f"dates from {sd}, on or before the deferral ({wait['deferred_at']}): it was already there when Debian chose to wait"
        if r['source'] == 'debian_tracker':
            m = re.match(r'fixed (\S+) vs bookworm (\S+)', r.get('versions') or '')
            if not m: return 'has no bookworm version to compare with'
            fixed, bw = m.group(1), m.group(2).split(',')
            if not DV.same_line(fixed, bw): return f"{fixed} is not on bookworm's version line ({', '.join(bw)}): another epoch"
            if not DV.fix_newer(fixed, bw): return f"{fixed} is not newer than bookworm {', '.join(bw)} in Debian version order"
        return None
    if j['met'] == 'yes':
        reasons = {c: why_not(ids[c]) for c in j['cites'] if c in ids}
        if not any(v is None for v in reasons.values()):
            told = '; '.join(f'{c} {v}' for c, v in reasons.items() if v != 'is not a fix row')
            problems.append('"met" needs a cited fix row that appeared after the deferral (and, for an unstable version, is on the bookworm version line and newer)'
                            + (f': {told}' if told else ': no fix row cited'))
    if not j['parsed']: problems.append('reply was not valid JSON')
    return not problems, problems
