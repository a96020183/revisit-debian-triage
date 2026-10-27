"""The model-backed agents. Every one of them is a Nemotron call through Meterless Nightshift (core/nightshift.py).
Every one goes through Meterless Nightshift (app/llm.py -> core/nightshift.py).
The model draws the conclusion; the program only parses, checks and routes.

  Planner     decides which evidence to pull from Zetaris and how deep the review goes (and re-plans on send-back)
  Evaluator   critiques the proposed decision against the evidence rows: accept / need_evidence / escalate
  ReopenJudge decides whether the condition the team wrote when it deferred the CVE is met today
The two decision paths (memory path and evidence path) are core/triage_agent.py run_OURS / run_S, unchanged from the
sealed exam, so the product's proposals are exactly what the exam measured."""
import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'core'))
import llm as ns   # Nightshift via app/llm.py (core/nightshift.py underneath)

MODEL = 'nvidia/nemotron-3-super-120b-a12b'   # requested; Nightshift routes inside its Nemotron lanes and the served model is logged
C = ['URGENT', 'NEXT', 'WONTFIX', 'NOTAFF']
MENU = {
    'package_history': 'this package\'s earlier bookworm decisions (Debian tracker snapshots, before the time wall)',
    'advisories': 'DSA/DLA advisories already published for this package (before the time wall)',
    'same_cve_other_packages': 'how Debian decided the same CVE in other source packages (before the time wall)',
    'kev': 'whether CISA lists this CVE as known exploited (before the time wall)',
    'cve_facts': 'the CVE record: description, attack scope, bookworm version, limited-support flag',
}
POLICY = ('You work in the Debian LTS security team for Debian 12 "bookworm". Decisions: URGENT = ship a DLA now; NEXT = affected but deferred '
          '(<no-dsa>/<postponed>); WONTFIX = will not be fixed (<ignored>/unimportant); NOTAFF = bookworm not affected.')


def _json(text):
    """last parseable JSON object in the reply (models sometimes think out loud first)"""
    for m in reversed(list(re.finditer(r'\{(?:[^{}]|\{[^{}]*\})*\}', text or '', re.S))):
        try: return json.loads(m.group(0))
        except Exception: continue
    return None


def _call(system, tag, max_tokens=4000):
    r = ns.chat([{'role': 'system', 'content': system}], MODEL, max_tokens=max_tokens, temperature=0.0, tag=tag, timeout=600)
    return r, _json(r['text'])


def rows_text(rows):
    return '\n'.join(f"[{r['id']}] {r['source']}: " + ' | '.join(str(r.get(k)) for k in ('ref', 'at', 'label', 'fact', 'detail') if r.get(k) not in (None, ''))
                     for r in rows) or '(no rows)'


def planner(it, proposals, gate, mem_summary, counts_hint, round_no=1, request=None, have=()):
    menu = '\n'.join(f'- {k}: {v}' for k, v in MENU.items() if k not in have)
    ask = (f"Round {round_no}. The Evaluator asked for more evidence: {request}\n" if request else '')
    sys_txt = f"""{POLICY}
You are the Planner. Two independent paths already proposed a decision for this CVE. Plan the review: which evidence the
Executor should pull from Zetaris for the Evaluator, and how deep the review must be.

CVE {it['cve']} in source package {it['pkg']} (bookworm ships {it['bw_version'] or 'unknown'}; attack scope: {it['scope'] or 'unknown'}).
Description: {it['desc'][:700]}
Evidence path proposal (raw tracker history, no memory): {proposals['S']['pred']} - {proposals['S'].get('reason')}
Memory path proposal (H-MEM recall): {proposals['OURS']['pred']} - {proposals['OURS'].get('reason')}
Scout memory-reliability check: rule '{gate['rule']}', proposed decision {gate['decision']} ({gate['path']} path).
H-MEM for this package: {mem_summary}
Rows available per source (counts only): {counts_hint}
{ask}
Evidence sources you may request (pick only what the review needs):
{menu}

Reply with one JSON object only:
{{"depth": "light|deep", "fetch": ["<source>", ...], "focus": "<one sentence: what the Evaluator must check>"}}"""
    r, d = _call(sys_txt, f'planner:{it["cve"]}|{it["pkg"]}:r{round_no}', 3000)
    d = d or {}
    fetch = [s for s in (d.get('fetch') or []) if s in MENU and s not in have]
    return dict(depth=d.get('depth') if d.get('depth') in ('light', 'deep') else 'deep', fetch=fetch, focus=str(d.get('focus') or '')[:300],
                parsed=bool(d), served=r['served'], replayed=bool(r.get('replayed')))


def evaluator(it, proposals, gate, rows, focus, round_no=1, verifier_note=None):
    note = f"\nThe Verifier rejected your previous answer: {verifier_note}. Cite only row ids that exist and only CVE/advisory ids that appear in the rows.\n" if verifier_note else ''
    sys_txt = f"""{POLICY}
You are the Evaluator. Critique the proposed decision using ONLY the evidence rows below (pulled from Zetaris).
CVE {it['cve']} in {it['pkg']} (bookworm ships {it['bw_version'] or 'unknown'}).
Description: {it['desc'][:700]}
Proposed decision: {gate['decision']} (chosen by Scout rule '{gate['rule']}' from the {gate['path']} path).
Evidence path said {proposals['S']['pred']}: {proposals['S'].get('reason')}
Memory path said {proposals['OURS']['pred']}: {proposals['OURS'].get('reason')}
Planner's focus: {focus}

Evidence rows:
{rows_text(rows)}
{note}
Verdicts:
- accept: the evidence supports the proposed decision.
- need_evidence: you cannot judge without another source; name it in "need" (one of: {', '.join(MENU)}).
- escalate: the evidence points to a different decision; give it in "suggested" and send it to the LTS lead.
Reply with one JSON object only:
{{"verdict": "accept|need_evidence|escalate", "suggested": "URGENT|NEXT|WONTFIX|NOTAFF", "need": ["<source>"], "cites": ["E1", ...], "reason": "<two sentences, citing row ids>"}}"""
    r, d = _call(sys_txt, f'evaluator:{it["cve"]}|{it["pkg"]}:r{round_no}', 4000)
    d = d or {}
    v = d.get('verdict') if d.get('verdict') in ('accept', 'need_evidence', 'escalate') else 'escalate'
    return dict(verdict=v, suggested=d.get('suggested') if d.get('suggested') in C else gate['decision'],
                need=[s for s in (d.get('need') or []) if s in MENU], cites=[str(c) for c in (d.get('cites') or [])],
                reason=str(d.get('reason') or ('unparsed reply' if not d else ''))[:600], parsed=bool(d), served=r['served'], replayed=bool(r.get('replayed')))


def reopen_judge(wait, commitment, latest, rows, verifier_note=None):
    note = f"\nThe Verifier rejected your previous answer: {verifier_note}\n" if verifier_note else ''
    sys_txt = f"""You work in the Debian LTS security team. A CVE in bookworm was deferred with a written condition. Decide whether that
condition is met TODAY, using only the evidence rows below (one Zetaris query over the Debian tracker, upstream links,
release-monitoring.org and OSV).

Wait: {wait['cve']} in {wait['pkg']}, deferred {wait['deferred_at']}.
Original commitment (what the team wrote when it deferred, kept in H-MEM): "{commitment}"
Latest tracker note: "{latest}"
Read each condition literally. "Fixed upstream" / "fixes available" needs a released upstream version or a Debian unstable
upload that carries the fix; a closed issue alone is not enough. "When a patch is available / merged" is met by a fix commit or a
merged pull request. If the original commitment and the latest note differ, judge both and say which one is met.

Evidence rows:
{rows_text(rows)}
{note}
Reply with one JSON object only:
{{"met": "yes|no|unclear", "which": "original|latest|both|none", "cites": ["E1", ...], "reason": "<two sentences citing row ids>"}}"""
    r, d = _call(sys_txt, f'reopen_judge:{wait["wait_id"]}', 3000)
    d = d or {}
    met = d.get('met') if d.get('met') in ('yes', 'no', 'unclear') else 'unclear'
    return dict(met=met, which=d.get('which'), cites=[str(c) for c in (d.get('cites') or [])], reason=str(d.get('reason') or ('unparsed reply' if not d else ''))[:600],
                parsed=bool(d), served=r['served'], replayed=bool(r.get('replayed')))
