"""Write the sealed pre-registration of the news exam (prereg_news.json) BEFORE any model call on its items; print its SHA-256.
Usage: python -I exam/write_prereg_news.py"""
import os, json, hashlib, collections, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sha = lambda p: hashlib.sha256(open(os.path.join(ROOT, p), 'rb').read()).hexdigest()
items = json.load(open(os.path.join(ROOT, 'data/news_items.json'), encoding='utf-8'))
meta = json.load(open(os.path.join(ROOT, 'data/news_build_meta.json'), encoding='utf-8'))
news = [i for i in items if i['set'] == 'news']; mix = [i for i in items if i['set'] == 'mix']

P = dict(
    title='Revisit 3 news exam: pre-registration (sealed before any model call on these items)',
    written='2026-10-26 (Asia/Taipei)',
    decision_under_test='For a newly tracked CVE in a Debian 12 bookworm source package, decide URGENT (the LTS team ships a DLA) vs NEXT / WONTFIX / NOTAFF.',
    answers='Debian\'s own records only: the bookworm decision in the Debian security tracker and the DSA/DLA lists fetched 2026-10-26 16:09 +08:00, '
            'labelled with the unchanged gold rule of ../revisit/prep_data.py gold_label (URGENT = a DSA/DLA lists the bookworm package for the CVE). No human or AI labels.',
    selection=dict(
        news_set='A: every CVE named in a Debian DSA or DLA dated 2026-10-01 .. 2026-10-26. B: every CVE CISA KEV added with dateAdded in 2026-10 '
                 '(catalog 2026.10.23). Item = (CVE, source package) for every source package the tracker lists, kept when Debian has a bookworm decision. '
                 'Excluded packages (bulk whole-version updates, same as every earlier exam): linux, linux-* backport kernels, chromium, firefox-esr, thunderbird, webkit2gtk, wpewebkit.',
        mix_set='Same size as the news set. Pool: (CVE, pkg) whose CVE first appears after the 2026-09-01 snapshot, not in A or B, package not excluded, bookworm '
                'record <no-dsa>, <postponed> or <not-affected> (or no bookworm line and unstable <not-affected>), gold NEXT or NOTAFF. '
                'For each news item in (cve, pkg) order, one pool item of the same package type (Section of the bookworm Sources entry) is drawn with '
                'random.Random(20261026); if that type is used up, from the whole remaining pool. Each news item and its drawn mix item form a pair.',
        not_hand_picked='PHP2Shell (CVE-2026-109618, CVE-2026-109619, php8.2) is in the news set only because DLA-4848-1 / DSA-6574-1 (2026-10-21) match rule A.',
        script='exam/make_news_exam.py', build_meta=meta,
        counts=dict(items=len(items), news=len(news), mix=len(mix), news_gold=dict(collections.Counter(i['cls'] for i in news)),
                    mix_gold=dict(collections.Counter(i['cls'] for i in mix)), walls=dict(collections.Counter(i['wall'] for i in items)),
                    own_cve_history_dropped=sum(i['drop_own_cve_history'] for i in items)),
        time_wall='Each item sees tracker history only up to the monthly snapshot before the CVE first appears. CVEs already in the earliest snapshot '
                  '(2026-06-01): wall 2026-06-01 and every record of that same CVE removed from what S, OURS, NN and R1 see.',
        items=[dict(cve=i['cve'], pkg=i['pkg'], answer=i['cls'], set=i['set'], pair=i['pair'], wall=i['wall']) for i in items]),
    arms=dict(
        S='evidence path, strong baseline without Meterless: same Nemotron request via Nightshift; policy + item facts + the package\'s 20 most recent raw tracker decision lines before the wall (core/triage_agent.py run_S).',
        OURS='memory path, always trust memory: Planner reads H-MEM (current stances after supersession, relevance recall, stance changes) -> Executor -> Evaluator (core/triage_agent.py run_OURS).',
        GATED='the frozen gatekeeper core/gate.py (byte-identical to ../revisit2/gate.py, frozen 2026-10-23 before fresh300) chooses the OURS or the S answer per item '
              'from the two answers and H-MEM features (data/news_feat.json, computed before any model call). The product runs the same rules as the Guard '
              'stage of its Meterless Scout Intent implementation; a test must show Scout and gate.py give identical choices on every scored item.',
        NN='time-walled TF-IDF nearest past decision inside the package; no model.',
        R1='rule: repeat the package\'s most recent recorded bookworm decision before the wall (NEXT if none); no model.',
        reported_only='package-mode baseline; ablation "gatekeeper without the H-MEM rule" (rules agree + class_unreliable only); removing the Scout gatekeeper = OURS or S alone.',
        code_changes_vs_earlier_runs='core/triage_agent.py = ../revisit/triage_agent.py with data paths switched to the news exam and the own-CVE history filter (lines marked REVISIT3). Prompts and Planner/Executor/Evaluator logic unchanged.'),
    run_rules=dict(
        nightshift='every model call through Meterless Nightshift only; meterless-scope iso-<uuid4> per request (REVISIT_SCOPE=iso); stream, tier-split off; '
                   'one request in flight in total (the box is shared with two other projects); backoff 15/30/60/120/180 s, 8 tries.',
        model='nvidia/nemotron-3-super-120b-a12b requested; Nightshift routes inside its Nemotron lanes; served model logged per call.',
        order='pairs in the order random.Random(20261027).shuffle(sorted pair keys); news item then mix item; S then OURS. New pairs are not started after '
              '2026-10-27 05:30 +08:00. Because the order is a sealed random permutation, the completed pairs are a random subset of the exam.',
        scored_set='every pair whose two items both have S and OURS answers. Unparsed replies count as the parser default (NEXT), as in every earlier run.'),
    metric=dict(main='URGENT F1 (and URGENT recall) over the scored items', secondary='macro-F1 over the four classes; per-class table; news half only',
                bootstrap='paired bootstrap over items, 2,000 resamples, random.Random(11), 95% interval = sorted[50], sorted[1949]; package-cluster bootstrap reported, not deciding.'),
    gate=dict(rule='PASS iff at least 50 complete pairs AND the lower 95% bound of GATED - S URGENT F1 > 0.',
              reported_not_deciding=['GATED - OURS', 'GATED - NN', 'GATED - R1', 'GATED - pkg_mode', 'GATED - (gatekeeper without H-MEM rule)', 'URGENT recall differences', 'macro-F1 differences', 'package-cluster intervals'],
              no_changes='The rule, the metric, the arms, the scored set and the code hashes below are not changed after this file is sealed.',
              if_fail='The product is still finished and submitted (user decision 2026-10-26). README then states the failed gate with its numbers and narrows the claim '
                      'to what passed (e.g. the reopen watcher and the measured trade-off), without claiming the memory gatekeeper improves urgent detection.'),
    input_hashes={p: sha(p) for p in ('data/news_items.json', 'data/news_events.json', 'data/news_feat.json', 'data/news_build_meta.json', 'exam/make_news_exam.py',
                                      'exam/run_news.py', 'exam/score_news.py', 'core/build_events.py', 'core/triage_agent.py', 'core/gate.py', 'core/hmem_features.py',
                                      'core/eval_core.py', 'core/nightshift.py', 'core/debparse.py', 'core/engines_client.py', 'engines/bridge.ts',
                                      'engines/hmem/index.ts', 'engines/world-model/index.ts')},
)
out = os.path.join(ROOT, 'prereg_news.json')
json.dump(P, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
h = sha('prereg_news.json'); open(os.path.join(ROOT, 'prereg_news.sha256'), 'w').write(f'{h}  prereg_news.json\n'); print(h)
