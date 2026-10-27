# Revisit

**A Debian LTS triage agent that remembers how each package was handled, checks that memory against the raw evidence, closes deferred CVEs bookworm already fixed, and reopens the ones whose written condition is met.**

User: the people who decide Debian 12 "bookworm" security work (Debian LTS, and derivative distributions that follow its tracker).
Built for Open Agent Hackathon 2026, track 3 (Reasoning Architecture).

## 60-second judge path

Needs Python 3.9+ (standard library only) and Node 18+.

```bash
npm install                                  # tsx, for the Meterless engines (H-MEM, World Model, Scout Intent)
python -I scripts/verify_prereg.py           # the sealed pre-registrations, checked against the committed git blobs
python -I app/run.py demo --sample           # no keys, no Nightshift, no Zetaris: replays the recorded run in seconds
python -I test/test_product.py               # replay == recorded live run; numbers recomputed from traces
python -I scripts/audit_time_wall.py         # no agent saw a row from after its item's time wall, in any recorded trace
python -I scripts/verify_forecast.py         # the sealed live forecast, scored against Debian's tracker as it is now
python -I app/server.py                      # open http://127.0.0.1:8765
```

What to look at:
1. **PHP2Shell replay** (first screen): the agent sees the tracker as it stood before the CVE existed; two Nemotron paths answer; Scout picks one; then Debian's real decision.
2. **Memory was wrong, Scout caught it**: one such case, shown next to the exam count (Scout overruled memory 40 times, right 13, memory had been right 18).
3. **Open any trace**: Scout → Executor (Zetaris SQL, as its own non-admin user) → H-MEM → two Nemotron paths → Scout guard → Planner ⇄ Evaluator ⇄ Verifier, every step with its SQL, rows and model output.

| Number | Value | Source |
|---|---|---|
| Sealed exam, pre-registered gate | passed | `runs/news_score.json`, prereg SHA-256 `6681509d2a09e7f6...` |
| Urgent F1, Revisit vs the same model given 20 raw history lines | 0.434 vs 0.280 (+0.154, CI [+0.084, +0.226]) | same |
| Urgent F1 of no-model baselines over the same package history | package mode 0.453, nearest past case 0.448: as good as Revisit | same |
| Same difference, resampling whole packages | CI [-0.028, +0.294]: crosses 0 | same |
| Scout's check vs always trusting memory | -0.020, CI [-0.051, +0.008]: no gain | same |
| Urgent recall, Revisit vs 20 raw history lines | 0.327 vs 0.187 | same |
| Reopen watch | shown as cases, no accuracy number: the independent truth (Debian's own bookworm fixes in the 4 days after the watch date) had 0 events among 275 open waits | `prereg_reopen_action.json`, `runs/reopen_action_score.json` |
| Recorded demo run | 40 live Nemotron answers, 16 reused from the sealed exam (exam items' decision paths only), 46 Zetaris queries | `runs/traces/*.json` |

## Live forecast: verify it yourself

The sealed exam (Results, below) was graded with answers that already existed. This part is graded by Debian's future decisions, so nobody (us included) could know the answers when the predictions were made.

1. **Registered first.** `prereg_forecast.json` (SHA-256 `5bd9407c8b6b5c994cfad64d02aa87293cf68120c76558ed346f0b967eeca981`) was written at 2026-10-27T04:38:10+00:00 (UTC), before any model call on these items; the first sealed prediction finished at 2026-10-27T04:39:16+00:00. It fixes the population, the sample, the arms, the outcome rule and the metrics.
2. **Population.** A fresh Debian security tracker snapshot, fetched 2026-10-27T04:34:40Z (`tracker.json` SHA-256 `af2c8492db234adaaea0e30e4cee66c53262ed141063bba318623b5d574517d2`; `list`, DSA and DLA lists hashed in the same file). Every (CVE, package) still undecided for bookworm in it: 1295. Sample: seed 20261027, the first 150 of a fixed shuffled order.
3. **Predicted.** The frozen product decision path (evidence path + memory path + the frozen gate, the same program as the exam; inputs only from that snapshot), and the no-model package-mode baseline. The evidence path and the memory path alone are reported too. Nightshift, one request at a time, stop at 2026-10-27T17:00:00+08:00.
4. **Sealed.** `forecast_sealed.json` (SHA-256 `ecbfb945f7d5c33a90a1eed655fa2d0c5e812ffa7145eaf974d02938cc73bc6d`), sealed 2026-10-27T06:52:29+00:00: **150 of 150** items (K = the first items of the registered order that finished before the stop), each with every arm's prediction, the gate rule and short reasons. Revisit predicted urgent for 27 of them; package mode for 12.
5. **Verify.** `python -I scripts/verify_forecast.py` checks both hashes, fetches the tracker as it is now and scores every sealed item Debian has decided since: urgent = fixed in bookworm through bookworm-security (a DSA/DLA upload); not urgent = marked postponed, ignored or no-dsa; anything else is excluded and counted. It prints the decided and excluded counts and, per arm, urgent F1 and accuracy with 95% bootstrap intervals; with fewer than 20 decided items it prints numbers only. Offline it says so and exits 2.

On the day of sealing every item was undecided, so there is no score yet. The runner was started with `python -I -c "import sys, os; sys.path.insert(0, os.path.join(os.getcwd(), 'core')); import hmem_features; keep = sys.stdout; import runpy; runpy.run_path(os.path.join('forecast', 'run_forecast.py'), run_name='__main__')"` (with `REVISIT_SCOPE=iso`): the first plain start answered item 1 and then stopped on a console-encoding clash between two modules that both rewrap stdout; the launcher only keeps that stream open, and the registered files are unchanged.

## What it claims

**With the same Nemotron, giving it the package's stances as organised by H-MEM misses fewer urgent CVEs than giving it only the 20 most recent raw history lines. A no-model baseline that just uses package statistics does as well, so the gain comes mainly from having an organised package memory, not from the model's judgment.** On a sealed exam built from Debian's October 2026 advisories the pre-registered gate passed. What limits the claim, all measured below: the two paths did not get the same information (the 20 lines cut the history short for 259 of 570 items, the memory path also sees per-class counts and makes an extra self-check call), so no arm isolates the H-MEM engine itself; Scout's memory check added nothing; and urgent recall is low (0.327: about two of three urgent CVEs are missed). Revisit is a second reader for the morning queue, not a filter. It also closes waits bookworm already fixed and calls back the ones whose written condition is met by a signal that appeared after the deferral; that part is shown as cases, without an accuracy number.

This is narrower than what we set out to show ("knows when not to trust memory"). The product keeps the sealed configuration (Scout-gated), because switching to the arm that scored better after seeing the results would be choosing by the answer key.

## The decision, the data, the output

*We are building an agent that helps Debian LTS triagers decide which newly tracked CVEs must be fixed now and which deferred ones to close or reopen today, by checking its memory of each package against the raw evidence and against the condition written at deferral time, using the Debian security tracker, DSA/DLA advisories, CISA KEV, upstream release data and OSV behind one Zetaris layer, producing a morning queue where every decision carries its evidence rows and the reason memory was or was not trusted.*

## How the agents work

```
TRIAGE  (a sealed-exam CVE replayed behind its time wall, or one still undecided in today's tracker)
  Scout Intent      recognise -> guard -> route -> signed contract (triage.new_cve)
  Executor          Zetaris, as user executor@revisit3.local: CVE record + decision history up to the wall (view rv3.decisions_<wall>)
  H-MEM             the package's current stances (superseded ones hidden), relevance recall
  two paths         evidence path: Nemotron + the package's 20 most recent raw tracker lines
                    memory path:   Nemotron + H-MEM, plus one rule-triggered self-check when it departs from memory
  Scout Guard       memory-reliability check on triage.commit_decision -> adopt the memory path or the evidence path
  Planner  <-+      Nemotron chooses which evidence the review needs (history, advisories, KEV, same CVE elsewhere)
  Executor   |      one federated Zetaris query over the walled views
  Evaluator  |      Nemotron: accept | need_evidence (back to the Planner) | escalate (to the LTS lead)
  Verifier --+      code: cited rows exist, every CVE/advisory id named is in a returned row; else send back once, then escalate
  -> proposal; committing it needs a human confirm (Scout marks triage.commit_decision high-risk)

REOPEN  (daily; watch date 2026-10-23)
  Zetaris           as user watcher@revisit3.local: rv3_resolved (waits bookworm already fixed -> close, no model call)
                    and the view rv3.reopen_due_v2 (the condition at deferral OR the latest note, compiled to SQL)
  Executor          one federated query per fired wait: tracker (Postgres) + upstream links and branch + release-monitoring.org (REST) + OSV (REST)
  Reopen judge      Nemotron: is the team's condition met today? (each row says whether it is new since the deferral)
  Verifier          code: cited rows exist; "met" must cite a fix row (unstable fixed version, a commit or PR that counts as the
                    fix, the fixed branch) dated after the deferral, and an unstable version must be on bookworm's version line
                    (same epoch) and newer than bookworm in Debian version order (recomputed in code, app/debver.py)
  H-MEM / World Model  bookkeeping: H-MEM holds the original commitment (never superseded) and the latest note (superseded); the
                    World Model records waits, condition rows and reopen events with an audit log. The decision comes from the view and the judge.
```

| Role | Model or code |
|---|---|
| Evidence path, memory path, Planner, Evaluator, reopen judge | Nemotron through Nightshift |
| Scout (routing, guard, memory-reliability rule, contracts), Executor (SQL), wall keeper, Verifier, watch view | code |

Every decision is a Nemotron answer; code only chooses which path's answer to trust (Scout's rule), checks citations and routes. The Verifier also checks that the component the Evaluator says the flaw is in is a source package the evidence attributes the CVE to (the CVE's package, its own tracker record for today's items, advisories); otherwise the answer goes back once, then to the lead. The path changes with
the data: whether H-MEM has history for the package, whether the paths agree, which rule of the memory check fires, what the Evaluator asks for,
whether the Verifier finds an unsupported claim, whether a wait is already fixed or its watch query returns a row, and whether a Scout contract
expired during a long model call (it is re-issued through `replan`, lineage kept).

Review loop on 30 sealed-exam items drawn with a fixed seed before running (`exam/run_review_rate.py`; Planner, Evaluator and Verifier live, paths reused from the exam): the Evaluator sent the plan back to the Planner on 2 items (2 send-backs in all, 32 Planner rounds), and the Verifier rejected an unsupported citation on 0 items. Final verdicts: accept 24, escalate 6. (The first 30-item run, before the Verifier's component check, had 3 Evaluator and 2 Verifier send-back items; `runs/old_review_rate_v1.json`.) Nothing was forced: same prompts and loop as the product. The demo includes the first item that looped (CVE-2026-27590|caddy); model answers vary between runs, and in the recorded demo the items that looped were: CVE-2026-116013|lua-nginx-dns, CVE-2026-27590|caddy.

## Results

### Sealed news exam (`prereg_news.json`, sealed before any model call on its items)

Selection rule, fixed in advance:
- every CVE named in a Debian DSA or DLA dated 2026-10-01 to 2026-10-26, kept when Debian has a bookworm decision, except packages updated as whole new versions (linux and linux-* kernels, chromium, firefox-esr, thunderbird, webkit2gtk, wpewebkit; 3555 (CVE, package) rows dropped);
- every CVE CISA added to KEV in October 2026 **as of KEV catalog 2026.10.23**, the catalog the exam was built from (26 October additions; the builder took them all without first filtering to Debian packages). None of those 26 had a bookworm decision, so none entered the exam through KEV and the `kev` evidence source is empty for every exam item. The live catalog has moved on: version 2026.10.26 lists 28 October additions; CVE-2026-109618, CVE-2026-109619 (PHP2Shell) were added to KEV on 2026-10-26, after the exam was built; they are in the exam through the Debian rule (DLA-4848-1), not through KEV (`scripts/check_kev.py`, `evidence/kev_check.json`, checked 2026-10-27);
- 285 news items; plus 285 non-urgent items (deferred or not affected) drawn at random from CVEs first seen after the 2026-09-01 snapshot, matched by package type.

PHP2Shell (CVE-2026-109618/109619, php8.2) is in because DLA-4848-1 matches the rule. Not every news item is a newly tracked CVE: 7 urgent items already had a bookworm DSA/DLA for the same CVE and package before October (fixes re-issued or regressions: expat, imagemagick, jq, redis, ruby-jwt; `runs/exam_reissues.json`). Answers are Debian's own decisions. 285 of 285 pairs finished (570 items, 251 urgent).

Gate: **Passed.** Revisit (Scout-gated) urgent F1 0.434 vs the evidence path alone 0.280: +0.154, 95% CI [+0.084, +0.226] (rule: lower bound > 0).

| Arm | Urgent F1 | Urgent recall | Urgent precision | Macro-F1 (4 classes) |
|---|---|---|---|---|
| **Revisit (Scout-gated, sealed design)** | 0.434 | 0.327 | 0.646 | 0.392 |
| Evidence path only (same model, 20 raw history lines) | 0.280 | 0.187 | 0.553 | 0.354 |
| Always trust the memory path | 0.454 | 0.362 | 0.607 | 0.400 |
| Scout check without its H-MEM rule | 0.451 | 0.359 | 0.608 | 0.391 |
| Nearest past case (no model) | 0.448 | 0.327 | 0.713 | 0.361 |
| Package mode (no model) | 0.453 | 0.323 | 0.757 | 0.369 |
| Repeat last decision (no model) | 0.131 | 0.076 | 0.487 | 0.265 |

**Scope header of the scored runs.** The exam, the review-rate run and the recorded demo sent `meterless-scope: iso-<uuid>` (a fresh scope per request), not the Power contract's default `user`: with `user`, Nightshift inserts up to three earlier answers into the prompt, so the evidence path and the memory path would stop being independent and a recording could not be replayed. The product's default is `user`; product-mode runs (`python -I app/run.py today 2`) made 16 such calls in 2 runs: 8 calls 04:45-04:47 on 2026-10-27 for edk2, ruby3.1; 8 calls 05:47-05:48 on 2026-10-27 for lua-nginx-dns, twisted (`runs/calls.jsonl`, `scope_mode: user`; traces of the later run in `runs/traces_scope_user/`, of the earlier one in `runs/old_traces_scope_user_20261027_0445/`). Details under Sponsor technology.

**How the exam ran.** The sealed exam read its inputs from sealed local snapshots (`data/news_items.json`, `data/news_events.json`), not through Zetaris, ran the two decision paths, and computed the Scout-gated answer with the frozen `core/gate.py`, not through the Scout engine or the review loop. The product's Scout engine picks exactly what `core/gate.py` picks (9,216/9,216, `evidence/scout_equivalence.txt`), and for exam items the product, reading through Zetaris, sends byte-identical decision-path requests (`test/test_product.py`). The review loop was measured separately (above).

**Reading the intervals.** The pre-registered interval resamples items. CVEs in the same package are not independent (one advisory can fix dozens of CVEs and both paths answer them alike), so we also resample whole packages: Revisit minus evidence-only is then [-0.028, +0.294], which crosses 0. The gate passed as registered; the evidence that the gain holds across packages, not just across many CVEs of a few packages, is weak.

**Ablation: where the gain comes from.**

| Remove | Urgent F1 change | 95% CI | Reading |
|---|---|---|---|
| the organised package memory (the evidence path alone: 20 raw tracker lines instead of H-MEM's stances over the whole history) | -0.154 | [-0.226, -0.084] | organised package memory helps; unequal information, see below |
| Scout's memory-reliability check (always trust the memory path) | +0.020 | [-0.008, +0.051] | Scout did not add |
| the H-MEM rule inside Scout's check | +0.017 | [-0.010, +0.047] | no measurable effect |
| Nemotron entirely (nearest past case over the same history) | +0.014 | [-0.056, +0.088] | a no-model baseline is as good on urgent F1 |
| Nemotron entirely (package mode: the package's most common decision) | +0.019 | [-0.047, +0.088] | as good again |

**This ablation does not isolate H-MEM.** The memory path and the evidence path differ in three ways at once: (1) the evidence path sees only the package's 20 most recent tracker lines, which cut the history short for 259 of 570 items (45%; the longest history has 318 lines), while the memory path sees H-MEM's stances over the whole history; (2) the memory path's prompt includes the package's per-class decision counts, the same information the package-mode baseline uses; (3) the memory path makes one extra self-check call when it departs from memory (193 of 570 items). No arm gives the model the whole history without the H-MEM engine. The evidence supports "an organised whole-history package memory helps the model", and the no-model baselines show that this memory, not the model's judgment, carries the result; it does not show what the H-MEM engine's supersession or recall add by themselves.

Scout overruled memory 40 times: the evidence path was right 13 times, memory had been right 18 times. Scout stays in the product as the sealed design and as the request router, guard and contract signer (conformance below); this exam does not show that its memory check improves decisions.

**Data after the time wall (found by QA, post hoc).** Both decision paths received the same CVE facts, built from the 2026-10-26 tracker:
- 11 of 570 items showed a bookworm version that first appeared in a Debian archive after the item's wall (snapshot.debian.org dates, `scripts/check_version_leaks.py`): curl 7.88.1-10+deb12u15 (first seen 2026-06-30; 3 items); imagemagick 8:6.9.11.60+dfsg-1.6+deb12u11 (first seen 2026-06-23; 1 item); jq 1.6-2.1+deb12u2 (first seen 2026-07-01; 1 item); mariadb 1:10.11.18-0+deb12u1 (first seen 2026-07-04; 6 items). For jq CVE-2026-32316 that version (DLA-4662-1) carries this CVE's first fix, which was incomplete (DLA-4840-1 completed it), so the answer leaked for that item;
- six wall-2026-10-01 items (nodejs 4, expat 2) had history events labelled urgent only because of a DLA dated 2026-10-01 itself, the wall day;
- descriptions and attack scope came from the 2026-10-26 tracker.

Dropping every affected pair (17 pairs; 268 left): Revisit minus evidence-only +0.152, CI [+0.078, +0.226], gate still passes. The sealed exam is not rebuilt; exams built after 2026-10-27 take bookworm versions from snapshot.debian.org at the wall date, descriptions from the first dated tracker snapshot listing the CVE, and no scope (`exam/build_item_facts.py`: the newer of bookworm and bookworm-security on the wall date; `test/test_exam_builder.py` checks it with the same dates and finds 0 such versions).

**Same period?** The news items span five time walls (2026-06-01 to 2026-10-01) and 49 packages; the non-urgent items come only from the last two walls. Wall and package alone therefore predict much of the answer. On the 73 pairs whose news item sits on those two walls: Revisit 0.624, evidence-only 0.357, package mode (no model) 0.787, nearest past case 0.701.

**Run incident.** Two copies of the exam runner ran at the same time from the start (a launch we believed had failed had started), so two requests were in flight instead of the one we promised the shared Nightshift box, and most items got two answers per path (68 evidence-path and 75 memory-path items got two different answers). The sealed scorer keeps the last answer per item (numbers above). Keeping the first answer instead: Revisit minus evidence-only +0.169, CI [+0.097, +0.236], gate passed (`runs/news_score_duplicates.json`).

Cost: 2.339 Nemotron calls per item (both paths always run). Models that served the exam (both paths, 1333 calls): nemotron-3-ultra-550b-a55b 1219, nemotron-3.5-super-vl-120b-a12b 61, nemotron-3.5-lightning-30b-a3b 53.

### Reopen (286 real conditional deferrals, from revisit2)

No accuracy number is reported for the reopen watch. The truth used earlier (revisit2: Debian unstable fixed, a fix commit in an upstream release tag, or OSV listing a fixed version) shares its signals with the watch, so an F1 against it measures how well the condition templates were parsed, not whether reopening was right; we withdrew that comparison. An independent truth was sealed instead (`prereg_reopen_action.json`, before the outcome data was fetched): Debian's own later action, a bookworm DSA/DLA or a fixed +deb12u bookworm line for the wait between the watch date 2026-10-23 and 2026-10-27. It found 0 such actions among 275 open waits (`runs/reopen_action_score.json`), below the sealed threshold of 10, so the watch is shown as cases only.

What changed in the watch after review, applied in `rv3.reopen_due_v2` (the sealed `rv3.reopen_due` is kept as it was):
- **Already fixed:** 11 of the 286 waits already had a bookworm DSA/DLA or a fixed +deb12u line by the watch date; the sealed watch flagged 10 of them. They are now closed, not reopened, with no model call.
- **A linked commit is not automatically the fix:** it counts only if the tracker note says "Fixed by", the commit names the CVE, or the commit's author date is after the deferral (tracker and OSV fixed versions count separately). The sealed watch had flagged 4 waits only through commits that fail this rule (CVE-2019-12067|qemu, CVE-2023-39327|openjpeg2, CVE-2023-5072|jenkins-json, CVE-2023-5072|libjettison-java); for qemu CVE-2019-12067 the linked commit is the 2014 change that introduced the code. The same rule is in the watch view, in the evidence rows the reopen judge reads (each commit is marked as counting or not), in the judge's prompt, and in the Verifier, which rejects a "met" that cites no fix.
- **Only a new signal, on bookworm's line, can trigger a wait:** a signal that already existed when Debian chose to wait was part of that decision. Each signal now carries its own date: an unstable fixed version the day it reached the Debian archive (snapshot.debian.org), a commit its author date (the date in the patch header; the commit date can be later), a release the date of the first upstream tag containing the fix (GitHub), a PR its merge date. 68 of the 86 unstable fixes were already in the archive on or before the deferral. An unstable version counts only on bookworm's version line: the same epoch and newer than bookworm in Debian version order. The sealed watch had flagged 2 waits through an unstable fix on another line (CVE-2022-29977|libsixel, CVE-2022-29978|libsixel; for example: unstable 1:1.8.7-1 (epoch 1) is not on bookworm's line (1.10.3-3, epoch 0)) and 53 waits only through signals that were already there (assimp, busybox, gobgp, hdrhistogram, libjson-java, libkcapi, libxslt, lrzip, nltk, node-elliptic, ofono, openexr, packagekit, phpldapadmin, python-redis, requests). The deferral date is the first monthly snapshot (from 2026-06-01) that shows the wait; for waits already open then, the real deferral may be older, and a signal between the two counts as already there. The same rule is in the view, in every evidence row the judge reads ("new since the deferral" or "already there when Debian deferred", and the version-line check), in the judge's prompt, and in the Verifier, which checks the dates and versions itself.
- The fixed watch fires on 16 of the remaining waits (edk2, ffmpeg, gdcm, glib-networking, libcrypt-passwdmd5-perl, msgpack-c, netcdf, netcdf-parallel). These rules were written after seeing the 286 waits; nothing here is a fresh confirmation.
- Reopen judge addendum (`prereg_reopen_judge.json`, sealed before any judge call): its result was scored against the earlier, circular truth, so it is not reported as accuracy.

The demo's reopen cases are picked by fixed rules (`scripts/pick_demo.py`): one wait for each kind of behaviour above.

## Sponsor technology

| Sponsor | What Revisit uses | Where | Evidence |
|---|---|---|---|
| **Zetaris** (local, Docker) | Every query the product and the watch make goes through Zetaris (the sealed exam did not: see below). Postgres tables (tracker history, CVE records, advisories, KEV, deferrals, upstream links, already-fixed waits) + REST tables (OSV, release-monitoring.org) in one SQL. Time walls are schema-store views (`decisions_`, `advisories_`, `kev_<wall>`, and for today's queue `cve_tracker_<wall>`): advisory and KEV rows strictly before the wall; history rows are the tracker snapshot taken on the wall date, whose urgent labels include DLAs dated that same day. Each agent role reads as its own non-admin Zetaris user. The triage executor holds no standing grant at all, not even on the CVE records (which hold today's descriptions): before an item runs, the wall keeper (setup identity) looks up the item's wall, grants the executor SELECT on the CVE records and that wall's views only, and revokes them afterwards, so a query for a later wall or the raw tables is refused by Zetaris; `scripts/audit_time_wall.py` checks every recorded trace. The watcher cannot see new CVEs; no agent can grant itself access | `app/zetaris_setup.py`, `scripts/setup_governance.py`, `app/evidence.py`, `app/sql/` | `evidence/zetaris_governance.txt`, `evidence/watch_equivalence.txt`, `runs/zetaris_sql_log.jsonl` |
| **Meterless H-MEM** | Package stances with supersession and relevance recall feed the memory path; the exam gain comes from that organised whole-history memory versus 20 raw lines, and no arm isolates the engine itself (see Ablation). Reopen: original commitment vs latest note (bookkeeping) | `engines/hmem/` | official conformance 13/13 (`evidence/hmem_conformance.txt`) |
| **Meterless Scout Intent** | Recognises each request, guards it (injection, RBAC, scope, PII, rate limit + the memory-reliability check), routes tools, signs 5-minute contracts the executor verifies | `engines/scout-intent/` | official eval runner exit 0, every hard floor cleared (`evidence/scout_conformance.txt`; how the fixture registry inflates top-1: `evidence/scout_conformance_notes.txt`, leave-one-out: `evidence/scout_loo.txt`); 9,216/9,216 equal to the frozen gate (`evidence/scout_equivalence.txt`); 21 unit tests |
| **Meterless World Model** | Waits, condition rows and reopen events with an audit log (bookkeeping) | `engines/world-model/` | official conformance 8/8 (`evidence/world_model_conformance.txt`) |
| **Nightshift + NVIDIA Nemotron** | Every model call: both decision paths, Planner, Evaluator, reopen judge. Stream, tier-split off, long content in the system message. Model: every request asks for `nvidia/nemotron-3-super-120b-a12b`; Nightshift routes it inside its Nemotron lanes and logs the model that actually served it: nemotron-3-ultra-550b-a55b 3105, nemotron-3.5-super-vl-120b-a12b 163, nemotron-3.5-lightning-30b-a3b 114 of 3382 logged answers (`runs/calls.jsonl`, fields `requested` and `served`) | `core/nightshift.py`, `app/llm.py` | exam: nemotron-3-ultra-550b-a55b 1219, nemotron-3.5-super-vl-120b-a12b 61, nemotron-3.5-lightning-30b-a3b 53; live answers in the recorded demo: nemotron-3-ultra-550b-a55b 39, nemotron-3.5-super-vl-120b-a12b 1 |

Re-run all three conformance suites: `python -I scripts/run_conformance.py` (each vendored harness runs in a temporary copy, Scout's with its own `npm install`; the outputs go to a temporary folder it prints, nothing in the repo changes; `--update-evidence` is how the committed `evidence/*_conformance.txt` were written).

**Scope header.** By default every request carries `meterless-app: revisit3` and `meterless-scope: user`, as the Power contract asks; product-mode runs (`python -I app/run.py today 2`) made 16 such calls in 2 runs: 8 calls 04:45-04:47 on 2026-10-27 for edk2, ruby3.1; 8 calls 05:47-05:48 on 2026-10-27 for lua-nginx-dns, twisted (`runs/calls.jsonl`, `scope_mode: user`; traces of the later run in `runs/traces_scope_user/`, of the earlier one in `runs/old_traces_scope_user_20261027_0445/`). Recorded and scored runs use `--record`, which sends a fresh `iso-<uuid>` per request: with `user` Nightshift inserts up to three earlier answers into the prompt (measured by our team on 2026-10-24: +307 to +683 prompt tokens, one earlier verdict injected), which would make the evidence path and the memory path stop being independent and make recordings unreplayable.

## Verifying the seal

`python -I scripts/verify_prereg.py` checks every SHA-256 the prereg files registered against the files in this repository (LF or CRLF form: the hashes were computed on a Windows working copy, git stores LF). The 18 news-exam inputs are unchanged since sealing; the reopen-judge addendum's inputs were edited after its run, so the versions that ran are kept in `sealed/reopen_judge_addendum/`. Before submission the git history was rebuilt as a single commit, because the working history held internal notes; the original commits, including the sealing commits, are kept in a private git bundle and can be provided on request. The proof of sealing here is therefore the registered hashes plus this script, not commit times (which were local and had no external timestamp anyway).

## Run it live

Needs Meterless Nightshift on `127.0.0.1:8088` (URL and runtime token in `../.env`, never in this repo) and the local Zetaris with the `revisit-pg` Postgres container on its Docker network.

```bash
python -I scripts/build_resolved.py <downloads>                    # data/reopen_resolved.json (DSA/DLA lists)
python -I scripts/build_today.py <tracker snapshots> <downloads>   # today's undecided queue and its history
python -I app/zetaris_setup.py <downloads>                         # tables, REST tables, walled views
python -I scripts/setup_governance.py                              # non-admin users per agent role; allowed / refused queries
python -I scripts/check_watch.py                                   # the two watch views against the recorded flags
python -I app/run.py today 3                                       # live, scope user: this morning's first 3 undecided CVEs
python -I app/run.py demo --record                                 # how the shipped traces were recorded
```

`<downloads>` holds the Debian tracker `list`, `data/DSA/list`, `data/DLA/list`, `tracker.json`, the CISA KEV feed and bookworm `Sources.xz`; `<tracker snapshots>` holds monthly `list` snapshots (2026-06-01 to 2026-10-01) and `ss13.txt`. The 286 waits and their condition templates are in `data/reopen_bundle.json` and `data/reopen_compiled.json` (from revisit2).

## Limits

- One month of news, 570 items; items in the same package are not independent, and wall and package predict much of the answer (above).
- Urgent recall 0.327.
- Unequal inputs on the exam: the evidence path's 20 lines cut the history short for 259 of 570 items (45%), the memory path also sees per-class counts and made an extra self-check call on 193 items. No arm isolates the H-MEM engine, and the no-model baselines do as well, so nothing here says the model judges better.
- Interval digits: the paired bootstrap (2,000 resamples, seed 11) draws from the scorer's pair order; recomputing it with pairs sorted by item key gives an interval that differs in the third decimal (QA got [0.083, 0.227] for [0.084, 0.226]). The gate result does not change.
- Each exam item's `why` (in `data/news_items.json`, sealed) lists every advisory naming the CVE, including other releases' advisories: for the PHP2Shell items it lists DSA-6574-1 (php8.4 in trixie) next to bookworm's DLA-4848-1. In October 2026 bookworm is in LTS, so the page shows only the DLAs as bookworm's.
- Exam reasons quote the tracker as it stood on the item's wall date. Example: on the expat card, CVE-2024-8176 appears as deferred in bookworm because that was its status then; bookworm later fixed it in a point release (2.5.0-1+deb12u2).
- The triage executor's grant on the CVE records is the whole table while an item runs: it could read other items' records (descriptions and versions, never answers). The product queries only its own item; every SQL statement is in the trace.
- Replays cut the tracker at monthly snapshots, not at the hour a CVE appeared.
- Both paths always run: 2.339 Nemotron calls per CVE.
- Planner, Evaluator and judge never query Zetaris directly; they see only rows the executor or watcher fetched.
- Today's queue has no answers yet; it shows the product working on live data (every answer for today's items is a live Nightshift call), not accuracy. A known wrong case from an earlier recording: ruby3.1 CVE-2026-97229, where both paths said not affected because the CVE text names GitLab although the flaw is in Ruby's own regex engine; the Evaluator, reading the CVE's tracker record, suggested urgent and sent it to the lead (`runs/old_traces_20261027_0600/today__CVE-2026-97229__ruby3.1.json`).
- The Debian tracker's `scope` field is a default (`local` for 558 of the 570 exam items), not an attack vector. The sealed exam's decision paths saw it, and saw the bookworm main version rather than the newer bookworm-security one (both kept for byte-identical replay); the product's Planner, Evaluator and evidence rows no longer show `scope` and use the version from bookworm plus bookworm-security on the wall date.
- The reopen REST tables (OSV, release-monitoring.org) are fetched when queried, not as they stood on the watch date; the reopen side has no time wall for them.
- `runs/reopen_judge.log` ends in a traceback: the judge script crashed while printing, after it had written its result files (fixed afterwards; the result files were complete).
- Scout's generic engine (`engines/scout-intent/index.ts`) ships the spec's default model profiles, which name OpenAI models; Revisit's Scout is built with its own two profiles (rules-local, Nightshift Nemotron) and no other provider.

## Existing components (declared)

Development period started 2026-10-22 00:00 UTC. Everything here was written in that period:
- `engines/hmem`, `engines/world-model`, `engines/bridge.ts`, `core/triage_agent.py`, `core/debparse.py`, `core/engines_client.py`: written 2026-10-23 for our first attempt (revisit), copied unchanged except the lines marked `REVISIT3`.
- `core/gate.py`, `core/hmem_features.py`, the reopen truth, bundle, condition templates and the 286-wait results: written 2026-10-23/24 for revisit2 (`evidence/from_revisit2/`, commit da961d7).
- New in revisit3 (2026-10-26/27): the news exam, the live forecast, Scout Intent, the Zetaris evidence layer, governance and watch views, the Planner/Evaluator/Verifier loop, the reopen judge, today's queue, the UI.
- Meterless harnesses (commit 1742dec) are vendored unmodified under `vendor/`. Data comes from public Debian, CISA, OSV, release-monitoring.org and snapshot.debian.org sources; no personal data.

## Repository map

`forecast/` live forecast (build, run, seal) · `app/` product · `core/` decision paths and Nightshift client (hash-sealed) · `engines/` Meterless engines · `exam/` sealed exam, rescoring and review-rate scripts · `data/` exam items, today's queue, history · `sample/` SAMPLE_MODE cassettes · `runs/` recorded runs and traces · `evidence/` tests and conformance · `ui/` interface · `test/` tests · `vendor/` official Meterless harnesses · `docs/` screenshots
