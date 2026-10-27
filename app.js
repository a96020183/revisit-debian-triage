/* Revisit UI. Renders window.REVISIT (ui/data.js, built by app/build_ui_data.py from traces and scored files).
   No number on this page is typed by hand: each one is read from a trace or a score file. */
(function () {
  const $ = (id) => document.getElementById(id);
  // A wrapped banner can change height on resize, zoom or font loading.
  const banner = $('replay-banner');
  const fitBanner = () => {
    if (banner) document.documentElement.style.setProperty('--banner-height', `${Math.ceil(banner.getBoundingClientRect().height)}px`);
  };
  fitBanner();
  if (banner && typeof ResizeObserver !== 'undefined') new ResizeObserver(fitBanner).observe(banner);
  window.addEventListener('resize', fitBanner);
  const D = window.REVISIT;
  if (!D || !D.exam || !Array.isArray(D.traces) || !D.forecast || !window.REVISIT_FORECAST || !Array.isArray(window.REVISIT_FORECAST.items)) {
    $('main').innerHTML = '<section class="hero"><h1>The replay data could not be opened.</h1><p class="lede">Keep the data folder, scripts and index.html together, then reopen the page. If you copied only this HTML file, copy the complete site folder.</p></section>';
    return;
  }
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const pct = (x) => (x == null ? 'n/a' : x.toFixed(3));
  const CLS = { URGENT: 'Urgent', NEXT: 'Defer', WONTFIX: "Won't fix", NOTAFF: 'Not affected' };
  const cls = (c) => CLS[c] || c || 'n/a';
  const tri = D.traces.filter((t) => t.kind === 'triage' && (t.result || {}).status !== 'unknown');
  const reo = D.traces.find((t) => t.kind === 'reopen');
  const ev = (t, agent, kind) => t.events.filter((e) => e.agent === agent && (!kind || e.kind === kind));
  const one = (t, agent, kind) => ev(t, agent, kind)[0];
  const pathOf = (t, p) => t.events.find((e) => e.kind === 'path' && e.detail.path === p);

  // ---------- header
  $('mode').innerHTML = `<b>Recorded run:</b> ${D.stats.nemotron_live || 0} Nemotron answers made during recording · ${D.stats.nemotron_reused || 0} reused from the sealed exam · ${D.stats.zetaris_queries || 0} recorded Zetaris queries`;
  $('foot').textContent = `Source commit ${D.source_commit.slice(0, 12)} · ${D.trace_dir}. Measured results come from the committed traces and score files.`;
  $('intro-recall').textContent = `${pct(D.exam.arms.GATED.URGENT_recall)} (about one in three)`;

  // ---------- hero: the case sample/sample_cases.json names first (its label comes from the demo-pick rule, not from this file)
  const whyAll = (D.cases && D.cases.triage_why) || {};
  const heroName = whyAll[(D.cases.triage || [])[0]];
  const php = tri.filter((t) => heroName && whyAll[t.subject] === heroName);
  const first = php[0] && D.answers[php[0].subject];
  const adv = first && (first.why || []).map((w) => /^(D[SL]A-\S+) \((\d{4}-\d{2}-\d{2})\)$/.exec(w)).find((m) => m && m[1].startsWith('DLA'));
  $('hero-h').textContent = heroName ? `The moment ${heroName} went public.` : 'Replay';
  $('hero-lede').textContent = first
    ? `${adv ? `${adv[2]}, ${adv[1]}. ` : ''}Replayed with Debian's tracker as it stood on ${first.wall}, before the CVE existed. Two Nemotron paths answer, Scout decides which one to trust. Then we show what Debian actually shipped.`
    : 'Run the demo to replay this case.';
  $('php-replay').innerHTML = php.map((t) => {
    const r = t.result || {}; const a = D.answers[t.subject] || {}; const hit = r.decision === a.answer;
    return `<div class="run">
      <div><div class="k">CVE</div><div class="v">${esc(r.cve)}</div><div class="n">${esc(r.pkg)} · bookworm</div></div>
      <div><div class="k">Evidence path</div><div class="v c-ev">${esc(cls(r.evidence_path))}</div><div class="n">20 most recent tracker lines</div></div>
      <div><div class="k">Memory path</div><div class="v c-mem">${esc(cls(r.memory_path))}</div><div class="n">H-MEM stances, whole history</div></div>
      <div><div class="k">Scout picks</div><div class="v">${esc(cls(r.decision))}</div><div class="n">rule <span class="mono">${esc(r.gate_rule)}</span> · ${esc(r.status === 'proposed' ? 'Evaluator accepted' : 'escalated to lead')}</div></div>
      <div><div class="k">Debian decided</div><div class="v ${hit ? 'verdict-match' : 'verdict-miss'}">${esc(cls(a.answer))}</div>
        <div class="n">${hit ? 'Agent matched.' : 'Agent missed.'} <button class="open" data-trace="${esc(t.subject)}">Open trace</button></div></div>
    </div>`;
  }).join('') || '<p class="empty">No replay trace in this build.</p>';

  // ---------- live forecast (forecast_sealed.json, prereg_forecast.json)
  const F = D.forecast;
  if (F) {
    $('forecast').hidden = false;
    $('forecast').innerHTML = `<p><b>Sealed forecast: ${F.K} of ${F.N} registered CVEs.</b> All were undecided in the ${esc(F.fetched_at)} snapshot. This replay shows the sealed predictions, with no current outcome score.</p><p>To verify later outcomes, run <code>python -I scripts/verify_forecast.py</code> in the original repository.</p>`;
  }

  // ---------- catch: Scout blocked the memory path
  const blocked = tri.filter((t) => { const g = one(t, 'scout', 'guard'); return g && g.detail.blocked; });
  const why = (D.cases && D.cases.triage_why) || {};
  const right = blocked.filter((t) => (D.answers[t.subject] || {}).answer === (t.result || {}).decision);
  const catchT = right.find((t) => /overruled memory and was right/.test(why[t.subject] || '')) || right[0] || blocked[0];
  if (catchT) {
    const r = catchT.result; const a = D.answers[catchT.subject] || {}; const g = one(catchT, 'scout', 'guard'); const m = one(catchT, 'memory', 'recall');
    const counts = m.detail.counts || {}; const n = m.detail.n || 1;
    const col = { URGENT: 'var(--urgent)', NEXT: 'var(--wait)', WONTFIX: 'var(--faint)', NOTAFF: 'var(--evidence)' };
    const gr = (D.exam && D.exam.gate_rules) || {}; const bl = ['class_unreliable', 'memory_disagrees_with_itself'].map((k) => gr[k] || { n: 0, chosen_right: 0, OURS_right: 0 });
    const bn = bl.reduce((x, y) => x + y.n, 0), br = bl.reduce((x, y) => x + y.chosen_right, 0), bw = bl.reduce((x, y) => x + y.OURS_right, 0);
    $('catch-sub').textContent = `${r.cve} in ${r.pkg}. ${g.detail.reason || ''} One case, not the rule: on the sealed exam Scout overruled memory ${bn} times and was right ${br} times, while memory had been right ${bw} times. The reasons quote the tracker as of ${r.wall}.`;
    $('catch').innerHTML = `<div class="case">
      <div class="panel"><h3>What happened</h3><ol class="steps">
        <li><span class="who">memory path</span><span>said <b class="c-mem">${esc(cls(r.memory_path))}</b></span></li>
        <li><span class="who">evidence path</span><span>said <b class="c-ev">${esc(cls(r.evidence_path))}</b></span></li>
        <li><span class="who">scout</span><span>rule <span class="mono">${esc(g.detail.rule)}</span>: ${esc(g.detail.reason || '')}</span></li>
        <li><span class="who">debian</span><span>decided <b class="${a.answer === r.decision ? 'verdict-match' : 'verdict-miss'}">${esc(cls(a.answer))}</b></span></li>
      </ol><p class="sub"><button class="open run-open" data-trace="${esc(catchT.subject)}">Open the full trace</button></p></div>
      <div class="panel"><h3>What H-MEM held for ${esc(r.pkg)}</h3>
        <div class="meter" role="img" aria-label="H-MEM current decisions by class">${Object.entries(counts).map(([k, v]) => `<span style="width:${(100 * v / n).toFixed(1)}%;background:${col[k]}"></span>`).join('')}</div>
        <div class="legend">${Object.entries(counts).map(([k, v]) => `<span><i style="background:${col[k]}"></i>${esc(cls(k))} ${v}</span>`).join('')}</div>
        <dl class="kv" style="margin-top:16px"><dt>top recall</dt><dd>${esc((m.detail.top_hits || []).map(cls).join(' · '))}</dd>
        <dt>superseded</dt><dd>${esc(m.detail.superseded)} older stances hidden by supersession</dd></dl></div>
    </div>`;
  } else {
    $('catch-sub').textContent = 'No demo case in this build where Scout overruled memory.';
  }

  // ---------- exam
  const X = D.exam;
  if (X) {
    const arms = [['GATED', 'Revisit (Scout-gated)'], ['S', 'Evidence path only'], ['OURS', 'Always trust memory'], ['pkg_mode', 'Package mode (no model)'], ['NN', 'Nearest past case (no model)'], ['R1', 'Repeat last decision (no model)']];
    const I = X.inputs || {};
    const max = Math.max(...arms.map(([a]) => X.arms[a] ? X.arms[a].URGENT_F1 : 0), 0.01);
    const d = X.diffs['GATED-S']; const pass = X.gate.pass_;
    $('exam-sub').textContent = `${X.n_items} CVEs (${X.n_pairs} pairs) picked by rule before any model ran: every CVE in a Debian DSA/DLA of 1–26 October 2026 with a bookworm decision, except bulk-update packages (kernels, browsers, Thunderbird, WebKit); plus as many non-urgent CVEs first seen in September–October, matched by package type. The answers are Debian's own decisions. The KEV rule used a catalog whose October additions had no bookworm decisions; PHP2Shell entered through Debian's advisory, not KEV.`;
    $('exam').innerHTML = `<div class="panel"><h3>Urgent F1 (finding the CVEs Debian shipped a fix for)</h3><div class="bars">${arms.filter(([a]) => X.arms[a]).map(([a, l]) =>
      `<div class="bar ${a === 'GATED' ? 'main' : ''}"><span class="lbl">${a === 'GATED' ? '<b>' + esc(l) + '</b>' : esc(l)}</span><span class="track"><span class="fill" style="width:${(100 * X.arms[a].URGENT_F1 / max).toFixed(1)}%"></span></span><span class="num">${pct(X.arms[a].URGENT_F1)}</span></div>`).join('')}</div>
      <div class="gate"><span class="c-muted">Pre-registered gate</span>
      <span class="big ${pass ? 'c-ok' : 'c-urg'}">${pass ? 'Passed' : 'Not passed'}</span>
      <span class="c-muted">Revisit minus evidence-only, urgent F1: ${d.point >= 0 ? '+' : ''}${d.point.toFixed(3)}, 95% interval [${d.ci95[0].toFixed(3)}, ${d.ci95[1].toFixed(3)}]. The rule was lower bound above 0.
        Resampling whole packages instead of CVEs gives [${d.ci95_package_clusters[0].toFixed(3)}, ${d.ci95_package_clusters[1].toFixed(3)}]: the gain is not shown to hold across packages.
        Against always trusting memory: ${X.diffs['GATED-OURS'].point.toFixed(3)} [${X.diffs['GATED-OURS'].ci95[0].toFixed(3)}, ${X.diffs['GATED-OURS'].ci95[1].toFixed(3)}]: Scout's check added nothing.
        What helps is giving the model an organised package memory instead of 20 raw lines, and the no-model baselines that use the same package statistics do as well, so this is not better model judgment.
        The two paths were not given equal information: the evidence path's 20 lines cut the package history short for ${I.history_cut} of ${I.items} items (longest ${I.history_max} lines), and the memory path made an extra self-check call on ${I.self_check} items.</span>
      <span class="mono c-muted">prereg_news.json sha256 ${esc(X.prereg_sha256.slice(0, 16))}…</span></div></div>
      <div class="panel"><h3>Urgent recall</h3><dl class="kv">${arms.filter(([a]) => X.arms[a]).map(([a, l]) => `<dt>${esc(l)}</dt><dd>${pct(X.arms[a].URGENT_recall)} recall · ${pct(X.arms[a].URGENT_precision)} precision</dd>`).join('')}</dl>
      ${D.sensitivity ? `<h3 style="margin-top:24px">Same analysis, post hoc</h3><dl class="kv">
        <dt>no post-wall data</dt><dd>${D.sensitivity.excl_postwall.n_pairs} pairs: Revisit − evidence-only ${D.sensitivity.excl_postwall.GATED_minus_S.point.toFixed(3)} [${D.sensitivity.excl_postwall.GATED_minus_S.ci95.map((x) => x.toFixed(3)).join(', ')}]</dd>
        <dt>same walls only</dt><dd>${D.sensitivity.same_period.n_pairs} pairs: Revisit ${pct(D.sensitivity.same_period.URGENT_F1.GATED)}, package mode (no model) ${pct(D.sensitivity.same_period.URGENT_F1.pkg_mode)}</dd></dl>` : ''}
      ${D.reopen_action ? `<h3 style="margin-top:24px">Reopen watch: no accuracy number</h3><p class="sub">The earlier outcome labels shared their signals with the watch. The independent truth sealed instead (Debian fixing a deferred CVE in bookworm between ${esc(D.reopen_action.window)}) found ${D.reopen_action.positives} such fixes among ${D.reopen_action.waits} open waits, so the watch is shown as cases only.</p>` : ''}</div>`;
  } else {
    $('exam-sub').textContent = 'The sealed exam has not been scored in this build.';
  }

  // ---------- queue
  const tcard = (t) => { const r = t.result || {}; const esc_ = r.status !== 'proposed';
    return `<li><button class="card" data-trace="${esc(t.subject)}"><div class="id">${esc(r.cve)}</div><div class="pkg">${esc(r.pkg)}</div>
      <div class="line"><span class="pill" style="color:${r.decision === 'URGENT' ? 'var(--urgent)' : 'var(--wait)'}">${esc(cls(r.decision))}</span> ${esc_ ? '<span class="pill c-warn">needs lead</span>' : ''}</div>
      <div class="meta">Scout rule ${esc(r.gate_rule)} · Evaluator ${esc(r.evaluator)}${r.status === 'escalated' && r.suggested && r.suggested !== r.decision ? ' (suggests ' + esc(cls(r.suggested)) + ')' : ''}${r.needs_confirmation ? ' · human confirm before commit' : ''}</div>
      ${(D.answers[t.subject] || {}).set === 'today' ? `<div class="meta">Snapshot case: still undecided in the ${esc(r.wall)} tracker at recording. Later outcomes are not checked here.</div>` : ''}
      ${(D.cases.known_wrong || {})[t.subject] ? `<div class="meta c-urg">Known wrong: ${esc(D.cases.known_wrong[t.subject])}</div>` : ''}
      ${why[t.subject] ? `<div class="meta">In the demo because: ${esc(why[t.subject])}${/review loop/.test(why[t.subject]) && !t.events.some((e) => e.kind === 'send_back') ? ' (in this recording the Evaluator did not send it back; the loop is in runs/review_rate)' : ''}. Debian decided ${esc(cls((D.answers[t.subject] || {}).answer))}.</div>` : ''}</button></li>`; };
  const rank = (t) => ((t.result || {}).decision === 'URGENT' ? 0 : 1);
  $('q-triage').innerHTML = tri.slice().sort((a, b) => rank(a) - rank(b)).map(tcard).join('') || '<li class="empty">Nothing to decide.</li>';
  const cards = reo ? reo.result.cards : [];
  const watchDate = reo ? (reo.result.watch_date || (reo.subject.match(/\d{4}-\d{2}-\d{2}/) || [''])[0]) : '';
  const todayT = tri.find((t) => (D.answers[t.subject] || {}).set === 'today'); const todayWall = todayT && todayT.result.wall;
  const rcard = (c) => `<li><button class="card" data-trace="${esc(reo.subject)}" data-wait="${esc(c.wait)}"><div class="id">${esc(c.cve)}</div><div class="pkg">${esc(c.pkg)}</div>
      <div class="line">“${esc(c.commitment)}”</div>
      <div class="meta">${c.status === 'resolved' ? `Close it: bookworm already fixed (${esc(c.resolved_by.ref)} ${esc(c.resolved_by.date)}).` : (c.rewritten ? `Note later rewritten to “${esc(c.latest)}”. ` : '') + (c.judge ? 'Judge: ' + esc(c.judge.met) : 'Watch query: no row in the recording')}</div>
      ${(c.why_quiet || []).length ? `<div class="meta">Why not: ${esc(c.why_quiet[0])}${c.why_quiet.length > 1 ? ` (+${c.why_quiet.length - 1} more)` : ''}</div>` : ''}
      ${(D.cases.reopen_why || {})[c.wait] ? `<div class="meta">In the demo because: ${esc(D.cases.reopen_why[c.wait])}.</div>` : ''}</button></li>`;
  $('q-reopen').innerHTML = cards.filter((c) => ['reopen', 'needs_lead', 'resolved'].includes(c.status)).map(rcard).join('') || '<li class="empty">No reopen or close case in this recording.</li>';
  $('q-wait').innerHTML = cards.filter((c) => c.status === 'waiting').map(rcard).join('') || '<li class="empty">Nothing waiting.</li>';
  $('queue-sub').textContent = reo ? `Exam replays sit behind each CVE's time wall; snapshot cards were CVEs still undecided in the ${esc(todayWall || 'latest')} tracker. The recorded reopen watch used the tracker of ${esc(watchDate)}: ${reo.result.resolved} of 286 deferrals were already fixed in bookworm (close them), ${reo.result.watch_fired} of the rest had a condition row in Zetaris. The cards are the demo set, picked by a fixed rule.` : '';

  // ---------- limits (numbers from the score files)
  const L = [];
  if (X) {
    const gr = X.gate_rules || {}; const blk = ['class_unreliable', 'memory_disagrees_with_itself'].map((k) => gr[k] || { n: 0, chosen_right: 0, OURS_right: 0 });
    const bn = blk.reduce((s, b) => s + b.n, 0), br = blk.reduce((s, b) => s + b.chosen_right, 0), bw = blk.reduce((s, b) => s + b.OURS_right, 0);
    L.push(`On the exam Scout overruled memory ${bn} times: the evidence path was right ${br} times, memory had been right ${bw} times.`);
    const I = X.inputs || {};
    L.push(`The comparison with the evidence path is not like for like. That path saw the 20 most recent tracker lines, which cut the history short for ${I.history_cut} of ${I.items} items (${Math.round(100 * I.history_cut / I.items)}%; longest ${I.history_max}); the memory path saw H-MEM's stances over the whole history, including per-class counts, and made an extra self-check call on ${I.self_check} items. No arm gives the model the whole history without H-MEM, so the result says organised package memory helps, not that the H-MEM engine itself does, and not that the model judges better.`);
    L.push(`The exam has ${X.n_items} items from one month; ${X.gold.URGENT || 0} are urgent. Items in the same package are not independent. News items span five time walls and 49 packages; the non-urgent items come only from the last two walls, so package and wall alone predict much of the answer (a no-model package-mode baseline scores like Revisit).`);
    if (D.leaks && D.sensitivity) L.push(`The sealed exam showed both paths some data from after the wall: ${D.leaks.n} of ${D.leaks.checked} items had a bookworm version that did not exist yet at their wall (for jq CVE-2026-32316 it carries that CVE's first, incomplete fix), and six histories had same-day DLA labels. Dropping every affected pair (${D.sensitivity.excl_postwall.n_pairs} left) keeps the gate passing; later exam builds take facts from dated snapshots.`);
  }
  if (D.reopen_measured) L.push(`Reopen numbers come from the 286-deferral set of ${esc(D.reopen_measured.source)}. Watching the original commitment was chosen after seeing that set; the checks for already-fixed waits, commits that are not the fix, signals that were already there at the deferral and versions on another line were all added after review; none is a fresh confirmation.`);
  L.push('Replays are cut at monthly tracker snapshots, not at the hour a CVE appeared. The agent sees less than a triager would.');
  L.push('Every decision is a proposal: committing it needs a human confirm (Scout marks triage.commit_decision high-risk).');
  $('limits').innerHTML = L.map((x) => `<li>${esc(x)}</li>`).join('');

  // Local forecast inspection. All rows were sealed, not generated by this page.
  const forecastItems = (window.REVISIT_FORECAST || {}).items || [];
  $('forecast-seal').innerHTML = `<dl class="kv"><dt>Snapshot (UTC)</dt><dd>${esc(F.fetched_at)}</dd><dt>Sealed (UTC)</dt><dd>${esc(F.sealed_at)}</dd><dt>Original prereg SHA-256</dt><dd><code>${esc(F.prereg_sha)}</code></dd><dt>Original forecast SHA-256</dt><dd><code>${esc(F.sealed_sha)}</code></dd></dl>`;
  function renderForecast() {
    const term = $('forecast-search').value.trim().toLowerCase();
    const items = forecastItems.filter(i => `${i.cve} ${i.pkg}`.toLowerCase().includes(term));
    $('forecast-count').textContent = `${items.length} of ${forecastItems.length} sealed predictions`;
    $('forecast-rows').innerHTML = items.map(i => `<tr><td><code>${esc(i.cve)}</code><small>${esc(i.pkg)}</small><details><summary>Recorded reasons</summary><p><b>Evidence path:</b> ${esc(i.reason_evidence_path)}</p><p><b>Memory path:</b> ${esc(i.reason_memory_path)}</p><p>Gate rule: <code>${esc(i.gate_rule)}</code> · recorded ${esc(i.predicted_at)}</p></details></td><td>${esc(cls(i.predictions.GATED))}</td><td>${esc(cls(i.predictions.pkg_mode))}</td></tr>`).join('') || '<tr><td colspan="3">No sealed prediction matches. Clear the search to see all items.</td></tr>';
  }
  $('forecast-search').addEventListener('input', renderForecast);
  renderForecast();

  const receiptLabels = ['Later time wall refused', 'Raw history refused', 'Self-granted access refused', 'Watcher boundary refused'];
  $('governance').innerHTML = D.governance.map(line => {
    const label = line.includes('GRANT SELECT') ? receiptLabels[2] : line.includes('[watcher]') ? receiptLabels[3] : line.includes('rv3.advisories_2026_10_26') ? receiptLabels[0] : receiptLabels[1];
    return `<details><summary>${esc(label)}</summary><pre>${esc(line)}</pre></details>`;
  }).join('');
  $('repo-link').addEventListener('click', e => {
    if ($('repo-link').getAttribute('href') === 'https://github.com/a96020183/revisit-debian-triage') {
      e.preventDefault(); $('repo-notice').hidden = false; location.hash = 'about-h';
    }
  });

  // The drawer retains the product timeline and adds accessible, local filters.
  const drawer = $('drawer'), scrim = $('scrim');
  const background = [$('site-header'), $('main'), $('site-footer'), $('replay-banner'), document.querySelector('.skip')];
  let lastFocus = null, currentEvents = [], currentSubject = '', currentWait = '', activeFilter = 'all';
  const matches = (e, filter) => filter === 'all' ||
    (filter === 'discussion' && (['planner', 'evaluator', 'judge', 'memory'].includes(e.agent) || ['path', 'guard', 'send_back'].includes(e.kind))) ||
    (filter === 'evidence' && (e.detail.sql || e.detail.rows || e.kind === 'recall' || ['grant', 'revoke', 'lookup', 'cache'].includes(e.kind))) ||
    (filter === 'receipts' && (['verified', 'check', 'final', 'grant', 'revoke', 'refused', 'replan', 'audit'].includes(e.kind)));
  function traceHash() {
    const p = new URLSearchParams({trace: currentSubject});
    if (currentWait) p.set('wait', currentWait);
    if (activeFilter !== 'all') p.set('view', activeFilter);
    return '#' + p.toString();
  }
  function filterEvents(filter) {
    activeFilter = ['all', 'discussion', 'evidence', 'receipts'].includes(filter) ? filter : 'all';
    const selected = currentEvents.filter(e => matches(e, activeFilter));
    document.querySelectorAll('[data-event-filter]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.eventFilter === activeFilter)));
    $('trace-filter-status').textContent = `Showing ${selected.length} of ${currentEvents.length} recorded events`;
    $('dr-events').innerHTML = selected.map(e => {
      const d = Object.assign({}, e.detail), sql = d.sql, rows = d.rows;
      delete d.sql; delete d.rows;
      const label = ['planner', 'evaluator', 'judge'].includes(e.agent) || e.kind === 'path' ? 'Recorded model response' : ['verified', 'check', 'final', 'grant', 'revoke', 'replan', 'audit'].includes(e.kind) ? 'Recorded receipt & details' : 'Recorded details';
      return `<li class="ev" data-seq="${e.seq}"><span class="ag ag-${esc(e.agent)}"><span class="event-seq">#${e.seq}</span>${esc(e.agent)}</span><div><div class="t">${esc(e.title)}</div>
        ${d.reason || d.focus ? `<p class="event-reason">${esc(d.reason || d.focus)}</p>` : ''}
        ${d.cites && d.cites.length ? `<p class="event-cites">Cited rows: <code>${esc(d.cites.join(', '))}</code></p>` : ''}
        ${sql ? `<details><summary>SQL sent to Zetaris${d.identity ? ' as ' + esc(d.identity) : ''}</summary><pre>${esc(sql)}</pre></details>` : ''}
        ${rows && rows.length ? `<details><summary>${rows.length} recorded evidence rows</summary><pre>${esc(rows.map(r => JSON.stringify(r)).join('\n'))}</pre></details>` : ''}
        ${Object.keys(d).length ? `<details><summary>${label}</summary><pre>${esc(JSON.stringify(d, null, 2))}</pre></details>` : ''}</div></li>`;
    }).join('') || '<li class="empty">This case has no events in this category. Choose All events.</li>';
    $('dr-events').scrollTop = 0;
    $('trace-permalink').href = traceHash();
  }
  function openTrace(subject, wait, filter = 'all', sync = true) {
    const t = D.traces.find(x => x.subject === subject);
    if (!t) { if (sync) return; close(false); return; }
    if (!drawer.classList.contains('open')) lastFocus = document.activeElement;
    currentSubject = subject; currentWait = wait || '';
    const wl = t.kind === 'triage' && t.result && t.result.wall;
    $('dr-kind').textContent = `Recorded ${t.kind} · ${t.started} (source timestamp; timezone not recorded)` + (wl ? ` · tracker wall ${wl}. Reasons quote that snapshot.` : ' · shared watch-query context is retained.');
    $('dr-title').textContent = wait || t.subject;
    const r = t.result || {}, answer = D.answers[t.subject] || {};
    if (t.kind === 'triage') {
      $('dr-case-summary').innerHTML = `<dl><div><dt>Evidence path</dt><dd class="c-ev">${esc(cls(r.evidence_path))}</dd></div><div><dt>Memory path</dt><dd class="c-mem">${esc(cls(r.memory_path))}</dd></div><div><dt>Scout picks</dt><dd>${esc(cls(r.decision))}</dd></div><div><dt>Debian outcome</dt><dd>${answer.answer ? esc(cls(answer.answer)) : 'Unresolved at recording'}</dd></div></dl><p>${r.status === 'escalated' ? 'Escalated to the lead.' : 'Proposal only.'} Human confirmation is required before commit.</p>`;
    } else {
      const c = (r.cards || []).find(c => c.wait === wait);
      $('dr-case-summary').innerHTML = c ? `<p><b>${esc(({reopen: 'Reopen proposal', resolved: 'Close: already fixed', waiting: 'Keep waiting', needs_lead: 'Needs lead'})[c.status] || c.status)}</b> · Original condition: “${esc(c.commitment)}”${c.rewritten ? ` · Latest note: “${esc(c.latest)}”` : ''}</p>` : '<p>Recorded daily watch. The timeline includes shared query context.</p>';
    }
    currentEvents = t.events.filter(e => !wait || !e.detail.wait || e.detail.wait === wait);
    const cnt = f => currentEvents.filter(f).length;
    const src = (e, k) => (e.detail.sources ? (e.detail.sources[k] || 0) : (k === 'exam') === !!e.detail.from_sealed_exam ? (e.detail.served || []).length : 0);
    const calls = currentEvents.reduce((s, e) => s + (e.kind === 'path' ? src(e, 'live') : (['planner', 'evaluator', 'judge'].includes(e.agent) && ['plan', 'verdict'].includes(e.kind) ? 1 : 0)), 0);
    const reused = currentEvents.reduce((s, e) => s + (e.kind === 'path' ? src(e, 'exam') : 0), 0);
    $('dr-stats').innerHTML = [['Model answers during recording', calls], ['Reused exam answers', reused], ['Recorded SQL queries', cnt(e => e.kind === 'zetaris' && e.detail.sql)], ['Send-backs', cnt(e => e.kind === 'send_back' || (e.agent === 'verifier' && e.detail.ok === false))]].map(([k, v]) => `<span>${k} <b>${v}</b></span>`).join('');
    $('trace-download').href = `data/traces/${t.subject.replace(/[^A-Za-z0-9._-]/g, '_')}.json`;
    filterEvents(filter);
    drawer.inert = false; scrim.hidden = false; drawer.classList.add('open'); drawer.setAttribute('aria-hidden', 'false');
    background.forEach(el => { el.inert = true; });
    document.body.style.overflow = 'hidden';
    $('dr-close').focus();
    if (sync && location.hash !== traceHash()) location.hash = traceHash();
  }
  function close(sync = true) {
    const wasOpen = drawer.classList.contains('open');
    drawer.classList.remove('open'); drawer.setAttribute('aria-hidden', 'true'); drawer.inert = true; scrim.hidden = true;
    background.forEach(el => { el.inert = false; }); document.body.style.overflow = '';
    if (wasOpen) (lastFocus && lastFocus !== document.body && lastFocus.isConnected ? lastFocus : $('main')).focus({preventScroll: true});
    if (sync && location.hash.startsWith('#trace=')) location.hash = '';
  }
  document.addEventListener('click', e => {
    const b = e.target.closest('[data-trace]');
    if (b) openTrace(b.dataset.trace, b.dataset.wait, b.dataset.filter || 'all');
    const f = e.target.closest('[data-event-filter]');
    if (f) { filterEvents(f.dataset.eventFilter); location.hash = traceHash(); }
  });
  $('dr-close').addEventListener('click', () => close()); scrim.addEventListener('click', () => close());
  document.addEventListener('keydown', e => {
    if (!drawer.classList.contains('open')) return;
    if (e.key === 'Escape') { e.preventDefault(); close(); }
    if (e.key === 'Tab') {
      const focusable = [...drawer.querySelectorAll('button, a[href], summary, input')].filter(el => el.getClientRects().length);
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
  function followHash() {
    const p = new URLSearchParams(location.hash.slice(1));
    if (p.has('trace')) {
      if (drawer.classList.contains('open') && p.get('trace') === currentSubject && (p.get('wait') || '') === currentWait) { filterEvents(p.get('view') || 'all'); return; }
      openTrace(p.get('trace'), p.get('wait'), p.get('view') || 'all', false);
    } else if (drawer.classList.contains('open')) close(false);
  }
  window.addEventListener('hashchange', followHash);
  followHash();
})();
