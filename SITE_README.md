# Revisit — offline replay

The replay banner wraps on narrow screens. Its measured height reserves space for the page header and trace drawer, including at a 390px viewport. Verification used local Chromium viewport emulation; it does not represent physical-device or Safari testing.

Open `index.html` directly, or serve this folder with any static web server. No installation, API key, backend or network connection is needed. Keep the files together. The site also works under a project subdirectory on GitHub Pages.

## What to try

1. Choose **Explore the PHP2Shell trace**. Compare the evidence path, memory path, Scout decision and Debian's recorded answer. Expand SQL, evidence rows, model responses and receipts in the trace drawer.
2. In **Explore the recorded queue**, follow **Evaluator asks for more evidence** or **Verifier rejects an unsupported citation**. The timeline contains the actual recorded returns. Use its discussion, evidence and receipt filters, then close with the Close button, Escape or the backdrop.
3. Open the urgent case Revisit missed, and the reopen, close and waiting cards. A watch card retains shared query context; its JSON download is the complete recorded watch trace.
4. Expand **Inspect the sealed forecast**. Search the sealed CVEs or packages, read the recorded reasons, or download the redacted JSON. These are predictions, not known outcomes.
5. Read the exam results and their limits, then expand the recorded Zetaris access refusals.

Each trace has a relative permalink. Reloading that link restores the selected trace, watch item and event filter. Browser Back also follows trace changes. Keyboard focus stays inside an open drawer and returns to its opener when closed.

## What is recorded

The source is repository commit `4d126dbe3c7639e336f5da08b39761ac74d2a065`. The product UI is adapted from `ui/index.html`, `ui/app.js` and `ui/style.css`. Data comes from the committed `runs/traces`, `sample/sample_cases.json`, scored exam files, governance evidence and `forecast_sealed.json`.

The bundled run contains 40 Nemotron answers made during recording, 16 decision-path answers reused from the sealed exam, and 46 recorded Zetaris queries. Every interaction in this site reads a recording. No model runs, SQL queries, role grants, decisions or reopen actions are executed here. Fields such as `mode: live` and `replayed: false` describe the original recording, not this website.

The classic local data scripts contain the same JSON as the downloadable exports. They allow double-click use without the browser restrictions on fetching JSON over `file://`. There are no remote fonts, analytics, external scripts, service workers or API calls.

Source URLs, email/account identifiers and unrelated organization names are replaced with visible redaction markers. Recorded model identifiers omit their provider prefix. These edits do not change CVE/package IDs, decision classes, cited evidence IDs, dates or measured scores. Forecast reasons are already shortened in the original sealed file; this page does not reconstruct missing text. Downloads are redacted exports, not byte-for-byte originals.

## Read the evidence conservatively

- With the same Nemotron, organized whole-history package memory missed fewer urgent CVEs than the 20-line raw-history path in the sealed exam. Revisit urgent F1 was 0.434 versus 0.280. No-model package mode was 0.453, and nearest past case 0.448: about as good.
- Urgent recall was 0.327, about one in three. This is a second reader, and every proposal requires human confirmation.
- Scout's memory check did not show a gain. The two model paths received unequal information; the experiment does not isolate the H-MEM engine. Resampling whole packages gives an interval crossing zero.
- Reopen behavior is shown as cases only. There is no reopen accuracy claim. The independent outcome window found zero fixes among 275 open waits.
- The sealed exam used local snapshots and the frozen gate. Product traces show Zetaris and the review loop; the exam did not measure that whole loop end to end. Some sealed inputs contained data after the wall; the on-page sensitivity result is a post hoc analysis.
- Queue cards described as today's items refer to the recorded tracker snapshot, not the date you open this site. Trace timestamps do not record a timezone, so the site does not assign one.

## Forecast and live verification

All 150 forecast items were undecided at the registered snapshot. This offline site neither fetches current Debian outcomes nor calculates a current forecast score. To check later outcomes, use the original repository's README and run:

```text
python -I scripts/verify_forecast.py
```

The original pre-registration and forecast SHA-256 values are shown in the forecast panel. They authenticate the original repository files, **not** these redacted exports. The original README describes the scope and limits of the sealing proof, including rebuilt history and the absence of an external timestamp.

The fixed banner preserves the required `https://github.com/a96020183/revisit-debian-triage` link placeholder. Until the coordinator supplies the public repository URL, clicking it explains that state locally. Live mode requires local Zetaris and Meterless Nightshift as documented in the original README. This delivery has not been uploaded or published.

## File guide

- `index.html`, `style.css`, `replay.css`, `app.js`: the static interface.
- `assets/mark.svg`: the local product mark.
- `data/replay.json`, `data/replay.js`: exported product recordings and exam evidence.
- `data/forecast.json`, `data/forecast.js`: the redacted sealed forecast.
- `data/traces/`: individual recorded trace downloads.

Build tools, test reports, screenshots and internal delivery notes are kept outside this public folder.

## Validation status

The shipped scripts were exercised with DOM checks over both local files and a nested local HTTP route. Source-data integrity, local links and the public-folder content scan passed. Browser launches were denied by the build environment, so Playwright, rendered desktop/mobile layout, native downloads and browser-level keyboard behavior remain unverified. The delivery includes a Playwright test script outside this folder for a later browser-enabled run. DOM checks do not establish browser compatibility or visual quality.
