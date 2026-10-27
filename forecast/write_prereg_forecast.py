"""Write prereg_forecast.json and prereg_forecast.sha256 BEFORE any model call on the forecast sample.
Usage: python -I forecast/write_prereg_forecast.py SNAPSHOT_DIR"""
import os, sys, json, hashlib, datetime
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda p: os.path.join(ROOT, p)
DL = sys.argv[1]
sha = lambda path: hashlib.sha256(open(path, 'rb').read().replace(b'\r\n', b'\n')).hexdigest()
shab = lambda path: hashlib.sha256(open(path, 'rb').read()).hexdigest()
POP = json.load(open(R('data/forecast_population.json'), encoding='utf-8'))
N = 150
order = POP['order'][:N]
P = dict(
    title='Revisit live forecast: pre-registration (written and hashed before any model call on these items)',
    registered_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
    snapshot=dict(fetched_at=POP['fetched_at'], wall=POP['wall'],
                  sources={'list.txt': 'https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/CVE/list',
                           'dsa.txt': 'https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list',
                           'dla.txt': 'https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DLA/list',
                           'tracker.json': 'https://security-tracker.debian.org/tracker/data/json',
                           'ss13.txt': 'https://salsa.debian.org/debian/debian-security-support/-/raw/master/security-support.deb12'},
                  sha256={f: shab(os.path.join(DL, f)) for f in ('list.txt', 'dsa.txt', 'dla.txt', 'tracker.json', 'ss13.txt')},
                  note='The snapshot files are not in the repository (150 MB); their SHA-256 are registered here. The time wall of every input is this snapshot.'),
    population=dict(rule="every (CVE, source package) undecided for bookworm in the snapshot: bookworm status open with no <no-dsa>/<postponed>/<ignored> mark, "
                         "no bookworm DSA/DLA, label OPEN (core/build_events.py labels); packages linux, linux-*, chromium, firefox-esr, thunderbird, webkit2gtk, "
                         "wpewebkit excluded as in every exam (forecast/build_forecast.py)", n=POP['n']),
    sample=dict(seed=POP['seed'], method='population sorted by (CVE, package), shuffled with Python random.Random(seed); the first N in that order',
                N=N, order=order,
                if_time_runs_out='items run in this order; at the stop time no new item starts; only the first K items of the order that have every '
                                 'prediction are sealed (K is reported); nothing after the first gap is sealed'),
    arms=dict(GATED='primary: the frozen product decision path. Evidence path (core/triage_agent.py run_S) + memory path (run_OURS, H-MEM loaded up to the snapshot) '
                    '+ the frozen gatekeeper core/gate.py over the two answers and H-MEM features (core/hmem_features.py); the same program as the sealed exam',
              pkg_mode='baseline, no model: the package\'s most common decision in its history up to the snapshot (core/eval_core.py base_preds; NEXT when the package has no history)',
              S='secondary, reported: the evidence path alone (computed anyway as part of GATED)',
              OURS='secondary, reported: the memory path alone (computed anyway as part of GATED)'),
    inputs=dict(items='data/forecast_items.json (tracker description, bookworm version from the snapshot, limited support from security-support.deb12, no scope)',
                history='data/forecast_events.json (revisit3 recorded history 2026-06-01..2026-10-26 + label changes in the snapshot, dated with the snapshot day)'),
    outcome=dict(rule_short='urgent = bookworm fixed through bookworm-security (DSA/DLA); not urgent = <postponed>/<ignored>/<no-dsa>; undecided and other outcomes excluded and counted',
                 rule='Read from the Debian security tracker JSON at verification time (scripts/verify_forecast.py). urgent: bookworm status resolved, its '
                      'bookworm-security version at or above the fixed version and bookworm main below it (the fix reached bookworm through a DSA/DLA upload). '
                      'not urgent: bookworm status open with a no-dsa mark (postponed, ignored or no-dsa). Excluded and counted: still undecided; decided another '
                      'way (not affected, or fixed outside bookworm-security); no longer listed for bookworm.',
                 prediction_mapping='a prediction is urgent when the arm answers URGENT; NEXT, WONTFIX and NOTAFF are not urgent'),
    metrics=dict(primary='urgent F1 and accuracy of each arm over the decided items, each with a 95% percentile bootstrap interval (2,000 resamples, seed 11)',
                 small_sample='with fewer than 20 decided items the numbers are reported and no conclusion is drawn',
                 no_gate='no pass/fail gate is registered; the forecast is published for anyone to verify'),
    run=dict(stop_starting_new_items_at='2026-10-27T17:00:00+08:00', nightshift='every model call through Meterless Nightshift; one request in flight; '
             'meterless-scope iso-<uuid> per request, as in the sealed exam (with user scope Nightshift inserts earlier answers into the prompt, so the two paths '
             'would stop being independent)', model='nvidia/nemotron-3-super-120b-a12b requested; the served model is logged per call'),
    input_hashes={p: sha(R(p)) for p in ('data/forecast_population.json', 'data/forecast_items.json', 'data/forecast_events.json', 'forecast/build_forecast.py',
                                         'forecast/run_forecast.py', 'forecast/seal_forecast.py', 'scripts/verify_forecast.py', 'core/triage_agent.py', 'core/gate.py',
                                         'core/hmem_features.py', 'core/eval_core.py', 'core/nightshift.py', 'app/debver.py', 'exam/build_item_facts.py')})
open(R('prereg_forecast.json'), 'w', encoding='utf-8', newline='\n').write(json.dumps(P, ensure_ascii=False, indent=1) + '\n')
h = sha(R('prereg_forecast.json'))
open(R('prereg_forecast.sha256'), 'w', encoding='utf-8', newline='\n').write(f'{h}  prereg_forecast.json\n')
print('prereg_forecast.json sha256', h, 'population', POP['n'], 'N', N)
