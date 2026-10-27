"""Verify Revisit's sealed live forecast yourself.
1. Checks prereg_forecast.json and forecast_sealed.json against their SHA-256 files (LF or CRLF working copy).
2. Fetches the Debian security tracker as it is now (https://security-tracker.debian.org/tracker/data/json), or reads a saved copy.
3. Scores every sealed item Debian has decided since, by the registered rule:
     urgent      bookworm resolved, its bookworm-security version at or above the fixed version and bookworm main below it
                 (the fix reached bookworm through a DSA/DLA upload, not a point release)
     not urgent  bookworm still open but marked <postponed>, <ignored> or <no-dsa>
     excluded    still undecided (open, no mark); decided another way (not affected, fixed only outside bookworm-security);
                 no longer listed. Each kind is counted.
   Prints the decided and excluded counts and, per arm, urgent F1 and accuracy with 95% bootstrap intervals (2,000 resamples,
   seed 11). With fewer than 20 decided items it prints the numbers and draws no conclusion.
Offline: says so and exits 2 without a traceback. Usage:
  python -I scripts/verify_forecast.py                 # fetch the tracker now
  python -I scripts/verify_forecast.py --tracker FILE  # a saved copy of the tracker JSON"""
import os, sys, json, hashlib, random, urllib.request, subprocess, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'app'))
from debver import vcmp
URL = 'https://security-tracker.debian.org/tracker/data/json'
ARMS = ('GATED', 'pkg_mode', 'S', 'OURS')
NAMES = dict(GATED='Revisit (Scout-gated, frozen product path)', pkg_mode='Package mode (no model)', S='Evidence path only', OURS='Memory path only')


def sha_ok(path, sha_path):
    b = open(path, 'rb').read(); want = open(sha_path).read().split()[0]
    return want in (hashlib.sha256(b).hexdigest(), hashlib.sha256(b.replace(b'\r\n', b'\n')).hexdigest())


def outcome(tj, cve, pkg):
    rel = ((tj.get(pkg) or {}).get(cve) or {}).get('releases', {}).get('bookworm')
    if rel is None: return 'excluded: not listed for bookworm now'
    st = rel.get('status'); repos = rel.get('repositories') or {}; fv = rel.get('fixed_version') or ''
    if st == 'resolved':
        if fv and fv != '0' and 'bookworm-security' in repos and vcmp(repos['bookworm-security'], fv) >= 0                 and ('bookworm' not in repos or vcmp(repos['bookworm'], fv) < 0): return 'urgent'   # the fix reached bookworm only through security
        return 'excluded: decided another way (not affected, or fixed outside bookworm-security)'
    if st == 'open' and 'nodsa' in rel: return 'not urgent'
    return 'excluded: still undecided'


def f1(p, g):
    tp = sum(1 for a, b in zip(p, g) if a and b); fp = sum(1 for a, b in zip(p, g) if a and not b); fn = sum(1 for a, b in zip(p, g) if b and not a)
    return 2 * tp / (2 * tp + fp + fn) if tp else 0.0


acc = lambda p, g: sum(a == b for a, b in zip(p, g)) / len(g) if g else 0.0


def ci(fn, p, g, B=2000, seed=11):
    rnd = random.Random(seed); n = len(g); xs = []
    for _ in range(B):
        idx = [rnd.randrange(n) for _ in range(n)]; xs.append(fn([p[i] for i in idx], [g[i] for i in idx]))
    xs.sort(); return xs[int(0.025 * B)], xs[int(0.975 * B) - 1]


def score(sealed, tj):
    rows = [(it, outcome(tj, it['cve'], it['pkg'])) for it in sealed['items']]
    dec = [(it, o) for it, o in rows if o in ('urgent', 'not urgent')]
    g = [o == 'urgent' for _, o in dec]
    res = dict(sealed=len(rows), decided=len(dec), urgent=sum(g), excluded=dict(collections.Counter(o for _, o in rows if o.startswith('excluded'))), arms={})
    for a in ARMS:
        p = [it['predictions'][a] == 'URGENT' for it, _ in dec]
        res['arms'][a] = dict(urgent_F1=f1(p, g), accuracy=acc(p, g), ci_F1=ci(f1, p, g) if dec else None, ci_accuracy=ci(acc, p, g) if dec else None)
    return res


def fetch():
    try:
        with urllib.request.urlopen(urllib.request.Request(URL, headers={'User-Agent': 'revisit-verify'}), timeout=120) as r: return json.loads(r.read().decode('utf-8'))
    except Exception:
        p = subprocess.run(['curl', '-sf', '-A', 'revisit-verify', URL], capture_output=True, timeout=300)
        if p.returncode: raise
        return json.loads(p.stdout.decode('utf-8'))


def main(argv):
    R = lambda p: os.path.join(ROOT, p)
    for f, s in (('prereg_forecast.json', 'prereg_forecast.sha256'), ('forecast_sealed.json', 'forecast_sealed.sha256')):
        if not os.path.exists(R(f)): print(f'{f} is missing: nothing has been sealed yet.'); return 2
        ok = sha_ok(R(f), R(s)); print(f"{'OK  ' if ok else 'FAIL'} {f} matches {s}")
        if not ok: return 1
    sealed = json.load(open(R('forecast_sealed.json'), encoding='utf-8'))
    print(f"Sealed: {sealed['K_sealed']} of {sealed['N_registered']} registered items; snapshot fetched {sealed['snapshot']['fetched_at']}; sealed {sealed['sealed_at']}")
    if '--tracker' in argv:
        tj = json.load(open(argv[argv.index('--tracker') + 1], encoding='utf-8')); src = argv[argv.index('--tracker') + 1]
    else:
        try: tj = fetch(); src = URL
        except Exception as e:
            print(f'Offline: could not fetch {URL} ({type(e).__name__}). The hashes above are verified; run again with network, '
                  'or pass a saved copy with --tracker FILE.'); return 2
    r = score(sealed, tj)
    print(f"Tracker read from {src}")
    print(f"Decided since the snapshot: {r['decided']} ({r['urgent']} urgent, {r['decided'] - r['urgent']} not urgent); excluded: {sum(r['excluded'].values())}")
    for k, v in sorted(r['excluded'].items()): print(f'  {v:4d}  {k[10:]}')
    for a in ARMS:
        x = r['arms'][a]
        if r['decided']:
            print(f"{NAMES[a]:<44} urgent F1 {x['urgent_F1']:.3f} [{x['ci_F1'][0]:.3f}, {x['ci_F1'][1]:.3f}]   accuracy {x['accuracy']:.3f} [{x['ci_accuracy'][0]:.3f}, {x['ci_accuracy'][1]:.3f}]")
    if r['decided'] < 20: print(f"Only {r['decided']} sealed items are decided (fewer than 20): numbers only, no conclusion.")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
