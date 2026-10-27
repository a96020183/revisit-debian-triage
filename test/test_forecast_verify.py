"""scripts/verify_forecast.py against fixtures (no network): the outcome rule, the counts, the metrics, the under-20 rule,
the hash check and the offline message.
Usage: python -I test/test_forecast_verify.py"""
import os, sys, json, tempfile, shutil, subprocess, io, contextlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'scripts')); sys.path.insert(0, os.path.join(ROOT, 'app'))
import verify_forecast as V
fails = []
def check(name, ok, info=''):
    print(('PASS ' if ok else 'FAIL ') + name + (f'  ({info})' if info else '')); ok or fails.append(name)

rel = lambda **k: {'releases': {'bookworm': k}}
TJ = {'a': {'CVE-1': rel(status='resolved', repositories={'bookworm': '1.0-1', 'bookworm-security': '1.0-1+deb12u1'}, fixed_version='1.0-1+deb12u1'),
            'CVE-2': rel(status='open', repositories={'bookworm': '1.0-1'}, nodsa='Minor issue', nodsa_reason='postponed'),
            'CVE-3': rel(status='open', repositories={'bookworm': '1.0-1'}),
            'CVE-4': rel(status='resolved', repositories={'bookworm': '1.0-1'}, fixed_version='0'),
            'CVE-5': rel(status='resolved', repositories={'bookworm': '1.0-1+deb12u1', 'bookworm-security': '1.0-1+deb12u2'}, fixed_version='1.0-1+deb12u1'),
            'CVE-6': rel(status='open', repositories={'bookworm': '1.0-1'}, nodsa='', nodsa_reason='ignored')}}
want = {'CVE-1': 'urgent', 'CVE-2': 'not urgent', 'CVE-3': 'excluded: still undecided', 'CVE-4': 'excluded: decided another way (not affected, or fixed outside bookworm-security)',
        'CVE-5': 'excluded: decided another way (not affected, or fixed outside bookworm-security)', 'CVE-6': 'not urgent', 'CVE-7': 'excluded: not listed for bookworm now'}
check('outcome rule: DLA fix urgent; postponed/ignored not urgent; undecided, not affected, point-release fix, unlisted excluded',
      all(V.outcome(TJ, c, 'a') == w for c, w in want.items()), str({c: V.outcome(TJ, c, 'a') for c in want}))

def item(c, g):
    return dict(cve=c, pkg='a', predictions=dict(GATED=g, pkg_mode='NEXT', S=g, OURS=g))
sealed = dict(items=[item('CVE-1', 'URGENT'), item('CVE-2', 'URGENT'), item('CVE-3', 'URGENT'), item('CVE-6', 'NEXT')])
r = V.score(sealed, TJ)
check('counts: 3 decided (1 urgent), 1 excluded', r['decided'] == 3 and r['urgent'] == 1 and sum(r['excluded'].values()) == 1, json.dumps(r['excluded']))
check('metrics: GATED F1 2/3, accuracy 2/3; package mode F1 0, accuracy 2/3',
      abs(r['arms']['GATED']['urgent_F1'] - 2 / 3) < 1e-9 and abs(r['arms']['GATED']['accuracy'] - 2 / 3) < 1e-9 and r['arms']['pkg_mode']['urgent_F1'] == 0
      and abs(r['arms']['pkg_mode']['accuracy'] - 2 / 3) < 1e-9)
lo, hi = r['arms']['GATED']['ci_F1']
check('bootstrap interval contains the point estimate', lo <= r['arms']['GATED']['urgent_F1'] <= hi, f'[{lo:.3f}, {hi:.3f}]')

# end-to-end on a temporary copy: hashes, the under-20 message, a tampered file, offline
tmp = tempfile.mkdtemp()
try:
    for d in ('scripts', 'app', 'exam', 'core'): shutil.copytree(os.path.join(ROOT, d), os.path.join(tmp, d), ignore=shutil.ignore_patterns('__pycache__'))
    for f in ('prereg_forecast.json', 'prereg_forecast.sha256'): shutil.copy(os.path.join(ROOT, f), tmp)
    sd = dict(sealed, K_sealed=4, N_registered=150, snapshot=dict(fetched_at='fixture'), sealed_at='fixture')
    open(os.path.join(tmp, 'forecast_sealed.json'), 'w', encoding='utf-8', newline='\n').write(json.dumps(sd))
    import hashlib
    open(os.path.join(tmp, 'forecast_sealed.sha256'), 'w').write(hashlib.sha256(open(os.path.join(tmp, 'forecast_sealed.json'), 'rb').read()).hexdigest() + '  forecast_sealed.json\n')
    json.dump(TJ, open(os.path.join(tmp, 'tj.json'), 'w'))
    run = lambda *a: subprocess.run([sys.executable, '-I', os.path.join(tmp, 'scripts', 'verify_forecast.py'), *a], capture_output=True, text=True, cwd=tmp)
    p = run('--tracker', os.path.join(tmp, 'tj.json'))
    check('end to end with a fixture tracker: hashes OK, 3 decided, under-20 rule printed', p.returncode == 0 and 'Decided since the snapshot: 3' in p.stdout and 'no conclusion' in p.stdout, p.stdout[-300:] + p.stderr[-300:])
    env = dict(os.environ, HTTPS_PROXY='http://127.0.0.1:9', HTTP_PROXY='http://127.0.0.1:9', https_proxy='http://127.0.0.1:9', http_proxy='http://127.0.0.1:9')
    p = subprocess.run([sys.executable, '-c', 'import runpy,sys,socket; socket.socket.connect=lambda *a,**k: (_ for _ in ()).throw(OSError("offline")); '
                        'import subprocess; subprocess.run=lambda *a,**k: type("P",(),{"returncode":7,"stdout":b""})(); sys.argv=["v"]; runpy.run_path(sys.argv[0] if False else r"' +
                        os.path.join(tmp, 'scripts', 'verify_forecast.py') + '", run_name="__main__")'], capture_output=True, text=True, cwd=tmp, env=env)
    check('offline: clear message, exit 2, no traceback', p.returncode == 2 and 'Offline' in p.stdout and 'Traceback' not in p.stderr, p.stdout[-200:] + p.stderr[-300:])
    open(os.path.join(tmp, 'forecast_sealed.json'), 'a').write(' ')
    p = run('--tracker', os.path.join(tmp, 'tj.json'))
    check('a changed sealed file fails the hash check', p.returncode == 1 and 'FAIL forecast_sealed.json' in p.stdout, p.stdout[-200:])
finally:
    shutil.rmtree(tmp, ignore_errors=True)
print('ALL PASS' if not fails else f'{len(fails)} FAILED: {fails}'); sys.exit(1 if fails else 0)
