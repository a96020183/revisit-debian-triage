"""Verify the sealed pre-registrations from the files themselves (no particular git commit is needed).
The repository history was rebuilt before submission (it held internal working notes); the original commits, including the sealing
commits, are kept in a private git bundle available on request. The proof here is the SHA-256 each prereg file registered:
  prereg_news.json            registered in prereg_news.sha256; it lists the SHA-256 of 18 input files (exam builder, data, decision
                              paths, gate, scorer, Nightshift client, engines). Each must match the file in HEAD, unchanged since sealing.
  prereg_reopen_judge.json    addendum 1 (its SHA-256 is recorded below, as reported when it was sealed). Its inputs were edited after the
                              judge run; the versions that ran are kept in sealed/reopen_judge_addendum/ and must match the registered
                              hashes; the script says which current files differ from them.
  prereg_reopen_action.json   addendum 2, registered in prereg_reopen_action.sha256.
A hash is accepted if it matches the file with LF or with CRLF line endings (the hashes were computed on a Windows working copy;
git stores LF). Exit 1 if anything fails. Usage: python -I scripts/verify_prereg.py"""
import json, hashlib, subprocess, sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(path):
    """the committed content of a file (HEAD blob), else the working copy"""
    p = subprocess.run(['git', '-C', ROOT, 'show', f'HEAD:{path}'], capture_output=True)
    return p.stdout if p.returncode == 0 else open(os.path.join(ROOT, path), 'rb').read()


def forms(b):
    lf = b.replace(b'\r\n', b'\n')
    return {'LF': hashlib.sha256(lf).hexdigest(), 'CRLF': hashlib.sha256(lf.replace(b'\n', b'\r\n')).hexdigest()}


def match(b, h):
    return next((k for k, v in forms(b).items() if v == h), None)


fail = 0
def report(ok, msg):
    global fail
    print(('OK   ' if ok else 'FAIL ') + msg); fail += not ok


h = read('prereg_news.sha256').decode().split()[0]
report(bool(match(read('prereg_news.json'), h)), f'prereg_news.json matches its registered SHA-256 {h[:16]}...')
for p, hh in json.loads(read('prereg_news.json'))['input_hashes'].items():
    m = match(read(p), hh); report(bool(m), f'  {p}: {m or "no"} form matches the sealed hash (unchanged since sealing)')

ADD1 = 'cfd8fcbd7e09b04565489d9fa43c13b9eb59d6bf7cdd9c4282833f5c2f296a1c'   # reported when addendum 1 was sealed
report(bool(match(read('prereg_reopen_judge.json'), ADD1)), f'prereg_reopen_judge.json matches {ADD1[:16]}...')
for p, hh in json.loads(read('prereg_reopen_judge.json'))['input_hashes'].items():
    sealed = read(f'sealed/reopen_judge_addendum/{p}'); m = match(sealed, hh)
    same = forms(sealed)['LF'] == forms(read(p))['LF']
    report(bool(m), f"  {p}: the version that ran ({'same as HEAD' if same else 'HEAD edited after the run'}) matches the sealed hash")

h2 = read('prereg_reopen_action.sha256').decode().split()[0]
report(bool(match(read('prereg_reopen_action.json'), h2)), f'prereg_reopen_action.json matches its registered SHA-256 {h2[:16]}...')
print('ALL SEALS VERIFIED' if not fail else f'{fail} FAILED'); sys.exit(1 if fail else 0)
