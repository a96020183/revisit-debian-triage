"""Re-run the three official Meterless conformance suites against this repo's engines and write evidence/*.txt.
The harnesses are vendored unmodified from the Meterless repo (commit 1742dec, 2026-10-19):
  vendor/scout-intent-evals/      engines/scout-intent/evals (runner + regression set + thresholds)
  vendor/hmem-conformance/        engines/hmem/conformance
  vendor/world-model-conformance/ engines/world-model/conformance
Each harness is copied to a temporary folder and run there (the Scout runner writes reports/latest.md next to itself; it needs the
'yaml' package, so npm install runs inside the temporary copy). Outputs go to a temporary folder whose path is printed; nothing in
the repo changes. With --update-evidence the outputs replace evidence/*_conformance.txt (how the committed files were made).
Local paths are written as <repo> and <harness>.
Usage: python -I scripts/run_conformance.py [--update-evidence]"""
import os, sys, shutil, subprocess, tempfile, datetime, hashlib, glob
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX = os.path.join(ROOT, 'node_modules', '.bin', 'tsx' + ('.cmd' if os.name == 'nt' else ''))
NPM = 'npm.cmd' if os.name == 'nt' else 'npm'
fwd = lambda p: p.replace('\\', '/')
now = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
results = {}
OUTDIR = os.path.join(ROOT, 'evidence') if '--update-evidence' in sys.argv else tempfile.mkdtemp(prefix='rv3-conformance-')


def run(name, vendor, cmd, env_var, impl, out, cwd_sub='', npm=False):
    tmp = tempfile.mkdtemp(prefix=f'rv3-{name}-')
    dst = os.path.join(tmp, 'h'); shutil.copytree(os.path.join(ROOT, vendor), dst, ignore=shutil.ignore_patterns('node_modules'))
    if npm: subprocess.run([NPM, 'install', '--silent', '--no-audit', '--no-fund'], cwd=dst, capture_output=True, text=True)
    env = dict(os.environ, **{env_var: fwd(os.path.join(ROOT, impl))})
    p = subprocess.run(cmd, cwd=os.path.join(dst, cwd_sub), env=env, capture_output=True, text=True, encoding='utf-8', errors='replace')
    files = sorted(glob.glob(os.path.join(ROOT, vendor, '**', '*'), recursive=True))
    digests = [f"  {hashlib.sha256(open(f, 'rb').read().replace(bytes([13, 10]), bytes([10]))).hexdigest()[:16]}  {fwd(os.path.relpath(f, ROOT))}"
               for f in files if os.path.isfile(f) and 'node_modules' not in f]   # SHA-256 of LF-normalised content
    txt = (f"{name} conformance, run {now}\nHarness: {vendor} (vendored unmodified from Meterless commit 1742dec56a66e58eef9dda2d2b865823758ca8cd, 2026-10-19)\n"
           f"Implementation: {impl}\nHarness files (sha256 of LF-normalised content):\n" + '\n'.join(digests) + "\nCommand:"
           f" {' '.join(cmd)} (in a temporary copy of the harness)\nExit code: {p.returncode}\n\n" + p.stdout + ('\n[stderr]\n' + p.stderr if p.stderr.strip() else ''))
    for a, b in ((dst, '<harness>'), (fwd(dst), '<harness>'), (ROOT, '<repo>'), (fwd(ROOT), '<repo>'), (TSX, 'tsx'), (fwd(TSX), 'tsx')):
        txt = txt.replace(a, b)
    open(os.path.join(OUTDIR, out), 'w', encoding='utf-8', newline=chr(10)).write(txt)
    shutil.rmtree(tmp, ignore_errors=True)
    results[name] = p.returncode
    print(f'{name}: exit {p.returncode} -> {os.path.join(OUTDIR, out)}')


run('Scout Intent', 'vendor/scout-intent-evals', [TSX, 'evals/runner/index.ts', 'all'], 'SCOUT_IMPL', 'engines/scout-intent/index.ts', 'scout_conformance.txt', npm=True)
run('H-MEM', 'vendor/hmem-conformance', [TSX, 'runner.ts'], 'HMEM_IMPL', 'engines/hmem/index.ts', 'hmem_conformance.txt')
run('World Model', 'vendor/world-model-conformance', [TSX, 'runner.ts'], 'WORLD_MODEL_IMPL', 'engines/world-model/index.ts', 'world_model_conformance.txt')
sys.exit(1 if any(results.values()) else 0)
