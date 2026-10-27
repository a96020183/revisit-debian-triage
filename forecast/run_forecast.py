"""Live forecast, step 2: the frozen decision paths on the sealed sample, in the registered order (prereg_forecast.json).
Same program as the exam and the product: core/triage_agent.py run_S (evidence path) and run_OURS (memory path, H-MEM loaded up
to the snapshot), core/hmem_features.py, and the frozen gatekeeper core/gate.py for GATED (the product's Scout picks exactly
what it picks, evidence/scout_equivalence.txt). The no-model package-mode baseline is core/eval_core.py base_preds.
Only the snapshot's data are read (data/forecast_items.json, data/forecast_events.json): the time wall is the snapshot.
Nightshift only, one request at a time (the loop is sequential), meterless-scope iso-<uuid> per request as in the exam.
Stops starting new items at the registered stop time. Resumable: runs/forecast_preds.jsonl.
Refuses to run unless prereg_forecast.json matches the SHA-256 in prereg_forecast.sha256.
Usage: REVISIT_SCOPE=iso python -I forecast/run_forecast.py"""
import sys, os, json, time, io, datetime, hashlib
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(ROOT, 'core'))
assert os.environ.get('REVISIT_SCOPE') == 'iso', 'scored runs use REVISIT_SCOPE=iso'
R = lambda p: os.path.join(ROOT, p)
raw = open(R('prereg_forecast.json'), 'rb').read().replace(b'\r\n', b'\n')
assert hashlib.sha256(raw).hexdigest() == open(R('prereg_forecast.sha256')).read().split()[0], 'prereg_forecast.json does not match its registered hash'
P = json.loads(raw)
import triage_agent as T
import hmem_features as HF
import gate as G
import eval_core as E
EVENTS = json.load(open(R('data/forecast_events.json'), encoding='utf-8'))
ITEMS = {f"{i['cve']}|{i['pkg']}": i for i in json.load(open(R('data/forecast_items.json'), encoding='utf-8'))}
T.EVENTS = EVENTS; E.EVENTS = EVENTS
WALL = P['snapshot']['wall']
T.SNAPS = T.SNAPS + [s for s in ('2026-10-26', WALL) if s not in T.SNAPS]
STOP = datetime.datetime.fromisoformat(P['run']['stop_starting_new_items_at'])
OUT = R('runs/forecast_preds.jsonl')


def done():
    s = set()
    if os.path.exists(OUT):
        for ln in open(OUT, encoding='utf-8'): s.add(json.loads(ln)['key'])
    return s


def main():
    D = done(); mem = None; t0 = time.time()
    order = P['sample']['order']
    for n, k in enumerate(order, 1):
        if k in D: continue
        if datetime.datetime.now(datetime.timezone.utc) > STOP: print('STOP time reached; no new items'); break
        it = ITEMS[k]
        if mem is None: mem = T.Memory({i['pkg'] for i in ITEMS.values()}); mem.advance_to(WALL)
        try:
            S = T.run_S(it, None); O = T.run_OURS(it, mem)
            f = HF.item_features(mem, it); g, rule = G.decide(f, S['pred'], O['pred'])
            mode = E.base_preds([it])[1][0]
        except Exception as e:
            print(f'[{n}] {k} error {str(e)[:200]}'); continue
        rec = dict(key=k, n=n, cve=it['cve'], pkg=it['pkg'], GATED=g, gate_rule=rule, pkg_mode=mode, S=S['pred'], OURS=O['pred'],
                   S_reason=(S.get('reason') or '')[:400], OURS_reason=(O.get('reason') or '')[:400],
                   served=[c['served'] for c in S['calls'] + O['calls']], ts=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'))
        with open(OUT, 'a', encoding='utf-8', newline='\n') as fh: fh.write(json.dumps(rec, ensure_ascii=False) + '\n')
        print(f"[{n}/{len(order)} {time.time() - t0:.0f}s] {k} GATED={g} ({rule}) S={S['pred']} OURS={O['pred']} mode={mode}", flush=True)
    if mem: mem.e.close()


if __name__ == '__main__':
    main()
