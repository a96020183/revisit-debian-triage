"""The product's door to Nemotron. Live calls go through core/nightshift.py (Meterless Nightshift, unchanged; it is
hash-sealed in prereg_news.json). This wrapper adds two things the product needs:
  - REVISIT_REUSE_RECORDED=1: when the product replays a sealed-exam item, the two decision paths send exactly the requests
    the sealed exam already sent. Those are answered from the exam's recording (runs/cassette.jsonl), so the product shows the
    answer the exam scored instead of a second, different sample. New requests (Planner, Evaluator, Judge) go live.
  - REVISIT_USED_LOG: every request key this run used is listed, so the SAMPLE_MODE cassette can be cut to exactly the demo.
In SAMPLE_MODE core/nightshift.py replays everything and never opens a socket."""
import os, sys, json, threading, collections
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'core'))
import nightshift as core

REUSE = os.environ.get('REVISIT_REUSE_RECORDED', '') in ('1', 'true', 'yes')
COUNT = collections.Counter()
_lock = threading.Lock()


def chat(messages, model, **kw):
    k = core.key_of(messages, model); tag = kw.get('tag', '')
    if os.environ.get('REVISIT_USED_LOG'):
        with _lock, open(os.environ['REVISIT_USED_LOG'], 'a', encoding='utf-8') as f: f.write(json.dumps(dict(kind='nightshift', key=k, tag=tag)) + chr(10))
    if REUSE and not core.SAMPLE_MODE:
        r = core._cassette().get(k)
        if r is not None:
            COUNT['recorded'] += 1
            return dict(text=r['text'], served=r['served'], usage=r.get('usage'), headers={}, raw=r['text'], replayed=True, key=k, recorded=True)
    r = core.chat(messages, model, **kw)
    COUNT['replayed' if r.get('replayed') else 'live'] += 1
    return r


key_of = core.key_of
