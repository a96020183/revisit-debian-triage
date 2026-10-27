"""The product's door to Nemotron. Live calls go through core/nightshift.py (Meterless Nightshift, unchanged; it is
hash-sealed in prereg_news.json). This wrapper adds what the product needs:
  - REVISIT_REUSE_RECORDED=1 (set by `run.py --record`): for a sealed-exam item, the two decision paths send exactly the requests
    the sealed exam sent; those, and only those, are answered from the exam's own recording, so the product shows the answer the
    exam scored. An answer counts as an exam answer only if its key was recorded by the sealed exam run itself: a decision-path
    tag (S: / OURS-) for a sealed-exam item, recorded before the exam ended (EXAM_END). Every other request goes live.
  - Source of every answer: 'exam' (reused from the sealed exam), 'live' (a Nightshift call in this run), or, in a SAMPLE replay,
    whatever the recorded run said ('exam', 'live', or 'earlier_product_run' for recordings that predate this rule).
  - REVISIT_USED_LOG: every request key this run used, with its source, so the SAMPLE cassette can be cut to exactly the demo.
In SAMPLE_MODE core/nightshift.py replays everything and never opens a socket."""
import os, sys, json, threading, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'core'))
import nightshift as core

REUSE = os.environ.get('REVISIT_REUSE_RECORDED', '') in ('1', 'true', 'yes')
EXAM_END = '2026-10-27T02:12:00'   # last call of the sealed exam run: 2026-10-27T02:11:35 (runs/calls.jsonl)
COUNT = collections.Counter()
_lock = threading.Lock()
_EXAM = None


def _item_of(tag):
    """'S:CVE-2026-1:pkg' / 'OURS-exec:CVE-2026-1:pkg' -> (cve, pkg)"""
    parts = tag.split(':')
    return (parts[1], parts[2]) if len(parts) >= 3 else (None, None)


def exam_answers():
    """{request key: recorded answer} for the sealed exam's own decision-path requests. When the exam recorded two answers for the
    same request (two runner copies ran at once, see README), the LAST one is kept, the same rule as the sealed scorer."""
    global _EXAM
    if _EXAM is None:
        items = {(i['cve'], i['pkg']) for i in json.load(open(os.path.join(ROOT, 'data', 'news_items.json'), encoding='utf-8'))}
        _EXAM = {}
        if core.CASSETTE.exists():
            for ln in open(core.CASSETTE, encoding='utf-8'):
                try: r = json.loads(ln)
                except Exception: continue
                if r.get('tag', '').startswith(('S:', 'OURS-')) and r.get('ts', '9999') <= EXAM_END and _item_of(r['tag']) in items:
                    _EXAM[r['key']] = r
    return _EXAM


def _used(k, tag, source, text=''):
    """text_sha lets scripts/make_sample.py pick this exact answer when the same request was answered more than once"""
    if os.environ.get('REVISIT_USED_LOG'):
        import hashlib, time
        with _lock, open(os.environ['REVISIT_USED_LOG'], 'a', encoding='utf-8') as f:
            f.write(json.dumps(dict(kind='nightshift', key=k, tag=tag, source=source, ts=time.strftime('%Y-%m-%dT%H:%M:%S'),
                                    text_sha=hashlib.sha256((text or '').encode('utf-8')).hexdigest())) + chr(10))


def chat(messages, model, **kw):
    k = core.key_of(messages, model); tag = kw.get('tag', '')
    if REUSE and not core.SAMPLE_MODE and tag.startswith(('S:', 'OURS-')):
        r = exam_answers().get(k)
        if r is not None:
            COUNT['exam'] += 1; _used(k, tag, 'exam', r['text'])
            return dict(text=r['text'], served=r['served'], usage=r.get('usage'), headers={}, raw=r['text'], replayed=True, key=k, source='exam')
    r = core.chat(messages, model, **kw)
    if core.SAMPLE_MODE:
        src = (core._cassette().get(k) or {}).get('source', 'live')
        src = {'sealed_exam': 'exam'}.get(src, src)
        COUNT[src] += 1; r['source'] = src
    else:
        COUNT['live'] += 1; _used(k, tag, 'live', r['text']); r['source'] = 'live'
    return r


key_of = core.key_of
