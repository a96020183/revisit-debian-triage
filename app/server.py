"""Serve the UI: python -I app/server.py [PORT]  ->  http://127.0.0.1:8765  (ui/index.html also opens directly from disk).
If ui/data.js does not exist yet (fresh clone), it is built from the committed recorded traces (runs/traces) first;
`python -I app/run.py demo --sample` rebuilds it from a fresh replay."""
import http.server, functools, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); UI = os.path.join(ROOT, 'ui')
if not os.path.exists(os.path.join(UI, 'data.js')):
    sys.path.insert(0, os.path.join(ROOT, 'app'))
    import build_ui_data
    print('ui/data.js missing: building it from the recorded traces in runs/traces', flush=True)
    build_ui_data.build(os.path.join(ROOT, 'runs', 'traces'))
port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=UI)
print(f'Revisit UI on http://127.0.0.1:{port}  (Ctrl+C to stop)', flush=True)
http.server.ThreadingHTTPServer(('127.0.0.1', port), h).serve_forever()
