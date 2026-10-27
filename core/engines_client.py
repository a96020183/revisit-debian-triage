"""Python side of the JSON-lines bridge to the TypeScript H-MEM / World Model (engines/bridge.ts)."""
import json, os, subprocess, threading

HERE = os.path.dirname(os.path.abspath(__file__))


class Engines:
    def __init__(self):
        self.p = subprocess.Popen(['node', '--import', 'tsx', os.path.join('engines', 'bridge.ts')], cwd=os.path.dirname(HERE),   # revisit3: engines/ and node_modules live at the repo root
                                 
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding='utf-8', bufsize=1)
        self.lock = threading.Lock(); self.n = 0

    def call(self, op, **kw):
        with self.lock:
            self.n += 1; kw.update(op=op, id=self.n)
            self.p.stdin.write(json.dumps(kw, ensure_ascii=False) + '\n'); self.p.stdin.flush()
            line = self.p.stdout.readline()
        r = json.loads(line)
        if not r.get('ok'): raise RuntimeError(f'{op}: {r.get("error")}')
        return r['result']

    def close(self):
        try: self.p.stdin.close(); self.p.wait(timeout=10)
        except Exception: self.p.kill()
