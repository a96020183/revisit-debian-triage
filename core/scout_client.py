"""Python side of the Scout Intent JSON-lines bridge (engines/scout_bridge.ts). Same protocol as engines_client.py.

Scout is a separate bridge process because engines/bridge.ts and core/engines_client.py are hash-sealed in
prereg_news.json. The HMAC secret comes from env REVISIT_SCOUT_SECRET (else the bridge makes a random one per process);
it is never passed on the command line, written to disk or logged.
"""
import json, os, subprocess, threading

HERE = os.path.dirname(os.path.abspath(__file__))


class ScoutBridge:
    def __init__(self):
        env = dict(os.environ)
        if os.environ.get('REVISIT_SAMPLE_MODE') == '1': env['REVISIT_SCOUT_VIRTUAL_CLOCK'] = '1'   # see engines/scout_bridge.ts
        self.p = subprocess.Popen(['node', '--import', 'tsx', os.path.join('engines', 'scout_bridge.ts')], cwd=os.path.dirname(HERE), env=env,
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

    def decide(self, prompt, user, surface='api', context=None, **kw):
        return self.call('scout_decide', prompt=prompt, user=user, surface=surface, context=context, **kw)

    def verify(self, contract, **kw):
        return self.call('scout_verify', contract=contract, **kw)

    def close(self):
        try: self.p.stdin.close(); self.p.wait(timeout=10)
        except Exception: self.p.kill()
