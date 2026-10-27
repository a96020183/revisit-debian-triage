// JSON-lines bridge so the Python agent drives the TypeScript H-MEM and World Model (the same code that passes
// the official conformance suites). One request per line on stdin, one JSON reply per line on stdout.
import readline from "node:readline";
import { HMEM } from "./hmem/index.ts";
import { WorldModel } from "./world-model/index.ts";

let now = Date.parse("2026-06-01T00:00:00Z");
const hmem = new HMEM({ clock: () => now, actor: "revisit" });
let world = new WorldModel({ namespace: "revisit", clock: () => new Date(now) });

const slim = (m: any) => m && ({ id: m.id, content: m.content, source: m.source, confidence: m.confidence, layer: m.layer, domain: m.domain,
  timestamp: m.timestamp, claimKey: m.claimKey, claimValue: m.claimValue, supersedes: m.supersedes, supersededBy: m.supersededBy, tags: m.tags, meta: m.meta });

const ops: Record<string, (r: any) => any> = {
  set_clock: (r) => { now = Date.parse(r.t); return { now }; },
  add: (r) => {
    const inp = { ...r.input };
    if (inp.claimKey && inp.supersedeCurrent) { const cur = hmem.store.currentClaim(inp.claimKey); if (cur) inp.supersedes = cur.id; }
    delete inp.supersedeCurrent;
    return slim(hmem.add(inp));
  },
  add_many: (r) => {
    let n = 0;
    for (const x of r.inputs) { const inp = { ...x }; if (inp.claimKey && inp.supersedeCurrent) { const cur = hmem.store.currentClaim(inp.claimKey); if (cur) inp.supersedes = cur.id; } delete inp.supersedeCurrent; hmem.add(inp); n++; }
    return { n };
  },
  query: (r) => {
    const res = hmem.query(r.q, { ...r.opts, filter: r.currentOnly ? (m: any) => !m.supersededBy : undefined });
    return { hits: res.memories.map((h) => ({ ...slim(h.memory), score: h.score })), context: res.context, trace: res.trace };
  },
  domain_records: (r) => [...(hmem.store.byDomain.get(r.domain) ?? [])].map((id) => slim(hmem.store.get(id))),
  current_claim: (r) => slim(hmem.store.currentClaim(r.key)),
  feedback: (r) => { hmem.feedback(r.id, r.kind); return slim(hmem.store.get(r.id)); },
  conflicts_scan: (r) => { const cs = hmem.conflicts.scan(r.ids); return cs.map((c) => ({ ...c, outcome: r.autoResolve ? hmem.conflicts.autoResolve(c) : undefined })); },
  review_queue: () => hmem.conflicts.queue(),
  ledger_stats: () => hmem.ledger.stats(),
  ledger_history: (r) => hmem.ledger.history(r.id),
  count: () => ({ n: hmem.store.all().length }),
  save: (r) => { hmem.save(r.file); return { ok: true }; },
  load: (r) => { hmem.load(r.file); return { n: hmem.store.all().length }; },
  // ---- World Model: waits and condition events
  wm_reset: () => { world = new WorldModel({ namespace: "revisit", clock: () => new Date(now) }); return { ok: true }; },
  wm_upsert: async (r) => world.upsertEntity(r.input),
  wm_relate: async (r) => world.relate(r.input),
  wm_fact: async (r) => world.assertFact(r.input),
  wm_ingest: async (r) => world.ingest(r.observations),
  wm_neighbors: (r) => world.neighborsOf(r.id, r.opts ?? {}),
  wm_incoming: (r) => world.incoming(r.id, r.opts ?? {}),
  wm_query: (r) => world.query({ type: r.type }),
  wm_about: (r) => world.about(r.id, r.opts ?? {}),
  wm_events: (r) => world.events().slice(r.since ?? 0),
  wm_audit_n: () => ({ n: world.audit().length }),
};

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", async (line) => {
  if (!line.trim()) return;
  let req: any; try { req = JSON.parse(line); } catch (e) { process.stdout.write(JSON.stringify({ ok: false, error: "bad json" }) + "\n"); return; }
  try {
    const f = ops[req.op]; if (!f) throw new Error(`unknown op ${req.op}`);
    const out = await f(req);
    process.stdout.write(JSON.stringify({ ok: true, id: req.id, result: out }) + "\n");
  } catch (e) { process.stdout.write(JSON.stringify({ ok: false, id: req.id, error: (e as Error).message }) + "\n"); }
});
