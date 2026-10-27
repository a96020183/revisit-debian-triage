// JSON-lines bridge for Scout Intent, driven from Python by core/scout_client.py. Same protocol as engines/bridge.ts
// (one request per line on stdin, one JSON reply per line on stdout). Kept as a separate process because
// engines/bridge.ts is hash-sealed in prereg_news.json and must stay byte-identical.
//
// HMAC secret: env REVISIT_SCOUT_SECRET, else a random per-process secret. It is never written to disk or logs,
// so a contract can only be verified by the same bridge process (or one started with the same env secret).
import readline from "node:readline";
import { randomBytes } from "node:crypto";
import { createRevisitScout } from "./scout-intent/revisit.ts";

const secretSource = process.env.REVISIT_SCOUT_SECRET ? "env" : "random-per-process";
const secret = process.env.REVISIT_SCOUT_SECRET || randomBytes(32).toString("hex");
delete process.env.REVISIT_SCOUT_SECRET;  // keep it out of any child process environment
// SAMPLE replay runs in seconds what the recording did in minutes. Scout's rate limits and contract TTLs read its clock, so a
// replay uses a virtual clock that advances 60 s per decision (REVISIT_SCOUT_VIRTUAL_CLOCK=1, set by SAMPLE_MODE); live runs use real time.
const virtual = process.env.REVISIT_SCOUT_VIRTUAL_CLOCK === "1";
let vnow = Date.parse("2026-10-27T00:00:00Z");
const scout = createRevisitScout(virtual ? { secret, clock: () => vnow } : { secret });

const ops: Record<string, (r: any) => any> = {
  /** Full pipeline. Returns intent, band, risk, toolPlan, the signed contract and this decision's telemetry events. */
  scout_decide: async (r) => {
    if (virtual) vnow += 60_000;
    const d = await scout.decide({ prompt: r.prompt, surface: r.surface, user: r.user, context: r.context, approvals: r.approvals,
      session: r.session, dataClass: r.dataClass, budget: r.budget });
    return {
      traceId: d.traceId, intent: d.intent.primary, confidence: d.intent.confidence, band: d.band, parameters: d.intent.parameters,
      plan: d.intent.plan, candidates: d.candidates.slice(0, 3).map((c) => ({ intent: c.intent, score: c.score })),
      clarification: d.clarification ?? null, explanation: d.explanation ?? null,
      risk: { level: d.risk.level, flags: d.risk.flags, reason: d.risk.reason ?? null, approvalsRequired: d.risk.approvalsRequired,
        layers: d.risk.layers.map((l) => ({ layer: l.layer, verdict: l.verdict, reason: l.reason ?? null })) },
      outcome: d.outcome ?? null, toolPlan: d.toolPlan, modelProfile: d.modelProfile ?? null,
      contract: d.executionContract ?? null, routingError: d.routingError ?? null, telemetry: d.telemetry,
    };
  },
  /** Boundary check for a downstream engine: signature, TTL, approvals, capability/tool scope. */
  scout_verify: (r) => scout.verify(r.contract, { engine: r.engine, capability: r.capability, tool: r.tool, requireApprovals: r.requireApprovals }),
  scout_classify: async (r) => scout.classify({ prompt: r.prompt, surface: r.surface }),
  scout_replan: async (r) => { const d = await scout.replan({ parent: r.parent, reason: r.reason, state: r.state }); return { contract: d.executionContract ?? null, risk: d.risk.level }; },
  scout_override: (r) => scout.override({ traceId: r.traceId, from: r.from, to: r.to, by: r.by }),
  scout_telemetry: (r) => scout.telemetry.events({ type: r.type, traceId: r.traceId }).slice(-(r.last ?? 50)),
  scout_info: () => ({ registryVersion: scout.registry.version, registryDigest: scout.registry.digest, intents: scout.registry.all().map((i) => i.id),
    selfTest: scout.selfTest, secretSource }),
};

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", async (line) => {
  if (!line.trim()) return;
  let req: any; try { req = JSON.parse(line); } catch { process.stdout.write(JSON.stringify({ ok: false, error: "bad json" }) + "\n"); return; }
  try {
    const f = ops[req.op]; if (!f) throw new Error(`unknown op ${req.op}`);
    const out = await f(req);
    process.stdout.write(JSON.stringify({ ok: true, id: req.id, result: out }) + "\n");
  } catch (e) { process.stdout.write(JSON.stringify({ ok: false, id: req.id, error: (e as Error).message }) + "\n"); }
});
