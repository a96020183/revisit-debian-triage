// Revisit domain pack for Scout Intent: the Debian LTS triage registry (revisit_registry.json), the Guard policy
// (memory-reliability check, read-only SQL check, role grants, rate limits), the capability graph tools and the
// model profiles. Everything plugs into the generic engine in ./index.ts through its public interfaces.

import path from "node:path";
import { fileURLToPath } from "node:url";
import { Scout, type CheckContext, type CheckResult, type ModelProfile, type PolicyPack, type ScoutOptions, type ToolRegistration } from "./index.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REVISIT_REGISTRY = path.join(HERE, "revisit_registry.json");

export const DECISION_CLASSES = ["URGENT", "NEXT", "WONTFIX", "NOTAFF"] as const;
export type DecisionClass = (typeof DECISION_CLASSES)[number];
export type ReliabilityRule = "agree" | "class_unreliable" | "memory_disagrees_with_itself" | "trust_memory";

/** H-MEM features for one CVE, as computed by core/hmem_features.py (only the fields the rule reads are typed). */
export interface HmemFeatures { n?: number | null; dom?: string | null; hits?: Array<{ v?: string; s?: number }> | null; [k: string]: unknown }

/** Python truthiness, so the port behaves exactly like `f.get('n')` / `f.get('hits')` in core/gate.py. */
function pyTruthy(v: unknown): boolean {
  if (v === undefined || v === null || v === false || v === 0 || v === "") return false;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === "object") return Object.keys(v as object).length > 0;
  return true;  // includes NaN, which Python also treats as true
}

// Mirrors core/gate.py CLASS_UNRELIABLE (fixed from the development set; see the docstring there).
const CLASS_UNRELIABLE = new Set<string>(["WONTFIX"]);

/**
 * Memory-reliability check: a line-by-line port of the frozen `decide(f, s_pred, o_pred)` in core/gate.py.
 *   sPred = evidence-path proposal (S: same model, raw tracker lines, no memory)
 *   oPred = memory-path proposal  (OURS: planner reads H-MEM)
 * Rules, in order: agree -> class_unreliable -> memory_disagrees_with_itself -> trust_memory.
 * test/test_scout_equivalence.py checks it against the Python function on all 570 x 16 inputs.
 */
export function memoryReliabilityGuard(f: HmemFeatures, sPred: string, oPred: string) {
  let decision: string; let rule: ReliabilityRule;
  const top = pyTruthy(f?.hits) ? (f.hits as Array<{ v?: string }>)[0].v : null;
  if (sPred === oPred) { decision = oPred; rule = "agree"; }                                         // rule 0
  else if (CLASS_UNRELIABLE.has(sPred)) { decision = sPred; rule = "class_unreliable"; }             // rule 1
  else if (pyTruthy(f?.n) && (f.dom === sPred || top === sPred)) { decision = sPred; rule = "memory_disagrees_with_itself"; }  // rule 2
  else { decision = oPred; rule = "trust_memory"; }                                                  // rule 3
  const path = rule === "agree" || rule === "trust_memory" ? "memory" : "evidence";
  const reason = {
    agree: `Both paths propose ${oPred}; nothing to arbitrate.`,
    class_unreliable: `The evidence path proposes ${sPred} (this CVE has no real impact). Memory is not a reliable judge for that class, so the evidence path wins over the memory path's ${oPred}.`,
    // The reason names the signal that actually fired (QA round 1: the old text said "not following memory" even when the
    // memory path had chosen H-MEM's dominant stance and only the top recall hit matched the evidence path).
    memory_disagrees_with_itself: f?.dom === sPred
      ? `H-MEM's dominant current stance for this package is ${sPred}, the evidence path's answer; the memory path chose ${oPred} anyway, so the evidence path wins.`
      : `H-MEM's most relevant past decision (top recall hit) is ${sPred}, the evidence path's answer` +
        (f?.dom === oPred ? `, although its dominant stance is ${oPred}, the memory path's answer` : ` (dominant stance ${f?.dom ?? "none"})`) +
        `. The rule sends the decision to the evidence path whenever H-MEM's top hit or dominant stance backs it.`,
    trust_memory: `The memory path (${oPred}) overrules the evidence path (${sPred}); nothing in H-MEM contradicts it.`,
  }[rule];
  return { decision: decision as DecisionClass, rule, path: path as "memory" | "evidence", tool: `decision.adopt_${path}`, reason };
}

/** Guard-stage check for triage.commit_decision (runs inside the policy gate, §6 layer 2). */
function memoryReliabilityCheck(ctx: CheckContext): CheckResult {
  const s = ctx.parameters.evidenceProposal as string | undefined;
  const o = ctx.parameters.memoryProposal as string | undefined;
  const f = ctx.context?.features;
  if (!s || !o || !f || typeof f !== "object")
    return { verdict: "block", reason: "memory-reliability check needs context.features, context.evidence and context.memory" };
  const r = memoryReliabilityGuard(f, s, o);
  return {
    // Agreement passes; any arbitration is a warning (lifts the level; the intent is already high-risk).
    verdict: r.rule === "agree" ? "pass" : "warn",
    flags: [{ kind: "memory-reliability", layer: "policy", rule: r.rule, reason: r.reason, decision: r.decision, path: r.path }],
    routeConstraints: { "decision.commit": r.tool },
    stepInputs: { "decision.commit": { decision: r.decision, rule: r.rule } },
    outcome: { decision: r.decision, rule: r.rule, path: r.path, reason: r.reason },
  };
}

const WRITE_SQL = /\b(?:insert\s+into|update\s+[\w.]+\s+set|delete\s+from|drop\s+(?:table|database|schema|view)|alter\s+table|truncate\s+(?:table\s+)?[\w.]+|grant\s+\w+\s+on|create\s+(?:table|database|schema))\b/i;
/** evidence.query is read-only: any write statement blocks. */
function readOnlySqlCheck(ctx: CheckContext): CheckResult {
  return WRITE_SQL.test(ctx.prompt) ? { verdict: "block", reason: "evidence.query is read-only; write SQL is refused" } : { verdict: "pass" };
}

export const REVISIT_POLICY_PACK: PolicyPack = {
  name: "revisit", version: 1,
  roleGrants: {
    lts_triager: ["zetaris:read", "hmem:write", "world:write", "decision:commit"],
    lts_lead: ["zetaris:read", "hmem:write", "world:write", "decision:commit"],
    viewer: ["zetaris:read"],
  },
  checks: { "memory-reliability": memoryReliabilityCheck, "read-only-sql": readOnlySqlCheck },
  policies: [
    { intent: "triage.commit_decision", allow: { roles: ["lts_triager", "lts_lead"] }, checks: ["memory-reliability"], rateLimitPerMinute: 30 },
    { intent: "evidence.query", checks: ["read-only-sql"] },
  ],
};

/** Capability graph for Revisit. decision.adopt_* are guard-selected: only the tool the memory-reliability check
 *  names can be routed, so a commit without arbitration is unroutable. */
export const REVISIT_TOOLS: ToolRegistration[] = [
  { capability: "evidence.query", toolId: "zetaris.sql", local: false, requiredPermissions: ["zetaris:read"], cost: { perCall: 0 }, latency: { p95Ms: 1500 } },
  { capability: "memory.recall", toolId: "hmem.query", local: true, latency: { p95Ms: 20 } },
  { capability: "memory.commit", toolId: "hmem.write", local: true, requiredPermissions: ["hmem:write"], latency: { p95Ms: 20 } },
  { capability: "world.query", toolId: "worldmodel.query", local: true, latency: { p95Ms: 20 } },
  { capability: "world.assert", toolId: "worldmodel.write", local: true, requiredPermissions: ["world:write"], latency: { p95Ms: 20 } },
  { capability: "reason.llm", toolId: "nightshift.chat", local: false, latency: { p95Ms: 120000 } },
  { capability: "decision.commit", toolId: "decision.adopt_memory", local: true, guardSelected: true, requiredPermissions: ["decision:commit"], latency: { p95Ms: 1 } },
  { capability: "decision.commit", toolId: "decision.adopt_evidence", local: true, guardSelected: true, requiredPermissions: ["decision:commit"], latency: { p95Ms: 1 } },
];

/** Model profiles. Intents with no model need route to the local rules profile; triage.new_cve needs text. */
export const REVISIT_MODEL_PROFILES: ModelProfile[] = [
  { id: "rules-local", provider: "scout", model: "deterministic-rules", local: true, context: 1_000_000, cost: { in: 0, out: 0 },
    latency: { p95Ms: 1 }, capabilities: ["deterministic"], dataClasses: ["public", "internal", "confidential", "restricted"], quality: 1 },
  { id: "nightshift-nemotron", provider: "nightshift", model: "nemotron (Meterless Nightshift)", local: false, context: 128000, cost: { in: 0, out: 0 },
    latency: { p95Ms: 120000 }, capabilities: ["text", "json-mode"], dataClasses: ["public", "internal"], quality: 2 },
];   // Revisit's Scout routes only to these two: every model call goes through Meterless Nightshift (no other provider is configured)

/** A Scout configured for Revisit (default + revisit policy packs, Revisit tools only, local-first models). */
export function createRevisitScout(opts: Partial<ScoutOptions> = {}): Scout {
  return new Scout({
    intentRegistry: REVISIT_REGISTRY,
    policyPack: ["default", REVISIT_POLICY_PACK],
    modelProfiles: REVISIT_MODEL_PROFILES,
    tools: REVISIT_TOOLS,
    includeDefaultTools: false,
    capabilityDeps: {},
    ...opts,
  });
}
