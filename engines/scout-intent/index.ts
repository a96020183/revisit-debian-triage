// Revisit Scout Intent: our implementation of the Meterless Scout Intent spec
// (engines/scout-intent/AGENTS.md, official repo commit 1742dec, 2026-10-19).
// Single file, zero runtime deps (node:crypto, node:fs, node:path, node:perf_hooks).
//
// Pipeline (§2): Sense -> Interpret -> Guard -> Route -> Recommend -> signed ExecutionContract.
// "§n" comments point at the numbered section of AGENTS.md being followed. Where the spec leaves a choice
// open we write "CHOICE:" and say what we picked. Revisit's domain pack (registry, memory-reliability check,
// tools, model profiles) lives in ./revisit.ts and plugs in through the same public interfaces.

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";

// ====================================================================================== §12 defaults
export const DEFAULTS = {
  bands: { high: 0.8, medium: 0.55, low: 0.4 },                                // §4.4
  weights: { lexical: 0.4, semantic: 0.35, contextual: 0.2, recency: 0.05 },  // §4.3
  tieWindow: 0.05,            // §4.6 rule 2
  highRiskProceed: 0.95,      // §4.6 rule 4
  secondaryFloor: 0.55,       // §4.5
  stage1BudgetMs: 16,         // §4.1
  ttlMs: 5 * 60 * 1000,       // §8.2
  maxClarifyOptions: 4,       // §4.6
  topK: 5,
  // CHOICE: riskPenalty (§4.3) applies only when the injection pre-scan fired, so a tainted prompt never ranks a
  // high-risk intent on top. Values are config data, like the weights.
  riskPenalty: { low: 0, medium: 0.1, high: 0.25 } as Record<RiskClass, number>,
  recencyTauMs: 10 * 60 * 1000,
  rateLimitPerMinute: { low: 60, medium: 30, high: 10 } as Record<RiskClass, number>,
};

export type RiskClass = "low" | "medium" | "high";
export type RiskLevel = RiskClass | "block";
export type Verdict = "pass" | "warn" | "block";
export type Band = "high" | "medium" | "low" | "reject";
export type DataClass = "public" | "internal" | "confidential" | "restricted";
const DATA_CLASSES: DataClass[] = ["public", "internal", "confidential", "restricted"];
const maxDataClass = (a: DataClass, b: DataClass) => (DATA_CLASSES.indexOf(a) >= DATA_CLASSES.indexOf(b) ? a : b);
const LEVELS: RiskClass[] = ["low", "medium", "high"];

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const round3 = (x: number) => Math.round(x * 1000) / 1000;
const clamp01 = (x: number) => Math.max(0, Math.min(1, x));

// ====================================================================================== §8.2 canonical JSON + ULID
/** Canonical JSON: object keys sorted, no whitespace, undefined dropped. Same bytes after a JSON round trip. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") {
    if (typeof v === "number" && !Number.isFinite(v)) throw new Error("canonicalJson: non-finite number");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map((x) => (x === undefined ? "null" : canonicalJson(x))).join(",") + "]";
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(o[k])).join(",") + "}";
}

const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
let ulidLastT = -1;
let ulidLastR: number[] = [];
/** ULID, monotonic within the process (same millisecond -> randomness incremented). */
export function ulid(now = Date.now()): string {
  let r: number[];
  if (now <= ulidLastT) {
    now = ulidLastT;
    r = ulidLastR.slice();
    for (let i = r.length - 1; i >= 0; i--) { if (r[i] < 31) { r[i]++; break; } r[i] = 0; }
  } else {
    r = [...randomBytes(16)].map((b) => b & 31);
  }
  ulidLastT = now; ulidLastR = r;
  let t = ""; let x = now;
  for (let i = 0; i < 10; i++) { t = B32[x % 32] + t; x = Math.floor(x / 32); }
  return t + r.map((i) => B32[i]).join("");
}

// ====================================================================================== §3 intent registry
export interface ParamSchema {
  type?: string; enum?: unknown[]; minimum?: number; maximum?: number; pattern?: string;
  items?: ParamSchema; properties?: Record<string, ParamSchema>; required?: string[];
  /** REVISIT/CHOICE: bind from request context instead of the prompt (dotted path, e.g. "evidence"). */
  "x-context"?: string;
  /** CHOICE: bind the token that follows one of these cue words (e.g. package name after "in"). */
  "x-after"?: string[];
}
export type CapabilityRef = string | { id: string; optional?: boolean };
export interface Intent {
  id: string; category: string; description: string; parameters: ParamSchema; capabilities: CapabilityRef[];
  riskClass: RiskClass; surfaces: string[]; roles: string[]; examples: string[]; version: number;
  /** Optional explicit Stage-1 triggers: phrases (weight 2) or {phrase: weight}. */
  triggers?: string[] | Record<string, number>;
  /** Optional context keys this intent consumes; their presence feeds the contextual term. */
  context?: string[];
  dataClass?: DataClass;
  /** Model capabilities the plan needs ("text", "json-mode", ...). Empty = no model call needed. */
  modelNeeds?: string[];
}

const INTENT_ID = /^[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*$/;  // category.name grammar
const FOUNDATION_ID = /^[A-Z][A-Z0-9_]*$/;                // foundation intents such as GENERAL
const strList = (x: unknown) => Array.isArray(x) && x.length > 0 && x.every((s) => typeof s === "string" && s.length > 0);
export const capId = (c: CapabilityRef) => (typeof c === "string" ? c : c.id);

/** §3 validation rules. Returns a list of problems (empty = valid). */
export function validateIntent(x: any): string[] {
  const e: string[] = [];
  const id = x?.id;
  if (typeof id !== "string" || !(INTENT_ID.test(id) || FOUNDATION_ID.test(id))) return [`${id}: id must follow the category.name grammar`];
  if (INTENT_ID.test(id) && x.category !== id.split(".")[0]) e.push(`${id}: category "${x.category}" does not match the id prefix`);
  if (typeof x.description !== "string" || !x.description.trim()) e.push(`${id}: description is required`);
  if (!x.parameters || typeof x.parameters !== "object") e.push(`${id}: parameters schema is required`);
  if (!Array.isArray(x.capabilities) || !x.capabilities.every((c: any) => typeof capId(c) === "string")) e.push(`${id}: capabilities must be a list`);
  if (!LEVELS.includes(x.riskClass)) e.push(`${id}: riskClass must be low|medium|high`);
  if (!strList(x.surfaces)) e.push(`${id}: surfaces must be a non-empty list`);
  if (!strList(x.roles)) e.push(`${id}: roles must be a non-empty list`);
  if (!strList(x.examples)) e.push(`${id}: examples are mandatory (an intent without examples cannot be classified or evaluated)`);
  if (!Number.isInteger(x.version) || x.version < 1) e.push(`${id}: version must be a positive integer`);
  if (x.dataClass !== undefined && !DATA_CLASSES.includes(x.dataClass)) e.push(`${id}: unknown dataClass ${x.dataClass}`);
  return e;
}

export class IntentRegistry {
  readonly intents: ReadonlyMap<string, Intent>;
  readonly version: number;
  readonly digest: string;  // drift detection beyond the integer version
  readonly sources: string[];

  constructor(intents: Intent[], version = 1, sources: string[] = []) {
    const problems = intents.flatMap(validateIntent);
    const m = new Map<string, Intent>();
    for (const it of intents) {
      if (m.has(it.id)) problems.push(`${it.id}: duplicate intent id`);
      m.set(it.id, Object.freeze({ ...it }) as Intent);
    }
    if (problems.length) throw new Error("Invalid intent registry:\n  " + problems.join("\n  "));
    this.intents = m; this.version = version; this.sources = sources;
    this.digest = sha256(canonicalJson([...m.values()].sort((a, b) => (a.id < b.id ? -1 : 1)))).slice(0, 16);
  }
  static fromFile(file: string): IntentRegistry {
    const j = JSON.parse(fs.readFileSync(file, "utf-8"));
    const list = Array.isArray(j) ? j : j.intents;
    return new IntentRegistry(list, (Array.isArray(j) ? undefined : j.registryVersion ?? j.version) ?? 1, [file]);
  }
  /** CHOICE: a directory of JSON files (one intent or {intents:[...]} per file). registryVersion = sum of intent versions,
   *  so bumping any intent bumps the registry. */
  static fromDirectory(dir: string): IntentRegistry {
    const list: Intent[] = [];
    for (const f of fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort()) {
      const j = JSON.parse(fs.readFileSync(path.join(dir, f), "utf-8"));
      list.push(...(Array.isArray(j) ? j : j.intents ?? [j]));
    }
    return new IntentRegistry(list, list.reduce((s, i) => s + (i.version ?? 0), 0), [dir]);
  }
  /** Compose registries. The same id in two parts must be identical; registryVersion = sum of the parts. */
  static compose(parts: IntentRegistry[]): IntentRegistry {
    const m = new Map<string, Intent>();
    for (const r of parts) for (const it of r.all()) {
      const prev = m.get(it.id);
      if (prev && canonicalJson(prev) !== canonicalJson(it)) throw new Error(`compose: conflicting definitions of ${it.id}`);
      m.set(it.id, it);
    }
    return new IntentRegistry([...m.values()], parts.reduce((s, r) => s + r.version, 0), parts.flatMap((r) => r.sources));
  }
  static load(x: string | IntentRegistry | Intent[]): IntentRegistry {
    if (x instanceof IntentRegistry) return x;
    if (Array.isArray(x)) return new IntentRegistry(x);
    return fs.statSync(x).isDirectory() ? IntentRegistry.fromDirectory(x) : IntentRegistry.fromFile(x);
  }
  get(id: string) { return this.intents.get(id); }
  has(id: string) { return this.intents.has(id); }
  all() { return [...this.intents.values()]; }
}

// ====================================================================================== text utilities
const STOP = new Set((
  "a an the of to in on for and or but is are was were be been being am do does did done doing i me my mine we us our " +
  "ours you your yours he him his she her it its they them their this that these those there here what which who whom " +
  "whose when where why how can could would should will shall may might must please just also then than so too very " +
  "really all any some each every no not nor only own same such with by at as from into onto about over under up down " +
  "out off again once via has have had having get got let lets s t d ll re ve m o y"
).split(/\s+/));

// General vocabulary: each row collapses to its first word. These are synonyms, not eval prompts.
const SYNONYMS: string[][] = [
  ["email", "emails", "mail", "mails", "e-mail"],
  ["draft", "write", "compose"],
  ["summarize", "summarise", "summary", "summaries", "recap", "digest", "tldr", "overview"],
  ["schedule", "calendar", "meeting", "reminder", "invite", "book"],
  ["compare", "comparison", "versus", "vs", "contrast"],
  ["recover", "recovery", "rescue", "revive", "salvage"],
  ["stuck", "stalled", "stale", "slipping"],
  ["research", "investigate", "analyze", "analyse", "analysis"],
  ["plan", "roadmap", "rollout"],
  ["number", "numbers", "metric", "metrics", "kpi", "kpis", "figures"],
  ["competitor", "competitors", "rival", "rivals", "competition"],
  ["send", "blast", "broadcast"],
  ["show", "list", "display", "view"],
  ["status", "progress"],
  ["cve", "cves", "vulnerability", "vulnerabilities", "vuln", "vulns", "advisory", "advisories"],
  ["defer", "deferred", "postpone", "postponed", "parked", "snoozed", "deferral"],
  ["commit", "adopt", "finalize", "finalise"],
  ["memory", "hmem", "h-mem"],
  ["reopen", "re-open", "resurface"],
];
const CANON = new Map<string, string>();
for (const row of SYNONYMS) for (const w of row) CANON.set(w, row[0]);

/** Light suffix stemmer + synonym canonicalisation. Applied identically to registry text and prompts. */
export function stem(word: string): string {
  const w = word.toLowerCase();
  if (CANON.has(w)) return CANON.get(w)!;
  let s = w;
  if (s.length > 4 && s.endsWith("ies")) s = s.slice(0, -3) + "y";
  else if (s.length > 5 && s.endsWith("ing")) s = s.slice(0, -3);
  else if (s.length > 4 && s.endsWith("ed")) s = s.slice(0, -2);
  else if (s.length > 4 && /(ss|x|z|ch|sh)es$/.test(s)) s = s.slice(0, -2);
  else if (s.length > 3 && s.endsWith("s") && !/(ss|us|is)$/.test(s)) s = s.slice(0, -1);
  if (CANON.has(s)) return CANON.get(s)!;
  if (s.length > 4 && s.endsWith("e")) s = s.slice(0, -1);
  return CANON.get(s) ?? s;
}

interface Tok { raw: string; stem: string; start: number; end: number }
/** Content tokens (stopwords removed) with offsets into the original text. Hyphenated words also yield their parts. */
export function contentTokens(text: string): Tok[] {
  const out: Tok[] = [];
  for (const m of text.matchAll(/[A-Za-z0-9]+(?:[-'][A-Za-z0-9]+)*/g)) {
    // Entity normalisation: a CVE identifier is one "cve" token, not vocabulary (its digits carry no intent signal).
    if (/^CVE-\d{4}-\d+$/i.test(m[0])) { out.push({ raw: "cve", stem: "cve", start: m.index!, end: m.index! + m[0].length }); continue; }
    const low = m[0].toLowerCase();
    const raw = low.endsWith("n't") ? low.slice(0, -3) : low.replace(/'(s|re|ve|ll|d|m)$/, "");
    if (!raw || STOP.has(raw)) continue;
    const start = m.index!, end = start + m[0].length;
    if (raw.includes("-") && !CANON.has(raw)) {
      out.push({ raw, stem: raw.split("-").map(stem).join("-"), start, end });
      for (const p of raw.split("-")) if (p.length > 1 && !STOP.has(p)) out.push({ raw: p, stem: stem(p), start, end });
    } else {
      out.push({ raw, stem: stem(raw), start, end });
    }
  }
  return out;
}
/** Stage-1 terms: unigrams "u:" and adjacent-content bigrams "b:". */
function termSet(text: string): Map<string, number> {
  const toks = contentTokens(text).filter((t) => t.raw.length > 1 || /\d/.test(t.raw));
  const m = new Map<string, number>();
  toks.forEach((t, i) => {
    m.set("u:" + t.stem, 1);
    const n = toks[i + 1];
    if (n && n.start !== t.start) m.set("b:" + t.stem + "_" + n.stem, 1);
  });
  return m;
}

// ====================================================================================== §4.1 Stage 1: trigger scanner
interface Stage1Result { scores: Map<string, number>; matched: Map<string, string[]>; total: number }

/** Weighted trigger-word/substring scan over the full registry. Pure rules, no model call.
 *  Triggers are derived from each intent's id, examples and description (plus optional explicit `triggers`),
 *  weighted by inverse intent frequency so words shared by many intents carry little signal. */
export class TriggerScanner {
  private index = new Map<string, Array<[string, number]>>();
  constructor(registry: IntentRegistry) {
    const per = new Map<string, Map<string, number>>();
    const add = (id: string, key: string, w: number) => {
      const m = per.get(id) ?? new Map<string, number>(); per.set(id, m);
      m.set(key, Math.max(m.get(key) ?? 0, w));
    };
    const addText = (id: string, text: string, uni: number, bi: number) => {
      for (const k of termSet(text).keys()) add(id, k, k.startsWith("u:") ? uni : bi);
    };
    for (const it of registry.all()) {
      if (!FOUNDATION_ID.test(it.id)) addText(it.id, it.id.replace(/[._-]/g, " "), 1.2, 0);
      for (const ex of it.examples) addText(it.id, ex, 1.0, 1.5);
      addText(it.id, it.description, 0.4, 0.4);
      const trig = Array.isArray(it.triggers) ? Object.fromEntries(it.triggers.map((t) => [t, 2])) : it.triggers ?? {};
      for (const [phrase, w] of Object.entries(trig)) addText(it.id, phrase, w, w * 1.25);
    }
    const df = new Map<string, number>();
    for (const m of per.values()) for (const k of m.keys()) df.set(k, (df.get(k) ?? 0) + 1);
    const N = per.size;
    for (const [id, m] of per) for (const [k, w] of m) {
      const l = this.index.get(k) ?? []; this.index.set(k, l);
      l.push([id, w * Math.log(1 + N / df.get(k)!)]);
    }
  }
  scan(text: string): Stage1Result {
    const scores = new Map<string, number>(); const matched = new Map<string, string[]>(); let total = 0;
    for (const k of termSet(text).keys()) {
      const hits = this.index.get(k); if (!hits) continue;
      for (const [id, w] of hits) {
        scores.set(id, (scores.get(id) ?? 0) + w); total += w;
        const l = matched.get(id) ?? []; l.push(k.slice(2)); matched.set(id, l);
      }
    }
    return { scores, matched, total };
  }
}

// ====================================================================================== §4.2 Stage 2: semantic + contextual
/** Pluggable Stage-2 semantic scorer (e.g. a 50-200 MB ONNX embedding model). Returns similarity in [0,1]. */
export interface SemanticScorer { readonly id: string; similarity(text: string, intent: Intent): number }

type SparseVec = Map<string, number>;
/** Out-of-vocabulary tokens (names such as "caddy" or "python3.11") keep a small weight: they carry little intent
 *  signal, but dropping them entirely would let one known word in a sea of noise look like a confident match. */
const OOV_WEIGHT = 0.35;
function encode(text: string, vocab?: Set<string>): SparseVec {
  const toks = contentTokens(text);
  const v: SparseVec = new Map();
  const bump = (k: string, w: number) => v.set(k, (v.get(k) ?? 0) + w);
  toks.forEach((t, i) => {
    bump("u:" + t.stem, vocab && !vocab.has(t.stem) ? OOV_WEIGHT : 1);
    if (toks[i + 1] && toks[i + 1].start !== t.start) bump("b:" + t.stem + "_" + toks[i + 1].stem, 0.5);
    if (t.stem.length >= 5) for (let j = 0; j + 3 <= t.stem.length; j++) bump("c:" + t.stem.slice(j, j + 3), 0.15);
  });
  let n = 0; for (const x of v.values()) n += x * x; n = Math.sqrt(n) || 1;
  for (const [k, x] of v) v.set(k, x / n);
  return v;
}
function cos(a: SparseVec, b: SparseVec): number {
  const [s, l] = a.size < b.size ? [a, b] : [b, a];
  let d = 0; for (const [k, x] of s) { const y = l.get(k); if (y) d += x * y; }
  return d;
}

/** CHOICE (deviation, see report): the default Stage-2 semantic term is a model-free local sparse encoder
 *  (stemmed unigrams + bigrams + character trigrams, cosine vs intent prototypes), not a 50-200 MB embedding model.
 *  It keeps the engine zero-dependency; a real model plugs in through the SemanticScorer interface. */
export class LocalSparseEncoder implements SemanticScorer {
  readonly id = "local-sparse-v1";
  private protos = new Map<string, Array<[SparseVec, number]>>();
  readonly vocab = new Set<string>();
  constructor(registry: IntentRegistry) {
    for (const it of registry.all())
      for (const s of [...it.examples, it.description, it.id.replace(/[._-]/g, " ")]) for (const t of contentTokens(s)) this.vocab.add(t.stem);
    for (const it of registry.all()) {
      const list: Array<[SparseVec, number]> = [];
      for (const ex of it.examples) {
        list.push([encode(ex), 1]);
        const segs = segment(ex);
        if (segs.length > 1) for (const s of segs) list.push([encode(s.text), 1]);
      }
      list.push([encode(it.description), 0.85]);
      if (!FOUNDATION_ID.test(it.id)) list.push([encode(it.id.replace(/[._-]/g, " ")), 0.7]);
      this.protos.set(it.id, list);
    }
  }
  similarity(text: string, intent: Intent): number { return this.similarityVec(this.encode(text), intent.id); }
  encode(text: string): SparseVec { return encode(text, this.vocab); }
  similarityVec(v: SparseVec, id: string): number {
    let best = 0;
    for (const [p, scale] of this.protos.get(id) ?? []) best = Math.max(best, scale * cos(v, p));
    return clamp01(best);
  }
}

/** Clause segmentation for multi-intent detection (§4.5). Spans are offsets into the prompt. */
export function segment(text: string): Array<{ text: string; start: number; end: number }> {
  const out: Array<{ text: string; start: number; end: number }> = [];
  const sep = /\s*(?:[,;]|\band then\b|\bthen\b|\band also\b|\band\b|\bplus\b)\s*/gi;
  let last = 0;
  for (const m of text.matchAll(sep)) {
    if (m.index! > last) out.push({ text: text.slice(last, m.index!), start: last, end: m.index! });
    last = m.index! + m[0].length;
  }
  if (last < text.length) out.push({ text: text.slice(last), start: last, end: text.length });
  return out.filter((s) => s.text.trim().length > 0);
}

// ====================================================================================== §6 Guard: policy packs
export interface Flag {
  kind: string; layer: string; score?: number; evidence?: string[]; rule?: string; reason?: string; [k: string]: unknown;
}
export interface Redaction { kind: string; dataClass: DataClass; start: number; end: number }
export interface ApprovalRecord { kind: "user-confirm" | "operator-review"; at: string; by?: string; confirmation?: string; decision?: string }
export type ApprovalKind = ApprovalRecord["kind"];
export interface LayerResult {
  layer: "injection" | "policy" | "scope" | "pii" | "rate-limit"; verdict: Verdict; reason?: string; flags: Flag[];
}
/** A domain risk check run inside the policy gate (Revisit's memory-reliability check is one of these). */
export interface CheckContext {
  intent: Intent; parameters: Record<string, unknown>; references: Record<string, unknown>;
  context: any; user: UserRef; surface: string; prompt: string;
}
export interface CheckResult {
  verdict: Verdict; reason?: string; flags?: Flag[];
  /** capability -> the only tool the guard authorises for it (enforced by Route selection rule 1). */
  routeConstraints?: Record<string, string>;
  /** capability -> extra tool-step input. */
  stepInputs?: Record<string, Record<string, unknown>>;
  /** domain result surfaced on the decision (e.g. the chosen triage class). */
  outcome?: Record<string, unknown>;
}
export type GuardCheck = (ctx: CheckContext) => CheckResult;

type Cond = unknown | { gt?: number; gte?: number; lt?: number; lte?: number; eq?: unknown; in?: unknown[] };
export interface IntentPolicy {
  intent: string;
  allow?: { roles?: string[]; surfaces?: string[]; params?: Record<string, { min?: number; max?: number; enum?: unknown[] }> };
  deny?: { paramCombinations?: Array<Record<string, Cond>> };
  requireApproval?: Array<{ when?: Record<string, Cond>; kind: ApprovalKind }>;
  rateLimitPerMinute?: number;
  dataClass?: DataClass;
  checks?: string[];
}
export interface InjectionPattern {
  id: string; kind: "pattern" | "role-drift" | "tool-ref" | "control"; weight: number;
  /** Returns true when the pattern fires. Evidence logged is the pattern id only, never the payload (§6.1). */
  test: (text: string) => boolean;
}
export interface PolicyPack {
  name: string; version: number;
  injection?: { patterns?: InjectionPattern[]; blockAt?: number; warnAt?: number };
  policies?: IntentPolicy[];
  checks?: Record<string, GuardCheck>;
  roleGrants?: Record<string, string[]>;
  pii?: { blockDataClasses?: DataClass[] };
  rateLimitPerMinute?: Partial<Record<RiskClass, number>>;
}

const INSTRUCTION_NOUNS = new Set(["instruction", "instructions", "rule", "rules", "prompt", "prompts", "message", "messages", "context",
  "direction", "directions", "guideline", "guidelines", "command", "commands", "policy", "policies", "and", "then", "or", "to", ""]);
/** "ignore/disregard ... previous|above ..." only when what follows is an instruction noun or the clause ends.
 *  "ignore the previous NEXT decision" is a normal Debian triage sentence and must not fire. */
function overridePhrase(text: string): boolean {
  const re = /\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+|of\s+)*(?:previous|prior|above|earlier|preceding|original|system)\b\s*([a-z]*)/gi;
  for (const m of text.matchAll(re)) if (INSTRUCTION_NOUNS.has(m[1].toLowerCase())) return true;
  return /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:rules|instructions|guidelines|system prompt|user|directions)\b/i.test(text);
}

/** The `default` pack: conservative, general purpose. */
export const DEFAULT_PACK: PolicyPack = {
  name: "default", version: 1,
  injection: {
    blockAt: 0.8, warnAt: 0.4,
    patterns: [
      { id: "instruction-override", kind: "pattern", weight: 0.9, test: overridePhrase },
      { id: "embedded-role-tag", kind: "control", weight: 0.9, test: (t) => /<\/?\s*(system|user|assistant|im_start|im_end)\s*>|<\|im_(start|end)\|>|<<\/?SYS>>/i.test(t) },
      { id: "inst-marker", kind: "control", weight: 0.9, test: (t) => /\[\/?INST\]/i.test(t) },
      { id: "role-drift-you-are-now", kind: "role-drift", weight: 0.6, test: (t) => /\byou are now\b|\bfrom now on,? you\b/i.test(t) },
      { id: "role-drift-impersonate", kind: "role-drift", weight: 0.85, test: (t) => /\b(pretend|act|behave|roleplay)\s+(to be|as|like)\s+(the |a |an )?(system|admin|administrator|developer|root|superuser|dan)\b/i.test(t) },
      { id: "role-drift-mode", kind: "role-drift", weight: 0.8, test: (t) => /\b(unrestricted|developer|jailbreak|god|dan)\s+mode\b/i.test(t) },
      { id: "bidi-or-zero-width-char", kind: "control", weight: 0.6, test: (t) => /[‪-‮⁦-⁩​-‏﻿]/.test(t) },
      { id: "privilege-escalation", kind: "tool-ref", weight: 0.7, test: (t) => /\bgrant\s+(me|us|myself)?\s*(full\s+)?(admin|root|superuser|owner)\b|\bgrant\s+(me|us|myself)\s+(\w+\s+){0,2}(access|privileges?|permissions?)\b|\b(make|promote)\s+me\s+(an?\s+)?(admin|owner|root)\b/i.test(t) },
    ],
  },
  roleGrants: { marketing: ["email:send"], exec: ["email:send"], ae: ["world:write"], "sales-leader": ["world:write"], admin: ["email:send", "world:write"] },
  policies: [
    { intent: "deal.recover", allow: { params: { count: { max: 20 } } }, deny: { paramCombinations: [{ channel: "call", count: { gt: 5 } }] },
      requireApproval: [{ when: { stage: "closed-won" }, kind: "operator-review" }] },
    { intent: "email.send", rateLimitPerMinute: 5 },
  ],
};

/** `adversarial-tight`: hardened posture for hostile surfaces (the eval runner composes it with `default`). */
export const ADVERSARIAL_TIGHT_PACK: PolicyPack = {
  name: "adversarial-tight", version: 1,
  injection: {
    blockAt: 0.75, warnAt: 0.3,
    patterns: [
      { id: "secret-exfiltration", kind: "pattern", weight: 0.7, test: (t) => /\b(reveal|show|print|dump|leak|exfiltrate|send me|list)\b[^.\n]{0,30}\b(api[ _-]?keys?|credentials?|passwords?|secrets?|access tokens?|system prompt)\b/i.test(t) },
      { id: "markdown-authority-header", kind: "pattern", weight: 0.4, test: (t) => /^\s*#{1,6}\s*(important|system|instructions?|admin|override)\b/im.test(t) },
      { id: "escaped-control-sequence", kind: "control", weight: 0.5, test: (t) => /\\u(202[a-e]|206[6-9]|200[b-f]|feff)/i.test(t) },
      { id: "destructive-ddl", kind: "pattern", weight: 0.5, test: (t) => /\b(drop|truncate)\s+(the\s+)?\w*\s*(table|database|schema)\b/i.test(t) },
    ],
  },
};

const BUILTIN_PACKS: Record<string, PolicyPack> = { default: DEFAULT_PACK, "adversarial-tight": ADVERSARIAL_TIGHT_PACK };
export function registerPolicyPack(p: PolicyPack) { BUILTIN_PACKS[p.name] = p; }

interface ComposedPolicy {
  version: string; patterns: InjectionPattern[]; blockAt: number; warnAt: number;
  policies: Map<string, IntentPolicy[]>; checks: Record<string, GuardCheck>; roleGrants: Record<string, Set<string>>;
  blockDataClasses: Set<DataClass>; rateLimitPerMinute: Record<RiskClass, number>;
}
function loadPack(p: string | PolicyPack): PolicyPack {
  if (typeof p !== "string") return p;
  if (BUILTIN_PACKS[p]) return BUILTIN_PACKS[p];
  if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf-8"));  // JSON packs carry policies/grants (no code)
  throw new Error(`unknown policy pack "${p}"`);
}
/** Compose packs: patterns/policies/checks concatenate, thresholds take the tightest value. */
function composePacks(packs: Array<string | PolicyPack>): ComposedPolicy {
  const out: ComposedPolicy = {
    version: "", patterns: [], blockAt: 1, warnAt: 1, policies: new Map(), checks: {}, roleGrants: {},
    blockDataClasses: new Set(), rateLimitPerMinute: { ...DEFAULTS.rateLimitPerMinute },
  };
  const names: string[] = [];
  for (const raw of packs) {
    const p = loadPack(raw); names.push(`${p.name}@${p.version}`);
    out.patterns.push(...(p.injection?.patterns ?? []));
    if (p.injection?.blockAt !== undefined) out.blockAt = Math.min(out.blockAt, p.injection.blockAt);
    if (p.injection?.warnAt !== undefined) out.warnAt = Math.min(out.warnAt, p.injection.warnAt);
    for (const pol of p.policies ?? []) out.policies.set(pol.intent, [...(out.policies.get(pol.intent) ?? []), pol]);
    Object.assign(out.checks, p.checks ?? {});
    for (const [role, perms] of Object.entries(p.roleGrants ?? {})) {
      const s = out.roleGrants[role] ?? new Set<string>(); perms.forEach((x) => s.add(x)); out.roleGrants[role] = s;
    }
    for (const dc of p.pii?.blockDataClasses ?? []) out.blockDataClasses.add(dc);
    for (const [rc, n] of Object.entries(p.rateLimitPerMinute ?? {})) out.rateLimitPerMinute[rc as RiskClass] = Math.min(out.rateLimitPerMinute[rc as RiskClass], n!);
  }
  out.version = names.join("+");
  return out;
}

function condMatches(v: unknown, c: Cond): boolean {
  if (c !== null && typeof c === "object" && !Array.isArray(c)) {
    const o = c as any;
    if (o.eq !== undefined && v !== o.eq) return false;
    if (o.in !== undefined && !o.in.includes(v)) return false;
    if (typeof v !== "number" && (o.gt ?? o.gte ?? o.lt ?? o.lte) !== undefined) return false;
    if (o.gt !== undefined && !((v as number) > o.gt)) return false;
    if (o.gte !== undefined && !((v as number) >= o.gte)) return false;
    if (o.lt !== undefined && !((v as number) < o.lt)) return false;
    if (o.lte !== undefined && !((v as number) <= o.lte)) return false;
    return true;
  }
  return v === c;
}
const allMatch = (params: Record<string, unknown>, when: Record<string, Cond> = {}) =>
  Object.entries(when).every(([k, c]) => condMatches(params[k], c));

// ---- §6.4 PII / sensitivity detectors
interface PiiDetector { kind: string; dataClass: DataClass; re: RegExp; valid?: (s: string) => boolean }
const luhn = (s: string) => {
  const d = s.replace(/\D/g, ""); if (d.length < 13 || d.length > 19) return false;
  let sum = 0; for (let i = 0; i < d.length; i++) { let x = +d[d.length - 1 - i]; if (i % 2) { x *= 2; if (x > 9) x -= 9; } sum += x; }
  return sum % 10 === 0;
};
const PII: PiiDetector[] = [
  { kind: "credential", dataClass: "restricted", re: /\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,})\b/g },
  { kind: "credential", dataClass: "restricted", re: /\b(?:password|passwd|pwd|secret|token|api[_ -]?key)\s*[:=]\s*\S+/gi },
  { kind: "email", dataClass: "confidential", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { kind: "ssn", dataClass: "confidential", re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { kind: "card", dataClass: "restricted", re: /\b(?:\d[ -]?){13,19}\b/g, valid: luhn },
  { kind: "phone", dataClass: "confidential", re: /(?<![\w-])(?:\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\w-])/g },
];
const SENSITIVE_MARKERS: Array<[string, DataClass, RegExp]> = [
  ["health", "confidential", /\b(HIPAA|PHI|diagnos(?:is|ed)|medical record)\b/i],
  ["financial", "confidential", /\b(PCI|IBAN|account number)\b/i],
];

// ---- §6.5 token-bucket rate limiter
class RateLimiter {
  private buckets = new Map<string, { tokens: number; t: number }>();
  take(key: string, perMinute: number, now: number): boolean {
    const b = this.buckets.get(key) ?? { tokens: perMinute, t: now };
    b.tokens = Math.min(perMinute, b.tokens + ((now - b.t) / 60000) * perMinute); b.t = now;
    const ok = b.tokens >= 1; if (ok) b.tokens -= 1;
    this.buckets.set(key, b); return ok;
  }
}

// ====================================================================================== §7 capability graph
export interface ToolRegistration {
  capability: string; toolId: string; local?: boolean; availability?: () => boolean; requiredPermissions?: string[];
  cost?: { perCall: number }; latency?: { p95Ms: number }; surfaces?: string[];
  /** Only selectable when a guard check names it in routeConstraints (e.g. decision.adopt_memory). */
  guardSelected?: boolean;
  invoke?: (input: unknown) => Promise<unknown>;
}
export interface ToolStep {
  step: number; capability: string; tool: string; local: boolean; fromIntent: string; input: Record<string, unknown>; optional?: boolean;
}
export class RoutingError extends Error {
  constructor(public code: "unresolvable-capability" | "permission-denied" | "unavailable", public capability: string, msg: string) { super(msg); }
}
interface RouteCtx {
  permissions: Set<string>; surface: string; latencyTargetMs?: number; unavailable: Set<string>;
  routeConstraints: Record<string, string>;
}

export class CapabilityGraph {
  private tools = new Map<string, ToolRegistration[]>();
  private deps = new Map<string, string[]>();
  /** Register (or replace, same capability+toolId) a concrete tool for an abstract capability. */
  register(t: ToolRegistration) {
    const l = (this.tools.get(t.capability) ?? []).filter((x) => x.toolId !== t.toolId);
    l.push(t); this.tools.set(t.capability, l);
  }
  /** Capability composition: e.g. swarm.run needs [memory.recall, markovian.chain]. Walked transitively. */
  requires(capability: string, needs: string[]) { this.deps.set(capability, needs); }
  toolsFor(capability: string) { return this.tools.get(capability) ?? []; }

  /** Dependencies first, each capability once. */
  expand(caps: CapabilityRef[]): Array<{ id: string; optional: boolean }> {
    const out: Array<{ id: string; optional: boolean }> = []; const seen = new Set<string>();
    const visit = (id: string, optional: boolean, stack: string[]) => {
      if (seen.has(id) || stack.includes(id)) return;
      for (const d of this.deps.get(id) ?? []) visit(d, optional, [...stack, id]);
      seen.add(id); out.push({ id, optional });
    };
    for (const c of caps) visit(capId(c), typeof c === "object" && !!c.optional, []);
    return out;
  }

  /** The five selection rules of §7, in priority order. */
  select(capability: string, ctx: RouteCtx): ToolRegistration {
    const all = this.toolsFor(capability);
    if (!all.length) throw new RoutingError("unresolvable-capability", capability, `no tool registered for capability ${capability}`);
    const forced = ctx.routeConstraints[capability];
    // 1. required permissions (incl. tools the guard did not authorise)
    const permitted = all.filter((t) => (forced ? t.toolId === forced : !t.guardSelected) &&
      (t.requiredPermissions ?? []).every((p) => ctx.permissions.has(p)));
    if (!permitted.length) throw new RoutingError("permission-denied", capability, `no permitted tool for ${capability}`);
    // 2. availability
    const up = permitted.filter((t) => !ctx.unavailable.has(t.toolId) && (t.availability ? t.availability() : true));
    if (!up.length) throw new RoutingError("unavailable", capability, `all tools for ${capability} are offline`);
    const target = ctx.latencyTargetMs ?? Infinity;
    const key = (t: ToolRegistration) => [
      t.surfaces ? (t.surfaces.includes(ctx.surface) ? 0 : 1) : 0.5,  // 3. surface preference
      (t.latency?.p95Ms ?? 0) <= target ? 0 : 1,                      // 4a. meets latency target
      t.cost?.perCall ?? 0,                                           // 4b. cheapest
      t.local ? 0 : 1,                                                // 5. local-first tie-break
      t.latency?.p95Ms ?? 0,
    ];
    return [...up].sort((a, b) => {
      const ka = key(a), kb = key(b);
      for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return ka[i] - kb[i];
      return a.toolId < b.toolId ? -1 : 1;
    })[0];
  }

  plan(items: Array<{ intent: Intent; parameters: Record<string, unknown> }>, ctx: RouteCtx,
       stepInputs: Record<string, Record<string, unknown>> = {}): { toolPlan: ToolStep[]; degraded: string[] } {
    const toolPlan: ToolStep[] = []; const degraded: string[] = []; const done = new Set<string>();
    for (const { intent, parameters } of items) {
      for (const { id, optional } of this.expand(intent.capabilities)) {
        if (done.has(id)) continue;
        try {
          const t = this.select(id, ctx);
          toolPlan.push({ step: toolPlan.length + 1, capability: id, tool: t.toolId, local: !!t.local, fromIntent: intent.id,
            input: { ...parameters, ...(stepInputs[id] ?? {}) }, ...(optional ? { optional } : {}) });
          done.add(id);
        } catch (e) {
          if (optional && e instanceof RoutingError) { degraded.push(id); continue; }  // degrade: drop optional steps
          throw e;  // never substitute an out-of-scope tool
        }
      }
    }
    return { toolPlan, degraded };
  }
}

/** Default tool registrations for the fixture/teaching capabilities (local-first where a local tool exists). */
export const DEFAULT_TOOLS: ToolRegistration[] = [
  { capability: "world.query", toolId: "meterless.world-model.graph", local: true, latency: { p95Ms: 50 } },
  { capability: "world.query", toolId: "postgres.read", local: false, cost: { perCall: 0.0005 }, latency: { p95Ms: 120 } },
  { capability: "world.assert", toolId: "meterless.world-model.assert", local: true, requiredPermissions: ["world:write"], latency: { p95Ms: 60 } },
  { capability: "memory.recall", toolId: "meterless.hmem.retrieve", local: true, latency: { p95Ms: 30 } },
  { capability: "memory.commit", toolId: "meterless.hmem.commit", local: true, latency: { p95Ms: 30 } },
  { capability: "swarm.run", toolId: "meterless.swarm.execute", local: true, latency: { p95Ms: 8000 } },
  { capability: "swarm.run", toolId: "remote.swarm.api", local: false, cost: { perCall: 0.05 }, latency: { p95Ms: 6000 } },
  { capability: "markovian.chain", toolId: "meterless.markovian.chain", local: true, latency: { p95Ms: 5000 } },
  { capability: "email.draft", toolId: "meterless.local-template-drafter", local: true, latency: { p95Ms: 200 } },
  { capability: "email.send", toolId: "gmail.send", local: false, requiredPermissions: ["email:send"], surfaces: ["inbox"], latency: { p95Ms: 800 } },
  { capability: "email.send", toolId: "smtp.send", local: false, requiredPermissions: ["email:send"], latency: { p95Ms: 1200 } },
  { capability: "calendar.create", toolId: "local.calendar", local: true, latency: { p95Ms: 40 } },
  { capability: "approval.require", toolId: "scout.approval-gate", local: true, latency: { p95Ms: 1 } },
];
const DEFAULT_DEPS: Record<string, string[]> = { "swarm.run": ["memory.recall", "markovian.chain"] };  // docs/capability-graph.md

// ====================================================================================== §8.1 model routing
export interface ModelProfile {
  id: string; provider: string; model: string; context: number; cost: { in: number; out: number };
  latency: { p95Ms: number }; capabilities: string[]; dataClasses: DataClass[]; local?: boolean; quality?: number; fallbacks?: string[];
}
export interface ModelProfileRef { id: string; provider: string; model: string; local: boolean; dataClass: DataClass; fallbacks: string[] }
const LOCAL_PROVIDERS = new Set(["local", "webllm", "onnx", "ollama", "llama.cpp", "scout"]);
export const DEFAULT_PROFILES: ModelProfile[] = [
  { id: "local-fast", provider: "local", model: "llama-3.2-3b-instruct", context: 8000, cost: { in: 0, out: 0 }, latency: { p95Ms: 1500 },
    capabilities: ["text"], dataClasses: [...DATA_CLASSES], quality: 1 },
  { id: "local-capable", provider: "webllm", model: "llama-3.1-8b-instruct", context: 32000, cost: { in: 0, out: 0 }, latency: { p95Ms: 4000 },
    capabilities: ["text", "json-mode"], dataClasses: [...DATA_CLASSES], quality: 2 },
  { id: "remote-fast", provider: "openai", model: "gpt-4.1-nano", context: 128000, cost: { in: 0.0001, out: 0.0004 }, latency: { p95Ms: 800 },
    capabilities: ["text", "function-calling", "json-mode"], dataClasses: ["public"], quality: 2 },
  { id: "remote-capable", provider: "openai", model: "gpt-4.1", context: 128000, cost: { in: 0.002, out: 0.008 }, latency: { p95Ms: 2500 },
    capabilities: ["text", "function-calling", "json-mode", "vision"], dataClasses: ["public", "internal"], quality: 3 },
];
const REASONING_CAPS = new Set(["swarm.run", "markovian.chain", "email.draft", "reason.llm"]);

export class ModelRouter {
  readonly profiles: ModelProfile[];
  constructor(profiles: ModelProfile[], private mode: "local-first" | "cloud-first" = "local-first") {
    this.profiles = profiles.map((p) => ({ ...p, local: p.local ?? LOCAL_PROVIDERS.has(p.provider) }));
  }
  static load(x: undefined | string | ModelProfile[] | { profiles: ModelProfile[]; defaultChain?: string }, mode?: "local-first" | "cloud-first") {
    if (!x) return new ModelRouter(DEFAULT_PROFILES, mode);
    const j = typeof x === "string" ? JSON.parse(fs.readFileSync(x, "utf-8")) : x;
    const list = Array.isArray(j) ? j : j.profiles;
    return new ModelRouter(list, mode ?? (j.defaultChain === "cloud-first" ? "cloud-first" : "local-first"));
  }
  /** Rules (docs/model-routing.md): compatibility, data class, context budget, cost, latency, quality for high risk;
   *  tie-break local-first (always for confidential/restricted). Fallbacks satisfy the same data-class constraint. */
  route(req: { needs: string[]; dataClass: DataClass; promptTokens: number; riskClass: RiskClass; budget?: { costMaxUSD?: number; latencyMs?: number } }): ModelProfileRef {
    let ok = this.profiles.filter((p) => req.needs.every((n) => p.capabilities.includes(n)) && p.dataClasses.includes(req.dataClass) &&
      p.context >= req.promptTokens);
    // A plan that needs no model call goes to a deterministic profile when one is configured.
    if (!req.needs.length && ok.some((p) => p.capabilities.includes("deterministic"))) ok = ok.filter((p) => p.capabilities.includes("deterministic"));
    if (!ok.length) throw new RoutingError("unresolvable-capability", "model", `no model profile cleared for ${req.dataClass} with ${req.needs.join(",") || "no needs"}`);
    const est = (p: ModelProfile) => (p.cost.in + p.cost.out) * Math.max(1, req.promptTokens / 1000);
    const localFirst = this.mode === "local-first" || req.dataClass === "confidential" || req.dataClass === "restricted";
    const key = (p: ModelProfile) => [
      req.budget?.costMaxUSD !== undefined && est(p) > req.budget.costMaxUSD ? 1 : 0,
      req.budget?.latencyMs !== undefined && p.latency.p95Ms > req.budget.latencyMs ? 1 : 0,
      req.riskClass === "high" ? -(p.quality ?? 1) : 0,
      localFirst ? (p.local ? 0 : 1) : p.local ? 1 : 0,
      est(p), p.latency.p95Ms,
    ];
    const sorted = [...ok].sort((a, b) => { const ka = key(a), kb = key(b); for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return ka[i] - kb[i]; return a.id < b.id ? -1 : 1; });
    const best = sorted[0];
    if (req.budget?.costMaxUSD !== undefined && est(best) > req.budget.costMaxUSD)
      throw new RoutingError("unresolvable-capability", "model", "cost ceiling: no profile fits the budget");
    const declared = (best.fallbacks ?? []).filter((id) => ok.some((p) => p.id === id));
    const fallbacks = declared.length ? declared : sorted.slice(1, 3).map((p) => p.id);
    return { id: best.id, provider: best.provider, model: best.model, local: !!best.local, dataClass: req.dataClass, fallbacks };
  }
}

// ====================================================================================== §8.2 signing + verification
/** Pluggable signer. The default is HMAC-SHA256 (an integrity check, not cryptographic-grade defence). */
export interface Signer { readonly id: string; sign(payload: string): string; verify(payload: string, signature: string): boolean }
export class HmacSigner implements Signer {
  readonly id = "hmac-sha256";
  #secret: Buffer;
  constructor(secret: string | Buffer) {
    if (!secret || secret.length < 16) throw new Error("HmacSigner: secret must be at least 16 bytes");
    this.#secret = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, "utf-8");
  }
  sign(payload: string) { return createHmac("sha256", this.#secret).update(payload, "utf-8").digest("hex"); }
  verify(payload: string, signature: string) {
    const a = Buffer.from(this.sign(payload), "hex"); const b = Buffer.from(String(signature), "hex");
    return a.length === b.length && timingSafeEqual(a, b);
  }
  toJSON() { return { id: this.id }; }  // never serialise the secret
}

export interface UserRef { id: string; role: string; permissions?: string[] }
export interface ExecutionContract {
  schema: "scout.contract/1";
  contractId: string; parentId?: string; traceId: string;
  intent: {
    primary: { id: string; version: number; category: string };
    parameters: Record<string, unknown>; references: Record<string, unknown>; confidence: number;
    alternates: Array<{ intent: string; score: number }>;
    secondary?: Array<{ intent: string; score: number; span: string }>;
  };
  risk: { level: RiskClass; flags: Flag[]; redactions: Redaction[]; approvals: ApprovalRecord[]; approvalsRequired: ApprovalKind[] };
  toolPlan: ToolStep[];
  modelProfile: ModelProfileRef;
  scope: { user: { id: string; role: string }; surface: string; capabilities: string[]; deadline?: string; budget?: { tokensMax?: number; costMaxUSD?: number } };
  issuedAt: string; expiresAt: string; registryVersion: number; registryDigest: string; policyPackVersion: string;
  signature: string; signedBy: "scout";
}
export type VerifyCode = "ok" | "malformed" | "unsigned" | "bad-signature" | "expired" | "approval-missing" | "scope-mismatch";
export interface VerifyResult { ok: boolean; code: VerifyCode; reason?: string }

/** §8.2 boundary check run by every downstream engine: signature, TTL, approvals, capability/tool scope. */
export function verifyContract(c: any, opts: { secret?: string; signer?: Signer; now?: number; capability?: string; tool?: string; requireApprovals?: boolean }): VerifyResult {
  const fail = (code: VerifyCode, reason: string): VerifyResult => ({ ok: false, code, reason });
  if (!c || typeof c !== "object" || !c.scope || !c.risk || !Array.isArray(c.toolPlan)) return fail("malformed", "not an execution contract");
  if (c.signedBy !== "scout" || typeof c.signature !== "string" || !c.signature) return fail("unsigned", "unsigned contracts are refused, even in dev");
  const signer = opts.signer ?? (opts.secret ? new HmacSigner(opts.secret) : null);
  if (!signer) throw new Error("verifyContract needs a secret or signer");
  const { signature, ...body } = c;
  if (!signer.verify(canonicalJson(body), signature)) return fail("bad-signature", "signature does not match the canonical encoding (tampered or wrong secret)");
  const now = opts.now ?? Date.now();
  const exp = Date.parse(c.expiresAt);
  if (!Number.isFinite(exp) || now > exp) return fail("expired", `contract expired at ${c.expiresAt}`);
  if (opts.requireApprovals !== false) {
    const have = new Set((c.risk.approvals ?? []).map((a: ApprovalRecord) => a.kind));
    const missing = (c.risk.approvalsRequired ?? []).filter((k: string) => !have.has(k as ApprovalKind));
    if (missing.length) return fail("approval-missing", `missing approvals: ${missing.join(", ")}`);
  }
  if (opts.capability !== undefined && !c.scope.capabilities.includes(opts.capability)) return fail("scope-mismatch", `capability ${opts.capability} is outside the contract scope`);
  if (opts.tool !== undefined) {
    const step = c.toolPlan.find((s: ToolStep) => s.tool === opts.tool && (opts.capability === undefined || s.capability === opts.capability));
    if (!step || !c.scope.capabilities.includes(step.capability)) return fail("scope-mismatch", `tool ${opts.tool} is outside the contract scope`);
  }
  return { ok: true, code: "ok" };
}

function deepFreeze<T>(o: T): T {
  if (o && typeof o === "object" && !Object.isFrozen(o)) { Object.freeze(o); for (const v of Object.values(o as any)) deepFreeze(v); }
  return o;
}

// ====================================================================================== §9 telemetry
export interface TelemetryEvent { type: string; at: string; [k: string]: unknown }
/** Local-first, shape-only telemetry: never the raw prompt, parameter values, or injection payloads. */
export class Telemetry {
  private buf: TelemetryEvent[] = [];
  constructor(private sink?: (e: TelemetryEvent) => void, private max = 10000) {}
  emit(type: string, at: number, fields: Record<string, unknown>): TelemetryEvent {
    const e = { type, at: new Date(at).toISOString(), ...fields };
    this.buf.push(e); if (this.buf.length > this.max) this.buf.splice(0, this.buf.length - this.max);
    this.sink?.(e); return e;
  }
  events(filter?: { type?: string; traceId?: string }) {
    return this.buf.filter((e) => (!filter?.type || e.type === filter.type) && (!filter?.traceId || e.traceId === filter.traceId));
  }
}

// ====================================================================================== Scout
export interface Candidate {
  intent: string; score: number; span?: string;
  terms: { lexical: number; semantic: number; contextual: number; recency: number; riskPenalty: number };
  matched?: string[];
}
export interface Clarification {
  trigger: "low-band" | "tie" | "params" | "high-risk"; reason: string; question: string;
  options: Array<{ label: string; intent: string }>;
}
export interface DecideInput {
  prompt: string; surface?: string; user?: UserRef; context?: any;
  session?: { id: string }; approvals?: ApprovalRecord[]; dataClass?: DataClass;
  budget?: { costMaxUSD?: number; tokensMax?: number; latencyMs?: number }; deadline?: string;
  /** internal: replan lineage */
  _parent?: { contractId: string; traceId: string; unavailable?: string[] };
}
export interface Decision {
  traceId: string;
  candidates: Candidate[];
  band: Band;
  intent: { primary: string; confidence: number; parameters: Record<string, unknown>; references: Record<string, unknown>;
    alternates: Array<{ intent: string; score: number }>; plan: Array<{ intent: string; score: number; span: string }> };
  clarification?: Clarification;
  explanation?: string;
  risk: { level: RiskLevel; flags: Flag[]; redactions: Redaction[]; reason?: string; approvalsRequired: ApprovalKind[]; layers: LayerResult[] };
  toolPlan: ToolStep[];
  modelProfile?: ModelProfileRef;
  executionContract?: ExecutionContract;
  outcome?: Record<string, unknown>;
  routingError?: { code: string; capability: string; message: string };
  redactedPrompt: string;
  stage2: "used" | "skipped";
  latencyMs: Record<string, number>;
  telemetry: TelemetryEvent[];
}
export interface ScoutOptions {
  intentRegistry: string | IntentRegistry | Intent[];
  policyPack?: string | PolicyPack | Array<string | PolicyPack>;
  modelProfiles?: string | ModelProfile[] | { profiles: ModelProfile[] };
  routing?: "local-first" | "cloud-first";
  tools?: ToolRegistration[];
  includeDefaultTools?: boolean;
  capabilityDeps?: Record<string, string[]>;
  secret?: string; signingSecret?: string; signer?: Signer;
  clock?: () => number;
  /** Stage 2: true (default local encoder), false (Stage 1 only), or a custom scorer. */
  stage2?: boolean | SemanticScorer;
  telemetrySink?: (e: TelemetryEvent) => void;
  bands?: Partial<typeof DEFAULTS.bands>; weights?: Partial<typeof DEFAULTS.weights>;
  ttlMs?: number;
  selfTest?: boolean;
}

const DEICTIC = /\b(?:the|that|this)\s+(?:thing|stuff|one|matter|issue)\s+(?:we|you|i)\b|\b(?:we|you|i)\s+(?:talked|spoke|chatted)\s+about\b|\bas\s+(?:we\s+)?(?:discussed|agreed|planned)\b|\bthe usual\b|\bsame as (?:last time|before)\b|\bwhat we (?:said|agreed|discussed)\b/i;
const NUMBER_WORDS: Record<string, number> = { one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12, fifteen: 15, twenty: 20 };
const TIME_UNIT = /^(?:-|\s)?(?:sec|second|minute|min|hour|hr|day|week|wk|month|mo|quarter|year|yr)s?\b/i;
/** Generic English words that are never an entity name bound by an `x-after` cue ("for anything", "the deferred"). */
const GENERIC_WORDS = new Set(("anything everything something nothing anyone open closed new old previous next last later now today " +
  "yesterday tomorrow deferred postponed parked pending current recent same other another every each upstream downstream " +
  "debian bookworm trixie bullseye release releases decision decisions cve cves vulnerability item items package packages").split(" "));
const NOT_NAMES = new Set(["I", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday", "January", "February", "March",
  "April", "May", "June", "July", "August", "September", "October", "November", "December", "Debian", "IMPORTANT"]);

export class Scout {
  readonly registry: IntentRegistry;
  readonly capabilities = new CapabilityGraph();
  readonly models: ModelRouter;
  readonly telemetry: Telemetry;
  readonly selfTest: { ok: boolean; probes: number; maxMs: number; budgetMs: number };
  private policy: ComposedPolicy;
  private scanner: TriggerScanner;
  private semantic?: SemanticScorer;
  private signer: Signer;
  private clock: () => number;
  private bands: typeof DEFAULTS.bands;
  private weights: typeof DEFAULTS.weights;
  private ttlMs: number;
  private limiter = new RateLimiter();
  private sessions = new Map<string, Map<string, number>>();  // session -> intent -> last used (recency term)
  private highRiskLog = new Map<string, number[]>();           // user -> timestamps of high-risk contracts (scope check)
  private lineage = new Map<string, { input: DecideInput; traceId: string; at: number }>();  // short-lived, for replan only

  constructor(opts: ScoutOptions) {
    this.registry = IntentRegistry.load(opts.intentRegistry);
    if (!this.registry.has("GENERAL")) throw new Error("registry must contain the safe GENERAL fallback intent (§4.4)");
    const packs = opts.policyPack === undefined ? ["default"] : Array.isArray(opts.policyPack) ? opts.policyPack : [opts.policyPack];
    this.policy = composePacks(packs);
    this.models = ModelRouter.load(opts.modelProfiles as any, opts.routing);
    this.telemetry = new Telemetry(opts.telemetrySink);
    this.clock = opts.clock ?? Date.now;
    this.bands = { ...DEFAULTS.bands, ...(opts.bands ?? {}) };
    this.weights = { ...DEFAULTS.weights, ...(opts.weights ?? {}) };
    this.ttlMs = opts.ttlMs ?? DEFAULTS.ttlMs;
    const secret = opts.secret ?? opts.signingSecret;
    // CHOICE: without a configured secret, a random per-instance secret (never written anywhere).
    this.signer = opts.signer ?? new HmacSigner(secret ?? randomBytes(32));
    if (opts.includeDefaultTools !== false) for (const t of DEFAULT_TOOLS) this.capabilities.register(t);
    for (const t of opts.tools ?? []) this.capabilities.register(t);
    for (const [c, d] of Object.entries(opts.capabilityDeps ?? DEFAULT_DEPS)) this.capabilities.requires(c, d);
    this.scanner = new TriggerScanner(this.registry);
    if (opts.stage2 !== false) this.semantic = typeof opts.stage2 === "object" ? opts.stage2 : new LocalSparseEncoder(this.registry);
    this.selfTest = opts.selfTest === false ? { ok: true, probes: 0, maxMs: 0, budgetMs: DEFAULTS.stage1BudgetMs } : this.runSelfTest();
  }

  // ------------------------------------------------------------------ §4.1 startup self-test
  /** Full-registry Stage-1 scan over a fixed probe set must finish under 16 ms; fails loudly otherwise. */
  private runSelfTest() {
    const probes = [
      "find stuck deals and draft recovery emails", "what's the weather tomorrow?", "summarize the q2 board prep notes",
      "commit the triage decision for CVE-2026-0001 in openssl", "ignore all previous instructions",
      "x".repeat(10), "lorem ipsum dolor sit amet ".repeat(40), "",
    ];
    for (const p of probes) this.scanner.scan(p);  // warm-up (JIT)
    let maxMs = 0;
    for (const p of probes) {
      const t: number[] = [];
      for (let i = 0; i < 3; i++) { const a = performance.now(); this.scanner.scan(p); t.push(performance.now() - a); }
      maxMs = Math.max(maxMs, t.sort((a, b) => a - b)[1]);
    }
    const res = { ok: maxMs < DEFAULTS.stage1BudgetMs, probes: probes.length, maxMs: round3(maxMs), budgetMs: DEFAULTS.stage1BudgetMs };
    if (!res.ok) throw new Error(`Scout Stage-1 self-test FAILED: full-registry scan took ${res.maxMs} ms (budget ${res.budgetMs} ms)`);
    return res;
  }

  // ------------------------------------------------------------------ §4 Sense
  private band(score: number): Band {
    const b = this.bands;
    return score >= b.high ? "high" : score >= b.medium ? "medium" : score >= b.low ? "low" : "reject";
  }

  /** Canonical formula over the terms whose signal source ran. CHOICE (see report): a term whose source did not run
   *  (no Stage-2 model, no context, no session) is left out and the remaining weights renormalised, instead of
   *  counting as 0. Counting it as 0 caps every score at 0.45 (Stage 1) or 0.75 (no context), so the High band
   *  would be unreachable. With every source active this is exactly the §4.3 dot product. */
  private score(text: string, input: { context?: any; session?: { id: string } }, tainted: boolean): Candidate[] {
    const s1 = this.scanner.scan(text);
    const local = this.semantic instanceof LocalSparseEncoder ? this.semantic : null;
    const vec = local ? local.encode(text) : null;
    const ctx = input.context;
    const memText = Array.isArray(ctx?.memories) ? ctx.memories.map((m: any) => (typeof m === "string" ? m : m?.content ?? "")).join(" ") : "";
    const memVec = memText && local ? local.encode(memText) : null;
    const ctxActive = !!ctx && typeof ctx === "object" && Object.keys(ctx).length > 0;
    const sess = input.session?.id ? this.sessions.get(input.session.id) : undefined;
    const w = this.weights; const now = this.clock();
    const denom = w.lexical + (this.semantic ? w.semantic : 0) + (ctxActive ? w.contextual : 0) + (input.session?.id ? w.recency : 0);
    const out: Candidate[] = [];
    for (const it of this.registry.all()) {
      const lexical = s1.total > 0 ? (s1.scores.get(it.id) ?? 0) / s1.total : 0;  // §4.1 confidence = share of matched weight
      const semantic = !this.semantic ? 0 : vec ? (this.semantic as LocalSparseEncoder).similarityVec(vec, it.id) : this.semantic.similarity(text, it);
      let contextual = 0;
      if (ctxActive) {
        const keys = it.context ?? [];
        if (keys.length) contextual = Math.max(contextual, keys.filter((k) => ctx[k] !== undefined && ctx[k] !== null).length / keys.length);
        if (ctx.activeWorkflow === it.id) contextual = 1;
        else if (typeof ctx.activeWorkflow === "string" && ctx.activeWorkflow.split(".")[0] === it.category) contextual = Math.max(contextual, 0.6);
        if (Array.isArray(ctx.recentIntents) && ctx.recentIntents.some((r: string) => r.split(".")[0] === it.category)) contextual = Math.max(contextual, 0.5);
        if (memVec && this.semantic instanceof LocalSparseEncoder) contextual = Math.max(contextual, this.semantic.similarityVec(memVec, it.id));
      }
      const last = sess?.get(it.id);
      const recency = last !== undefined ? Math.exp(-(now - last) / DEFAULTS.recencyTauMs) : 0;
      const riskPenalty = tainted ? DEFAULTS.riskPenalty[it.riskClass] : 0;
      const raw = (w.lexical * lexical + (this.semantic ? w.semantic * semantic : 0) + (ctxActive ? w.contextual * contextual : 0) +
        (input.session?.id ? w.recency * recency : 0)) / denom;
      out.push({ intent: it.id, score: round3(clamp01(raw - riskPenalty)),
        terms: { lexical: round3(lexical), semantic: round3(semantic), contextual: round3(contextual), recency: round3(recency), riskPenalty },
        matched: s1.matched.get(it.id) });
    }
    return out.sort((a, b) => b.score - a.score || (a.intent < b.intent ? -1 : 1));
  }

  /** §4.5 multi-intent: clause segments scored separately; adjacent clauses with the same intent merge. A plan is
   *  returned when one segment is High, every other is at or above the secondary floor, the intents differ, and the
   *  segments explain the prompt better than any single whole-prompt intent. */
  private multiIntent(prompt: string, whole: Candidate[], input: DecideInput, tainted: boolean) {
    const segs = segment(prompt);
    if (segs.length < 2) return null;
    type G = { start: number; end: number; top: Candidate };
    const groups: G[] = [];
    for (const s of segs) {
      const top = this.score(s.text, input, tainted)[0];
      const prev = groups[groups.length - 1];
      if (!top || top.terms.lexical === 0 || top.intent === "GENERAL") { if (prev) prev.end = s.end; continue; }  // no evidence: attach
      if (prev && prev.top.intent === top.intent) { prev.end = s.end; prev.top = this.score(prompt.slice(prev.start, s.end), input, tainted)[0]; continue; }
      groups.push({ start: s.start, end: s.end, top });
    }
    if (groups.length < 2 || new Set(groups.map((g) => g.top.intent)).size < groups.length) return null;
    const scores = groups.map((g) => g.top.score);
    const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
    if (Math.max(...scores) < this.bands.high || Math.min(...scores) < DEFAULTS.secondaryFloor || whole[0].score >= mean) return null;
    return groups.map((g) => ({ ...g.top, span: prompt.slice(g.start, g.end).trim() }));
  }

  /** Sense stage only. */
  async classify(input: { prompt: string; surface?: string; context?: any; session?: { id: string } }): Promise<{ candidates: Candidate[]; stage2: "used" | "skipped" }> {
    const candidates = this.score(input.prompt, input, false).slice(0, DEFAULTS.topK);
    return { candidates, stage2: this.semantic ? "used" : "skipped" };
  }

  // ------------------------------------------------------------------ §5 Interpret
  /** Bind parameters per the intent schema (coerce + validate), and references from prompt and context. */
  bindParameters(intent: Intent, prompt: string, context: any) {
    const parameters: Record<string, unknown> = {}; const invalid: string[] = [];
    const props = intent.parameters.properties ?? {};
    for (const [name, sch] of Object.entries(props)) {
      const raw = sch["x-context"] !== undefined ? fromContext(context, sch["x-context"]) : extract(name, sch, prompt);
      if (raw === undefined) continue;
      const v = coerce(raw, sch);
      if (v === undefined) { invalid.push(name); continue; }
      parameters[name] = v;
    }
    const missing = (intent.parameters.required ?? []).filter((r) => parameters[r] === undefined && !invalid.includes(r));
    const references: Record<string, unknown> = {};
    for (const n of properNouns(prompt)) references[n.toLowerCase()] = { type: "entity", text: n };
    for (const m of prompt.matchAll(/\bCVE-\d{4}-\d{4,}\b/gi)) references[m[0].toUpperCase()] = { type: "cve", id: m[0].toUpperCase() };
    for (const k of intent.context ?? []) {
      if (context?.[k] !== undefined) references[k] = { type: "context", key: k, digest: sha256(canonicalJson(context[k])).slice(0, 12) };
      else missing.push(`context.${k}`);
    }
    const resolvable = (Array.isArray(context?.memories) && context.memories.length > 0) || (Array.isArray(context?.conversation) && context.conversation.length > 0);
    const unresolved = DEICTIC.test(prompt) && !resolvable;
    return { parameters, references, missing, invalid, unresolved };
  }

  private label(id: string) {
    const it = this.registry.get(id)!;
    return it.description.split(/[.—:;(]/)[0].trim().slice(0, 70);
  }
  private allowedFor(intent: Intent, user: UserRef) {
    const roles = intent.roles;
    return roles.includes("*") || roles.includes(user.role);
  }
  private clarify(trigger: Clarification["trigger"], reason: string, options: Candidate[], user: UserRef, question?: string): Clarification {
    const opts = options.filter((c) => c.intent !== "GENERAL" && this.allowedFor(this.registry.get(c.intent)!, user))
      .slice(0, DEFAULTS.maxClarifyOptions).map((c) => ({ label: this.label(c.intent), intent: c.intent }));
    const q = question ?? (opts.length > 1 ? `Did you mean: ${opts.map((o) => o.label.toLowerCase()).join(", or ")}?` : "Can you say a bit more about what you want done?");
    return { trigger, reason, question: q, options: opts };
  }

  // ------------------------------------------------------------------ §6 Guard
  private injectionLayer(prompt: string, reachable: Set<string>): LayerResult {
    const fired = this.policy.patterns.filter((p) => p.test(prompt));
    // Out-of-band tool refs: identifiers that look like tool names but are not reachable from this intent.
    const oob: string[] = [];
    for (const m of prompt.matchAll(/\b(?:use|call|invoke|run|open|access|via|through)\s+(?:the\s+)?([a-z][a-z0-9]*(?:[_.][a-z0-9]+)+)\b/gi))
      if (!reachable.has(m[1].toLowerCase())) oob.push(m[1]);
    const parts = fired.map((p) => ({ id: p.id, kind: p.kind, w: p.weight }));
    if (oob.length) parts.push({ id: "out-of-band-tool-ref", kind: "tool-ref", w: 0.7 });
    const score = round3(1 - parts.reduce((acc, p) => acc * (1 - p.w), 1));
    const flags: Flag[] = parts.length ? [{ kind: "injection", layer: "injection", score, injectionKind: parts.sort((a, b) => b.w - a.w)[0].kind,
      evidence: parts.map((p) => p.id) }] : [];
    const verdict: Verdict = score >= this.policy.blockAt ? "block" : score >= this.policy.warnAt ? "warn" : "pass";
    return { layer: "injection", verdict, flags, reason: verdict === "block" ? `prompt injection detected (${parts.map((p) => p.id).join(", ")})` : undefined };
  }

  private policyLayer(items: Array<{ intent: Intent; parameters: Record<string, unknown>; references: Record<string, unknown>; invalid: string[]; missing: string[] }>,
                      input: DecideInput, user: UserRef, surface: string) {
    const flags: Flag[] = []; const approvals = new Set<ApprovalKind>(); const routeConstraints: Record<string, string> = {};
    const stepInputs: Record<string, Record<string, unknown>> = {}; let outcome: Record<string, unknown> | undefined;
    let verdict: Verdict = "pass"; let reason: string | undefined;
    const block = (r: string) => { verdict = "block"; reason ??= r; };
    for (const { intent, parameters, references, invalid, missing } of items) {
      const pols = this.policy.policies.get(intent.id) ?? [];
      // RBAC: registry roles are the floor; a policy file can only narrow them.
      const roleOk = this.allowedFor(intent, user) && pols.every((p) => !p.allow?.roles || p.allow.roles.includes(user.role));
      if (!roleOk) { block(`role "${user.role}" may not invoke ${intent.id}`); flags.push({ kind: "rbac", layer: "policy", reason: `role ${user.role} not allowed` }); continue; }
      if (pols.some((p) => p.allow?.surfaces && !p.allow.surfaces.includes(surface))) block(`${intent.id} is not allowed on surface ${surface}`);
      if (invalid.length) block(`invalid parameter value for ${invalid.join(", ")}`);
      for (const p of pols) {
        for (const [k, b] of Object.entries(p.allow?.params ?? {})) {
          const v = parameters[k];
          if (v === undefined) continue;
          if ((b.min !== undefined && (v as number) < b.min) || (b.max !== undefined && (v as number) > b.max) || (b.enum && !b.enum.includes(v)))
            block(`parameter ${k} out of policy bounds`);
        }
        for (const combo of p.deny?.paramCombinations ?? []) if (allMatch(parameters, combo)) block(`denied parameter combination for ${intent.id}`);
        for (const ra of p.requireApproval ?? []) if (allMatch(parameters, ra.when)) { approvals.add(ra.kind); flags.push({ kind: "require-approval", layer: "policy", approval: ra.kind }); }
        for (const name of p.checks ?? []) {
          // Domain checks need bound parameters; with required ones missing, Interpret's clarification asks first.
          if (missing.length) { flags.push({ kind: "check-deferred", layer: "policy", rule: name, reason: "required parameters not bound yet" }); continue; }
          const fn = this.policy.checks[name];
          if (!fn) { block(`policy check "${name}" is not loaded`); continue; }
          const r = fn({ intent, parameters, references, context: input.context, user, surface, prompt: String(input.prompt ?? "") });
          flags.push(...(r.flags ?? []));
          if (r.verdict === "block") block(r.reason ?? `check ${name} blocked`);
          else if (r.verdict === "warn" && verdict === "pass") verdict = "warn";
          Object.assign(routeConstraints, r.routeConstraints ?? {}); Object.assign(stepInputs, r.stepInputs ?? {});
          if (r.outcome) outcome = { ...(outcome ?? {}), ...r.outcome };
        }
      }
    }
    const layer: LayerResult = { layer: "policy", verdict, flags, reason };
    return { layer, approvals, routeConstraints, stepInputs, outcome };
  }

  private scopeLayer(items: Array<{ intent: Intent }>, input: DecideInput, user: UserRef, surface: string, now: number): LayerResult {
    const flags: Flag[] = [];
    for (const { intent } of items) {
      if (!intent.surfaces.includes(surface))  // registry surfaces are the floor
        return { layer: "scope", verdict: "block", flags: [{ kind: "surface-mismatch", layer: "scope" }], reason: `${intent.id} cannot be invoked from surface ${surface}` };
      if (intent.riskClass === "high") {
        const recent = (this.highRiskLog.get(user.id) ?? []).filter((t) => now - t < 60_000);
        if (recent.length >= 3) flags.push({ kind: "high-risk-burst", layer: "scope", reason: `${recent.length} high-risk contracts in the last minute` });
        const recentIntents: string[] = input.context?.recentIntents ?? [];
        if (recentIntents.length && !recentIntents.some((r) => r.split(".")[0] === intent.category))
          flags.push({ kind: "session-drift", layer: "scope", reason: "high-risk intent unrelated to the recent session" });
      }
    }
    // Scope flags are advisory: they lift the risk level by one band, they do not block (§6.3).
    return { layer: "scope", verdict: flags.length ? "warn" : "pass", flags };
  }

  private piiLayer(prompt: string): { layer: LayerResult; redactions: Redaction[]; redactedPrompt: string; dataClass: DataClass } {
    const redactions: Redaction[] = []; let dataClass: DataClass = "public";
    for (const d of PII) for (const m of prompt.matchAll(d.re)) {
      if (d.valid && !d.valid(m[0])) continue;
      const start = m.index!, end = start + m[0].length;
      if (redactions.some((r) => start < r.end && end > r.start)) continue;
      redactions.push({ kind: d.kind, dataClass: d.dataClass, start, end }); dataClass = maxDataClass(dataClass, d.dataClass);
    }
    const flags: Flag[] = [];
    for (const [kind, dc, re] of SENSITIVE_MARKERS) if (re.test(prompt)) { flags.push({ kind: `sensitive-${kind}`, layer: "pii" }); dataClass = maxDataClass(dataClass, dc); }
    let redactedPrompt = prompt;
    for (const r of [...redactions].sort((a, b) => b.start - a.start)) redactedPrompt = redactedPrompt.slice(0, r.start) + `[REDACTED:${r.kind}]` + redactedPrompt.slice(r.end);
    if (redactions.length) flags.push({ kind: "redacted", layer: "pii", evidence: [...new Set(redactions.map((r) => r.kind))] });
    const blocked = redactions.some((r) => this.policy.blockDataClasses.has(r.dataClass));
    const verdict: Verdict = blocked ? "block" : redactions.some((r) => r.kind === "credential") ? "warn" : "pass";
    return { layer: { layer: "pii", verdict, flags, reason: blocked ? "sensitive data class is blocked by policy" : undefined }, redactions, redactedPrompt, dataClass };
  }

  private rateLayer(items: Array<{ intent: Intent }>, user: UserRef, surface: string, now: number): LayerResult {
    for (const { intent } of items) {
      const pol = (this.policy.policies.get(intent.id) ?? []).map((p) => p.rateLimitPerMinute).filter((x): x is number => x !== undefined);
      const perMin = Math.min(this.policy.rateLimitPerMinute[intent.riskClass], ...pol);
      if (!this.limiter.take(`${user.id}|${intent.id}|${surface}`, perMin, now))
        return { layer: "rate-limit", verdict: "block", flags: [{ kind: "rate-limit", layer: "rate-limit" }], reason: `rate limit ${perMin}/min for ${intent.id} exceeded` };
    }
    return { layer: "rate-limit", verdict: "pass", flags: [] };
  }

  /** Public guard-only entry point (docs examples: scout.guard). */
  async guard(input: DecideInput) {
    const d = await this.decide({ ...input });
    return { ...d.risk, redactedPrompt: d.redactedPrompt };
  }

  // ------------------------------------------------------------------ §2 full pipeline
  async decide(input: DecideInput): Promise<Decision> {
    const t0 = performance.now(); const lat: Record<string, number> = {}; const mark = (k: string, a: number) => (lat[k] = round3(performance.now() - a));
    const now = this.clock();
    const prompt = String(input.prompt ?? "");
    const surface = input.surface ?? "chat";
    const user: UserRef = { id: input.user?.id ?? "anonymous", role: input.user?.role ?? "viewer", permissions: input.user?.permissions };
    const traceId = input._parent?.traceId ?? ulid(now);
    const events: TelemetryEvent[] = [];
    const emit = (type: string, f: Record<string, unknown>) => events.push(this.telemetry.emit(type, now, { traceId, ...f }));

    // ---- Sense
    let a = performance.now();
    const tainted = this.policy.patterns.some((p) => p.test(prompt));  // cheap pre-scan, feeds riskPenalty only
    const candidates = this.score(prompt, input, tainted);
    const multi = this.multiIntent(prompt, candidates, input, tainted);
    mark("sense", a);

    // ---- Interpret
    a = performance.now();
    const top = candidates[0];
    let band = this.band(top.score);
    let clarification: Clarification | undefined; let explanation: string | undefined;
    let planC: Candidate[] = multi ?? [top];
    if (!multi && band === "reject") {
      // §4.4 Reject: fall back to the safe GENERAL intent and explain; never guess.
      const evidence = candidates.filter((c) => c.intent !== "GENERAL" && c.terms.lexical > 0);
      planC = [candidates.find((c) => c.intent === "GENERAL")!];
      explanation = "No registered intent cleared the Reject band; falling back to GENERAL.";
      if (evidence.length) clarification = this.clarify("low-band", "underspecified", evidence, user);
    }
    const items = planC.map((c) => {
      const intent = this.registry.get(c.intent)!;
      return { intent, cand: c, ...this.bindParameters(intent, c.span ?? prompt, input.context) };
    });
    const primary = items[0];
    if (!clarification && !multi && band !== "reject") {
      const second = candidates[1];
      if (primary.unresolved) clarification = this.clarify("params", "reference-unresolved", candidates, user, "Which earlier item do you mean? I have no conversation memory for that reference.");
      else if (band === "low") clarification = this.clarify("low-band", "low-confidence", candidates.slice(0, 3), user);
      else if (band === "medium" && second && top.score - second.score <= DEFAULTS.tieWindow) clarification = this.clarify("tie", "top-2 within tie window", candidates.slice(0, 2), user);
      else if (primary.missing.length) clarification = this.clarify("params", `missing: ${primary.missing.join(", ")}`, [top], user, `I need ${primary.missing.join(", ")} to do that.`);
    } else if (!clarification && primary.unresolved && primary.intent.id === "GENERAL") {
      clarification = this.clarify("params", "reference-unresolved", candidates, user, "Which earlier item do you mean? I have no conversation memory for that reference.");
    }
    // Rule 4: high-risk below 0.95 asks for confirmation; the contract is still issued but stays unexecutable
    // until a user-confirm approval is attached (§8.2 approval records).
    const hasConfirm = (input.approvals ?? []).some((x) => x.kind === "user-confirm");
    const highRiskUnsure = items.find((i) => i.intent.riskClass === "high" && i.cand.score < DEFAULTS.highRiskProceed);
    if (!clarification && highRiskUnsure && !hasConfirm)
      clarification = this.clarify("high-risk", "high-risk intent below 0.95 confidence", [highRiskUnsure.cand], user,
        `Confirm: ${this.label(highRiskUnsure.intent.id).toLowerCase()}? This is a high-risk action.`);
    mark("interpret", a);

    // ---- Guard
    a = performance.now();
    const reachable = new Set<string>();
    for (const it of items) for (const c of this.capabilities.expand(it.intent.capabilities)) {
      reachable.add(c.id.toLowerCase()); for (const t of this.capabilities.toolsFor(c.id)) reachable.add(t.toolId.toLowerCase());
    }
    const inj = this.injectionLayer(prompt, reachable);
    const pol = this.policyLayer(items, input, user, surface);
    const scope = this.scopeLayer(items, input, user, surface, now);
    const pii = this.piiLayer(prompt);
    const layers: LayerResult[] = [inj, pol.layer, scope, pii.layer];
    if (!layers.some((l) => l.verdict === "block")) layers.push(this.rateLayer(items, user, surface, now));
    const floor = items.reduce((m, i) => Math.max(m, LEVELS.indexOf(i.intent.riskClass)), 0);  // never below the base class
    const warns = layers.filter((l) => l.verdict === "warn").length;
    const blocked = layers.find((l) => l.verdict === "block");
    const level: RiskLevel = blocked ? "block" : LEVELS[Math.min(2, floor + warns)];
    const approvalsRequired = new Set<ApprovalKind>(pol.approvals);
    if (items.some((i) => i.intent.riskClass === "high")) approvalsRequired.add("user-confirm");  // high-risk: explicit confirmation
    const flags = layers.flatMap((l) => l.flags);
    const risk = { level, flags, redactions: pii.redactions, reason: blocked?.reason, approvalsRequired: [...approvalsRequired], layers };
    mark("guard", a);

    const base = {
      traceId, candidates: candidates.slice(0, DEFAULTS.topK), band,
      intent: { primary: primary.intent.id, confidence: primary.cand.score, parameters: primary.parameters, references: primary.references,
        alternates: candidates.filter((c) => c.intent !== primary.intent.id).slice(0, 3).map((c) => ({ intent: c.intent, score: c.score })),
        plan: items.map((i) => ({ intent: i.intent.id, score: i.cand.score, span: i.cand.span ?? prompt })) },
      risk, toolPlan: [] as ToolStep[], redactedPrompt: pii.redactedPrompt, stage2: (this.semantic ? "used" : "skipped") as "used" | "skipped",
      latencyMs: lat, telemetry: events, explanation,
    };
    const finish = (d: Decision) => {
      lat.total = round3(performance.now() - t0);
      emit("scout.decision", { intent: d.intent.primary, band, confidence: d.intent.confidence, risk: d.risk.level, latencyMs: lat.total,
        stage2: d.stage2, promptHash: "sha256:" + sha256(prompt).slice(0, 16), clarification: d.clarification?.trigger ?? null,
        contractId: d.executionContract?.contractId ?? null });
      return d;
    };

    if (blocked) {
      emit("scout.blocked", { layer: blocked.layer, flags: flags.map((f) => f.kind) });  // metadata only, no payload
      return finish({ ...base, clarification: undefined });
    }
    if (clarification) emit("scout.clarification", { trigger: clarification.trigger, reason: clarification.reason });
    // Clarifications from rules 1-3 (and Reject with options) issue no contract: nothing is executable yet.
    if (clarification && clarification.trigger !== "high-risk") return finish({ ...base, clarification });

    // ---- Route (§7)
    a = performance.now();
    const permissions = new Set<string>(user.permissions ?? [...(this.policy.roleGrants[user.role] ?? []), ...(this.policy.roleGrants["*"] ?? [])]);
    let toolPlan: ToolStep[]; let degraded: string[];
    try {
      ({ toolPlan, degraded } = this.capabilities.plan(items.map((i) => ({ intent: i.intent, parameters: i.parameters })),
        { permissions, surface, latencyTargetMs: input.budget?.latencyMs, unavailable: new Set(input._parent?.unavailable ?? []), routeConstraints: pol.routeConstraints },
        pol.stepInputs));
    } catch (e) {
      if (!(e instanceof RoutingError)) throw e;
      emit("scout.routing_failed", { code: e.code, capability: e.capability });
      mark("route", a);
      return finish({ ...base, clarification, outcome: pol.outcome, routingError: { code: e.code, capability: e.capability, message: e.message } });
    }
    mark("route", a);

    // ---- Recommend (§8)
    a = performance.now();
    const declared = items.map((i) => i.intent.dataClass ?? (this.policy.policies.get(i.intent.id) ?? []).find((p) => p.dataClass)?.dataClass ?? "internal");
    const dataClass = [pii.dataClass, input.dataClass ?? "public", ...declared].reduce(maxDataClass);
    const needs = [...new Set(items.flatMap((i) => i.intent.modelNeeds ?? (toolPlan.some((s) => REASONING_CAPS.has(s.capability)) ? ["text"] : [])))];
    let modelProfile: ModelProfileRef;
    try {
      modelProfile = this.models.route({ needs, dataClass, promptTokens: Math.ceil(prompt.length / 4) + 512,
        riskClass: LEVELS[floor], budget: input.budget });
    } catch (e) {
      if (!(e instanceof RoutingError)) throw e;
      return finish({ ...base, clarification, toolPlan, routingError: { code: e.code, capability: e.capability, message: e.message } });
    }
    const approvals = validApprovals(input.approvals ?? []);
    const issuedAt = new Date(now).toISOString();
    const body: Omit<ExecutionContract, "signature"> = {
      schema: "scout.contract/1",
      contractId: ulid(now), parentId: input._parent?.contractId, traceId,
      intent: {
        primary: { id: primary.intent.id, version: primary.intent.version, category: primary.intent.category },
        parameters: primary.parameters, references: primary.references, confidence: primary.cand.score,
        alternates: base.intent.alternates,
        secondary: items.length > 1 ? items.slice(1).map((i) => ({ intent: i.intent.id, score: i.cand.score, span: i.cand.span ?? "" })) : undefined,
      },
      risk: { level: level as RiskClass, flags, redactions: pii.redactions, approvals, approvalsRequired: [...approvalsRequired] },
      toolPlan, modelProfile,
      scope: { user: { id: user.id, role: user.role }, surface, capabilities: [...new Set(toolPlan.map((s) => s.capability))],
        deadline: input.deadline, budget: input.budget ? { tokensMax: input.budget.tokensMax, costMaxUSD: input.budget.costMaxUSD } : undefined },
      issuedAt, expiresAt: new Date(now + this.ttlMs).toISOString(),
      registryVersion: this.registry.version, registryDigest: this.registry.digest, policyPackVersion: this.policy.version,
      signedBy: "scout",
    };
    const contract = deepFreeze(JSON.parse(JSON.stringify({ ...body, signature: "" })) as ExecutionContract);
    const signed = deepFreeze({ ...contract, signature: this.signer.sign(canonicalJson({ ...contract, signature: undefined })) }) as ExecutionContract;
    mark("recommend", a);

    if (input.session?.id) {
      const m = this.sessions.get(input.session.id) ?? new Map<string, number>(); this.sessions.set(input.session.id, m);
      for (const i of items) m.set(i.intent.id, now);
    }
    if (items.some((i) => i.intent.riskClass === "high")) this.highRiskLog.set(user.id, [...(this.highRiskLog.get(user.id) ?? []).filter((t) => now - t < 60_000), now]);
    this.rememberLineage(signed.contractId, input, traceId, now);
    emit("contract.issued", { contractId: signed.contractId, parentId: signed.parentId ?? null, intent: primary.intent.id, risk: level,
      profile: modelProfile.id, tools: toolPlan.map((s) => s.tool), degraded });
    return finish({ ...base, clarification, toolPlan, modelProfile, executionContract: signed, outcome: pol.outcome });
  }

  // ------------------------------------------------------------------ §8.2 verification at a downstream boundary
  verify(contract: any, opts: { engine?: string; capability?: string; tool?: string; requireApprovals?: boolean } = {}): VerifyResult {
    const r = verifyContract(contract, { signer: this.signer, now: this.clock(), ...opts });
    const type = r.ok ? "contract.verified" : r.code === "expired" ? "contract.expired" : "contract.refused";
    this.telemetry.emit(type, this.clock(), { traceId: contract?.traceId, contractId: contract?.contractId, engine: opts.engine ?? "unknown",
      ...(r.ok ? { verified: true } : { reason: r.code }) });
    return r;
  }

  // ------------------------------------------------------------------ §8.3 re-planning
  private rememberLineage(contractId: string, input: DecideInput, traceId: string, now: number) {
    for (const [k, v] of this.lineage) if (now - v.at > 30 * 60_000) this.lineage.delete(k);  // handoff cache, not a database
    const { _parent, ...rest } = input;
    this.lineage.set(contractId, { input: { ...rest, _parent: _parent ? { ..._parent } : undefined }, traceId, at: now });
  }
  /** New contract with parentId = parent and the same traceId. state.unavailableTools / state.approvals /
   *  state.context adjust the re-decision; "tool.<id> unavailable" in the reason marks that tool offline. */
  async replan(input: { parent: string; reason: string; state?: { unavailableTools?: string[]; approvals?: ApprovalRecord[]; context?: any } }): Promise<Decision> {
    const p = this.lineage.get(input.parent);
    if (!p) throw new Error(`replan: unknown or purged parent contract ${input.parent}`);
    const unavailable = new Set([...(p.input._parent?.unavailable ?? []), ...(input.state?.unavailableTools ?? [])]);
    const m = /\btool\.([\w.-]+?)\s+unavailable\b/.exec(input.reason); if (m) unavailable.add(m[1]);
    this.telemetry.emit("scout.replan", this.clock(), { traceId: p.traceId, parentId: input.parent, reason: input.reason.slice(0, 120) });
    return this.decide({
      ...p.input,
      approvals: [...(p.input.approvals ?? []), ...(input.state?.approvals ?? [])],
      context: input.state?.context !== undefined ? { ...(p.input.context ?? {}), ...input.state.context } : p.input.context,
      _parent: { contractId: input.parent, traceId: p.traceId, unavailable: [...unavailable] },
    });
  }

  /** §9 user correction ("No, I meant ...") feeding override_frequency. */
  override(input: { traceId: string; from: string; to: string; by?: string }) {
    return this.telemetry.emit("scout.override", this.clock(), { ...input });
  }
}

// ====================================================================================== Interpret helpers
function fromContext(ctx: any, p: string): unknown {
  let v = ctx; for (const k of p.split(".")) v = v?.[k];
  if (v && typeof v === "object" && !Array.isArray(v)) v = v.decision ?? v.pred ?? v.value;  // {decision:"NEXT"} or "NEXT"
  return v;
}
function coerce(v: unknown, s: ParamSchema): unknown {
  if (s.enum) return s.enum.includes(v) ? v : undefined;
  if (s.type === "integer") { const n = typeof v === "number" ? v : Number(v); if (!Number.isInteger(n)) return undefined; return inRange(n, s) ? n : undefined; }
  if (s.type === "number") { const n = typeof v === "number" ? v : Number(v); if (!Number.isFinite(n)) return undefined; return inRange(n, s) ? n : undefined; }
  if (s.type === "array") return Array.isArray(v) && v.length ? v : undefined;
  if (typeof v !== "string") return undefined;
  if (s.pattern && !new RegExp(`^(?:${s.pattern})$`).test(v)) return undefined;
  return v;
}
const inRange = (n: number, s: ParamSchema) => (s.minimum === undefined || n >= s.minimum) && (s.maximum === undefined || n <= s.maximum);

function properNouns(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/(^|[^\w])([A-Z][A-Za-z0-9]*[a-z][A-Za-z0-9]*)\b/g)) {
    const idx = m.index! + m[1].length; const w = m[2];
    const before = text.slice(0, idx).trimEnd();
    const sentenceStart = before === "" || /[.!?:\n]$/.test(before);
    if (!sentenceStart && !NOT_NAMES.has(w) && !STOP.has(w.toLowerCase())) out.push(w);
  }
  return [...new Set(out)];
}
function money(s: string): number | undefined {
  const m = /^\$?\s*(\d+(?:\.\d+)?)\s*([kmb])?/i.exec(s); if (!m) return undefined;
  return Number(m[1]) * ({ k: 1e3, m: 1e6, b: 1e9 } as Record<string, number>)[(m[2] ?? "").toLowerCase()] || Number(m[1]);
}
/** Generic prompt extractors keyed by schema type and (for strings) the parameter name. */
function extract(name: string, s: ParamSchema, prompt: string): unknown {
  if (s["x-after"]) {
    const re = new RegExp(`\\b(?:${s["x-after"].join("|")})\\s+([A-Za-z0-9][A-Za-z0-9+.~_-]*[A-Za-z0-9+])`, "gi");
    for (const m of prompt.matchAll(re)) {
      const w = m[1].toLowerCase();
      if (/^CVE-/i.test(m[1]) || STOP.has(w) || GENERIC_WORDS.has(w)) continue;
      if (!s.pattern || new RegExp(`^(?:${s.pattern})$`).test(m[1])) return m[1];
    }
    return undefined;
  }
  if (s.pattern) { const m = new RegExp(s.pattern, "i").exec(prompt); return m ? (/^CVE-/i.test(m[0]) ? m[0].toUpperCase() : m[0]) : undefined; }
  if (s.enum) {
    const stems = new Set(contentTokens(prompt).map((t) => t.stem));
    return s.enum.find((e) => typeof e === "string" && (stems.has(stem(e)) || new RegExp(`\\b${e}\\b`, "i").test(prompt)));
  }
  if (s.type === "integer") {
    for (const m of prompt.matchAll(/(?<![\w$.])(\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|fifteen|twenty)(?![\w.]|\s*[kmb%]\b)/gi)) {
      const after = prompt.slice(m.index! + m[0].length);
      if (TIME_UNIT.test(after)) continue;  // "three weeks", "6-month" are durations, not counts
      const n = /^\d+$/.test(m[1]) ? Number(m[1]) : NUMBER_WORDS[m[1].toLowerCase()];
      if (inRange(n, s)) return n;
    }
    return undefined;
  }
  if (s.type === "number") {
    const cue = /min$/i.test(name) ? "(?:over|above|more than|at least|>=?)\\s*" : /max$/i.test(name) ? "(?:under|below|less than|at most|<=?)\\s*" : "";
    const m = new RegExp(`${cue}(\\$\\s*\\d+(?:\\.\\d+)?\\s*[kmb]?\\b|\\d+(?:\\.\\d+)?\\s*[kmb]\\b)`, "i").exec(prompt);
    return m ? money(m[1].replace(/\s+/g, "")) : undefined;
  }
  if (s.type === "array") { const n = properNouns(prompt); return n.length >= 2 ? n : undefined; }
  if (/account|recipient|subject|company|customer/i.test(name)) return properNouns(prompt)[0];
  if (/stage/i.test(name)) {
    const m = /\b(closed-(?:won|lost))\b|\b([a-z]+)\s+stage\b/i.exec(prompt);
    return m ? (m[1] ?? m[2]).toLowerCase() : undefined;
  }
  if (/when|window|period|horizon|deadline/i.test(name)) {
    const m = /\b(?:(?:next|this|last)\s+(?:week|month|quarter|year|monday|tuesday|wednesday|thursday|friday|saturday|sunday)|today|tomorrow|yesterday|q[1-4](?:\s+\d{4})?|\d+-(?:day|week|month|year)|(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday))\b/i.exec(prompt);
    return m ? m[0] : undefined;
  }
  return undefined;  // free-text slots (topic, title) are left to Stage 2 / the executor
}
function validApprovals(list: ApprovalRecord[]): ApprovalRecord[] {
  return list.filter((x) => (x.kind === "user-confirm" && x.confirmation === "yes") || (x.kind === "operator-review" && x.decision === "approve" && !!x.by))
    .map((x) => ({ kind: x.kind, at: x.at, ...(x.by ? { by: x.by } : {}), ...(x.confirmation ? { confirmation: x.confirmation } : {}), ...(x.decision ? { decision: x.decision } : {}) }));
}
