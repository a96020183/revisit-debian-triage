// Revisit H-MEM: our implementation of the Meterless H-MEM spec (engines/hmem/AGENTS.md).
// Written for Revisit during the hackathon. Single file, zero runtime deps, optional JSON persistence.
// Revisit-specific additions are marked "REVISIT:" (domain-filtered query, claimKey divergent-claim
// conflicts, human review queue export). Everything else follows the spec numbers exactly.

import fs from "node:fs";
import path from "node:path";

export type Layer = "short_term" | "working" | "long_term";
export type MemoryType = "personal" | "factual" | "preference" | "general";
export type FeedbackKind = "helpful" | "not_helpful" | "wrong";
export type AuditAction =
  | "create" | "read" | "update" | "delete" | "feedback" | "promote" | "demote" | "merge"
  | "conflict_detected" | "conflict_resolved" | "sleep_consolidate" | "sleep_archive" | "sleep_synthesize"
  | "dream_proposed" | "dream_approved" | "dream_rejected" | "restore";
export type MiningEventType =
  | "chat_message" | "user_correction" | "file_save" | "file_open" | "file_edit" | "model_response" | "plan_completion";

export interface Provenance { origin: string; learnedAt: number; label: string; refs?: string[] }
export interface MemoryRecord {
  id: string; content: string; type: MemoryType; layer: Layer;
  timestamp: number; lastAccessed: number; accessCount: number; tags: string[];
  embedding: number[]; score?: number;
  confidence: number; source: string; provenance: Provenance;
  chatId?: string; missionId?: string; goalRunId?: string;
  domain: string; namespace: string;
  entities: { name: string; type: string }[]; relatedTo: string[];
  supersedes?: string; supersededBy?: string; derivedFrom: string[];
  claimKey?: string; claimValue?: string; // REVISIT: same-entity claims (e.g. "ffmpeg|CVE-2026-1" -> "NEXT")
  meta?: Record<string, unknown>;
}
export interface AddInput {
  content: string; source: string; type?: MemoryType; layer?: Layer; confidence?: number; tags?: string[];
  domain?: string; namespace?: string; entities?: { name: string; type: string }[]; relatedTo?: string[];
  supersedes?: string; derivedFrom?: string[]; chatId?: string; missionId?: string; goalRunId?: string;
  provenance?: Partial<Provenance>; claimKey?: string; claimValue?: string; meta?: Record<string, unknown>;
  timestamp?: number; id?: string;
}
export interface AuditEntry {
  seq: number; memoryId: string; action: AuditAction; actor: string; timestamp: number;
  previousState?: Record<string, unknown>; newState?: Record<string, unknown>; details?: Record<string, unknown>;
}

export const DEFAULTS = {
  topN: 5, threshold: 0.35, consolidateDays: 7, archiveDays: 30, archiveMaxAccess: 2, synthCosine: 0.82,
  dreamMinCluster: 2, dreamRelatedness: 0.35, dreamMaxPerType: 8, conflictGate: 0.70, entityCap: 10, relatedCap: 5,
  recencyTauDays: 14,
};
const DAY = 24 * 60 * 60 * 1000;
const clamp01 = (x: number) => Math.max(0, Math.min(1, x));
const round = (x: number) => Math.round(x * 1e12) / 1e12;

// ------------------------------------------------------------------ text utils
const STOP = new Set("the a an of to in on for and or is are was be with by at as it this that from we our".split(" "));
export function tokenize(s: string): string[] {
  return (s.toLowerCase().match(/[a-z0-9][a-z0-9._+-]*/g) ?? []).filter((t) => t.length > 1 && !STOP.has(t));
}
export function jaccard<T>(a: Set<T>, b: Set<T>): number {
  if (!a.size && !b.size) return 0;
  let i = 0; for (const x of a) if (b.has(x)) i++;
  return i / (a.size + b.size - i);
}
const DIM = 512;
function h32(s: string): number { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
export function embed(text: string): number[] {
  // Lightweight deterministic embedding: hashed unigrams + bigrams, L2-normalised.
  const v = new Array(DIM).fill(0); const t = tokenize(text);
  for (let i = 0; i < t.length; i++) {
    v[h32(t[i]) % DIM] += 1;
    if (i + 1 < t.length) v[h32(t[i] + "_" + t[i + 1]) % DIM] += 0.5;
  }
  const n = Math.sqrt(v.reduce((a, b) => a + b * b, 0)) || 1;
  return v.map((x) => x / n);
}
export function cosine(a: number[], b: number[]): number { let s = 0; for (let i = 0; i < a.length; i++) s += a[i] * b[i]; return s; }
function topKeywords(s: string, k = 8): string[] {
  const c = new Map<string, number>(); for (const t of tokenize(s)) c.set(t, (c.get(t) ?? 0) + 1);
  return [...c.entries()].sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1)).slice(0, k).map((e) => e[0]);
}

// ------------------------------------------------------------------ enrichment (domain / namespace / entities)
const TECH = ["react", "python", "docker", "postgres", "sql", "typescript", "rust", "kubernetes", "api"];
const DOMAIN_KW: Record<string, string[]> = {
  work: ["meeting", "deploy", "roadmap", "release", "office", "deadline", "quarterly"],
  tech: ["code", "bug", "api", "docker", "python", "sql", "server", "telemetry", "cve", "vulnerability", "overflow"],
  personal: ["i", "my", "family", "parking", "birthday"],
};
export function classifyDomain(content: string, tags: string[], type?: MemoryType): string {
  const p = tags.find((t) => t.startsWith("project:")); if (p) return p.slice(8);
  const tt = tags.find((t) => t.startsWith("tech:")); if (tt) return "tech";
  const toks = new Set(tokenize(content));
  for (const t of TECH) if (toks.has(t)) return "tech";
  let best = "general", bs = 0;
  for (const [d, kws] of Object.entries(DOMAIN_KW)) {
    const s = kws.filter((k) => toks.has(k)).length + (type === "personal" && d === "personal" ? 1 : 0);
    if (s > bs) { bs = s; best = d; }
  }
  return best;
}
export function extractEntities(content: string): { name: string; type: string }[] {
  const out: { name: string; type: string }[] = []; const seen = new Set<string>();
  const push = (name: string, type: string) => { const k = type + ":" + name.toLowerCase(); if (!seen.has(k)) { seen.add(k); out.push({ name: name.toLowerCase(), type }); } };
  for (const m of content.match(/CVE-\d{4}-\d+/g) ?? []) push(m, "cve");
  for (const t of tokenize(content)) if (TECH.includes(t)) push(t, "technology");
  for (const m of content.match(/\b[A-Z][a-z]+ [A-Z][a-z]+\b/g) ?? []) push(m, "person");
  return out.slice(0, DEFAULTS.entityCap);
}

// ------------------------------------------------------------------ trust ledger (append-only)
export class TrustLedgerService {
  private entries: AuditEntry[] = []; private seq = 0;
  constructor(private clock: () => number) {}
  log(memoryId: string, action: AuditAction, actor: string, extra: Partial<AuditEntry> = {}): AuditEntry {
    const e: AuditEntry = { seq: ++this.seq, memoryId, action, actor, timestamp: this.clock(), ...extra };
    this.entries.push(e); return e;
  }
  history(memoryId: string): AuditEntry[] { return this.entries.filter((e) => e.memoryId === memoryId); }
  all(): readonly AuditEntry[] { return this.entries; }
  stats(): Record<string, number> { const s: Record<string, number> = {}; for (const e of this.entries) s[e.action] = (s[e.action] ?? 0) + 1; return s; }
  export(): AuditEntry[] { return this.entries.map((e) => ({ ...e })); }
  load(entries: AuditEntry[]) { this.entries = entries; this.seq = entries.length ? entries[entries.length - 1].seq : 0; }
}

// ------------------------------------------------------------------ store
let idCounter = 0;
export class MemoryStoreService {
  private recs = new Map<string, MemoryRecord>();
  readonly byDomain = new Map<string, Set<string>>();   // REVISIT: index for domain-filtered recall
  readonly byClaim = new Map<string, Set<string>>();
  constructor(private clock: () => number, private ledger: TrustLedgerService, private actor: string) {}
  add(input: AddInput): MemoryRecord {
    if (!input || typeof input.source !== "string" || !input.source.trim()) throw new Error("H-MEM: record rejected, source is mandatory");
    if (typeof input.content !== "string" || !input.content.trim()) throw new Error("H-MEM: record rejected, empty content");
    const now = input.timestamp ?? this.clock();
    const tags = [...new Set(input.tags ?? [])];
    const domain = input.domain ?? classifyDomain(input.content, tags, input.type);
    const m: MemoryRecord = {
      id: input.id ?? `mem_${now.toString(36)}_${(++idCounter).toString(36)}`,
      content: input.content, type: input.type ?? "general", layer: input.layer ?? "working",
      timestamp: now, lastAccessed: now, accessCount: 0, tags,
      embedding: embed(input.content), confidence: clamp01(input.confidence ?? 0.7), source: input.source,
      provenance: { origin: input.provenance?.origin ?? input.source, learnedAt: input.provenance?.learnedAt ?? now,
        label: input.provenance?.label ?? `${input.source} @ ${new Date(now).toISOString()}`, refs: input.provenance?.refs },
      chatId: input.chatId, missionId: input.missionId, goalRunId: input.goalRunId,
      domain, namespace: input.namespace ?? `${domain}/${input.type ?? "general"}`,
      entities: (input.entities ?? extractEntities(input.content)).slice(0, DEFAULTS.entityCap),
      relatedTo: (input.relatedTo ?? []).slice(0, DEFAULTS.relatedCap),
      supersedes: input.supersedes, derivedFrom: input.derivedFrom ?? [],
      claimKey: input.claimKey, claimValue: input.claimValue, meta: input.meta,
    };
    this.recs.set(m.id, m); this.index(m);
    this.ledger.log(m.id, "create", this.actor, { newState: { content: m.content, confidence: m.confidence, layer: m.layer, source: m.source } });
    if (m.supersedes) {
      const old = this.recs.get(m.supersedes);
      if (old) { const prev = { supersededBy: old.supersededBy }; old.supersededBy = m.id; this.ledger.log(old.id, "update", this.actor, { previousState: prev, newState: { supersededBy: m.id } }); }
    }
    // relatedTo discovery: shared entities in same domain (bidirectional, capped)
    if (!input.relatedTo && m.entities.length) {
      const ents = new Set(m.entities.map((e) => e.type + ":" + e.name));
      for (const id of this.byDomain.get(domain) ?? []) {
        if (m.relatedTo.length >= DEFAULTS.relatedCap) break;
        const o = this.recs.get(id)!; if (o.id === m.id) continue;
        if (o.entities.some((e) => ents.has(e.type + ":" + e.name)) && o.relatedTo.length < DEFAULTS.relatedCap) { m.relatedTo.push(o.id); o.relatedTo.push(m.id); }
      }
    }
    return m;
  }
  private index(m: MemoryRecord) {
    if (!this.byDomain.has(m.domain)) this.byDomain.set(m.domain, new Set()); this.byDomain.get(m.domain)!.add(m.id);
    if (m.claimKey) { if (!this.byClaim.has(m.claimKey)) this.byClaim.set(m.claimKey, new Set()); this.byClaim.get(m.claimKey)!.add(m.id); }
  }
  private unindex(m: MemoryRecord) { this.byDomain.get(m.domain)?.delete(m.id); if (m.claimKey) this.byClaim.get(m.claimKey)?.delete(m.id); }
  get(id: string): MemoryRecord | undefined { return this.recs.get(id); }
  all(): MemoryRecord[] { return [...this.recs.values()]; }
  update(id: string, patch: Partial<MemoryRecord>, action: AuditAction = "update", details?: Record<string, unknown>): MemoryRecord {
    const m = this.recs.get(id); if (!m) throw new Error(`H-MEM: no memory ${id}`);
    const prev: Record<string, unknown> = {}; for (const k of Object.keys(patch)) prev[k] = (m as any)[k];
    this.unindex(m); Object.assign(m, patch); if (patch.content) m.embedding = embed(m.content); this.index(m);
    this.ledger.log(id, action, this.actor, { previousState: prev, newState: { ...patch, embedding: undefined }, details });
    return m;
  }
  remove(id: string, action: AuditAction = "delete") {
    const m = this.recs.get(id); if (!m) return; this.unindex(m); this.recs.delete(id);
    this.ledger.log(id, action, this.actor, { previousState: { content: m.content } });
  }
  snapshot(): MemoryRecord[] { return JSON.parse(JSON.stringify(this.all())); }
  restoreFrom(recs: MemoryRecord[]) { this.recs.clear(); this.byDomain.clear(); this.byClaim.clear(); for (const r of recs) { this.recs.set(r.id, r); this.index(r); } }
  /** REVISIT: the current (non-superseded) claim for a key, ties broken by later timestamp */
  currentClaim(key: string): MemoryRecord | undefined {
    let best: MemoryRecord | undefined;
    for (const id of this.byClaim.get(key) ?? []) { const m = this.recs.get(id)!; if (m.supersededBy) continue; if (!best || m.timestamp >= best.timestamp) best = m; }
    return best;
  }
}

// ------------------------------------------------------------------ retrieval / reinjection
export interface QueryHit { memory: MemoryRecord; score: number; components: Record<string, number> }
export interface QueryResult { memories: QueryHit[]; context: string; trace: { retrievalReason: string; strategy: string; scores: Record<string, number> } }
const LAYER_W: Record<Layer, number> = { long_term: 1.0, working: 0.8, short_term: 0.6 };
export class MemoryRetrievalService {
  constructor(private store: MemoryStoreService, private ledger: TrustLedgerService, private clock: () => number, private actor: string) {}
  score(m: MemoryRecord, q: { emb: number[]; kw: Set<string>; dom: string; ents: Set<string> }): { score: number; c: Record<string, number> } {
    const mt = new Set(tokenize(m.content));
    const semantic = clamp01(cosine(q.emb, m.embedding));
    const keyword = jaccard(q.kw, mt);
    const tagToks = new Set(m.tags.flatMap((t) => tokenize(t.replace(/[:/]/g, " "))));
    const tag = tagToks.size ? [...tagToks].filter((t) => q.kw.has(t)).length / tagToks.size : 0;
    const domain = m.domain === q.dom ? 1 : 0;
    const me = new Set(m.entities.map((e) => e.name));
    const entity = q.ents.size ? [...q.ents].filter((e) => me.has(e)).length / q.ents.size : 0;
    const layer = LAYER_W[m.layer];
    const recency = Math.exp(-(this.clock() - m.lastAccessed) / (DEFAULTS.recencyTauDays * DAY));
    const superseded = m.supersededBy ? 1 : 0;
    const raw = 0.35 * semantic + 0.20 * keyword + 0.10 * tag + 0.10 * domain + 0.15 * entity + 0.05 * layer + 0.05 * recency - 0.20 * superseded;
    return { score: clamp01(raw) * m.confidence, c: { semantic, keyword, tag, domain, entity, layer, recency, superseded } };
  }
  query(query: string, opts: { topN?: number; threshold?: number; chatId?: string; domain?: string; filter?: (m: MemoryRecord) => boolean; touch?: boolean; entities?: string[] } = {}): QueryResult {
    const topN = opts.topN ?? DEFAULTS.topN, threshold = opts.threshold ?? DEFAULTS.threshold;
    const dom = opts.domain ?? classifyDomain(query, []);
    const q = { emb: embed(query), kw: new Set(topKeywords(query)), dom, ents: new Set([...extractEntities(query).map((e) => e.name), ...(opts.entities ?? []).map((e) => e.toLowerCase())]) }; // REVISIT: caller may name query entities
    // REVISIT: when a domain is given, candidates are that domain's records (index lookup); scoring is unchanged
    const pool = opts.domain ? [...(this.store.byDomain.get(opts.domain) ?? [])].map((id) => this.store.get(id)!) : this.store.all();
    const hits: QueryHit[] = [];
    for (const m of pool) {
      if (opts.chatId && m.chatId && m.chatId !== opts.chatId) continue;
      if (opts.filter && !opts.filter(m)) continue;
      const { score, c } = this.score(m, q);
      if (score >= threshold) hits.push({ memory: m, score, components: c });
    }
    hits.sort((a, b) => b.score - a.score || b.memory.timestamp - a.memory.timestamp);
    const sel = hits.slice(0, topN);
    if (opts.touch !== false) for (const h of sel) { h.memory.accessCount += 1; h.memory.lastAccessed = this.clock(); this.ledger.log(h.memory.id, "read", this.actor, { details: { query, score: h.score } }); }
    for (const h of sel) h.memory.score = h.score;
    const groups = new Map<string, QueryHit[]>(); for (const h of sel) { if (!groups.has(h.memory.domain)) groups.set(h.memory.domain, []); groups.get(h.memory.domain)!.push(h); }
    const context = [...groups.entries()].map(([d, hs]) => `## ${d}\n` + hs.map((h) =>
      `- [${h.memory.layer}${h.memory.supersededBy ? ", superseded" : ""}] ${h.memory.content}${h.memory.entities.length ? ` {${h.memory.entities.map((e) => e.name).join(", ")}}` : ""}`).join("\n")).join("\n");
    const strategy = sel.length === 0 ? "none" : sel.length <= 2 ? "minimal" : sel.some((h) => h.memory.type === "personal") ? "personal" : "comprehensive";
    return { memories: sel, context, trace: { retrievalReason: `${sel.length}/${hits.length} above ${threshold} (domain ${dom})`, strategy, scores: Object.fromEntries(sel.map((h) => [h.memory.id, round(h.score)])) } };
  }
  feedback(memoryId: string, kind: FeedbackKind) {
    const m = this.store.get(memoryId); if (!m) throw new Error(`H-MEM: no memory ${memoryId}`);
    const prev = { confidence: m.confidence, accessCount: m.accessCount, tags: [...m.tags] };
    if (kind === "helpful") { m.accessCount += 1; m.confidence = round(clamp01(m.confidence + 0.05)); }
    else if (kind === "not_helpful") m.confidence = round(clamp01(m.confidence - 0.03));
    else { m.confidence = round(clamp01(m.confidence - 0.20)); if (!m.tags.includes("review")) m.tags.push("review"); }
    this.ledger.log(m.id, "feedback", this.actor, { previousState: prev, newState: { confidence: m.confidence, accessCount: m.accessCount, tags: [...m.tags] }, details: { kind } });
  }
}

// ------------------------------------------------------------------ conflicts
export interface Conflict { id: string; a: string; b: string; kind: "opposing" | "numeric" | "divergent_claim"; reason: string; confidence: number }
const OPP: [string, string][] = [["always", "never"], ["enable", "disable"], ["enabled", "disabled"], ["allow", "deny"], ["true", "false"], ["yes", "no"], ["include", "exclude"], ["affected", "not-affected"]];
const RELIABILITY: Record<string, number> = { user_correction: 1.0, human_ruling: 1.0, lts_tracker: 0.9, debian_tracker: 0.9, agent_proposal: 0.4, dreaming: 0.5 };
export class ConflictDetectionService {
  private reviewQueue: Conflict[] = []; private n = 0;
  constructor(private store: MemoryStoreService, private ledger: TrustLedgerService, private clock: () => number, private actor: string) {}
  private linked(a: MemoryRecord, b: MemoryRecord) { return a.supersedes === b.id || b.supersedes === a.id || a.supersededBy === b.id || b.supersededBy === a.id; }
  detect(a: MemoryRecord, b: MemoryRecord): Conflict | null {
    if (this.linked(a, b) || a.supersededBy || b.supersededBy) return null;
    let kind: Conflict["kind"] | null = null, reason = "";
    if (a.claimKey && a.claimKey === b.claimKey && a.claimValue !== b.claimValue) { kind = "divergent_claim"; reason = `${a.claimKey}: ${a.claimValue} vs ${b.claimValue}`; }
    const ta = tokenize(a.content), tb = tokenize(b.content);
    if (!kind) for (const [x, y] of OPP) {
      if ((ta.includes(x) && tb.includes(y) && !ta.includes(y)) || (ta.includes(y) && tb.includes(x) && !ta.includes(x))) {
        const rest = (t: string[]) => new Set(t.filter((w) => w !== x && w !== y));
        if (jaccard(rest(ta), rest(tb)) >= 0.5) { kind = "opposing"; reason = `${x}/${y}`; break; }
      }
    }
    if (!kind) {
      const na = a.content.match(/\d+(\.\d+)?/g), nb = b.content.match(/\d+(\.\d+)?/g);
      if (na && nb && cosine(a.embedding, b.embedding) >= 0.8 && na.join() !== nb.join()) { kind = "numeric"; reason = `${na} vs ${nb}`; }
    }
    if (!kind) return null;
    const ea = new Set(a.entities.map((e) => e.name)); const shared = b.entities.some((e) => ea.has(e.name));
    let conf = 0.55 + (shared ? 0.15 : 0) + (a.domain === b.domain ? 0.1 : 0) - (a.relatedTo.includes(b.id) ? 0.1 : 0);
    return { id: `cf_${++this.n}`, a: a.id, b: b.id, kind, reason, confidence: clamp01(conf) };
  }
  scan(ids?: string[]): Conflict[] {
    const recs = (ids ? ids.map((i) => this.store.get(i)!).filter(Boolean) : this.store.all()).filter((m) => !m.supersededBy);
    const out: Conflict[] = [];
    // REVISIT: compare within domain only (pairs across packages are never the same claim)
    const byDom = new Map<string, MemoryRecord[]>(); for (const m of recs) { if (!byDom.has(m.domain)) byDom.set(m.domain, []); byDom.get(m.domain)!.push(m); }
    for (const g of byDom.values()) for (let i = 0; i < g.length; i++) for (let j = i + 1; j < g.length; j++) {
      const c = this.detect(g[i], g[j]);
      if (c) { out.push(c); this.ledger.log(c.a, "conflict_detected", this.actor, { details: { ...c } }); this.ledger.log(c.b, "conflict_detected", this.actor, { details: { ...c } }); }
    }
    return out;
  }
  private merit(m: MemoryRecord): number {
    const age = (this.clock() - m.timestamp) / DAY;
    return 0.25 * Math.exp(-age / 30) + 0.15 * Math.min(1, m.accessCount / 10) + 0.30 * m.confidence + 0.10 * Math.min(1, m.content.length / 200)
      + 0.20 * (RELIABILITY[m.source] ?? 0.6);
  }
  /** decision confidence = 0.5 + merit gap; ≥ 0.70 auto-resolves (loser supersededBy winner), else queued for a human */
  autoResolve(c: Conflict): "resolved" | "queued" {
    const a = this.store.get(c.a)!, b = this.store.get(c.b)!;
    let ma = this.merit(a), mb = this.merit(b);
    if (c.kind === "divergent_claim" && a.timestamp !== b.timestamp && (RELIABILITY[a.source] ?? 0.6) === (RELIABILITY[b.source] ?? 0.6)) {
      // same reliability, explicit later decision on the same claim: recency is decisive
      if (a.timestamp > b.timestamp) ma += 0.3; else mb += 0.3;
    }
    const decision = clamp01(0.5 + Math.abs(ma - mb));
    if (decision < DEFAULTS.conflictGate) { this.reviewQueue.push(c); return "queued"; }
    const [win, lose] = ma >= mb ? [a, b] : [b, a];
    this.resolve(c, win.id === a.id ? "keep_a" : "keep_b", { decision });
    return "resolved";
  }
  resolve(c: Conflict, strategy: "keep_a" | "keep_b" | "keep_both" | "merge" | "delete_both", details: Record<string, unknown> = {}) {
    const a = this.store.get(c.a)!, b = this.store.get(c.b)!;
    if (strategy === "keep_a" || strategy === "keep_b") {
      const [win, lose] = strategy === "keep_a" ? [a, b] : [b, a];
      const prev = { supersededBy: lose.supersededBy }; lose.supersededBy = win.id;
      this.ledger.log(lose.id, "conflict_resolved", this.actor, { previousState: prev, newState: { supersededBy: win.id }, details: { ...details, conflict: c.id, strategy } });
    } else if (strategy === "merge") {
      const m = this.store.add({ content: `${a.content}; ${b.content}`, source: "merge", derivedFrom: [a.id, b.id], layer: "long_term", domain: a.domain });
      for (const x of [a, b]) { x.supersededBy = m.id; this.ledger.log(x.id, "conflict_resolved", this.actor, { newState: { supersededBy: m.id }, details: { conflict: c.id, strategy } }); }
    } else if (strategy === "delete_both") { this.store.remove(a.id); this.store.remove(b.id); }
    else this.ledger.log(a.id, "conflict_resolved", this.actor, { details: { conflict: c.id, strategy } });
    this.reviewQueue = this.reviewQueue.filter((q) => q.id !== c.id);
  }
  queue(): readonly Conflict[] { return this.reviewQueue; }
}

// ------------------------------------------------------------------ sleep
export interface SleepPreview { toConsolidate: string[]; toArchive: string[]; toSynthesize: string[][] }
export class SleepCycleService {
  private backups = new Map<string, MemoryRecord[]>(); private n = 0;
  constructor(private store: MemoryStoreService, private ledger: TrustLedgerService, private clock: () => number, private actor: string) {}
  private protectedIds(): Set<string> {
    const all = this.store.all(); const refs = new Map<string, number>();
    const bump = (id?: string) => { if (id) refs.set(id, (refs.get(id) ?? 0) + 1); };
    for (const m of all) { m.relatedTo.forEach(bump); m.derivedFrom.forEach(bump); bump(m.supersedes); bump(m.supersededBy); }
    const p = new Set<string>();
    for (const m of all) {
      if (m.supersedes || m.derivedFrom.length || m.source === "dreaming" || m.tags.includes("pinned") || (refs.get(m.id) ?? 0) >= 3 || m.relatedTo.length >= 3) p.add(m.id);
    }
    return Object.assign(p, { refs });
  }
  preview(): SleepPreview {
    const now = this.clock(); const prot = this.protectedIds() as Set<string> & { refs: Map<string, number> };
    const all = this.store.all();
    const toConsolidate = all.filter((m) => m.layer === "short_term" && now - m.lastAccessed >= DEFAULTS.consolidateDays * DAY).map((m) => m.id);
    const toArchive = all.filter((m) => !prot.has(m.id) && m.layer !== "long_term" && now - m.timestamp >= DEFAULTS.archiveDays * DAY
      && m.accessCount <= DEFAULTS.archiveMaxAccess && !(prot.refs.get(m.id))).map((m) => m.id);
    const arch = new Set(toArchive); const used = new Set<string>(); const toSynthesize: string[][] = [];
    const cand = all.filter((m) => !prot.has(m.id) && !arch.has(m.id) && !m.supersededBy);
    for (let i = 0; i < cand.length; i++) {
      if (used.has(cand[i].id)) continue; const g = [cand[i].id];
      for (let j = i + 1; j < cand.length; j++) if (!used.has(cand[j].id) && cand[i].domain === cand[j].domain && cosine(cand[i].embedding, cand[j].embedding) >= DEFAULTS.synthCosine) g.push(cand[j].id);
      if (g.length > 1) { g.forEach((x) => used.add(x)); toSynthesize.push(g); }
    }
    return { toConsolidate, toArchive, toSynthesize };
  }
  execute(p: SleepPreview) {
    const backupId = `bk_${this.clock().toString(36)}_${++this.n}`; this.backups.set(backupId, this.store.snapshot());
    const prot = this.protectedIds(); const log: string[] = [];
    for (const id of p.toConsolidate) if (this.store.get(id)) { this.store.update(id, { layer: "long_term" }, "sleep_consolidate"); log.push(`consolidate ${id}`); }
    for (const id of p.toArchive) if (this.store.get(id) && !prot.has(id)) { this.store.remove(id, "sleep_archive"); log.push(`archive ${id}`); }
    for (const g of p.toSynthesize) {
      const ms = g.map((id) => this.store.get(id)).filter((m): m is MemoryRecord => !!m && !prot.has(m.id)); if (ms.length < 2) continue;
      const s = this.store.add({ content: ms.map((m) => m.content).join(" | "), source: "sleep_synthesis", layer: "long_term", domain: ms[0].domain,
        tags: [...new Set(ms.flatMap((m) => m.tags))], entities: ms.flatMap((m) => m.entities).slice(0, DEFAULTS.entityCap), derivedFrom: ms.map((m) => m.id) });
      for (const m of ms) this.store.remove(m.id, "sleep_synthesize"); log.push(`synthesize ${s.id}`);
    }
    return { backupId, actions: log, counts: { consolidated: p.toConsolidate.length, archived: p.toArchive.length, synthesized: p.toSynthesize.length } };
  }
  restore(backupId: string) { const b = this.backups.get(backupId); if (!b) throw new Error("no backup"); this.store.restoreFrom(JSON.parse(JSON.stringify(b))); this.ledger.log(backupId, "restore", this.actor); }
}

// ------------------------------------------------------------------ dreaming (human approval boundary)
export interface DreamProposal { id: string; kind: "insight" | "domain" | "invariant"; content: string; sources: string[]; domain?: string; status: "proposed" | "approved" | "rejected" }
export class DreamingService {
  private proposals = new Map<string, DreamProposal>(); private n = 0;
  constructor(private store: MemoryStoreService, private ledger: TrustLedgerService, private clock: () => number, private actor: string) {}
  relatedness(a: MemoryRecord, b: MemoryRecord): number {
    const ta = new Set(a.tags), tb = new Set(b.tags); const ea = new Set(a.entities.map((e) => e.name)), eb = new Set(b.entities.map((e) => e.name));
    return 0.4 * clamp01(cosine(a.embedding, b.embedding)) + 0.2 * jaccard(ta, tb) + 0.2 * (a.domain === b.domain ? 1 : 0) + 0.1 * (a.type === b.type ? 1 : 0) + 0.1 * jaccard(ea, eb);
  }
  dream(): DreamProposal[] {
    const recs = this.store.all().filter((m) => !m.supersededBy); const used = new Set<string>(); const clusters: MemoryRecord[][] = [];
    for (const m of recs) {
      if (used.has(m.id)) continue; const c = [m];
      for (const o of recs) if (o.id !== m.id && !used.has(o.id) && this.relatedness(m, o) >= DEFAULTS.dreamRelatedness) c.push(o);
      if (c.length >= DEFAULTS.dreamMinCluster) { c.forEach((x) => used.add(x.id)); clusters.push(c); }
    }
    const out: DreamProposal[] = []; const mk = (kind: DreamProposal["kind"], content: string, sources: string[], domain?: string) => {
      if (out.filter((p) => p.kind === kind).length >= DEFAULTS.dreamMaxPerType) return;
      const p: DreamProposal = { id: `dr_${++this.n}`, kind, content, sources, domain, status: "proposed" }; this.proposals.set(p.id, p); out.push(p);
      this.ledger.log(p.id, "dream_proposed", this.actor, { details: { kind, sources } });
    };
    for (const c of clusters) mk("insight", `Across ${c.length} related memories: ${c.slice(0, 4).map((m) => m.content).join("; ")}`, c.map((m) => m.id), c[0].domain);
    // phase 5: invariants come from preference / personal / correction signals (not from clusters)
    const prefs = recs.filter((m) => m.type === "preference" || m.type === "personal" || m.tags.includes("correction"));
    const byDom = new Map<string, MemoryRecord[]>(); for (const m of prefs) { if (!byDom.has(m.domain)) byDom.set(m.domain, []); byDom.get(m.domain)!.push(m); }
    const groups = [...byDom.values()].filter((g) => g.length >= DEFAULTS.dreamMinCluster);
    if (!groups.length && prefs.length >= DEFAULTS.dreamMinCluster) groups.push(prefs);
    for (const g of groups) mk("invariant", `Stable pattern: ${g.map((m) => m.content).join("; ")}`, g.map((m) => m.id), g[0].domain);
    const general = recs.filter((m) => m.domain === "general");
    for (const m of general) { const d = classifyDomain(m.content, m.tags.concat(["x"]), m.type); if (d !== "general") mk("domain", d, [m.id], d); }
    return out;
  }
  approve(id: string): MemoryRecord | null {
    const p = this.proposals.get(id); if (!p || p.status !== "proposed") return null; p.status = "approved";
    this.ledger.log(id, "dream_approved", this.actor, { details: { kind: p.kind } });
    if (p.kind === "domain") { for (const s of p.sources) if (this.store.get(s)) this.store.update(s, { domain: p.domain! }); return null; }
    return this.store.add({ content: p.content, source: "dreaming", layer: "long_term", type: p.kind === "invariant" ? "preference" : "factual", derivedFrom: p.sources, domain: p.domain });
  }
  reject(id: string) { const p = this.proposals.get(id); if (!p) return; p.status = "rejected"; this.ledger.log(id, "dream_rejected", this.actor); }
  list(): DreamProposal[] { return [...this.proposals.values()]; }
}

// ------------------------------------------------------------------ mining
export function parseStrictJsonArray(text: string): string[] {
  const t = text.replace(/```(?:json)?/g, "").trim(); const s = t.indexOf("["), e = t.lastIndexOf("]");
  if (s < 0 || e < s) return [];
  try { const a = JSON.parse(t.slice(s, e + 1)); return Array.isArray(a) ? a.filter((x) => typeof x === "string" && x.trim().length >= 8) : []; } catch { return []; }
}
export class MemoryMiningService {
  constructor(private store: MemoryStoreService, private minerFn?: (prompt: string) => Promise<string>) {}
  async mineInteraction(event: MiningEventType, text: string, opts: { chatId?: string; domain?: string } = {}): Promise<MemoryRecord[]> {
    const type: MemoryType = event === "user_correction" ? "preference" : event.startsWith("file") ? "factual" : "general";
    if (!this.minerFn) return [this.store.add({ content: text.slice(0, 280), source: event, layer: "short_term", type, tags: [`event:${event}`], chatId: opts.chatId, domain: opts.domain })];
    const raw = await this.minerFn(`Extract durable, reusable facts or decisions from this ${event}. Return a strict JSON array of strings.\n\n${text.slice(0, 6000)}`);
    const items = parseStrictJsonArray(raw);
    if (!items.length) return [this.store.add({ content: text.slice(0, 280), source: event, layer: "short_term", type, tags: [`event:${event}`], chatId: opts.chatId, domain: opts.domain })];
    return items.map((c) => this.store.add({ content: c, source: event, layer: "working", type, tags: [`event:${event}`], chatId: opts.chatId, domain: opts.domain }));
  }
}

// ------------------------------------------------------------------ facade
export class HMEM {
  readonly clock: () => number; readonly ledger: TrustLedgerService; readonly store: MemoryStoreService;
  readonly retrieval: MemoryRetrievalService; readonly conflicts: ConflictDetectionService; readonly sleep: SleepCycleService;
  readonly dreaming: DreamingService; readonly mining: MemoryMiningService;
  constructor(opts: { clock?: () => number; actor?: string; minerFn?: (p: string) => Promise<string> } = {}) {
    this.clock = opts.clock ?? Date.now; const actor = opts.actor ?? "system";
    this.ledger = new TrustLedgerService(this.clock); this.store = new MemoryStoreService(this.clock, this.ledger, actor);
    this.retrieval = new MemoryRetrievalService(this.store, this.ledger, this.clock, actor);
    this.conflicts = new ConflictDetectionService(this.store, this.ledger, this.clock, actor);
    this.sleep = new SleepCycleService(this.store, this.ledger, this.clock, actor);
    this.dreaming = new DreamingService(this.store, this.ledger, this.clock, actor);
    this.mining = new MemoryMiningService(this.store, opts.minerFn);
  }
  add(input: AddInput): MemoryRecord { return this.store.add(input); }
  query(q: string, opts?: Parameters<MemoryRetrievalService["query"]>[1]): QueryResult { return this.retrieval.query(q, opts); }
  feedback(id: string, kind: FeedbackKind) { this.retrieval.feedback(id, kind); }
  mine(event: MiningEventType, text: string, opts?: { chatId?: string; domain?: string }) { return this.mining.mineInteraction(event, text, opts); }
  save(file: string) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify({ v: 1, records: this.store.all().map((m) => ({ ...m, embedding: undefined })), ledger: this.ledger.export() }));
  }
  load(file: string) {
    if (!fs.existsSync(file)) return; const d = JSON.parse(fs.readFileSync(file, "utf-8"));
    this.store.restoreFrom(d.records.filter((r: MemoryRecord) => r.layer !== "short_term").map((r: MemoryRecord) => ({ ...r, embedding: embed(r.content) })));
    this.ledger.load(d.ledger);
  }
}
