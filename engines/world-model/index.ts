// Revisit World Model: our implementation of the Meterless World Model spec (engines/world-model/AGENTS.md).
// Event-sourced, append-only log; every read view is a projection of the log. Single-writer FIFO queue.
// Revisit uses it only for waits (deferrals) and condition events; see revisit/agent code.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface Provenance { kind: string; at: string; by?: string; runId?: string; ref?: string }
export interface Entity { id: string; type: string; name?: string; attrs: Record<string, unknown>; state: "emerging" | "active" | "archived"; firstSeenAt: string; lastSeenAt: string; source: Provenance; aliases: string[] }
export interface Relationship { id: string; from: string; type: string; to: string; context?: string; attrs?: Record<string, unknown>; validFrom: string; validTo?: string; source: Provenance }
export interface Fact { id: string; about: string; predicate: string; value: unknown; confidence: number; context?: string; source: Provenance; supersededBy?: string }
export interface WorldEvent { seq: number; id: string; kind: string; at: string; payload: any }
export interface AuditEntry { seq: number; action: string; actor: string; summary: string; eventId?: string; at: string }
export interface MergeProposal { id: string; a: string; b: string; similarity: number; status: "pending" | "approved" | "rejected" }
export interface IngestObservation { externalId: string; title?: string; at: string; source: Provenance; entities?: { type: string; name: string }[]; attrs?: Record<string, unknown>; type?: string }

// ------------------------------------------------------------------ stable ids
export function normalizeName(name: string): string {
  return name.toLowerCase().normalize("NFKD").replace(/[̀-ͯ]/g, "").replace(/[\s ]+/g, " ").trim();
}
export function sha256Hex(s: string): string { return crypto.createHash("sha256").update(s).digest("hex"); }
export function entityIdFromName(type: string, name: string): string { return `ent_${sha256Hex(`${type}:${normalizeName(name)}`).slice(0, 16)}`; }
export function externalId(type: string, system: string, id: string): string { return `${type}:${system}:${id}`; }
export function canonicalJson(v: unknown): string {
  if (v === undefined) return "null";
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(",")}}`;
}
export function relationshipId(from: string, type: string, to: string, context?: string, validFrom?: string): string {
  return `rel_${sha256Hex(canonicalJson({ from, type, to, context, validFrom })).slice(0, 16)}`;
}

// ------------------------------------------------------------------ resolution bands
export function levenshtein(a: string, b: string): number {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}
export function nameSimilarity(a: string, b: string): number {
  const x = normalizeName(a), y = normalizeName(b); const m = Math.max(x.length, y.length); return m ? 1 - levenshtein(x, y) / m : 1;
}
/** ≥ 0.85 auto-merge; [0.82, 0.85) operator review; below: new entity. Compared on a 1e-9 grid so 0.85 / 0.82 land inclusive. */
export function decide(similarity: number): "auto-merge" | "review" | "new" {
  const s = Math.round(similarity * 1e9) / 1e9;
  if (s >= 0.85) return "auto-merge"; if (s >= 0.82) return "review"; return "new";
}
export function jaccard<T>(a: Set<T>, b: Set<T>): number { if (!a.size && !b.size) return 0; let i = 0; for (const x of a) if (b.has(x)) i++; return i / (a.size + b.size - i); }

// ------------------------------------------------------------------ world
export class WorldModel {
  private log: WorldEvent[] = []; private auditLog: AuditEntry[] = []; private seq = 0; private aseq = 0;
  private entities = new Map<string, Entity>(); private rels = new Map<string, Relationship>(); private facts = new Map<string, Fact>();
  private aliases = new Map<string, string>(); private proposals = new Map<string, MergeProposal>(); private obsHash = new Map<string, string>();
  private lock: Promise<unknown> = Promise.resolve(); private subs = new Set<(e: WorldEvent) => void>();
  private clock: () => Date; readonly namespace: string; private file?: string;
  constructor(opts: { namespace: string; storage?: "memory" | "file"; directory?: string; clock?: () => Date }) {
    if (!opts?.namespace) throw new Error("WorldModel: namespace is required");
    this.namespace = opts.namespace; this.clock = opts.clock ?? (() => new Date());
    if (opts.storage === "file") { this.file = path.join(opts.directory ?? ".", `${opts.namespace}.events.jsonl`); this.replayFile(); }
  }
  private enqueue<T>(fn: () => T): Promise<T> { const p = this.lock.then(fn); this.lock = p.catch(() => undefined); return p; }
  private prov(s: Provenance | undefined): Provenance {
    if (!s || typeof s !== "object" || !s.kind || !s.at) throw new Error("WorldModel: write rejected, provenance {kind, at} is required");
    return { ...s };
  }
  private append(kind: string, payload: any, at: string, actor = "system", summary = kind): WorldEvent {
    const e: WorldEvent = { seq: ++this.seq, id: `evt_${sha256Hex(canonicalJson({ kind, payload })).slice(0, 16)}_${this.seq}`, kind, at, payload };
    this.log.push(e); this.project(e);
    this.auditLog.push({ seq: ++this.aseq, action: kind, actor, summary, eventId: e.id, at });
    if (this.file) fs.appendFileSync(this.file, JSON.stringify(e) + "\n");
    for (const f of this.subs) f(e);
    return e;
  }
  private replayFile() { if (!this.file || !fs.existsSync(this.file)) return; for (const ln of fs.readFileSync(this.file, "utf-8").split("\n")) if (ln.trim()) { const e = JSON.parse(ln); this.log.push(e); this.seq = e.seq; this.project(e); } }
  /** projection: the only place state changes; views are rebuilt from the log */
  private project(e: WorldEvent) {
    const p = e.payload;
    if (e.kind === "entity.upserted") {
      const old = this.entities.get(p.id);
      this.entities.set(p.id, { ...p, firstSeenAt: old?.firstSeenAt ?? p.firstSeenAt, aliases: old?.aliases ?? [] });
    } else if (e.kind === "relationship.opened") {
      for (const r of this.rels.values()) if (!p.multi && r.from === p.rel.from && r.type === p.rel.type && r.to !== p.rel.to && !r.validTo && r.validFrom <= p.rel.validFrom) r.validTo = p.rel.validFrom;
      this.rels.set(p.rel.id, { ...p.rel });
    } else if (e.kind === "relationship.closed") { const r = this.rels.get(p.id); if (r) r.validTo = p.validTo; }
    else if (e.kind === "fact.asserted") {
      for (const f of this.facts.values()) if (f.about === p.about && f.predicate === p.predicate && !f.supersededBy && f.id !== p.id) f.supersededBy = p.id;
      this.facts.set(p.id, { ...p });
    } else if (e.kind === "entity.merged") { this.aliases.set(p.alias, p.primary); const pr = this.entities.get(p.primary); if (pr && !pr.aliases.includes(p.alias)) pr.aliases.push(p.alias); }
    else if (e.kind === "observation.recorded") this.obsHash.set(p.externalId, p.hash);
  }
  resolveAlias(id: string): string { let x = id; for (let i = 0; i < 10 && this.aliases.has(x); i++) x = this.aliases.get(x)!; return x; }

  // ---------------------------------------------------------------- writes
  upsertEntity(input: { type: string; externalKey?: { system: string; id: string }; name?: string; attrs?: Record<string, unknown>; source: Provenance; state?: Entity["state"] }): Promise<Entity> {
    return this.enqueue(() => this.upsertEntitySync(input));
  }
  private upsertEntitySync(input: { type: string; externalKey?: { system: string; id: string }; name?: string; attrs?: Record<string, unknown>; source: Provenance; state?: Entity["state"] }): Entity {
    const source = this.prov(input.source);
    if (!input.externalKey && !input.name) throw new Error("WorldModel: entity needs externalKey or name");
    let id = input.externalKey ? externalId(input.type, input.externalKey.system, input.externalKey.id) : entityIdFromName(input.type, input.name!);
    id = this.resolveAlias(id);
    const old = this.entities.get(id);
    const next = { id, type: input.type, name: input.name ?? old?.name, attrs: { ...(old?.attrs ?? {}), ...(input.attrs ?? {}) }, state: input.state ?? old?.state ?? "active",
      firstSeenAt: old?.firstSeenAt ?? source.at, lastSeenAt: old && old.lastSeenAt > source.at ? old.lastSeenAt : source.at, source };
    if (old && canonicalJson({ ...old, aliases: undefined, source: undefined }) === canonicalJson({ ...next, aliases: undefined, source: undefined })) return old; // no-op, no event
    if (!old && input.name && !input.externalKey) this.proposeMerges(id, input.type, input.name, source.at);
    this.append("entity.upserted", next, source.at, source.by, `upsert ${id}`);
    return this.entities.get(id)!;
  }
  private proposeMerges(id: string, type: string, name: string, at: string) {
    for (const e of this.entities.values()) {
      if (e.type !== type || !e.name || e.id === id) continue;
      const s = nameSimilarity(e.name, name); const d = decide(s);
      if (d === "new") continue;
      const pid = `mp_${sha256Hex([e.id, id].sort().join("|")).slice(0, 12)}`;
      if (!this.proposals.has(pid)) this.proposals.set(pid, { id: pid, a: e.id, b: id, similarity: s, status: "pending" });
      this.auditLog.push({ seq: ++this.aseq, action: "merge.proposed", actor: "resolver", summary: `${e.id}~${id} ${s.toFixed(3)} ${d}`, at });
    }
  }
  relate(input: { from: string; type: string; to: string; context?: string; attrs?: Record<string, unknown>; validFrom?: string; validTo?: string; source: Provenance; multi?: boolean }): Promise<Relationship> {
    return this.enqueue(() => {
      const source = this.prov(input.source); const from = this.resolveAlias(input.from), to = this.resolveAlias(input.to);
      const id = relationshipId(from, input.type, to, input.context, input.validFrom);
      if (this.rels.has(id)) return this.rels.get(id)!;
      const rel: Relationship = { id, from, type: input.type, to, context: input.context, attrs: input.attrs, validFrom: input.validFrom ?? source.at, validTo: input.validTo, source };
      this.append("relationship.opened", { rel, multi: !!input.multi }, source.at, source.by, `${from} -[${input.type}]-> ${to}`);
      return this.rels.get(id)!;
    });
  }
  closeRelationship(id: string, validTo: string, source: Provenance): Promise<void> {
    return this.enqueue(() => { this.prov(source); if (this.rels.get(id) && !this.rels.get(id)!.validTo) this.append("relationship.closed", { id, validTo }, source.at, source.by, `close ${id}`); });
  }
  assertFact(input: { about: string; predicate: string; value: unknown; confidence?: number; context?: string; source: Provenance }): Promise<Fact> {
    return this.enqueue(() => {
      const source = this.prov(input.source); const about = this.resolveAlias(input.about);
      const id = `fact_${sha256Hex(canonicalJson({ about, predicate: input.predicate, value: input.value, context: input.context })).slice(0, 16)}`;
      const cur = this.facts.get(id); if (cur && !cur.supersededBy) return cur;
      this.append("fact.asserted", { id, about, predicate: input.predicate, value: input.value, confidence: input.confidence ?? 1, context: input.context, source }, source.at, source.by, `${about}.${input.predicate}`);
      return this.facts.get(id)!;
    });
  }
  /** per-observation path: extract → normalize → resolve → validate → append → project. Re-ingesting the same batch appends nothing. */
  ingest(observations: IngestObservation[]): Promise<{ changed: boolean; appended: number; skipped: number }> {
    return this.enqueue(() => {
      const before = this.seq; let skipped = 0;
      for (const o of observations) {
        const source = this.prov(o.source);
        const norm = { externalId: o.externalId, title: o.title ?? "", at: o.at, type: o.type ?? "observation", attrs: o.attrs ?? {},
          entities: (o.entities ?? []).map((e) => ({ type: e.type, name: normalizeName(e.name) })).sort((a, b) => (a.type + a.name < b.type + b.name ? -1 : 1)) };
        const hash = sha256Hex(canonicalJson(norm));
        if (this.obsHash.get(o.externalId) === hash) { skipped++; continue; }
        const obsId = externalId(norm.type, this.namespace, o.externalId);
        this.upsertEntitySync({ type: norm.type, externalKey: { system: this.namespace, id: o.externalId }, name: o.title, attrs: { title: norm.title, at: o.at, ...norm.attrs }, source });
        for (const e of o.entities ?? []) {
          const ent = this.upsertEntitySync({ type: e.type, name: e.name, source });
          const rid = relationshipId(obsId, "mentions", ent.id, undefined, o.at);
          if (!this.rels.has(rid)) this.append("relationship.opened", { rel: { id: rid, from: obsId, type: "mentions", to: ent.id, validFrom: o.at, source }, multi: true }, source.at, source.by, `${obsId} mentions ${ent.id}`);
        }
        this.append("observation.recorded", { externalId: o.externalId, hash }, source.at, source.by, `observation ${o.externalId}`);
      }
      const appended = this.seq - before; return { changed: appended > 0, appended, skipped };
    });
  }
  approveMerge(id: string, by: string): Promise<void> {
    return this.enqueue(() => { const p = this.proposals.get(id); if (!p || p.status !== "pending") return; p.status = "approved"; this.append("entity.merged", { alias: p.b, primary: p.a, by }, this.clock().toISOString(), by, `merge ${p.b} -> ${p.a}`); });
  }
  rejectMerge(id: string, by: string): Promise<void> { return this.enqueue(() => { const p = this.proposals.get(id); if (p) p.status = "rejected"; this.auditLog.push({ seq: ++this.aseq, action: "merge.rejected", actor: by, summary: id, at: this.clock().toISOString() }); }); }
  mergeQueue(): readonly MergeProposal[] { return [...this.proposals.values()].filter((p) => p.status === "pending"); }

  // ---------------------------------------------------------------- reads
  entity(id: string): Entity | undefined { return this.entities.get(this.resolveAlias(id)); }
  private validAt(r: Relationship, at?: string) { if (!at) return !r.validTo; return r.validFrom <= at && (!r.validTo || at < r.validTo); }
  neighborsOf(id: string, opts: { via?: string; at?: string; inContext?: string } = {}): Entity[] {
    const x = this.resolveAlias(id); const out: Entity[] = [];
    for (const r of this.rels.values()) if (r.from === x && (!opts.via || r.type === opts.via) && (!opts.inContext || r.context === opts.inContext) && this.validAt(r, opts.at)) { const e = this.entities.get(r.to); if (e) out.push(e); }
    return out;
  }
  incoming(id: string, opts: { via?: string; at?: string } = {}): Entity[] {
    const x = this.resolveAlias(id); const out: Entity[] = [];
    for (const r of this.rels.values()) if (r.to === x && (!opts.via || r.type === opts.via) && this.validAt(r, opts.at)) { const e = this.entities.get(r.from); if (e) out.push(e); }
    return out;
  }
  query(opts: { type?: string; where?: (e: Entity) => boolean } = {}): Entity[] { return [...this.entities.values()].filter((e) => (!opts.type || e.type === opts.type) && (!opts.where || opts.where(e))); }
  about(id: string, opts: { includeSuperseded?: boolean } = {}): Fact[] { const x = this.resolveAlias(id); return [...this.facts.values()].filter((f) => f.about === x && (opts.includeSuperseded || !f.supersededBy)); }
  view(name: string): any {
    if (name === "graph") return { neighborsOf: (id: string, o?: any) => this.neighborsOf(id, o), incoming: (id: string, o?: any) => this.incoming(id, o) };
    if (name === "entities") return { all: () => this.query(), byType: (t: string) => this.query({ type: t }) };
    if (name === "timeline") return { events: () => [...this.log] };
    throw new Error(`WorldModel: unknown view ${name}`);
  }
  events(): readonly WorldEvent[] { return this.log; }
  audit(): readonly AuditEntry[] { return this.auditLog; }
  subscribeEvents(fn: (e: WorldEvent) => void): () => void { this.subs.add(fn); return () => this.subs.delete(fn); }
  stateShape(): unknown {
    const strip = (o: any) => { const { source, firstSeenAt, lastSeenAt, ...rest } = o; return rest; };
    return {
      entities: [...this.entities.values()].map(strip).sort((a, b) => (a.id < b.id ? -1 : 1)),
      relationships: [...this.rels.values()].map(({ source, ...r }) => r).sort((a, b) => (a.id < b.id ? -1 : 1)),
      facts: [...this.facts.values()].map(({ source, ...f }) => f).sort((a, b) => (a.id < b.id ? -1 : 1)),
      aliases: [...this.aliases.entries()].sort(),
    };
  }
  stateShapeCanonical(): string { return canonicalJson(this.stateShape()); }
}
