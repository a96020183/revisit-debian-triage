// Leave-one-out check for the Scout eval (not part of the official harness).
// The official fixture registry lists every intent-labeled v1 prompt verbatim as an intent example (Meterless: examples
// are "classifier seeds AND eval fixtures"). So the official intent_top1 partly measures recall of seen examples.
// Here each labeled prompt is removed from its intent's examples before that prompt is classified (an intent left
// with no examples keeps only its description as the seed). Run: node --import tsx test/scout_loo.ts
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Scout } from "../engines/scout-intent/index.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EVALS = path.join(ROOT, "vendor", "scout-intent-evals", "evals");
const fixture = JSON.parse(fs.readFileSync(path.join(EVALS, "fixtures", "intents.json"), "utf-8"));
const dir = path.join(EVALS, "regression-set", "v1", "intents");
const edge = path.join(EVALS, "regression-set", "v1", "edge-cases");
const examples = [dir, edge].flatMap((d) => fs.readdirSync(d).flatMap((f) =>
  fs.readFileSync(path.join(d, f), "utf-8").split("\n").filter(Boolean).map((l) => JSON.parse(l)))).filter((e) => e.expected.intent);

let top1 = 0, top3 = 0, ranked = 0;
for (const ex of examples) {
  const intents = fixture.intents.map((it: any) => {
    const kept = it.examples.filter((s: string) => s !== ex.prompt);
    return { ...it, examples: kept.length ? kept : [it.description] };
  });
  const scout = new Scout({ intentRegistry: intents, policyPack: ["default", "adversarial-tight"], selfTest: false });
  const out = await scout.decide({ prompt: ex.prompt, user: { id: "loo", role: ex.user?.role ?? "ae" }, surface: ex.surface ?? "chat" });
  const got = out.executionContract?.intent.primary.id ?? `(${out.clarification ? "clarify:" + out.clarification.trigger : "none"} top=${out.candidates[0].intent})`;
  const hit = got === ex.expected.intent; const hit3 = out.candidates.slice(0, 3).some((c) => c.intent === ex.expected.intent);
  top1 += +hit; top3 += +hit3; ranked += +(out.candidates[0].intent === ex.expected.intent);
  console.log(`${hit ? "ok  " : "MISS"} ${ex.id.padEnd(20)} expected ${ex.expected.intent.padEnd(20)} got ${got}  (top: ${out.candidates[0].intent} ${out.candidates[0].score})`);
}
const n = examples.length; const f = (k: number) => `${(k / n).toFixed(3)} (${k}/${n})`;
console.log(`\nleave-one-out, ${n} intent-labeled prompts:`);
console.log(`  ranked first (top candidate == label) ${f(ranked)}`);
console.log(`  contract issued for the label (official top-1 definition) ${f(top1)}  <- unseen phrasings mostly fall in the Low band and get a clarification instead of a guess`);
console.log(`  label in top 3 ${f(top3)}`);
