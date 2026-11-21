// Exercises context-compact.ts against a stub Pi. The behaviours that matter are about ordering and
// notification, so the stub records every call: the tool must never call ctx.compact itself (it aborts the
// running agent), compaction must happen from agent_settled, and the agent must always be told.
import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { execSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = execSync("npm root -g", { encoding: "utf8" }).trim();
const typebox = join(root, "@earendil-works", "pi-coding-agent", "node_modules", "typebox", "build", "index.mjs");
if (!existsSync(typebox)) { console.log("SKIP: Pi's typebox not found"); process.exit(77); }
registerHooks({ resolve(spec, ctx, next) {
  return spec === "typebox" ? { url: pathToFileURL(typebox).href, shortCircuit: true } : next(spec, ctx);
} });
const mod = pathToFileURL(join(here, "../../src/graphify_ghidra/pi_package/extensions/context-compact.ts")).href;

// Hermetic: the extension reads Pi's settings.json to estimate when Pi will compact on its own. Point "home" at a
// temp dir so the tests never read (or depend on) the real user's settings.
const home = mkdtempSync(join(tmpdir(), "cc-home-"));
process.env.USERPROFILE = home; process.env.HOME = home;
const project = mkdtempSync(join(tmpdir(), "cc-proj-"));
const writeJson = (path, obj) => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, JSON.stringify(obj)); };
const globalSettings = (obj) => writeJson(join(home, ".pi", "agent", "settings.json"), obj);
const projectSettings = (obj) => writeJson(join(project, ".pi", "settings.json"), obj);
const resetSettings = () => { globalSettings({}); projectSettings({}); };
resetSettings();

function load({ ghidra = false } = {}) {
  const tools = {}, handlers = {}, sent = [];
  const pi = {
    registerTool: (t) => (tools[t.name] = t),
    on: (e, h) => (handlers[e] ||= []).push(h),
    sendMessage: (m, o) => sent.push({ m, o }),
    getAllTools: () => (ghidra ? [{ name: "ghidra_status" }] : [{ name: "read" }]),
  };
  return import(mod + "?" + Math.random()).then((m) => { m.default(pi); return { tools, handlers, sent }; });
}
const mkctx = (percent, extra = {}) => {
  const calls = { compact: [], notify: [] };
  const win = 100_000;
  const usage = percent === null ? { tokens: null, contextWindow: win, percent: null } : { tokens: Math.round(win * percent / 100), contextWindow: win, percent };
  return { calls, cwd: project, model: { provider: "p", id: "m" }, hasUI: true, ui: { notify: (...a) => calls.notify.push(a) }, getContextUsage: () => usage,
    compact: (o) => { calls.compact.push(o); extra.onCompact?.(o); }, ...extra };
};
const run = (h, name, ev, ctx) => Promise.all((h.handlers[name] ?? []).map((f) => f(ev, ctx)));
const call = (h, params, ctx) => h.tools.compact_context.execute("id", params, undefined, undefined, ctx);
const txt = (r) => r.content[0].text;

const tests = [];
const t = (n, f) => tests.push([n, f]);

t("tool never calls ctx.compact itself, and schedules only at/above the threshold", async () => {
  const h = await load();
  for (const [pct, scheduled] of [[10, false], [79.9, false], [80, true], [95, true]]) {
    const hh = await load();
    const ctx = mkctx(pct);
    const r = await call(hh, {}, ctx);
    assert.equal(ctx.calls.compact.length, 0, "ctx.compact aborts the running agent: the tool must not call it");
    assert.equal(Boolean(r.terminate), scheduled, `terminate at ${pct}%`);
    assert.equal(/Refused/.test(txt(r)), !scheduled);
    if (!scheduled) assert.match(txt(r), /below the 80% threshold/);
    else assert.match(txt(r), /CONTEXT RESET/);
  }
});

t("unknown usage is refused with an explanation", async () => {
  const h = await load();
  const r = await call(h, {}, mkctx(null));
  assert.match(txt(r), /unknown/i); assert.equal(Boolean(r.terminate), false);
  const noUsage = await call(h, {}, { ...mkctx(50), getContextUsage: () => undefined });
  assert.match(txt(noUsage), /unknown/i);
});

t("percent is derived from tokens when Pi omits it", async () => {
  const h = await load();
  const ctx = { ...mkctx(0), getContextUsage: () => ({ tokens: 90_000, contextWindow: 100_000, percent: null }) };
  assert.equal(Boolean((await call(h, {}, ctx)).terminate), true);
});

t("check_only reports and never schedules", async () => {
  const h = await load();
  const r = await call(h, { check_only: true }, mkctx(92));
  assert.match(txt(r), /92%/); assert.match(txt(r), /ALLOWED now/); assert.equal(Boolean(r.terminate), false);
  await run(h, "agent_settled", { aborted: false }, mkctx(92));
  assert.equal(h.sent.length, 0);
  assert.match(txt(await call(h, { check_only: true }, mkctx(30))), /not allowed until 80%/);
});

t("compaction runs at agent_settled with the agent's focus; a second request is not queued twice", async () => {
  const h = await load();
  const ctx = mkctx(85, { onCompact: (o) => o.onComplete({ tokensBefore: 85_000, estimatedTokensAfter: 12_000 }) });
  await call(h, { focus: "function names assigned so far" }, ctx);
  assert.match(txt(await call(h, {}, ctx)), /already scheduled/);
  assert.equal(ctx.calls.compact.length, 0, "nothing compacts before the agent settles");
  await run(h, "agent_settled", { aborted: false }, ctx);
  assert.equal(ctx.calls.compact.length, 1);
  assert.match(ctx.calls.compact[0].customInstructions, /85% usage/);
  assert.match(ctx.calls.compact[0].customInstructions, /function names assigned so far/);
  await run(h, "agent_settled", { aborted: false }, ctx);
  assert.equal(ctx.calls.compact.length, 1, "the request was consumed");
});

t("the agent is told its context was reset, and its next turn is started", async () => {
  const h = await load({ ghidra: true });
  const ctx = mkctx(85, { onCompact: (o) => o.onComplete({ tokensBefore: 85_000, estimatedTokensAfter: 12_000 }) });
  await call(h, { focus: "the worklist position" }, ctx);
  await run(h, "agent_settled", { aborted: false }, ctx);
  assert.equal(h.sent.length, 1);
  const { m, o } = h.sent[0];
  assert.equal(m.customType, "context-reset"); assert.equal(m.display, true);
  for (const needle of ["CONTEXT RESET", "no longer visible to you", "Do not trust your memory", "85,000 tokens", "12,000 after",
                        "85%", "the worklist position", "ghidra_status", "Your original task has not changed"]) {
    assert.ok(m.content.includes(needle), `message lacks ${JSON.stringify(needle)}`);
  }
  assert.deepEqual(o, { triggerTurn: true, deliverAs: "followUp" }, "starts the next turn so work resumes");
});

t("no ghidra hint when those tools are absent", async () => {
  const h = await load({ ghidra: false });
  const ctx = mkctx(85, { onCompact: (o) => o.onComplete({ tokensBefore: 1 }) });
  await call(h, {}, ctx); await run(h, "agent_settled", { aborted: false }, ctx);
  assert.ok(!h.sent[0].m.content.includes("ghidra_status"));
});

t("a session_compact fired by our own compaction does not announce a second time", async () => {
  const h = await load();
  const ctx = mkctx(85, { onCompact: async (o) => { await run(h, "session_compact", { reason: "manual", compactionEntry: { tokensBefore: 85_000 } }, ctx); o.onComplete({ tokensBefore: 85_000 }); } });
  await call(h, {}, ctx);
  await run(h, "agent_settled", { aborted: false }, ctx);
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(h.sent.length, 1, "exactly one reset message");
});

t("an aborted run drops the request instead of compacting behind the user's back", async () => {
  const h = await load();
  const ctx = mkctx(90);
  await call(h, {}, ctx);
  await run(h, "agent_settled", { aborted: true }, ctx);
  assert.equal(ctx.calls.compact.length, 0); assert.equal(h.sent.length, 0);
  await run(h, "agent_settled", { aborted: false }, ctx);
  assert.equal(ctx.calls.compact.length, 0, "and it stays dropped");
  assert.match(txt(await call(h, {}, ctx)), /scheduled/, "the agent can ask again");
});

t("a failed compaction tells the agent nothing was reset and resumes it", async () => {
  const h = await load();
  const ctx = mkctx(90, { onCompact: (o) => o.onError(new Error("Nothing to compact (session too small)")) });
  await call(h, {}, ctx); await run(h, "agent_settled", { aborted: false }, ctx);
  const { m, o } = h.sent[0];
  assert.match(m.content, /COMPACTION FAILED: Nothing to compact/); assert.match(m.content, /NOT reset/);
  assert.equal(o.triggerTurn, true);
  // and selfCompacting was cleared: a later foreign compaction is announced
  await run(h, "session_compact", { reason: "threshold", compactionEntry: { tokensBefore: 5 } }, ctx);
  assert.equal(h.sent.length, 2);
});

t("compactions we did not start still tell the agent (queued, no new turn)", async () => {
  for (const [reason, phrase] of [["threshold", "automatically at its context threshold"], ["overflow", "after the context overflowed"], ["manual", "the user ran /compact"]]) {
    const h = await load();
    await run(h, "session_compact", { reason, compactionEntry: { tokensBefore: 120_000 } }, mkctx(10));
    assert.equal(h.sent.length, 1, reason);
    const { m, o } = h.sent[0];
    assert.match(m.content, /CONTEXT RESET/); assert.ok(m.content.includes(phrase)); assert.match(m.content, /120,000 tokens/);
    assert.deepEqual(o, { deliverAs: "steer" }, "no triggerTurn: it rides along with the next model call");
  }
});

t("the agent is warned once on crossing, re-armed only after usage clearly drops", async () => {
  const h = await load();
  const at = (p) => run(h, "turn_end", {}, mkctx(p));
  await at(50); assert.equal(h.sent.length, 0);
  await at(85); assert.equal(h.sent.length, 1);
  assert.equal(h.sent[0].m.customType, "context-warning");
  assert.match(h.sent[0].m.content, /85%/); assert.match(h.sent[0].m.content, /compact_context is now allowed/);
  assert.deepEqual(h.sent[0].o, { deliverAs: "steer" });
  await at(88); assert.equal(h.sent.length, 1, "not nagging every turn");
  await at(75); await at(86); assert.equal(h.sent.length, 1, "75% is not clearly below: still armed off");
  await at(60); await at(86); assert.equal(h.sent.length, 2, "re-armed after dropping below threshold - 10");
  await run(h, "turn_end", {}, mkctx(null)); assert.equal(h.sent.length, 2, "unknown usage is ignored");
});

t("no warning while a compaction is already pending", async () => {
  const h = await load();
  await call(h, {}, mkctx(90));
  await run(h, "turn_end", {}, mkctx(91));
  assert.equal(h.sent.length, 0);
});

t("the threshold can be overridden, and bad values fall back to 80", async () => {
  const h = await load();
  for (const [env, pct, scheduled] of [["50", 60, true], ["50", 40, false], ["abc", 79, false], ["0", 79, false], ["101", 79, false], [undefined, 80, true]]) {
    if (env === undefined) delete process.env.PI_COMPACT_MIN_PERCENT; else process.env.PI_COMPACT_MIN_PERCENT = env;
    const hh = await load();
    assert.equal(Boolean((await call(hh, {}, mkctx(pct))).terminate), scheduled, `env=${env} pct=${pct}`);
  }
  delete process.env.PI_COMPACT_MIN_PERCENT;
});

t("without a UI nothing throws", async () => {
  const h = await load();
  const ctx = mkctx(90, { hasUI: false, ui: undefined, onCompact: (o) => o.onComplete({ tokensBefore: 9 }) });
  await call(h, {}, ctx); await run(h, "agent_settled", { aborted: true }, ctx);
  await call(h, {}, ctx); await run(h, "agent_settled", { aborted: false }, ctx);
  assert.equal(h.sent.length, 1);
});

const check = (h, ctx) => h.tools.check_context.execute("id", {}, undefined, undefined, ctx);

t("check_context reports usage, the 80% gate and Pi's own automatic compaction", async () => {
  resetSettings();
  const h = await load();
  const r = txt(await check(h, mkctx(50)));
  assert.match(r, /Context: 50,000 of 100,000 tokens \(50%\)/);
  assert.match(r, /not allowed until 80% \(about 80,000 tokens\); 30,000 tokens to go/);
  assert.match(r, /starts above 83,616 tokens \(84%\), reserve 16,384 from Pi's default; 33,616 tokens of room left/);
  assert.ok(!/NOTE:/.test(r));
  assert.match(txt(await check(h, mkctx(85))), /ALLOWED now/);
});

t("check_context never changes anything", async () => {
  const h = await load(); const ctx = mkctx(95);
  await check(h, ctx); await check(h, ctx);
  await run(h, "agent_settled", { aborted: false }, ctx);
  assert.equal(ctx.calls.compact.length, 0); assert.equal(h.sent.length, 0);
});

t("a per-model reserve that makes Pi compact before 80% is called out", async () => {
  globalSettings({ compaction: { reserveTokens: 16384, modelOverrides: { "p/m": { reserveTokens: 40000 } } } });
  const h = await load();
  const r = txt(await check(h, mkctx(30)));
  assert.match(r, /starts above 60,000 tokens \(60%\), reserve 40,000 from the override for p\/m/);
  assert.match(r, /NOTE: Pi will compact automatically at 60%, before the 80% threshold, so compact_context will never become available/);
  resetSettings();
});

t("settings merge like Pi's: project over global, and model overrides are exact provider/id keys", async () => {
  globalSettings({ compaction: { reserveTokens: 10000, modelOverrides: { "other/m": { reserveTokens: 50000 } } } });
  const h = await load();
  assert.match(txt(await check(h, mkctx(10))), /reserve 10,000 from compaction\.reserveTokens/, "another model's override is ignored");
  projectSettings({ compaction: { reserveTokens: 30000 } });
  assert.match(txt(await check(h, mkctx(10))), /starts above 70,000 tokens \(70%\), reserve 30,000/);
  resetSettings();
});

t("disabled auto-compaction and invalid values are handled", async () => {
  globalSettings({ compaction: { enabled: false } });
  const h = await load();
  assert.match(txt(await check(h, mkctx(10))), /automatic compaction: disabled in settings/);
  globalSettings({ compaction: { reserveTokens: -5 } });
  assert.match(txt(await check(h, mkctx(10))), /reserve 16,384 from Pi's default/, "a negative reserve is ignored, as Pi would reject it");
  globalSettings({ compaction: { reserveTokens: "lots" } });
  assert.match(txt(await check(h, mkctx(10))), /reserve 16,384 from Pi's default/);
  resetSettings();
});

t("check_context warns when close to Pi's automatic compaction, notes a pending request, and handles unknown usage", async () => {
  resetSettings();
  const h = await load();
  assert.match(txt(await check(h, mkctx(81))), /close to Pi's automatic compaction/);
  assert.match(txt(await check(h, mkctx(null))), /unknown right now/);
  await call(h, {}, mkctx(90));
  assert.match(txt(await check(h, mkctx(90))), /already scheduled/);
});

t("every check carries the looseness reminder, and compact_context check_only shares the report", async () => {
  resetSettings();
  const h = await load();
  for (const p of [10, 85]) {
    const r = txt(await check(h, mkctx(p)));
    assert.match(r, /Budget note: be loose about this, and compact only at a good time/);
  }
  assert.equal(txt(await call(h, { check_only: true }, mkctx(40))), txt(await check(h, mkctx(40))));
});

t("the tagged guidance goes into the system prompt as a section, without clobbering others", async () => {
  const h = await load();
  const options = { sections: { other_tag: "keep me" }, promptGuidelines: [] };
  await run(h, "before_agent_start", { systemPromptOptions: options, systemPrompt: "x" }, mkctx(10));
  assert.equal(options.sections.other_tag, "keep me");
  const g = options.sections.context_budget;
  for (const needle of ["budget for time and attention", "check_context sparingly", "Be loose", "Do not wrap up early",
                        "Compact only at a good time", "Never mid-edit", "late compaction at a good time beats an early one", "CONTEXT RESET"]) {
    assert.ok(g.includes(needle), `guidance lacks ${JSON.stringify(needle)}`);
  }
  assert.ok(g.includes("80%"));
  const bare = {};
  await run(h, "before_agent_start", { systemPromptOptions: bare }, mkctx(10));
  assert.ok(bare.sections.context_budget, "creates the sections map when absent");
  await run(h, "before_agent_start", {}, mkctx(10));                      // no options at all: must not throw
  const again = { sections: {} };
  await run(h, "before_agent_start", { systemPromptOptions: again }, mkctx(10));
  assert.equal(again.sections.context_budget, g, "static text: identical every turn, so the prompt cache stays warm");
});

t("the guidance and tool text follow the configured threshold", async () => {
  process.env.PI_COMPACT_MIN_PERCENT = "65";
  const h = await load();
  const o = { sections: {} };
  await run(h, "before_agent_start", { systemPromptOptions: o }, mkctx(10));
  assert.ok(o.sections.context_budget.includes("65%") && !o.sections.context_budget.includes("80%"));
  assert.match(h.tools.compact_context.description, /65% or more/);
  delete process.env.PI_COMPACT_MIN_PERCENT;
});

t("tool wording and the warning tell the agent to be loose and to pick good moments", async () => {
  const h = await load();
  const c = h.tools.check_context, k = h.tools.compact_context;
  assert.match(c.description, /sparingly/); assert.match(c.description, /Be loose/);
  assert.match(c.promptGuidelines[0], /sparingly/); assert.match(k.description, /good time/);
  assert.match(k.description, /never mid-edit/); assert.match(k.promptGuidelines[0], /fine to wait/);
  await run(h, "turn_end", {}, mkctx(86));
  const w = h.sent[0].m.content;
  assert.match(w, /you do not have to compact immediately/); assert.match(w, /good time/); assert.match(w, /never mid-edit/);
  assert.match(w, /check_context/);
});

let failed = 0;
for (const [name, fn] of tests) {
  try { await fn(); console.log("ok   -", name); } catch (e) { failed++; console.log("FAIL -", name, "\n      ", e.message); }
}
process.exit(failed ? 1 : 0);
