import assert from "node:assert/strict";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
const here = dirname(fileURLToPath(import.meta.url));
const lib = pathToFileURL(join(here, "../../src/graphify_ghidra/pi_package/extensions/lib/mcp-client.ts")).href;
const { McpClient, cleanSchema, loadServerSpec } = await import(lib);
const spec = { command: process.execPath, args: [join(here, "fake_mcp_server.mjs")] };
const results = [];
const t = (name, fn) => results.push([name, fn]);

t("handshake, paging, banner lines ignored, schema cleaning", async () => {
  const c = new McpClient(spec, "fake");
  const tools = await c.listTools();
  assert.equal(tools.length, 6, "two pages of tools are merged");
  assert.deepEqual(c.serverInfo, { name: "fake", version: "9.9" });
  assert.equal("$schema" in cleanSchema(tools[0].inputSchema), false);
  assert.deepEqual(cleanSchema(undefined), { type: "object", properties: {} });
  c.stop();
});
t("content kinds are flattened to text", async () => {
  const c = new McpClient(spec, "fake");
  assert.equal((await c.callTool("echo", { text: "hi" })).text, "echo:hi");
  const multi = await c.callTool("multi", {});
  assert.equal(multi.text, "a\n[image omitted]\nres\n[audio omitted]");
  assert.equal((await c.callTool("struct", {})).text, '{"n":1}');
  const e = await c.callTool("err", {});
  assert.deepEqual(e, { text: "boom", isError: true });
  c.stop();
});
t("JSON-RPC errors reject with the server's message", async () => {
  const c = new McpClient(spec, "fake");
  await assert.rejects(c.callTool("rpcerr", {}), /server says no/);
  c.stop();
});
t("concurrent first calls share one handshake", async () => {
  const c = new McpClient(spec, "fake");
  const r = await Promise.all([1, 2, 3, 4].map((i) => c.callTool("echo", { text: String(i) })));
  assert.deepEqual(r.map((x) => x.text), ["echo:1", "echo:2", "echo:3", "echo:4"]);
  c.stop();
});
t("a request times out instead of hanging", async () => {
  const c = new McpClient(spec, "fake");
  await c.ensure();
  await assert.rejects(c.callTool("slow", {}, 300), /timed out/);
  c.stop();
});
t("abort signal cancels a pending call", async () => {
  const c = new McpClient(spec, "fake");
  await c.ensure();
  const ac = new AbortController();
  const p = c.callTool("slow", {}, 10_000, ac.signal);
  setTimeout(() => ac.abort(), 100);
  await assert.rejects(p, /cancelled/);
  c.stop();
});
t("a crashing server rejects pending calls, then restarts on the next call", async () => {
  const c = new McpClient(spec, "fake");
  await assert.rejects(c.callTool("crash", {}), /exited \(3\)/);
  assert.equal(c.running, false);
  assert.equal((await c.callTool("echo", { text: "again" })).text, "echo:again", "restarted transparently");
  c.stop();
});
t("server-initiated requests: ping answered, unsupported methods refused", async () => {
  const c = new McpClient(spec, "fake");
  const replies = JSON.parse((await c.callTool("asks", {})).text);
  const byId = Object.fromEntries(replies.map((r) => [r.id, r]));
  assert.deepEqual(byId[900].result, {});
  assert.equal(byId[901].error.code, -32601);
  c.stop();
});
t("a missing executable gives an actionable error", async () => {
  const c = new McpClient({ command: "definitely-not-a-real-binary-xyz", args: [] }, "ghost");
  await assert.rejects(c.ensure(5000), /could not start ghost/);
});
t("config lookup is by name and tolerant of absence", async () => {
  assert.equal(loadServerSpec("no-such-server-in-any-config"), null);
});

let failed = 0;
for (const [name, fn] of results) {
  try { await fn(); console.log("ok   -", name); }
  catch (e) { failed++; console.log("FAIL -", name, "\n      ", e.message); }
}
process.exit(failed ? 1 : 0);
