// A tiny MCP stdio server with deliberately awkward behaviour, for testing the client.
import { createInterface } from "node:readline";
const rl = createInterface({ input: process.stdin });
const replies = [];
const send = (o) => process.stdout.write(JSON.stringify(o) + "\n");
const tools = Array.from({ length: 5 }, (_, i) => ({ name: `t${i}`, description: `tool ${i}`, inputSchema: { $schema: "x", type: "object", properties: {} } }))
  .concat([{ name: "echo", description: "echo", inputSchema: { type: "object", properties: { text: { type: "string" } } } }]);
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === undefined && m.id !== undefined) { replies.push(m); return; }          // client's answer to *our* request
  if (m.method === "initialize") return send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "fake", version: "9.9" } } });
  if (m.method === "tools/list") {
    process.stdout.write("this line is a banner, not protocol\n");
    const start = m.params?.cursor ? Number(m.params.cursor) : 0;
    return send({ jsonrpc: "2.0", id: m.id, result: { tools: tools.slice(start, start + 4), ...(start + 4 < tools.length ? { nextCursor: String(start + 4) } : {}) } });
  }
  if (m.method === "tools/call") {
    const { name, arguments: a } = m.params;
    const ok = (content, extra = {}) => send({ jsonrpc: "2.0", id: m.id, result: { content, ...extra } });
    if (name === "echo") return ok([{ type: "text", text: `echo:${a.text}` }]);
    if (name === "multi") return ok([{ type: "text", text: "a" }, { type: "image", data: "xx", mimeType: "image/png" }, { type: "resource", resource: { text: "res" } }, { type: "audio" }]);
    if (name === "struct") return ok([], { structuredContent: { n: 1 } });
    if (name === "err") return ok([{ type: "text", text: "boom" }], { isError: true });
    if (name === "rpcerr") return send({ jsonrpc: "2.0", id: m.id, error: { code: -32000, message: "server says no" } });
    if (name === "slow") return setTimeout(() => ok([{ type: "text", text: "late" }]), 3000);
    if (name === "crash") process.exit(3);
    if (name === "asks") {
      send({ jsonrpc: "2.0", id: 900, method: "ping" });
      send({ jsonrpc: "2.0", id: 901, method: "sampling/createMessage", params: {} });
      return setTimeout(() => ok([{ type: "text", text: JSON.stringify(replies) }]), 200);
    }
  }
});
