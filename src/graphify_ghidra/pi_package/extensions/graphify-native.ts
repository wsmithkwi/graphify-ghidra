/**
 * Native graphify tools for Pi.
 *
 * Starts the user's own `graphify-mcp` (the exact entry from their MCP config) against the project's graph and
 * registers each of its tools as an ordinary Pi tool named `graphify_<tool>`, with the server's own JSON schema.
 * No reimplementation: whatever graphify's server does, these do. They are read-only graph queries.
 *
 * Which graph: $GRAPHIFY_GRAPH, else <cwd>/graphify-out/graph.json, else the graph path in the user's `graphify`
 * MCP entry. If none exists, nothing is registered.
 *
 * Unlike the MCP adapter (proxy tools behind `mcp`), these are first-class tools the model sees directly.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { McpClient, cleanSchema, loadServerSpec } from "./lib/mcp-client.ts";

function capText(text: string, max = 24_000): string {
	if (text.length <= max) return text;
	return text.slice(0, max) + `\n\n[output cut at ${max} characters of ${text.length}; narrow the query (smaller token_budget/depth)]`;
}

function firstSentence(s: string, n = 140): string {
	const one = s.replace(/\s+/g, " ").trim();
	const dot = one.search(/[.!?](\s|$)/);
	const cut = dot > 20 ? one.slice(0, dot + 1) : one;
	return cut.length > n ? cut.slice(0, n - 1) + "…" : cut;
}

function findGraph(cwd: string): { path: string; source: string } | null {
	const env = process.env.GRAPHIFY_GRAPH;
	if (env && existsSync(env)) return { path: resolve(env), source: "$GRAPHIFY_GRAPH" };
	const local = join(cwd, "graphify-out", "graph.json");
	if (existsSync(local)) return { path: local, source: "this project's graphify-out" };
	const configured = loadServerSpec("graphify")?.args?.[0];
	if (configured && existsSync(configured)) return { path: configured, source: "your graphify MCP config" };
	return null;
}

export default function (pi: ExtensionAPI) {
	let client: McpClient | null = null;
	let graph: { path: string; source: string } | null = null;
	const registered = new Set<string>();

	pi.on("session_start", async (_event, ctx) => {
		const found = findGraph(ctx.cwd);
		if (!found) return;
		if (client && graph?.path === found.path) return; // reload: tools already registered for this graph
		client?.stop();
		graph = found;
		const spec = loadServerSpec("graphify");
		client = new McpClient(
			{ command: spec?.command ?? "graphify-mcp", args: [found.path], env: spec?.env, cwd: ctx.cwd },
			"graphify-mcp",
		);
		const c = client;
		try {
			const tools = await c.listTools();
			for (const t of tools) {
				const name = `graphify_${t.name}`;
				if (registered.has(name)) continue;
				registered.add(name);
				const desc = (t.description ?? t.name).replace(/\s+/g, " ").trim();
				pi.registerTool({
					name,
					label: `Graphify ${t.name}`,
					description: `${desc.slice(0, 600)} (graph: ${found.path})`,
					promptSnippet: firstSentence(desc),
					promptGuidelines:
						t.name === "query_graph"
							? ["Use graphify_query_graph for architecture and 'how does X relate to Y' questions before reading many files; keep token_budget small."]
							: undefined,
					parameters: Type.Unsafe<any>(cleanSchema(t.inputSchema)),
					executionMode: "sequential",
					async execute(_id, params, signal) {
						try {
							const r = await c.callTool(t.name, params, 120_000, signal);
							return { content: [{ type: "text", text: capText(r.text || "(empty result)") }], details: {}, ...(r.isError ? { isError: true } : {}) };
						} catch (e) {
							return { content: [{ type: "text", text: (e as Error).message }], details: {}, isError: true };
						}
					},
				});
			}
		} catch (e) {
			ctx.ui.notify(`graphify native tools unavailable: ${(e as Error).message}`, "warning");
		}
	});

	pi.registerCommand("graphify", {
		description: "Show which graph the native graphify tools are using",
		handler: async (_args, ctx) => {
			ctx.ui.notify(
				graph
					? `graphify tools (${registered.size}) read ${graph.path} (from ${graph.source}); server ${client?.serverInfo?.name ?? "?"} ${client?.serverInfo?.version ?? ""}`
					: "No graph found: run graphify here, or set GRAPHIFY_GRAPH",
				"info",
			);
		},
	});

	pi.on("session_shutdown", async () => {
		client?.stop();
		client = null;
	});
}
