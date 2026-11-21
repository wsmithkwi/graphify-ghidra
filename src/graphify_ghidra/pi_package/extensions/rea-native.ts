/**
 * Native REA (Reverse Engineer Anything) tools for Pi.
 *
 * REA exposes ~255 MCP tools; putting all of them in front of a model is useless (and costs the context a small
 * local model does not have). So:
 *
 *   rea_tools   search the REA catalogue by keyword, or fetch one tool's full description and input schema
 *   rea_call    call any REA tool by name with JSON arguments (output capped; high-impact tools ask first)
 *   rea_<tool>  the everyday read-only native-analysis tools promoted to direct tools with REA's own schemas
 *               (open_binary, list_procedures, analyze_function, procedure_pseudo_code, xrefs, ...)
 *
 * The server is the user's own entry from their MCP config (`rea mcp` with its Ghidra environment), started on
 * first use and kept alive for the session, so an opened binary stays open between calls. The catalogue is cached
 * on disk so the direct tools exist from session start without launching REA.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { McpClient, cleanSchema, loadServerSpec, type McpTool } from "./lib/mcp-client.ts";

/** Everyday read-only analysis tools worth having as direct tools. Only those REA actually serves are registered. */
const CURATED = [
	"open_binary", "binary_session", "list_procedures", "search_procedures", "analyze_function",
	"procedure_pseudo_code", "procedure_references", "procedure_callers", "procedure_callees", "xrefs",
	"list_strings", "search_strings", "list_segments", "inspect_analysis_view",
];

/**
 * Tools that run, instrument, drive or change something (execute, observe, frida, debug sessions, capture,
 * install, start/stop, annotate/set...) need a human yes. Calibrated against REA 6.9's real catalogue: read-only
 * parsers (inspect_*, list_*, compare_*, decode_*, identify_*) and *_status are exempt even when their names
 * mention "capture" or "frida", and uninstall / act_on_* are added because their verbs hide inside longer names.
 */
const RISKY_VERB = /(^|_)(execute|launch|run|spawn|inject|attach|debug|emulate|patch|mutate|capture|install|uninstall|download|delete|kill|apply|observe|write|start|stop|set|update|annotate|rename|act_on|instrument)(_|$)|frida/i;
const READ_ONLY_PREFIX = /^(inspect|list|compare|decode|identify|check|measure)_|_status$/;
const isRisky = (name: string): boolean => RISKY_VERB.test(name) && !READ_ONLY_PREFIX.test(name);

const CACHE = join(homedir(), ".pi", "agent", "cache", "graphify-ghidra-rea-tools.json");
const DEFAULT_MAX_CHARS = 20_000;

function readCache(): McpTool[] | null {
	try {
		const c = JSON.parse(readFileSync(CACHE, "utf8"));
		return Array.isArray(c.tools) && c.tools.length ? (c.tools as McpTool[]) : null;
	} catch {
		return null;
	}
}

function writeCache(tools: McpTool[], version: string | undefined): void {
	try {
		if (!existsSync(dirname(CACHE))) mkdirSync(dirname(CACHE), { recursive: true });
		// Keep full schemas only for the curated tools; the rest need just a name and a short description.
		const slim = tools.map((t) =>
			CURATED.includes(t.name) ? t : { name: t.name, description: (t.description ?? "").slice(0, 300) },
		);
		writeFileSync(CACHE, JSON.stringify({ version, tools: slim }));
	} catch {
		/* cache is an optimisation only */
	}
}

function capChars(text: string, max: number): string {
	if (text.length <= max) return text;
	return (
		text.slice(0, max) +
		`\n\n[cut at ${max} of ${text.length} characters. REA keeps full results as Evidence: page them with ` +
		`inspect_analysis_view (offset/limit) or raise max_chars (up to 50000).]`
	);
}

function oneLine(s: string | undefined, n: number): string {
	const t = (s ?? "").replace(/\s+/g, " ").trim();
	return t.length > n ? t.slice(0, n - 1) + "…" : t;
}

export default function (pi: ExtensionAPI) {
	let client: McpClient | null = null;
	let catalogue: McpTool[] | null = readCache();
	let serverVersion: string | undefined;
	const registered = new Set<string>();

	const getClient = (cwd?: string): McpClient => {
		if (!client) {
			const spec = loadServerSpec("rea") ?? { command: "rea", args: ["mcp"] };
			client = new McpClient({ ...spec, cwd: spec.cwd ?? cwd }, "rea");
		}
		return client;
	};

	const promote = (tools: McpTool[]) => {
		for (const t of tools) {
			if (!CURATED.includes(t.name) || !t.inputSchema) continue; // cache entries without a schema cannot be direct tools
			const name = `rea_${t.name}`;
			if (registered.has(name)) continue;
			registered.add(name);
			const desc = oneLine(t.description, 700);
			pi.registerTool({
				name,
				label: `REA ${t.name}`,
				description: desc || t.name,
				promptSnippet: oneLine(t.description, 110),
				parameters: Type.Unsafe<any>(cleanSchema(t.inputSchema)),
				executionMode: "sequential", // one REA session: calls must not interleave
				async execute(_id, params, signal, _u, ctx) {
					return runRea(t.name, params, DEFAULT_MAX_CHARS, signal, ctx.cwd);
				},
			});
		}
	};

	async function ensureCatalogue(cwd?: string, force = false): Promise<McpTool[]> {
		if (catalogue && !force && catalogue.some((t) => t.inputSchema)) return catalogue;
		const c = getClient(cwd);
		const tools = await c.listTools();
		serverVersion = c.serverInfo?.version;
		catalogue = tools;
		writeCache(tools, serverVersion);
		promote(tools);
		return tools;
	}

	async function runRea(tool: string, args: unknown, maxChars: number, signal: AbortSignal | undefined, cwd: string) {
		try {
			const r = await getClient(cwd).callTool(tool, args, 600_000, signal);
			return {
				content: [{ type: "text" as const, text: capChars(r.text || "(empty result)", maxChars) }],
				details: {},
				...(r.isError ? { isError: true } : {}),
			};
		} catch (e) {
			return { content: [{ type: "text" as const, text: (e as Error).message }], details: {}, isError: true };
		}
	}

	if (catalogue) promote(catalogue); // direct tools from the cache, available at session start

	pi.registerTool({
		name: "rea_tools",
		label: "REA tool search",
		description:
			"Search REA's ~255 reverse-engineering tools by keyword (query), or pass name to get one tool's full description and input schema. " +
			"Use before rea_call to find the right tool and its arguments.",
		promptSnippet: "Search REA's reverse-engineering tool catalogue / show a tool's schema",
		parameters: Type.Object({
			query: Type.Optional(Type.String({ description: "Keywords, e.g. 'pe imports' or 'decompile'" })),
			name: Type.Optional(Type.String({ description: "Exact tool name to describe in full" })),
			limit: Type.Optional(Type.Number({ description: "Max results (default 12, max 30)" })),
		}),
		async execute(_id, params, _signal, _u, ctx) {
			try {
				const tools = await ensureCatalogue(ctx.cwd);
				if (params.name) {
					const t = tools.find((x) => x.name === params.name);
					if (!t) {
						const near = tools.filter((x) => x.name.includes(params.name!.toLowerCase())).slice(0, 8).map((x) => x.name);
						return { content: [{ type: "text", text: `No REA tool named '${params.name}'.` + (near.length ? ` Similar: ${near.join(", ")}` : "") }], details: {} };
					}
					const schema = JSON.stringify(cleanSchema(t.inputSchema));
					return {
						content: [{ type: "text", text: `${t.name}\n${t.description ?? ""}\n\ninput schema:\n${capChars(schema, 6000)}\n\nCall it with rea_call {tool: "${t.name}", arguments: {...}}.` }],
						details: {},
					};
				}
				const limit = Math.min(30, Math.max(1, Math.floor(params.limit ?? 12)));
				const words = (params.query ?? "").toLowerCase().split(/\s+/).filter(Boolean);
				if (!words.length) {
					return {
						content: [{
							type: "text",
							text: `REA has ${tools.length} tools. Everyday ones are direct tools (rea_open_binary, rea_list_procedures, rea_analyze_function, ...). ` +
								`Search with query=..., e.g. "pe imports", "elf", "apk", "javascript", "memory", "compare".`,
						}],
						details: {},
					};
				}
				const scored = tools
					.map((t) => {
						const name = t.name.toLowerCase();
						const desc = (t.description ?? "").toLowerCase();
						let s = 0;
						for (const w of words) s += (name.includes(w) ? 3 : 0) + (desc.includes(w) ? 1 : 0);
						return { t, s };
					})
					.filter((x) => x.s > 0)
					.sort((a, b) => b.s - a.s)
					.slice(0, limit);
				const lines = scored.map(({ t }) => `${t.name} - ${oneLine(t.description, 130)}`);
				return {
					content: [{ type: "text", text: lines.length ? `${lines.length} match(es):\n${lines.join("\n")}\n\nUse rea_tools name=<tool> for its schema, then rea_call.` : `No REA tool matches '${params.query}'.` }],
					details: {},
				};
			} catch (e) {
				return { content: [{ type: "text", text: (e as Error).message }], details: {}, isError: true };
			}
		},
	});

	pi.registerTool({
		name: "rea_call",
		label: "REA call",
		description:
			"Call any REA tool by name with JSON arguments. Find tools and schemas with rea_tools. Output is capped (max_chars, default 20000). " +
			"Tools that run, instrument or change a target ask the user for confirmation first.",
		promptSnippet: "Call any REA reverse-engineering tool by name with JSON arguments",
		promptGuidelines: [
			"Use rea_tools to find the right REA tool and its schema before rea_call; open a binary with rea_open_binary first.",
		],
		parameters: Type.Object({
			tool: Type.String({ description: "REA tool name, e.g. inspect_pe" }),
			arguments: Type.Optional(Type.Object({}, { additionalProperties: true, description: "Arguments per the tool's schema" })),
			max_chars: Type.Optional(Type.Number({ description: "Cap on returned characters (default 20000, max 50000)" })),
		}),
		async execute(_id, params, signal, _u, ctx) {
			try {
				const tools = await ensureCatalogue(ctx.cwd);
				if (!tools.some((t) => t.name === params.tool)) {
					const near = tools.filter((t) => t.name.includes(params.tool.toLowerCase().slice(0, 12))).slice(0, 8).map((t) => t.name);
					return { content: [{ type: "text", text: `No REA tool named '${params.tool}'. ` + (near.length ? `Similar: ${near.join(", ")}. ` : "") + "Use rea_tools to search." }], details: {}, isError: true };
				}
				if (isRisky(params.tool)) {
					if (!ctx.hasUI) {
						return { content: [{ type: "text", text: `'${params.tool}' can run, instrument or change a target; it needs interactive confirmation and this session has no UI.` }], details: {}, isError: true };
					}
					const ok = await ctx.ui.confirm("REA: high-impact tool", `Allow rea_call ${params.tool}?\n\n${JSON.stringify(params.arguments ?? {}).slice(0, 600)}`);
					if (!ok) return { content: [{ type: "text", text: "The user declined this REA call." }], details: {}, isError: true };
				}
				const max = Math.min(50_000, Math.max(2_000, Math.floor(params.max_chars ?? DEFAULT_MAX_CHARS)));
				return await runRea(params.tool, params.arguments ?? {}, max, signal, ctx.cwd);
			} catch (e) {
				return { content: [{ type: "text", text: (e as Error).message }], details: {}, isError: true };
			}
		},
	});

	pi.registerCommand("rea", {
		description: "Connect to REA and show its tool catalogue size",
		handler: async (_args, ctx) => {
			try {
				const tools = await ensureCatalogue(ctx.cwd, true);
				ctx.ui.notify(`REA ${serverVersion ?? ""}: ${tools.length} tools; ${registered.size} direct (rea_*), plus rea_tools / rea_call`, "info");
			} catch (e) {
				ctx.ui.notify(`REA unavailable: ${(e as Error).message}`, "error");
			}
		},
	});

	pi.on("session_shutdown", async () => {
		client?.stop();
		client = null;
	});
}
