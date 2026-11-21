/**
 * A minimal MCP (Model Context Protocol) stdio client, used to expose MCP servers as *native* Pi tools.
 *
 * Deliberately dependency-free and erasable-TypeScript only (no enums / parameter properties), so it loads
 * under Pi's jiti and also under plain `node` for tests. It speaks newline-delimited JSON-RPC 2.0:
 * initialize -> notifications/initialized -> tools/list, tools/call. One child process is kept alive for the
 * session; server state (e.g. an opened binary) therefore persists between calls.
 */

import { spawn } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join } from "node:path";

export interface McpTool {
	name: string;
	description?: string;
	inputSchema?: Record<string, unknown>;
}

export interface ServerSpec {
	command: string;
	args: string[];
	env?: Record<string, string>;
	cwd?: string;
}

export interface CallResult {
	text: string;
	isError: boolean;
}

interface Pending {
	resolve: (v: any) => void;
	reject: (e: Error) => void;
	timer: ReturnType<typeof setTimeout>;
}

const PROTOCOL_VERSION = "2025-03-26";

// ---------------------------------------------------------------------------- config

function stripJsonComments(text: string): string {
	// Conservative: only whole-line // comments and /* */ blocks outside strings are handled well enough for
	// hand-edited MCP configs; anything fancier falls through to a JSON.parse error the caller reports.
	return text.replace(/^\s*\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
}

function readJson(path: string): any | null {
	try {
		const raw = readFileSync(path, "utf8").replace(/^﻿/, "");
		try {
			return JSON.parse(raw);
		} catch {
			return JSON.parse(stripJsonComments(raw));
		}
	} catch {
		return null;
	}
}

function expandHome(s: string): string {
	return s.startsWith("~/") || s.startsWith("~\\") ? join(homedir(), s.slice(2)) : s;
}

/** Look a server up in Pi's and the global MCP config; the user's existing entry is the source of truth. */
export function loadServerSpec(name: string): ServerSpec | null {
	const files = [join(homedir(), ".pi", "agent", "mcp.json"), join(homedir(), ".config", "mcp", "mcp.json")];
	for (const f of files) {
		const cfg = readJson(f);
		const entry = cfg?.mcpServers?.[name] ?? cfg?.servers?.[name];
		if (entry && typeof entry.command === "string") {
			const env: Record<string, string> = {};
			for (const [k, v] of Object.entries(entry.env ?? {})) if (typeof v === "string") env[k] = v;
			return {
				command: expandHome(entry.command),
				args: Array.isArray(entry.args) ? entry.args.map((a: unknown) => expandHome(String(a))) : [],
				env,
				cwd: typeof entry.cwd === "string" ? expandHome(entry.cwd) : undefined,
			};
		}
	}
	return null;
}

/**
 * On Windows, npm-installed CLIs are `.cmd` shims, which cannot be spawned without a shell (and a shell would
 * re-parse arguments). Resolve the shim to the package's real node entry point instead.
 */
export function resolveCommand(command: string, args: string[]): { command: string; args: string[] } {
	if (process.platform !== "win32" || /[\\/]/.test(command) || /\.(exe|com)$/i.test(command)) {
		return { command, args };
	}
	for (const dir of (process.env.PATH ?? "").split(delimiter)) {
		if (!dir) continue;
		const exe = join(dir, command + ".exe");
		if (existsSync(exe)) return { command: exe, args };
		if (!existsSync(join(dir, command + ".cmd"))) continue;
		const nm = join(dir, "node_modules");
		let pkgs: string[] = [];
		try {
			pkgs = readdirSync(nm).flatMap((p) => (p.startsWith("@") ? readdirSync(join(nm, p)).map((q) => join(p, q)) : [p]));
		} catch {
			/* no global node_modules next to the shim */
		}
		for (const p of pkgs) {
			const pj = readJson(join(nm, p, "package.json"));
			const bin = typeof pj?.bin === "string" ? (pj.name === command ? pj.bin : null) : pj?.bin?.[command];
			if (bin) return { command: process.execPath, args: [join(nm, p, bin), ...args] };
		}
	}
	return { command, args };
}

// ---------------------------------------------------------------------------- client

export class McpClient {
	spec: ServerSpec;
	label: string;
	private child: ReturnType<typeof spawn> | null = null;
	private starting: Promise<void> | null = null;
	private pending = new Map<number, Pending>();
	private nextId = 1;
	private buf = "";
	private stderrTail = "";
	serverInfo: { name?: string; version?: string } = {};

	constructor(spec: ServerSpec, label: string) {
		this.spec = spec;
		this.label = label;
	}

	get running(): boolean {
		return this.child !== null && this.child.exitCode === null;
	}

	/** Start (once) and complete the MCP handshake. Safe to call concurrently. */
	ensure(timeoutMs = 60_000): Promise<void> {
		if (this.running && !this.starting) return Promise.resolve();
		if (this.starting) return this.starting;
		this.starting = this.start(timeoutMs).finally(() => {
			this.starting = null;
		});
		return this.starting;
	}

	private async start(timeoutMs: number): Promise<void> {
		const { command, args } = resolveCommand(this.spec.command, this.spec.args);
		const child = spawn(command, args, {
			cwd: this.spec.cwd,
			env: { ...process.env, ...(this.spec.env ?? {}) },
			stdio: ["pipe", "pipe", "pipe"],
			windowsHide: true,
		});
		this.child = child;
		this.buf = "";
		child.stdout!.setEncoding("utf8");
		child.stdout!.on("data", (c: string) => this.onData(c));
		child.stderr!.setEncoding("utf8");
		child.stderr!.on("data", (c: string) => {
			this.stderrTail = (this.stderrTail + c).slice(-1500);
		});
		const fail = (why: string) => {
			if (this.child === child) this.child = null;
			for (const [id, p] of this.pending) {
				clearTimeout(p.timer);
				p.reject(new Error(why));
				this.pending.delete(id);
			}
		};
		child.on("error", (e) => fail(`could not start ${this.label} ('${command}'): ${e.message}`));
		child.on("exit", (code) => fail(`${this.label} exited (${code}). ${this.stderrTail.trim().slice(-400)}`));

		const init = await this.request(
			"initialize",
			{ protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "graphify-ghidra-pi", version: "0.1.0" } },
			timeoutMs,
		);
		this.serverInfo = init?.serverInfo ?? {};
		this.notify("notifications/initialized", {});
	}

	private onData(chunk: string): void {
		this.buf += chunk;
		let i: number;
		while ((i = this.buf.indexOf("\n")) >= 0) {
			const line = this.buf.slice(0, i).trim();
			this.buf = this.buf.slice(i + 1);
			if (!line) continue;
			let msg: any;
			try {
				msg = JSON.parse(line);
			} catch {
				continue; // not protocol (a banner or log line)
			}
			if (msg.id !== undefined && (msg.result !== undefined || msg.error !== undefined) && this.pending.has(msg.id)) {
				const p = this.pending.get(msg.id)!;
				clearTimeout(p.timer);
				this.pending.delete(msg.id);
				if (msg.error) p.reject(new Error(`${this.label}: ${msg.error.message ?? JSON.stringify(msg.error)}`));
				else p.resolve(msg.result);
			} else if (msg.method && msg.id !== undefined) {
				// A server-initiated request. We advertise no capabilities, so only ping is legitimate.
				const reply =
					msg.method === "ping"
						? { jsonrpc: "2.0", id: msg.id, result: {} }
						: { jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "method not supported by this client" } };
				this.write(reply);
			}
		}
	}

	private write(obj: unknown): void {
		this.child?.stdin?.write(JSON.stringify(obj) + "\n");
	}

	private notify(method: string, params: unknown): void {
		this.write({ jsonrpc: "2.0", method, params });
	}

	private request(method: string, params: unknown, timeoutMs: number, signal?: AbortSignal): Promise<any> {
		return new Promise((resolve, reject) => {
			if (signal?.aborted) return reject(new Error("cancelled"));
			if (!this.child) return reject(new Error(`${this.label} is not running`));
			const id = this.nextId++;
			const timer = setTimeout(() => {
				this.pending.delete(id);
				reject(new Error(`${this.label}: ${method} timed out after ${Math.round(timeoutMs / 1000)}s`));
			}, timeoutMs);
			this.pending.set(id, { resolve, reject, timer });
			signal?.addEventListener("abort", () => {
				const p = this.pending.get(id);
				if (p) {
					clearTimeout(p.timer);
					this.pending.delete(id);
					reject(new Error("cancelled"));
					this.notify("notifications/cancelled", { requestId: id, reason: "cancelled by the client" });
				}
			});
			this.write({ jsonrpc: "2.0", id, method, params });
		});
	}

	async listTools(timeoutMs = 60_000): Promise<McpTool[]> {
		await this.ensure();
		const out: McpTool[] = [];
		let cursor: string | undefined;
		for (let page = 0; page < 20; page++) {
			const res = await this.request("tools/list", cursor ? { cursor } : {}, timeoutMs);
			out.push(...((res?.tools ?? []) as McpTool[]));
			cursor = res?.nextCursor;
			if (!cursor) break;
		}
		return out;
	}

	async callTool(name: string, args: unknown, timeoutMs = 300_000, signal?: AbortSignal): Promise<CallResult> {
		await this.ensure();
		const res = await this.request("tools/call", { name, arguments: args ?? {} }, timeoutMs, signal);
		const parts: string[] = [];
		for (const c of res?.content ?? []) {
			if (c.type === "text" && typeof c.text === "string") parts.push(c.text);
			else if (c.type === "image") parts.push("[image omitted]");
			else if (c.type === "resource" && c.resource?.text) parts.push(String(c.resource.text));
			else parts.push(`[${c.type ?? "content"} omitted]`);
		}
		let text = parts.join("\n");
		if (!text && res?.structuredContent !== undefined) text = JSON.stringify(res.structuredContent);
		return { text, isError: Boolean(res?.isError) };
	}

	stop(): void {
		const c = this.child;
		this.child = null;
		if (c) {
			try {
				c.stdin?.end(); // well-behaved servers exit on EOF and clean up what they started
			} catch {
				/* already gone */
			}
			setTimeout(() => {
				try {
					c.kill();
				} catch {
					/* gone */
				}
			}, 8000).unref();
		}
	}
}

/** Strip keys some validators reject, keeping the rest of the server's JSON Schema intact. */
export function cleanSchema(schema: Record<string, unknown> | undefined): Record<string, unknown> {
	const s = { ...(schema ?? { type: "object", properties: {} }) } as Record<string, unknown>;
	delete s["$schema"];
	if (s.type === undefined) s.type = "object";
	if (s.type === "object" && s.properties === undefined) s.properties = {};
	return s;
}

export function dirOf(p: string): string {
	return dirname(p);
}
