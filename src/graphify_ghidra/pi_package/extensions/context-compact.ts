/**
 * compact_context: lets the agent choose to compact its own context, but only once it is at 80% or more,
 * and always tells the agent afterwards that its context was reset.
 *
 * Why it is shaped this way (verified against Pi's source, not assumed):
 *
 *  - `ctx.compact()` first calls `abort()` on the running agent. A tool that called it directly would kill the very
 *    run that is executing the tool. So the tool only records the request and ends the turn (`terminate: true`);
 *    compaction runs from `agent_settled`, when the agent is idle. This is the same pattern Pi's own reload example
 *    uses for the same reason.
 *  - Compaction replaces older conversation with a summary, so the model no longer "remembers" it. A model that is
 *    not told will happily keep acting as if it did. Every compaction therefore ends with a CONTEXT RESET message
 *    that the model sees: for a compaction the agent asked for it also starts the agent's next turn, so work resumes
 *    by itself; for any other compaction (Pi's automatic threshold/overflow compaction, or the user's /compact) it
 *    is queued for the next model call.
 *  - The agent is warned once when usage crosses the threshold (it cannot otherwise see its own context usage), and
 *    the tool refuses below it, so a model cannot throw its working memory away early.
 *  - An aborted run (the user pressed Escape) drops a pending request instead of compacting behind their back.
 *
 * Threshold: 80%, overridable for testing with PI_COMPACT_MIN_PERCENT (1-100). Note Pi compacts by itself when
 * `contextWindow - reserveTokens` is crossed; if your reserveTokens puts that below 80% of the window, automatic
 * compaction happens first and this tool is rarely reachable.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

function minPercent(): number {
	const v = Number(process.env.PI_COMPACT_MIN_PERCENT);
	return Number.isFinite(v) && v >= 1 && v <= 100 ? v : 80;
}

interface Usage {
	tokens: number | null;
	contextWindow: number;
	percent: number | null;
}

/** Percent of the context window in use (0-100), or null when Pi does not know yet (e.g. right after a compaction). */
function percentOf(u: Usage | undefined): number | null {
	if (!u) return null;
	if (u.percent != null && Number.isFinite(u.percent)) return u.percent;
	if (u.tokens != null && u.contextWindow > 0) return (u.tokens / u.contextWindow) * 100;
	return null;
}

const fmt = (n: number | null | undefined) => (n == null ? "unknown" : n.toLocaleString("en-US"));

function readJson(path: string): Record<string, any> {
	try {
		return JSON.parse(readFileSync(path, "utf8").replace(/^﻿/, ""));
	} catch {
		return {};
	}
}

/** Pi merges global and project settings recursively, the project winning. */
function mergeDeep(a: any, b: any): any {
	if (b === undefined) return a;
	if (a && b && typeof a === "object" && typeof b === "object" && !Array.isArray(a) && !Array.isArray(b)) {
		const out: Record<string, any> = { ...a };
		for (const k of Object.keys(b)) out[k] = mergeDeep(a[k], b[k]);
		return out;
	}
	return b;
}

interface AutoCompaction {
	enabled: boolean;
	reserveTokens: number;
	source: string;
	triggerTokens: number;
	triggerPercent: number;
}

/**
 * When Pi will compact by itself: it starts once usage exceeds `contextWindow - reserveTokens`, where
 * reserveTokens is the model's `compaction.modelOverrides["provider/modelId"]` value, else `compaction.reserveTokens`,
 * else 16384 (global and project settings merged). Read from the settings files, so it is an estimate of Pi's own
 * resolution, not a call into it.
 */
function autoCompaction(cwd: string | undefined, model: { provider?: string; id?: string } | undefined, windowTokens: number): AutoCompaction | null {
	if (!windowTokens || windowTokens <= 0) return null;
	const globalSettings = readJson(join(homedir(), ".pi", "agent", "settings.json"));
	const settings = cwd ? mergeDeep(globalSettings, readJson(join(cwd, ".pi", "settings.json"))) : globalSettings;
	const c = settings.compaction ?? {};
	const key = model?.provider && model?.id ? `${model.provider}/${model.id}` : undefined;
	const override = key ? c.modelOverrides?.[key]?.reserveTokens : undefined;
	const valid = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
	const [reserve, source] = valid(override)
		? [override, `the override for ${key}`]
		: valid(c.reserveTokens)
			? [c.reserveTokens, "compaction.reserveTokens"]
			: [16384, "Pi's default"];
	const trigger = Math.max(0, windowTokens - reserve);
	return { enabled: c.enabled !== false, reserveTokens: reserve, source, triggerTokens: trigger, triggerPercent: (trigger / windowTokens) * 100 };
}

interface Request {
	focus?: string;
	percent: number;
	tokens: number | null;
}

export default function (pi: ExtensionAPI) {
	let pending: Request | null = null;
	let selfCompacting = false; // true while a compaction WE started is running, so session_compact does not double-notify
	let warned = false;

	const hasGhidra = () => {
		try {
			return pi.getAllTools().some((t: { name: string }) => t.name.startsWith("ghidra_"));
		} catch {
			return false;
		}
	};

	/**
	 * The tagged guidance block (rendered by Pi as <context_budget>...</context_budget> in the system prompt). Static
	 * for a given threshold, so the provider's prompt cache stays warm.
	 */
	function budgetGuidance(): string {
		const min = minPercent();
		return [
			"Your context window is a budget for time and attention, not a hard limit to manage anxiously.",
			"- Use check_context sparingly: to decide how much to take on next (before a large read or a long batch of work), not every turn. If unsure, assume you have room.",
			`- Be loose with it. Sitting at 60% or even 75% is fine. Do not wrap up early, shrink your work, or skip reading something useful to save space. Nothing is lost by crossing ${min}%.`,
			`- compact_context only works at ${min}% or more, and even then you do not have to do it at once. Compact only at a good time: after you finish a unit of work, with decisions and progress saved outside your context (files, notes, names, commits). Never mid-edit, mid-investigation, or between a tool result and acting on it. A late compaction at a good time beats an early one at a bad time.`,
			"- After a compaction you will see CONTEXT RESET: older details are gone from your view, so re-read before relying on them.",
		].join("\n");
	}

	/** A plain-text account of where the agent stands: usage, the 80% gate, and Pi's own automatic compaction. */
	function report(ctx: { cwd: string; model?: unknown; getContextUsage: () => unknown }): string {
		const usage = ctx.getContextUsage() as Usage | undefined;
		const pct = percentOf(usage);
		const min = minPercent();
		if (!usage || pct == null) {
			return "Context usage is unknown right now (it is unknown just after a compaction, until the next model response). " +
				"Nothing to act on yet; keep working and check again after your next response.";
		}
		const lines = [`Context: ${fmt(usage.tokens)} of ${fmt(usage.contextWindow)} tokens (${pct.toFixed(0)}%).`];
		const gateTokens = Math.ceil((usage.contextWindow * min) / 100);
		lines.push(
			pct >= min
				? `compact_context: ALLOWED now (threshold ${min}%).`
				: `compact_context: not allowed until ${min}% (about ${fmt(gateTokens)} tokens); ${fmt(Math.max(0, gateTokens - (usage.tokens ?? 0)))} tokens to go.`,
		);
		if (pending) lines.push("A compaction you requested is already scheduled; it runs when this turn ends.");
		const auto = autoCompaction(ctx.cwd, ctx.model as { provider?: string; id?: string } | undefined, usage.contextWindow);
		if (auto && !auto.enabled) {
			lines.push("Pi's automatic compaction: disabled in settings. Only you (compact_context) or the user (/compact) will compact; if the window fills, the request will fail.");
		} else if (auto) {
			lines.push(
				`Pi's automatic compaction: starts above ${fmt(auto.triggerTokens)} tokens (${auto.triggerPercent.toFixed(0)}%), reserve ${fmt(auto.reserveTokens)} from ${auto.source}` +
					(usage.tokens != null ? `; ${fmt(Math.max(0, auto.triggerTokens - usage.tokens))} tokens of room left.` : "."),
			);
			if (auto.triggerPercent < min) {
				lines.push(
					`NOTE: Pi will compact automatically at ${auto.triggerPercent.toFixed(0)}%, before the ${min}% threshold, so compact_context will never become available ` +
						"for this model. You cannot choose when; Pi decides, and you will be told afterwards. Keep your working state written down outside your context.",
				);
			} else if (pct >= auto.triggerPercent - 5) {
				lines.push("You are close to Pi's automatic compaction. If you want to control what the summary keeps, finish the current unit of work and then call compact_context with focus.");
			}
		}
		lines.push("Budget note: be loose about this, and compact only at a good time (a unit of work finished, state saved outside your context).");
		return lines.join("\n");
	}

	/** The message the agent reads after its context was replaced by a summary. */
	function resetMessage(opts: { tokensBefore?: number; tokensAfter?: number; percent?: number; why: string; focus?: string }) {
		const lines = [
			"CONTEXT RESET.",
			`Your context was compacted (${opts.why}).` +
				(opts.percent != null ? ` It was at ${opts.percent.toFixed(0)}% of the window.` : "") +
				(opts.tokensBefore != null ? ` About ${fmt(opts.tokensBefore)} tokens before` : "") +
				(opts.tokensAfter != null ? `, about ${fmt(opts.tokensAfter)} after.` : opts.tokensBefore != null ? "." : ""),
			"",
			"What this means for you:",
			"- Everything older than the summary at the top of your context is no longer visible to you. You keep that summary and the most recent messages, nothing else. You are not in the state you were in a moment ago.",
			"- Do not trust your memory of earlier tool output, file contents, identifiers or addresses. Re-read or re-query anything you are about to edit, quote or rely on.",
			"- State that lives outside your context is unchanged: files on disk, git history, saved notes, and any graph or annotation store." +
				(hasGhidra() ? " ghidra_status shows what has been named so far." : ""),
			"- Your original task has not changed. Read the summary, say in one or two lines what your current goal and next step are, then carry on.",
		];
		if (opts.focus) lines.push("", `You asked the summary to keep: ${opts.focus}`);
		return { customType: "context-reset", content: lines.join("\n"), display: true };
	}

	pi.registerTool({
		name: "check_context",
		label: "Check context",
		description:
			"Report how full your context window is, whether compact_context is allowed yet, and when Pi will compact automatically. " +
			"Read-only and cheap, but use it sparingly: to budget how much to take on next (before a large read or a long batch of work), not every turn. " +
			"Be loose about the answer; there is no need to economise until you are told you have crossed the compaction threshold.",
		promptSnippet: "Check context usage to budget how much to take on next (sparingly; be loose)",
		promptGuidelines: [
			"Use check_context sparingly, to budget time before a large read or long batch of work rather than every turn, and treat its numbers loosely.",
		],
		parameters: Type.Object({}),
		executionMode: "sequential",
		async execute(_id, _params, _signal, _update, ctx) {
			return { content: [{ type: "text", text: report(ctx as never) }], details: {} };
		},
	});

	pi.registerTool({
		name: "compact_context",
		label: "Compact context",
		description:
			`Compact your own context (replace older conversation with a summary). Only allowed when your context is at ${minPercent()}% or more; ` +
			"below that it refuses and tells you your usage. Be loose about it: you never have to compact the moment you are allowed. Compact only at a good time, " +
			"meaning a unit of work is finished and your decisions and progress are saved outside your context; never mid-edit or mid-investigation. Compaction runs once this turn " +
			"ends, then you receive a CONTEXT RESET message: everything older than the summary is gone from your view, so re-read what you need. " +
			"Use focus to say what the summary must keep. check_only=true just reports usage.",
		promptSnippet: `Compact your context, only at a good time and only at ${minPercent()}% or more (it refuses below that)`,
		promptGuidelines: [
			`Use compact_context only at a good time (a unit of work finished, state saved outside your context) and only once you are at ${minPercent()}% or more; it is fine to wait. After it you will get a CONTEXT RESET message, and anything older than the summary must be re-read, not remembered.`,
		],
		parameters: Type.Object({
			focus: Type.Optional(
				Type.String({ description: "What the summary must preserve: goal, decisions, identifiers, open questions, next steps" }),
			),
			check_only: Type.Optional(Type.Boolean({ description: "Only report context usage; do not compact" })),
		}),
		executionMode: "sequential",
		async execute(_id, params, _signal, _update, ctx) {
			const usage = ctx.getContextUsage() as Usage | undefined;
			const pct = percentOf(usage);
			const min = minPercent();
			const where = usage
				? `${fmt(usage.tokens)} of ${fmt(usage.contextWindow)} tokens` + (pct != null ? ` (${pct.toFixed(0)}%)` : "")
				: "unknown";
			if (pct == null) {
				return {
					content: [{ type: "text", text: `Context usage is unknown right now (${where}); it is unknown just after a compaction until the next model response. Not compacting. Keep working.` }],
					details: {},
				};
			}
			if (params.check_only) {
				return { content: [{ type: "text", text: report(ctx as never) }], details: {} };
			}
			if (pct < min) {
				return {
					content: [{ type: "text", text: `Refused: your context is at ${pct.toFixed(0)}% (${where}), below the ${min}% threshold. Compacting now would discard working memory you do not need to lose yet. Keep working; you will be told when you cross ${min}%.` }],
					details: {},
				};
			}
			if (pending) {
				return { content: [{ type: "text", text: "A compaction is already scheduled. Finish this turn without further tool calls." }], details: {} };
			}
			pending = { focus: params.focus?.trim() || undefined, percent: pct, tokens: usage?.tokens ?? null };
			return {
				content: [{
					type: "text",
					text:
						`Compaction scheduled (context at ${pct.toFixed(0)}%, ${where}). This turn ends now: do not call more tools. ` +
						"Once it finishes you will receive a message headed CONTEXT RESET. Everything before the summary will be gone from your view, so expect to re-orient and re-read what you need, then continue your task.",
				}],
				details: {},
				terminate: true, // ends the run so agent_settled fires and compaction can start while the agent is idle
			};
		},
	});

	// The tagged guidance: a custom system-prompt section, which Pi wraps as <context_budget>...</context_budget>.
	pi.on("before_agent_start", async (event) => {
		const opts = (event as { systemPromptOptions?: { sections?: Record<string, string> } }).systemPromptOptions;
		if (!opts) return;
		opts.sections = opts.sections ?? {};
		opts.sections.context_budget = budgetGuidance();
	});

	// The agent cannot see its own usage, so tell it once when it crosses the threshold.
	pi.on("turn_end", async (_event, ctx) => {
		const p = percentOf(ctx.getContextUsage() as Usage | undefined);
		if (p == null) return;
		const min = minPercent();
		if (p < min - 10) warned = false; // re-arm only after usage has clearly dropped
		if (p >= min && !warned && !pending) {
			warned = true;
			pi.sendMessage(
				{
					customType: "context-warning",
					content:
						`Context is at ${p.toFixed(0)}% of your window (check_context shows details). compact_context is now allowed, but you do not have to compact immediately. ` +
						"Keep working, and compact at a good time: after you finish a unit of work with your progress saved outside your context, never mid-edit. " +
						"Pass focus to say what must survive. Compaction replaces older conversation with a summary, and you will be told when it has happened.",
					display: true,
				},
				{ deliverAs: "steer" },
			);
		}
	});

	// Run the requested compaction once the agent is idle. ctx.compact() aborts the running agent, so never earlier.
	pi.on("agent_settled", async (event, ctx) => {
		if (!pending) return;
		const req = pending;
		pending = null;
		if (event.aborted) {
			if (ctx.hasUI) ctx.ui.notify("Compaction request dropped: the run was aborted.", "info");
			return;
		}
		selfCompacting = true;
		if (ctx.hasUI) ctx.ui.notify(`Compacting context (${req.percent.toFixed(0)}%)...`, "info");
		const instructions =
			`The agent chose to compact at ${req.percent.toFixed(0)}% usage while it was working. Make the summary good enough to continue the task ` +
			"without the old messages: keep the goal, decisions and the reasons for them, every name/identifier/address/path assigned or touched, " +
			"what is done, what is in progress, open questions, and the exact next steps." +
			(req.focus ? ` The agent specifically asked to keep: ${req.focus}` : "");
		ctx.compact({
			customInstructions: instructions,
			onComplete: (result: { tokensBefore?: number; estimatedTokensAfter?: number }) => {
				selfCompacting = false;
				warned = false;
				// triggerTurn: the agent is idle, so this starts its next turn and work resumes by itself.
				pi.sendMessage(
					resetMessage({
						tokensBefore: result?.tokensBefore ?? req.tokens ?? undefined,
						tokensAfter: result?.estimatedTokensAfter,
						percent: req.percent,
						why: "at your request",
						focus: req.focus,
					}),
					{ triggerTurn: true, deliverAs: "followUp" },
				);
			},
			onError: (error: Error) => {
				selfCompacting = false;
				pi.sendMessage(
					{
						customType: "context-reset",
						content:
							`COMPACTION FAILED: ${error.message}. Your context was NOT reset; nothing was lost. ` +
							"Continue working. If you are near the limit, keep tool output small; compact_context may be tried again later.",
						display: true,
					},
					{ triggerTurn: true, deliverAs: "followUp" },
				);
			},
		});
	});

	// Any compaction we did not start (Pi's automatic threshold/overflow compaction, or the user's /compact):
	// the agent must still be told its context was replaced. Queued, not a new turn.
	pi.on("session_compact", async (event) => {
		if (selfCompacting) return; // ours is announced by onComplete, with a turn
		warned = false;
		const entry = (event as { compactionEntry?: { tokensBefore?: number } }).compactionEntry;
		const reason = (event as { reason?: string }).reason;
		const why =
			reason === "manual" ? "the user ran /compact" : reason === "overflow" ? "Pi compacted automatically after the context overflowed" : "Pi compacted automatically at its context threshold";
		pi.sendMessage(resetMessage({ tokensBefore: entry?.tokensBefore, why }), { deliverAs: "steer" });
	});
}
