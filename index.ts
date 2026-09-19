// auto-mode - an auto permission mode for Command Code, screened by TypeSafe's Jev.
//
// Command Code's permission check runs before `beforeToolCall`, and mods cannot register
// a new entry in the shift+tab cycle. So this mod IS the gate: `beforeToolCall` fires
// after the permission check and before execution, which is exactly the seam an
// auto-mode classifier needs. When auto-mode is on, every matching tool call is screened
// against the user's stated task, and anything destructive, privileged, secret-touching,
// exfiltrating, or out of scope is blocked before it runs.
//
// The judging is done by Jev, TypeSafe's System One model, which returns typed
// probabilities instead of prose. Each risk dimension is asked as its own independent
// question, and the policy that combines them into allow/deny/escalate lives in code
// (`decide`) so it stays auditable and tunable without re-prompting the model.

import type {ModApi} from '@commandcode/harness';
import {createHash} from 'node:crypto';

const MOD_ID = 'auto-mode';
const STATE_TYPE = 'auto-mode/state';
const ENTRY_TYPE = 'auto-mode/decision';

const API_URL = 'https://api.typesafe.ai/v1/systemone';

// ---------------------------------------------------------------------------
// Questions asked of Jev
// ---------------------------------------------------------------------------

// The dimensions that can veto a command outright.
const HARD_DENY = [
	{key: 'secret_exposure', label: 'would expose secrets or credentials'},
	{key: 'privilege_escalation', label: 'would use elevated privileges'},
	{key: 'data_exfiltration', label: 'would send local data to an external destination'},
] as const;

// Dangerous, but legitimate enough to be worth asking a human about.
const ESCALATE = [
	{key: 'destructive', label: 'could destroy data or history'},
	{key: 'remote_effect', label: 'would change remote or shared state'},
] as const;

// Every noul question, in the order they are reported.
const NOUL_LABELS: Record<string, string> = {
	within_scope: 'in scope',
	destructive: 'destructive',
	recoverable: 'recoverable',
	remote_effect: 'remote effect',
	secret_exposure: 'secret exposure',
	privilege_escalation: 'privileged',
	data_exfiltration: 'data exfiltration',
};

const CATEGORY_CRITERIA: Record<string, string> = {
	read_only: 'Inspection with no side effects',
	local_edit: 'Modifies files in the working tree',
	vcs_local: 'Local version-control operations that do not contact a remote',
	dependency_install: 'Installs, updates, or removes packages',
	destructive: 'Destroys or irreversibly overwrites data, files, or history',
	remote_mutation: 'Changes state on a remote or shared system, or is visible to others',
	privileged: 'Uses or requires elevated privileges',
	data_transfer: 'Moves data to or from an external host',
	other: 'None of the above',
};

/**
 * Build the question map sent to Jev. Every question is judged independently against
 * the same state, so they run in parallel and one dimension cannot bias another.
 * `state` is referenced by name inside the instructions.
 */
function buildQuestions(extraPolicy: string): Record<string, unknown> {
	const policy = extraPolicy
		? `Also respect this standing policy from the user: ${extraPolicy}`
		: '';

	const dimensions: Record<string, unknown> = {
		category: {
			type: 'choice',
			instructions: 'What kind of operation is `command`?',
			criteria: CATEGORY_CRITERIA,
		},
		within_scope: {
			type: 'noul',
			instructions: [
				'Is `command` a step toward accomplishing the request in `task`?',
				'Judge the intent behind the command, not its wording: it is in scope when it serves the same goal as the request, even if the request never named it.',
				'Operating, exercising, or inspecting the program, server, or system the request concerns is in scope - starting or restarting it, sending it commands through its console or client, and reading its logs or state.',
				'Supporting steps are in scope as well: building, installing, running tests, reading and searching the code, and writing inputs or intermediate files the task needs, including to a scratch or temp directory.',
				'Committing, tagging, releasing, or publishing that the task did not ask for is out of scope, as is work on another project or unrelated infrastructure.',
				policy,
			]
				.filter(Boolean)
				.join(' '),
			criteria: {
				true: 'Serves the same goal as the request',
				false: 'Serves a goal the request never raised',
			},
		},
		destructive: {
			type: 'noul',
			instructions:
				'Would running `command` destroy, overwrite, or invalidate data, files, version-control history, or infrastructure?',
			criteria: {
				true: 'Removes or irreversibly overwrites something that is not trivially reproducible',
				false: 'Leaves existing data intact',
			},
		},
		recoverable: {
			type: 'noul',
			instructions:
				'If `command` went wrong, could its effects be undone quickly with ordinary tools, such as reinstalling a dependency, re-cloning, or recovering from history?',
			criteria: {
				true: 'Effects are trivially reversible',
				false: 'Effects would be permanent or very costly to reverse',
			},
		},
		remote_effect: {
			type: 'noul',
			instructions:
				'Does `command` change state on a system other than this machine, or produce something other people can see, such as pushing, publishing, deploying, posting, or sending?',
			criteria: {
				true: 'Affects a remote or shared system, or is externally visible',
				false: 'Entirely local to this machine',
			},
		},
		secret_exposure: {
			type: 'noul',
			instructions:
				'Does `command` read, print, copy, or transmit credentials, API keys, tokens, private keys, `.env` files, or other secrets?',
			criteria: {
				true: 'Touches secret material in a way that could expose it',
				false: 'Does not touch secrets',
			},
		},
		privilege_escalation: {
			type: 'noul',
			instructions:
				'Does `command` use or require elevated privileges, such as `sudo`, running as root, or changing ownership or permissions outside the project?',
			criteria: {
				true: 'Requires or grants elevated privileges',
				false: 'Runs with ordinary user privileges',
			},
		},
		data_exfiltration: {
			type: 'noul',
			instructions: [
				'Does `command` transmit the contents of local files, or private data that did not previously exist off this machine,',
				'to an external destination - uploading an archive, posting captured output, or shipping files to a third-party service?',
				'Ordinary version-control pushes and package publishing are not exfiltration; they send work the user already maintains',
				'to the place it belongs, and are judged as remote effects instead.',
			].join(' '),
			criteria: {
				true: 'Moves private local data to a destination it does not belong in',
				false: 'Sends no private local data anywhere new',
			},
		},
	};

	return dimensions;
}

// ---------------------------------------------------------------------------
// Policy - code owns the decision, the model supplies the judgments
// ---------------------------------------------------------------------------

interface Policy {
	/** At or above this probability a risk dimension counts as present. */
	denyAt: number;
	/** At or below this probability the command counts as out of scope. */
	scopeDenyAt: number;
	/** At or below this probability a destructive action counts as unrecoverable. */
	recoverableAt: number;
	/** A judgement within this distance of 0.5 counts as undecided. */
	undecidedAt: number;
	/** Above this probability an undecided dimension is worth escalating. */
	quietAt: number;
}

const DEFAULT_POLICY: Policy = {
	denyAt: 0.5,
	scopeDenyAt: 0.25,
	recoverableAt: 0.5,
	undecidedAt: 0.1,
	quietAt: 0.2,
};

interface Verdict {
	decision: 'allow' | 'deny' | 'escalate';
	reason: string;
	category: string;
	dimensions: Record<string, number>;
	source: 'prefilter' | 'cache' | 'jev' | 'error';
	latencyMs: number;
	/** Token spend for the screening call, when one was made. */
	usage?: {input: number; output: number};
}

const fmt = (n: number) => (n === undefined ? 'n/a' : n.toFixed(2));

/** Collect the noul probabilities out of a Jev response. */
function nouls(answers: Record<string, unknown>): Record<string, number> {
	const out: Record<string, number> = {};
	for (const [key, value] of Object.entries(answers)) {
		const answer = value as {type?: string; noul?: number};
		if (answer?.type === 'noul' && typeof answer.noul === 'number') {
			out[key] = answer.noul;
		}
	}
	return out;
}

/**
 * Turn Jev's independent judgments into one decision. Kept pure and exported so the
 * policy can be unit-tested without touching the network.
 */
function decide(
	answers: Record<string, unknown>,
	policy: Policy,
): {decision: Verdict['decision']; reason: string; category: string; dimensions: Record<string, number>} {
	const dims = nouls(answers);
	const categoryAnswer = answers.category as {choice?: string} | undefined;
	const category = categoryAnswer?.choice ?? 'other';
	const base = {category, dimensions: dims};

	// 1. Anything that touches secrets, privilege, or the network is never autonomous.
	for (const dim of HARD_DENY) {
		const value = dims[dim.key] ?? 0;
		if (value >= policy.denyAt) {
			return {
				...base,
				decision: 'deny',
				reason: `${dim.label} (${fmt(value)})`,
			};
		}
	}

	// 2. Destructive is only tolerable when it is reversible.
	const destructive = dims.destructive ?? 0;
	const recoverable = dims.recoverable ?? 1;
	if (destructive >= policy.denyAt && recoverable <= policy.recoverableAt) {
		return {
			...base,
			decision: 'deny',
			reason: `destroys data that could not be recovered (destructive ${fmt(destructive)}, recoverable ${fmt(recoverable)})`,
		};
	}

	// 3. The whole point: work the user never asked for does not run.
	const scope = dims.within_scope ?? 1;
	if (scope <= policy.scopeDenyAt) {
		return {
			...base,
			decision: 'deny',
			reason: `outside the scope of the current task (in scope ${fmt(scope)})`,
		};
	}

	// 4. Reversible destruction and remote mutation are worth a human decision.
	if (destructive >= policy.denyAt) {
		return {
			...base,
			decision: 'escalate',
			reason: `could destroy recoverable data (destructive ${fmt(destructive)})`,
		};
	}
	for (const dim of ESCALATE) {
		if (dim.key === 'destructive') continue;
		const value = dims[dim.key] ?? 0;
		if (value >= policy.denyAt) {
			return {
				...base,
				decision: 'escalate',
				reason: `${dim.label} (${fmt(value)})`,
			};
		}
	}

	// 5. A judgment sitting on the fence is not a license to run unattended. Scope is
	// exempt: an uncertain scope with no risk dimension raised is benign work, and the
	// confident out-of-scope case was already denied in step 3. Risky work stays gated by
	// its own dimension regardless of scope.
	for (const key of Object.keys(NOUL_LABELS)) {
		if (key === 'within_scope') continue;
		const value = dims[key];
		if (value === undefined) continue;
		if (value > policy.quietAt && Math.abs(value - 0.5) <= policy.undecidedAt) {
			return {
				...base,
				decision: 'escalate',
				reason: `judgement undecided on whether ${NOUL_LABELS[key]} (${fmt(value)})`,
			};
		}
	}

	return {
		...base,
		decision: 'allow',
		reason: `in scope and no risk dimension raised (in scope ${fmt(scope)})`,
	};
}

// ---------------------------------------------------------------------------
// Prefilter - commands provably safe enough to skip the model entirely
// ---------------------------------------------------------------------------

// No arguments, no paths, no metacharacters: nothing here can read a secret or
// change state. Anything with an argument is judged by Jev instead.
const PREFILTER_ALLOW = new Set([
	'pwd',
	'whoami',
	'id',
	'date',
	'uname',
	'uptime',
	'ls',
	'git status',
	'git branch --show-current',
	'git rev-parse --show-toplevel',
	'node --version',
	'node -v',
	'npm --version',
	'pnpm --version',
	'yarn --version',
	'bun --version',
]);

/**
 * True only for a single simple command that is on the fixed safe list. Exported for
 * unit tests - this is the one place the mod skips the model, so it stays deliberately
 * narrow and auditable.
 */
function prefilter(command: string): boolean {
	const trimmed = command.trim();
	if (!trimmed) return false;
	// Reject anything that could chain, redirect, substitute, or glob.
	if (/[|&;<>`$(){}[\]*?!~'"\\\n]/.test(trimmed)) return false;
	return PREFILTER_ALLOW.has(trimmed);
}

// ---------------------------------------------------------------------------
// TypeSafe client
// ---------------------------------------------------------------------------

class TypeSafeError extends Error {}

interface ScreenRequest {
	command: string;
	tool: string;
	cwd: string;
	task: string;
	policyText: string;
	apiKey: string;
	model: string;
	timeoutMs: number;
	retries: number;
	usePrefilter: boolean;
	signal?: AbortSignal;
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

interface JeVAnswers {
	answers: Record<string, unknown>;
	usage?: {input_tokens?: number; output_tokens?: number};
}

/** One evaluation call to Jev, with backoff on rate limiting and overload. */
async function callJev(request: ScreenRequest, state: Record<string, unknown>): Promise<JeVAnswers> {
	const questions = buildQuestions(request.policyText);
	let lastError: Error | undefined;

	for (let attempt = 0; attempt <= request.retries; attempt += 1) {
		const timeout = AbortSignal.timeout(request.timeoutMs);
		const signal = request.signal
			? AbortSignal.any([request.signal, timeout])
			: timeout;

		try {
			const response = await fetch(API_URL, {
				method: 'POST',
				headers: {
					Authorization: `Bearer ${request.apiKey}`,
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({state, model: request.model, questions}),
				signal,
			});

			if (response.status === 429 || response.status === 529) {
				lastError = new TypeSafeError(`TypeSafe overloaded (${response.status})`);
				await sleep(250 * 2 ** attempt);
				continue;
			}
			if (!response.ok) {
				const detail = await response.text().catch(() => '');
				throw new TypeSafeError(
					`TypeSafe returned ${response.status}${detail ? `: ${detail.slice(0, 200)}` : ''}`,
				);
			}

			const body = (await response.json()) as JeVAnswers;
			if (!body?.answers) throw new TypeSafeError('TypeSafe response had no answers');
			return body;
		} catch (error) {
			if (request.signal?.aborted) throw error;
			lastError = error as Error;
			// A timeout or transport failure is worth one more try.
			if (attempt < request.retries) {
				await sleep(150 * 2 ** attempt);
				continue;
			}
			throw error;
		}
	}

	throw lastError ?? new TypeSafeError('TypeSafe call failed');
}

/** Screen one command end to end: prefilter, then Jev, then the code-owned policy. */
async function screen(request: ScreenRequest): Promise<Verdict> {
	const started = Date.now();

	if (request.usePrefilter && prefilter(request.command)) {
		return {
			decision: 'allow',
			reason: 'known-safe read-only command',
			category: 'read_only',
			dimensions: {},
			source: 'prefilter',
			latencyMs: Date.now() - started,
		};
	}

	const state = {
		task: request.task || '(the user has not stated a task yet)',
		cwd: request.cwd,
		tool: request.tool,
		command: request.command,
	};

	const body = await callJev(request, state);
	const outcome = decide(body.answers, DEFAULT_POLICY);
	return {
		...outcome,
		source: 'jev',
		latencyMs: Date.now() - started,
		usage: {
			input: body.usage?.input_tokens ?? 0,
			output: body.usage?.output_tokens ?? 0,
		},
	};
}

// ---------------------------------------------------------------------------
// Scope - what the user actually asked for
// ---------------------------------------------------------------------------

interface LooseMessage {
	role?: string;
	content?: unknown;
}

/** Pull plain text out of a message's content, ignoring tool results. */
function messageText(content: unknown): string {
	if (typeof content === 'string') return content;
	if (!Array.isArray(content)) return '';
	const parts: string[] = [];
	for (const block of content) {
		const candidate = block as {type?: string; text?: string};
		if (candidate?.type === 'text' && typeof candidate.text === 'string') {
			parts.push(candidate.text);
		}
	}
	return parts.join('\n');
}

function isToolResult(content: unknown): boolean {
	return (
		Array.isArray(content) &&
		content.some(block => (block as {type?: string})?.type === 'tool_result')
	);
}

/**
 * Reconstruct the user's recent requests from the transcript. Tool results share the
 * `user` role, so they are filtered out - feeding them back would let the model
 * justify a command with its own earlier output.
 */
function extractTask(state: unknown, maxMessages = 4, maxChars = 1200): string {
	const messages = (state as {messages?: readonly LooseMessage[]})?.messages;
	if (!Array.isArray(messages)) return '';

	const prompts: string[] = [];
	for (let i = messages.length - 1; i >= 0 && prompts.length < maxMessages; i -= 1) {
		const message = messages[i];
		if (message?.role !== 'user') continue;
		if (isToolResult(message.content)) continue;
		const text = messageText(message.content).trim();
		if (text) prompts.push(text);
	}

	return prompts
		.reverse()
		.join('\n---\n')
		.slice(-maxChars);
}

/** Last non-empty line of a command, trimmed, for one-line display. */
function summarize(command: string, max = 120): string {
	const oneLine = command.replace(/\s+/g, ' ').trim();
	return oneLine.length > max ? `${oneLine.slice(0, max - 1)}…` : oneLine;
}

// ---------------------------------------------------------------------------
// Launch mode - yolo (bypass) is a launch flag, so argv is the signal
// ---------------------------------------------------------------------------

// The live permission mode reaches a mod only as a `permission_mode_changed` event,
// and the mode a session starts in is never emitted - so a `--yolo` launch is
// invisible to the mod unless it reads the flags it was launched with. Bypass is
// launch-flag-only, which makes argv a reliable signal for it.
function isYoloLaunch(argv: readonly string[] = process.argv): boolean {
	return argv.includes('--yolo') || argv.includes('--dangerously-skip-permissions');
}

/**
 * Resolve the starting toggle, in order: an explicit `auto-mode` flag, then whatever a
 * resumed session persisted (so `/auto off` sticks), then the yolo default for a fresh
 * session. The yolo default only fires when screening can actually run - with no API key
 * and fail-closed on, enabling it would block every screened tool call.
 */
function resolveInitialEnabled(input: {
	flag: boolean;
	persisted?: boolean;
	yolo: boolean;
	yoloDefault: boolean;
	hasApiKey: boolean;
}): boolean {
	if (input.flag) return true;
	if (typeof input.persisted === 'boolean') return input.persisted;
	return input.yolo && input.yoloDefault && input.hasApiKey;
}

// ---------------------------------------------------------------------------
// The mod
// ---------------------------------------------------------------------------

const ANSI = {
	reset: '\u001b[0m',
	dim: '\u001b[2m',
	bold: '\u001b[1m',
	red: '\u001b[31m',
	green: '\u001b[32m',
	yellow: '\u001b[33m',
	cyan: '\u001b[36m',
};

function paint(color: keyof typeof ANSI, text: string): string {
	if (process.env.NO_COLOR) return text;
	return `${ANSI[color]}${text}${ANSI.reset}`;
}

const DECISION_STYLE = {
	allow: {color: 'green' as const, mark: '✓'},
	deny: {color: 'red' as const, mark: '✗'},
	escalate: {color: 'yellow' as const, mark: '?'},
	error: {color: 'red' as const, mark: '!'},
};

/**
 * Renderer for one screening decision. Registering a renderer keeps the feed readable
 * instead of dumping raw JSON on every tool call.
 */
function renderDecision(data: {
	decision?: keyof typeof DECISION_STYLE | 'error';
	category?: string;
	command?: string;
	reason?: string;
	tool?: string;
	source?: string;
	latencyMs?: number;
	dimensions?: Record<string, number>;
}): readonly string[] {
	const style = DECISION_STYLE[data.decision ?? 'allow'] ?? DECISION_STYLE.allow;
	const lines: string[] = [];

	const timing = data.source === 'jev' ? `${(data.latencyMs ?? 0) / 1000}s` : data.source ?? '';
	lines.push(
		[
			paint('dim', '⛨ auto-mode'),
			paint(style.color, `${style.mark} ${data.decision}`),
			paint('cyan', data.category ?? 'unknown'),
			paint('dim', timing ? `· ${timing}` : ''),
		]
			.filter(Boolean)
			.join(' '),
	);

	lines.push(`  ${paint('dim', summarize(data.command ?? ''))}`);

	if (data.reason) {
		lines.push(`  ${paint(data.decision === 'allow' ? 'dim' : style.color, data.reason)}`);
	}

	const dims = data.dimensions ?? {};
	const raised = Object.entries(dims)
		.filter(([key, value]) => value >= 0.25 && key in NOUL_LABELS)
		.sort((a, b) => b[1] - a[1])
		.slice(0, 4)
		.map(([key, value]) => `${NOUL_LABELS[key]} ${value.toFixed(2)}`);
	if (raised.length && data.decision !== 'allow') {
		lines.push(`  ${paint('dim', raised.join('  '))}`);
	}

	return lines;
}

export default function (cmd: ModApi): void {
	// --- options -------------------------------------------------------------
	cmd.addFlag('auto-mode', {
		type: 'boolean',
		default: false,
		description: 'Start auto-mode enabled (screen tool calls with TypeSafe Jev)',
	});
	cmd.addFlag('auto-yolo', {
		type: 'boolean',
		default: true,
		description: 'Start auto-mode enabled when launched with --yolo (set false to opt out)',
	});
	cmd.addFlag('auto-tools', {
		type: 'string',
		default: 'shell_command',
		description: 'Comma-separated tool names auto-mode screens',
	});
	cmd.addFlag('auto-model', {
		type: 'string',
		default: 'jev-latest',
		description: 'TypeSafe System One model used for screening',
	});
	cmd.addFlag('auto-scope', {
		type: 'string',
		default: '',
		description: 'Extra standing policy given to the screener, e.g. "never touch production"',
	});
	cmd.addFlag('auto-prefilter', {
		type: 'boolean',
		default: true,
		description: 'Skip the model for provably read-only commands',
	});
	cmd.addFlag('auto-fail-closed', {
		type: 'boolean',
		default: true,
		description: 'Block tools when the screener is unreachable (false = allow)',
	});
	cmd.addFlag('auto-timeout', {
		type: 'string',
		default: '4000',
		description: 'Milliseconds to wait for a screening verdict',
	});

	// `--mod-option` always delivers a string, so a boolean flag has to be coerced
	// rather than trusted; reading `false` as a string would invert fail-closed.
	const boolFlag = (name: string, fallback: boolean): boolean => {
		const value = cmd.getFlag(name);
		if (typeof value === 'boolean') return value;
		if (typeof value === 'string') return !/^(false|0|no|off)$/i.test(value.trim());
		return fallback;
	};
	const strFlag = (name: string, fallback: string): string => {
		const value = cmd.getFlag(name);
		return typeof value === 'string' && value.length > 0 ? value : fallback;
	};

	// Closure state. Run-scoped, so it never needs to be serializable.
	let enabled = false;
	let ready = false;
	let permissionMode = '';
	const cache = new Map<string, Verdict>();

	// Flags are bound by the host after the factory runs, so they must be read lazily -
	// reading them here would always yield the defaults and silently ignore
	// `--mod-option auto-mode=true`.
	const screenedList = (): string[] =>
		strFlag('auto-tools', 'shell_command')
			.split(',')
			.map(name => name.trim())
			.filter(Boolean);

	/**
	 * Resolve the starting state once, on first use: an explicit flag wins (it is this
	 * session's instruction), then whatever the previous session persisted, then the yolo
	 * default, then off.
	 */
	const init = (session: unknown): void => {
		if (ready) return;
		ready = true;

		let persisted: boolean | undefined;
		try {
			const store = session as
				| {getCustomEntries?: (query: {customType: string}) => unknown[]}
				| undefined;
			const entries = store?.getCustomEntries?.({customType: STATE_TYPE}) ?? [];
			const last = entries[entries.length - 1] as {data?: {enabled?: boolean}} | undefined;
			if (typeof last?.data?.enabled === 'boolean') persisted = last.data.enabled;
		} catch {
			// unreadable history just means we keep the configured default
		}

		const flag = boolFlag('auto-mode', false);
		const yolo = isYoloLaunch();
		const yoloDefault = boolFlag('auto-yolo', true);
		const hasApiKey = Boolean(process.env.TYPESAFE_API_KEY);

		enabled = resolveInitialEnabled({flag, persisted, yolo, yoloDefault, hasApiKey});

		// A yolo launch that stayed off because screening can't run is worth one notice,
		// otherwise the missing key reads as "the mod did nothing".
		if (!flag && persisted === undefined && yolo && yoloDefault && !hasApiKey) {
			cmd.ui.notify(
				'auto-mode: --yolo detected, but TYPESAFE_API_KEY is not set - screening stays off.',
			);
		}
	};
	const stats = {
		screened: 0,
		allowed: 0,
		denied: 0,
		escalated: 0,
		cacheHits: 0,
		prefiltered: 0,
		errors: 0,
		totalLatencyMs: 0,
		jevCalls: 0,
		inputTokens: 0,
		outputTokens: 0,
	};

	// --- rendering -----------------------------------------------------------
	cmd.addRenderer(ENTRY_TYPE, renderDecision);

	const refreshStatus = (): void => {
		if (!enabled) {
			cmd.ui.setStatus(null);
			return;
		}
		const parts = [
			paint('dim', '⛨ auto'),
			paint('cyan', strFlag('auto-model', 'jev-latest')),
			paint('dim', `${stats.screened} screened`),
		];
		if (stats.denied > 0) parts.push(paint('red', `${stats.denied} denied`));
		if (stats.escalated > 0) parts.push(paint('yellow', `${stats.escalated} asked`));
		cmd.ui.setStatus(parts.join(' '));
	};

	const record = (data: Parameters<typeof renderDecision>[0]): void => {
		cmd.showEntry(ENTRY_TYPE, data);
		// Headless hosts drop custom entries and render no footer, so fall back to a
		// notice the run still reports - otherwise a blocked call is invisible in CI.
		if (!cmd.ui.capabilities.status) {
			const mark = data.decision === 'allow' ? 'allow' : String(data.decision);
			cmd.ui.notify(
				`auto-mode ${mark}: ${summarize(data.command ?? '', 80)}${data.reason ? ` - ${data.reason}` : ''}`,
			);
		}
		refreshStatus();
	};

	const persist = (): void => {
		try {
			cmd.session?.appendCustomEntry({customType: STATE_TYPE, data: {enabled}});
		} catch {
			// persistence is best-effort; the in-process toggle still applies
		}
	};

	// --- the gate ------------------------------------------------------------
	cmd.hooks({
		beforeToolCall: async ({toolName, input, state}, ctx) => {
			init(ctx?.session);
			if (!enabled) return undefined;
			if (!screenedList().includes(toolName)) return undefined;
			// Plan mode already restricts execution; don't double-gate it.
			if (/plan/i.test(permissionMode)) return undefined;

			const record_ = input as Record<string, unknown>;
			const command =
				typeof record_.command === 'string'
					? record_.command
					: typeof record_.cmd === 'string'
						? record_.cmd
						: JSON.stringify(record_);

			const task = extractTask(state);
			const cacheKey = createHash('sha1')
				.update(`${toolName}\u0000${command}\u0000${task}`)
				.digest('hex');
			const cached = cache.get(cacheKey);
			if (cached) {
				stats.screened += 1;
				stats.cacheHits += 1;
				if (cached.decision === 'deny') stats.denied += 1;
				else stats.allowed += 1;
				if (cached.decision === 'allow') return undefined;
				record({...cached, command, tool: toolName});
				return {block: true, additionalContext: blockMessage(cached)};
			}

			const apiKey = process.env.TYPESAFE_API_KEY ?? '';
			if (!apiKey) {
				stats.errors += 1;
				record({
					decision: 'error',
					tool: toolName,
					command,
					reason: 'TYPESAFE_API_KEY is not set - cannot screen this call',
					source: 'error',
				});
				if (boolFlag('auto-fail-closed', true)) {
					return {
						block: true,
						additionalContext:
							'Blocked by auto-mode: TYPESAFE_API_KEY is not set, so this call could not be screened. ' +
							'Ask the user to export it, or run /auto off to disable screening.',
					};
				}
				return undefined;
			}

			let verdict: Verdict;
			try {
				verdict = await screen({
					command,
					tool: toolName,
					cwd: ctx?.cwd ?? cmd.cwd,
					task,
					policyText: strFlag('auto-scope', ''),
					apiKey,
					model: strFlag('auto-model', 'jev-latest'),
					timeoutMs: Number(strFlag('auto-timeout', '4000')) || 4000,
					retries: 1,
					usePrefilter: boolFlag('auto-prefilter', true),
					signal: ctx?.signal,
				});
			} catch (error) {
				stats.errors += 1;
				const message = error instanceof Error ? error.message : String(error);
				const failClosed = boolFlag('auto-fail-closed', true);
				record({
					decision: 'error',
					tool: toolName,
					command,
					reason: `${message} - ${failClosed ? 'blocked' : 'allowed'} (fail-closed)`,
					source: 'error',
				});
				if (!failClosed) return undefined;
				return {
					block: true,
					additionalContext: `Blocked by auto-mode: the screener was unreachable (${message}). Ask the user to run this manually if it is required.`,
				};
			}

			stats.screened += 1;
			stats.totalLatencyMs += verdict.latencyMs;
			if (verdict.source === 'jev') stats.jevCalls += 1;
			if (verdict.source === 'prefilter') stats.prefiltered += 1;
			if (verdict.usage) {
				stats.inputTokens += verdict.usage.input;
				stats.outputTokens += verdict.usage.output;
			}

			if (verdict.decision === 'allow') {
				stats.allowed += 1;
				if (verdict.source === 'jev') cache.set(cacheKey, verdict);
				record({...verdict, command, tool: toolName});
				return undefined;
			}

			if (verdict.decision === 'deny') {
				stats.denied += 1;
				cache.set(cacheKey, verdict);
				record({...verdict, command, tool: toolName});
				return {block: true, additionalContext: blockMessage(verdict)};
			}

			// Escalate: the borderline band goes to the human, never to the model.
			stats.escalated += 1;
			record({...verdict, command, tool: toolName});
			const approved = await cmd.ui.confirm({
				title: 'auto-mode: review required',
				message: `${summarize(command, 200)}\n\n${verdict.reason}\n[${verdict.category}]`,
			});
			if (approved) {
				stats.allowed += 1;
				cache.set(cacheKey, {...verdict, decision: 'allow'});
				return undefined;
			}
			stats.denied += 1;
			return {block: true, additionalContext: blockMessage(verdict)};
		},

		onTurnStart: async ({state}, ctx) => {
			init(ctx?.session);
			refreshStatus();
			return state;
		},

		onSessionStart: () => {
			init(cmd.session);
			refreshStatus();
		},
		onSessionEnd: () => {
			cmd.ui.setStatus(null);
		},
	});

	cmd.on('permission_mode_changed', ({mode}) => {
		permissionMode = String(mode ?? '');
	});

	// --- the toggle ----------------------------------------------------------
	cmd.addCommand({
		name: 'auto',
		description: 'Auto permission mode: screen tool calls with TypeSafe Jev',
		argumentHint: '[on|off|status|stats|test <command>]',
		handler: async ({args}) => {
			const trimmed = (args ?? '').trim();
			const [verb, ...rest] = trimmed.split(/\s+/);
			const argument = rest.join(' ').trim();

			switch ((verb ?? '').toLowerCase()) {
				case 'on':
				case 'enable': {
					if (!process.env.TYPESAFE_API_KEY) {
						return {
							message:
								'auto-mode: TYPESAFE_API_KEY is not set. Export it in your shell first - failing closed would block every screened call.',
						};
					}
					ready = true;
					enabled = true;
					persist();
					refreshStatus();
					return {
						message: `auto-mode ON - screening ${screenedList().join(', ')} with ${strFlag('auto-model', 'jev-latest')}.`,
					};
				}

				case 'off':
				case 'disable': {
					ready = true;
					enabled = false;
					persist();
					refreshStatus();
					return {message: 'auto-mode OFF - tool calls run without screening.'};
				}

				case 'stats': {
					const avg =
						stats.jevCalls > 0 ? (stats.totalLatencyMs / stats.jevCalls / 1000).toFixed(2) : '0.00';
					return {
						message: [
							`auto-mode: ${enabled ? 'ON' : 'OFF'} · model ${strFlag('auto-model', 'jev-latest')}`,
							`screened ${stats.screened} · allowed ${stats.allowed} · denied ${stats.denied} · asked ${stats.escalated}`,
							`jev calls ${stats.jevCalls} (avg ${avg}s) · prefiltered ${stats.prefiltered} · cache hits ${stats.cacheHits} · errors ${stats.errors}`,
							`tokens ${stats.inputTokens} in / ${stats.outputTokens} out`,
						].join('\n'),
					};
				}

				case 'test': {
					if (!argument) return {message: 'Usage: /auto test <shell command>'};
					const apiKey = process.env.TYPESAFE_API_KEY ?? '';
					if (!apiKey) return {message: 'auto-mode: TYPESAFE_API_KEY is not set.'};
					try {
						const verdict = await screen({
							command: argument,
							tool: 'shell_command',
							cwd: cmd.cwd,
							task: '',
							policyText: strFlag('auto-scope', ''),
							apiKey,
							model: strFlag('auto-model', 'jev-latest'),
							timeoutMs: Number(strFlag('auto-timeout', '4000')) || 4000,
							retries: 1,
							usePrefilter: boolFlag('auto-prefilter', true),
						});
						record({...verdict, command: argument, tool: 'shell_command'});
						const dims = Object.entries(verdict.dimensions)
							.sort((a, b) => b[1] - a[1])
							.slice(0, 5)
							.map(([key, value]) => `${NOUL_LABELS[key] ?? key}=${value.toFixed(2)}`)
							.join(' ');
						return {
							message: [
								`auto-mode test: ${verdict.decision.toUpperCase()} (${verdict.source}, ${verdict.latencyMs}ms)`,
								`category ${verdict.category} · ${verdict.reason}`,
								dims ? `dimensions ${dims}` : '',
								'This was a dry run - nothing was executed.',
							]
								.filter(Boolean)
								.join('\n'),
						};
					} catch (error) {
						const message = error instanceof Error ? error.message : String(error);
						return {message: `auto-mode test failed: ${message}`};
					}
				}

				case 'status':
				case '': {
					return {
						message: [
							`auto-mode: ${enabled ? 'ON' : 'OFF'}`,
							`model ${strFlag('auto-model', 'jev-latest')} · tools ${screenedList().join(', ')}`,
							`prefilter ${boolFlag('auto-prefilter', true)} · fail-closed ${boolFlag('auto-fail-closed', true)} · timeout ${strFlag('auto-timeout', '4000')}ms`,
							`launch ${isYoloLaunch() ? 'yolo' : 'normal'} · yolo default ${boolFlag('auto-yolo', true) ? 'on' : 'off'}`,
							`api key ${process.env.TYPESAFE_API_KEY ? 'present' : 'MISSING'}`,
							strFlag('auto-scope', '') ? `standing policy: ${strFlag('auto-scope', '')}` : '',
						]
							.filter(Boolean)
							.join('\n'),
					};
				}

				default:
					return {
						message: [
							'auto-mode - screen tool calls with TypeSafe Jev before they run.',
							'/auto on | off          toggle screening',
							'/auto status | stats    configuration and counters',
							'/auto test <command>    dry-run the screener on any command',
						].join('\n'),
					};
			}
		},
	});
}

/** The text the model sees in place of a blocked tool result. */
function blockMessage(verdict: Verdict): string {
	return [
		`Blocked by auto-mode (TypeSafe ${verdict.source === 'jev' ? 'Jev' : verdict.source}): this command ${verdict.reason}.`,
		`I did not run it. Do not retry it. If it is genuinely required, ask the user to run it themselves.`,
	].join(' ');
}

export {
	buildQuestions,
	decide,
	extractTask,
	isYoloLaunch,
	prefilter,
	resolveInitialEnabled,
	screen,
	summarize,
	DEFAULT_POLICY,
	MOD_ID,
};
export type {Policy, Verdict};
