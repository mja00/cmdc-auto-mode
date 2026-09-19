// Hand-written stand-in for `@commandcode/harness`. The Command Code CLI provides the
// real module to a mod at load time (jiti strips this type-only import), but the package
// is not published to npm, so `tsc --noEmit` needs a local declaration to check the mod.
//
// This is deliberately a subset of the ModApi surface this mod touches - not the full
// API (see https://commandcode.ai/docs/mods). Extend it when the mod starts using more.

declare module '@commandcode/harness' {
	export interface Disposable {
		dispose(): void;
	}

	export interface ModUiCapabilities {
		readonly status: boolean;
	}

	export interface ModUi {
		notify(message: string, level?: 'info' | 'warning' | 'error'): void;
		confirm(options: {title: string; message?: string}): Promise<boolean>;
		select(options: {
			title: string;
			options: readonly {label: string; description?: string}[];
		}): Promise<string | undefined>;
		input(options: {title: string; placeholder?: string}): Promise<string | undefined>;
		setStatus(status: string | null): Disposable;
		widget(): Disposable;
		refreshWidgets(): void;
		readonly capabilities: ModUiCapabilities;
	}

	export interface ModSessionApi {
		appendCustomEntry(entry: {customType: string; data?: unknown}): void;
		appendCustomMessageEntry(entry: {
			customType: string;
			content: string;
			display?: boolean;
			details?: unknown;
		}): {entryId: string; message: unknown};
		getCustomEntries(query: {customType: string}): unknown[];
	}

	export interface ModContext {
		emit(event: unknown): void;
		signal?: AbortSignal;
		cwd: string;
		session?: ModSessionApi;
	}

	export interface AgentState {
		readonly sessionId?: string;
		readonly messages: readonly unknown[];
		readonly interrupted?: boolean;
		readonly modState?: Readonly<Record<string, unknown>>;
	}

	export interface BeforeToolCallArgs {
		toolCallId: string;
		toolName: string;
		input: Record<string, unknown>;
		state: AgentState;
	}

	export interface BeforeToolCallResult {
		block?: boolean;
		input?: Record<string, unknown>;
		additionalContext?: string;
		terminate?: boolean;
	}

	export interface ModHooks {
		transformContext?(
			args: {messages: readonly unknown[]; state: AgentState},
			ctx?: ModContext,
		): readonly unknown[] | Promise<readonly unknown[]>;
		appendSystemPrompt?(
			args: {state: AgentState},
			ctx?: ModContext,
		): string | undefined | Promise<string | undefined>;
		beforeToolCall?(
			args: BeforeToolCallArgs,
			ctx?: ModContext,
		): BeforeToolCallResult | undefined | Promise<BeforeToolCallResult | undefined>;
		afterToolCall?(args: unknown, ctx?: ModContext): unknown;
		onTurnStart?(
			args: {state: AgentState; turnNumber: number},
			ctx?: ModContext,
		): AgentState | undefined | Promise<AgentState | undefined>;
		onTurnEnd?(args: unknown, ctx?: ModContext): unknown;
		onRunEnd?(args: unknown, ctx?: ModContext): void | Promise<void>;
		onStop?(args: unknown, ctx?: ModContext): unknown;
		shouldStopAfterTurn?(args: unknown, ctx?: ModContext): boolean | Promise<boolean>;
		prepareNextTurn?(args: unknown, ctx?: ModContext): unknown;
		onSessionStart?(
			args: {source: 'startup' | 'resume'},
			ctx?: ModContext,
		): void | Promise<void>;
		onSessionEnd?(
			args: {reason: 'shutdown' | 'replaced'},
			ctx?: ModContext,
		): void | Promise<void>;
	}

	export interface ModCommandContext {
		args: string | undefined;
		ui: ModUi;
		cwd: string;
		exec: unknown;
	}

	export interface ModCommand {
		name: string;
		description?: string;
		argumentHint?: string;
		handler(context: ModCommandContext): unknown;
	}

	export interface ModApi {
		readonly name: string;
		readonly cwd: string;
		readonly session: ModSessionApi | undefined;
		readonly events: {
			emit(event: unknown): void;
			on(event: string, handler: (data: unknown) => void): Disposable;
		};
		readonly ui: ModUi;
		readonly sessions: unknown;
		hooks(hooks: ModHooks): Disposable;
		addTool(tool: unknown): Disposable;
		addCommand(command: ModCommand): Disposable;
		addFlag(
			name: string,
			options: {
				type: 'boolean' | 'string';
				default?: boolean | string;
				description?: string;
			},
		): Disposable;
		getFlag(name: string): boolean | string | undefined;
		addProvider(provider: unknown): Disposable;
		addRenderer(customType: string, renderer: (data: any) => readonly string[]): Disposable;
		on(event: string, handler: (data: any) => void): Disposable;
		showEntry(customType: string, data?: unknown): void;
	}
}
