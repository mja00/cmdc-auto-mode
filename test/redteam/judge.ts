// One attack in, one graded outcome out - the adapter both runners share.
//
// The live path goes through the mod's own `screen`, so the red team exercises exactly
// what production runs: the prefilter, the Jev call, and the code-owned policy. A
// transport failure is reported as `error`, not as `held`: the guards fail closed in
// production, but the attacker must not score a timeout as a catch.

import {screen} from '../../index.ts';
import type {Attack} from './mutations.ts';
import type {Outcome} from './scoring.ts';
import {stubScreen} from './stub.ts';

export interface JudgeConfig {
	mode: 'live' | 'stub';
	apiKey: string;
	model: string;
	policyText: string;
	timeoutMs: number;
	retries: number;
	usePrefilter: boolean;
}

export interface Judgement {
	outcome: Outcome;
	reason: string;
	category: string;
	dimensions: Record<string, number>;
	latencyMs: number;
	source: string;
	error?: string;
	tokens?: {input: number; output: number};
}

export async function judgeAttack(attack: Attack, config: JudgeConfig): Promise<Judgement> {
	if (config.mode === 'stub') {
		try {
			const verdict = stubScreen({
				command: attack.command,
				tool: attack.tool,
				cwd: attack.cwd,
				task: attack.task,
				usePrefilter: config.usePrefilter,
			});
			return {...verdict, outcome: verdict.decision};
		} catch (error) {
			return {
				outcome: 'error',
				reason: '',
				category: 'other',
				dimensions: {},
				latencyMs: 0,
				source: 'error',
				error: error instanceof Error ? error.message : String(error),
			};
		}
	}

	try {
		const verdict = await screen({
			command: attack.command,
			tool: attack.tool,
			cwd: attack.cwd,
			task: attack.task,
			policyText: config.policyText,
			apiKey: config.apiKey,
			model: config.model,
			timeoutMs: config.timeoutMs,
			retries: config.retries,
			usePrefilter: config.usePrefilter,
		});
		return {
			outcome: verdict.decision,
			reason: verdict.reason,
			category: verdict.category,
			dimensions: verdict.dimensions,
			latencyMs: verdict.latencyMs,
			source: verdict.source,
			tokens: verdict.usage,
		};
	} catch (error) {
		return {
			outcome: 'error',
			reason: '',
			category: 'other',
			dimensions: {},
			latencyMs: 0,
			source: 'error',
			error: error instanceof Error ? error.message : String(error),
		};
	}
}
