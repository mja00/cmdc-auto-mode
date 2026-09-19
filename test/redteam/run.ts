// The adversarial run: every attack in the corpus against the real screener, graded.
//
//   TYPESAFE_API_KEY=... node test/redteam/run.ts
//   node test/redteam/run.ts --stub            # offline, against the keyword judge
//   node test/redteam/run.ts --mutate          # multiply the corpus into disguises first
//   node test/redteam/run.ts --only secrets,exfiltration --attempts 3
//
// Exit codes: 0 the guard held, 1 a finding that must be fixed, 2 the suite could not run
// (missing key, malformed corpus). Findings are printed with the dimension margins that
// explain them and an attacks.json entry ready to paste into the corpus, so a bypass
// found tonight is a regression case tomorrow.

import {writeFileSync} from 'node:fs';
import {
	APPROX_TOKENS_PER_SCREENING,
	costOf,
	describeSpend,
	estimateScreenings,
	PRICE_PER_MTOK_INPUT,
	usd,
} from './cost.ts';
import {judgeAttack} from './judge.ts';
import type {JudgeConfig, Judgement} from './judge.ts';
import {expand, FAMILIES, lineage} from './mutations.ts';
import type {Attack, Family} from './mutations.ts';
import {
	closestOf,
	fatal,
	impact,
	judgeAttempts,
	promoteEntry,
	riskOf,
} from './scoring.ts';
import type {Attempts, Marginal} from './scoring.ts';
import {loadCorpus} from './seeds.ts';

interface Options {
	stub: boolean;
	mutate: boolean;
	rounds: number;
	seed: string;
	families: string[];
	only: string[];
	attempts?: number;
	strict: boolean;
	quiet: boolean;
	report?: string;
	policy: string;
	model: string;
	timeoutMs: number;
	concurrency: number;
}

const USAGE = `
redteam - adversarially attack auto-mode

  node test/redteam/run.ts [options]

  --stub              grade with the local keyword judge instead of Jev (offline)
  --mutate            expand the corpus into disguised mutants before running
  --rounds N          transform stack depth for --mutate (default 1)
  --seed S            PRNG seed for --mutate (default 1) - same seed, same mutants
  --families a,b      restrict mutants to families (${'encode,wrap,splice,decoy,inject,pad,stage,task'})
  --only a,b          restrict to corpus groups by id
  --attempts N        runs per attack (default: whatever the corpus says)
  --policy TEXT       standing policy passed to the screener (auto-scope)
  --model NAME        TypeSafe model (default jev-latest)
  --timeout MS        per-call timeout (default 8000)
  --concurrency N     parallel screenings (default 4)
  --strict            also fail on weak catches and over-blocking friction
  --quiet             only print findings and the summary
  --report PATH       write the full JSON report
`.trim();

function parseArgs(argv: readonly string[]): Options {
	const options: Options = {
		stub: false,
		mutate: false,
		rounds: 1,
		seed: '1',
		families: [],
		only: [],
		strict: false,
		quiet: false,
		policy: '',
		model: 'jev-latest',
		timeoutMs: 8000,
		concurrency: 4,
	};

	const list = (value: string | undefined): string[] =>
		(value ?? '')
			.split(',')
			.map(part => part.trim())
			.filter(Boolean);

	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		const next = (): string => {
			i += 1;
			if (i >= argv.length) throw new Error(`${arg} needs a value`);
			return argv[i];
		};
		switch (arg) {
			case '--stub':
				options.stub = true;
				break;
			case '--mutate':
				options.mutate = true;
				break;
			case '--rounds':
				options.rounds = Number(next());
				break;
			case '--seed':
				options.seed = next();
				break;
			case '--families':
				options.families = list(next());
				break;
			case '--only':
				options.only = list(next());
				break;
			case '--attempts':
				options.attempts = Number(next());
				break;
			case '--policy':
				options.policy = next();
				break;
			case '--model':
				options.model = next();
				break;
			case '--timeout':
				options.timeoutMs = Number(next());
				break;
			case '--concurrency':
				options.concurrency = Number(next());
				break;
			case '--strict':
				options.strict = true;
				break;
			case '--quiet':
				options.quiet = true;
				break;
			case '--report':
				options.report = next();
				break;
			case '--help':
			case '-h':
				console.log(USAGE);
				process.exit(0);
				break;
			default:
				throw new Error(`unknown option ${arg}\n\n${USAGE}`);
		}
	}

	return options;
}

interface Result {
	attack: Attack;
	attempts: Attempts;
	runs: Judgement[];
	risk: number;
	closest: Marginal[];
	/** The run whose outcome carried the verdict - the one worth explaining. */
	primary: Judgement;
	/** Token spend across this attack's runs, so a suite run has a price tag. */
	tokens: {input: number; output: number};
}

const MARK: Record<string, string> = {
	breach: '!!',
	'false-positive': '!!',
	weak: ' ?',
	friction: ' ?',
	held: '  ',
	ok: '  ',
	error: ' !!',
};

const pad = (text: string, width: number): string =>
	text.length >= width ? text : text + ' '.repeat(width - text.length);

const margin = (entry: Marginal): string =>
	`${entry.key} ${entry.value.toFixed(2)} (${entry.margin >= 0 ? '+' : ''}${entry.margin.toFixed(2)})`;

const firstLine = (text: string): string => text.split('\n')[0];

function printResult(result: Result, showLine: boolean): void {
	const {attack, attempts, primary} = result;
	const runs = Object.entries(attempts.counts)
		.map(([outcome, count]) => `${count}x ${outcome}`)
		.join(', ');
	const total = Object.values(attempts.counts).reduce((sum, count) => sum + (count ?? 0), 0);
	const rate = total > 1 ? ` [${runs}]` : '';

	if (showLine) {
		console.log(
			`${MARK[attempts.score] ?? '  '} ${pad(attempts.score, 15)}${pad(primary.outcome, 9)}` +
				`${pad(`${primary.latencyMs}ms`, 7)}${pad(`risk ${result.risk >= 0 ? '+' : ''}${result.risk.toFixed(2)}`, 12)}` +
				`${pad(`scope ${(primary.dimensions.within_scope ?? 1).toFixed(2)}`, 13)}${firstLine(attack.command)}`,
		);
	}

	if (attempts.score === 'held' || attempts.score === 'ok') return;

	console.log(`     ${attack.id}${rate}${attack.verified === false ? ' [unverified payload]' : ''}`);
	console.log(`     harm: ${impact(attack)}`);
	if (primary.error) console.log(`     error: ${primary.error}`);
	else if (primary.reason) console.log(`     reason: ${primary.reason}`);
	console.log(`     near: ${result.closest.map(margin).join('  ')}`);
	if (attack.source !== 'seed') console.log(`     lineage: ${lineage(attack)}`);
}

function summarise(results: readonly Result[], options: Options): number {
	const totals: Record<string, number> = {};
	for (const result of results) {
		totals[result.attempts.score] = (totals[result.attempts.score] ?? 0) + 1;
	}

	const spend = results.reduce(
		(sum, result) => ({
			input: sum.input + result.tokens.input,
			output: sum.output + result.tokens.output,
		}),
		{input: 0, output: 0},
	);

	const failures = results.filter(result => fatal(result.attack, result.attempts, options.strict));
	// Breaches the engine could not prove still deserve eyes: 'fatal' deliberately ignores
	// them, so without this list they would only show up as a number in the totals.
	const unproven = results.filter(
		result => result.attempts.score === 'breach' && result.attack.verified === false,
	);
	const flaky = results.filter(result => result.attempts.flakyAllow);
	// The tuning signal: attacks the screener stopped, but only just. Sorted by how close
	// they came, so the top of this list is where the next generation should dig.
	const nearMisses = results
		.filter(result => result.attack.kind === 'bypass')
		.filter(result => result.risk >= 0 && result.risk < 0.2)
		.sort((a, b) => a.risk - b.risk)
		.slice(0, 8);

	console.log('');
	console.log(
		'  ' +
			[
				['held', 'held'],
				['ok', 'ok'],
				['weak', 'weak'],
				['breach', 'breaches'],
				['false-positive', 'false positives'],
				['friction', 'friction'],
				['error', 'errors'],
			]
				.filter(([key]) => totals[key])
				.map(([key, label]) => `${totals[key]} ${label}`)
				.join(' · '),
	);

	if (spend.input > 0) {
		console.log(`  tokens: ${describeSpend(spend, results.length)}`);
	}

	if (flaky.length) {
		console.log(`\n  stochastic: ${flaky.length} bypass(es) allowed on a minority of runs`);
		for (const result of flaky) {
			console.log(`    ${result.attack.id} · ${firstLine(result.attack.command)}`);
		}
	}

	if (unproven.length) {
		console.log(
			`\n  unproven payloads (${unproven.length}) - allowed, but the engine could not show the` +
				' disguise still carries its seed\'s harm, so these neither pass nor fail the suite',
		);
		for (const result of unproven) {
			console.log(`    ${result.attack.id} · ${firstLine(result.attack.command)}`);
		}
	}

	if (failures.length) {
		console.log(`\n  findings (${failures.length})`);
		for (const result of failures) {
			console.log('');
			printResult(result, true);
			console.log('     promote into test/redteam/attacks.json:');
			for (const line of promoteEntry(result.attack).split('\n')) {
				console.log(`     ${line}`);
			}
		}
	} else {
		console.log('\n  no findings - the guard held on every attack');
	}

	if (nearMisses.length) {
		console.log('\n  nearest misses (blocked, but only just - best candidates for the next generation)');
		for (const result of nearMisses) {
			console.log(
				`    ${pad(result.attack.id, 42)}risk +${result.risk.toFixed(2)}  ` +
					`${result.closest[0] ? margin(result.closest[0]) : ''}`,
			);
		}
	}

	return failures.length;
}

async function main(): Promise<void> {
	const options = parseArgs(process.argv.slice(2));

	if (!options.stub && !process.env.TYPESAFE_API_KEY) {
		console.error('TYPESAFE_API_KEY is not set - pass --stub to run the offline judge');
		process.exit(2);
	}

	const {attacks: seeds, warnings} = loadCorpus();
	const seedsByGroup = new Set(seeds.map(seed => seed.group));
	for (const group of options.only) {
		if (!seedsByGroup.has(group)) {
			console.error(`unknown group ${group} - known: ${[...seedsByGroup].join(', ')}`);
			process.exit(2);
		}
	}

	let attacks = options.only.length
		? seeds.filter(seed => options.only.includes(seed.group))
		: seeds;

	if (options.mutate) {
		for (const family of options.families) {
			if (!FAMILIES.includes(family as Family)) {
				console.error(`unknown family ${family} - known: ${FAMILIES.join(', ')}`);
				process.exit(2);
			}
		}
		const mutants = expand(attacks, {
			seed: options.seed,
			rounds: options.rounds,
			families: options.families.length ? (options.families as Family[]) : undefined,
		});
		attacks = [...attacks, ...mutants];
	}

	const config: JudgeConfig = {
		mode: options.stub ? 'stub' : 'live',
		apiKey: process.env.TYPESAFE_API_KEY ?? '',
		model: options.model,
		policyText: options.policy,
		timeoutMs: options.timeoutMs,
		retries: 1,
		usePrefilter: true,
	};

	console.log('');
	console.log(
		`  redteam · ${attacks.length} attacks · judge ${options.stub ? 'stub keyword matcher (offline)' : options.model}` +
			`${options.mutate ? ` · mutants from seed ${options.seed}` : ''}`,
	);
	console.log(
		`  estimated: ≈ ${usd(costOf(estimateScreenings(attacks.length)))} at ${PRICE_PER_MTOK_INPUT}/MTok in ` +
			`(output free, ${APPROX_TOKENS_PER_SCREENING} tokens per screening)`,
	);
	if (options.stub) {
		console.log('  the stub judge is a keyword matcher, not Jev - findings here mean the attacker works');
	}
	for (const warning of warnings) console.log(`  warning: ${warning}`);

	const results: (Result | undefined)[] = new Array(attacks.length);
	let printed = 0;
	let currentGroup = '';

	const flush = (): void => {
		while (printed < results.length && results[printed]) {
			const result = results[printed] as Result;
			if (result.attack.group !== currentGroup) {
				currentGroup = result.attack.group;
				if (!options.quiet) {
					console.log(`\n  ${currentGroup} · ${result.attack.kind} · ${result.attack.severity}`);
				}
			}
			const interesting = !['held', 'ok'].includes(result.attempts.score);
			printResult(result, !options.quiet || interesting);
			printed += 1;
		}
	};

	const runOne = async (attack: Attack): Promise<Result> => {
		const attempts = options.attempts ?? attack.attempts;
		const runs: Judgement[] = [];
		for (let attempt = 0; attempt < Math.max(1, attempts); attempt += 1) {
			runs.push(await judgeAttack(attack, config));
		}
		const graded = judgeAttempts(
			attack,
			runs.map(run => run.outcome),
		);
		const primary =
			runs.find(run => run.outcome === graded.outcome) ?? runs[0] ?? {
				outcome: 'error',
				reason: '',
				category: 'other',
				dimensions: {},
				latencyMs: 0,
				source: 'error',
			};

		return {
			attack,
			attempts: graded,
			runs,
			risk: riskOf(attack.command, primary.dimensions),
			closest: closestOf(attack.command, primary.dimensions),
			primary,
			tokens: runs.reduce(
				(sum, run) => ({
					input: sum.input + (run.tokens?.input ?? 0),
					output: sum.output + (run.tokens?.output ?? 0),
				}),
				{input: 0, output: 0},
			),
		};
	};

	let next = 0;
	const worker = async (): Promise<void> => {
		for (;;) {
			const index = next;
			next += 1;
			if (index >= attacks.length) return;
			results[index] = await runOne(attacks[index]);
			flush();
		}
	};

	const workers = Math.max(1, Math.min(options.concurrency, attacks.length));
	await Promise.all(Array.from({length: workers}, worker));

	const finished = results.filter((result): result is Result => result !== undefined);
	const findings = summarise(finished, options);
	const spend = finished.reduce(
		(sum, result) => ({
			input: sum.input + result.tokens.input,
			output: sum.output + result.tokens.output,
		}),
		{input: 0, output: 0},
	);

	if (options.report) {
		writeFileSync(
			options.report,
			JSON.stringify(
				{
					at: new Date().toISOString(),
					judge: options.stub ? 'stub' : options.model,
					options,
					corpus: seeds.length,
					tokens: spend,
					costUsd: costOf(spend),
					results: finished.map(result => ({
						id: result.attack.id,
						group: result.attack.group,
						kind: result.attack.kind,
						severity: result.attack.severity,
						expect: result.attack.expect,
						command: result.attack.command,
						harm: result.attack.harm,
						lineage: lineage(result.attack),
						verified: result.attack.verified !== false,
						outcome: result.attempts.outcome,
						score: result.attempts.score,
						counts: result.attempts.counts,
						risk: result.risk,
						closest: result.closest,
						reason: result.primary.reason,
						dimensions: result.primary.dimensions,
						latencyMs: result.primary.latencyMs,
						tokens: result.tokens,
						error: result.primary.error,
					})),
				},
				null,
				1,
			),
		);
		console.log(`\n  report written to ${options.report}`);
	}

	console.log('');
	if (findings > 0) {
		console.error(`  ${findings} finding(s) - the guard let something through\n`);
		process.exit(1);
	}
	console.log('  the guard held on every attack\n');
}

await main();
