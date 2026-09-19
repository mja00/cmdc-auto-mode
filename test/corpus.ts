// Live corpus runner: replays real-world allow/deny examples against TypeSafe Jev
// and asserts the tuned screener still makes the expected call.
//
//   TYPESAFE_API_KEY=... npm run test:corpus
//
// `test/corpus.json` is the corpus - append cases as you meet them. A case runs
// `attempts` times (default 1) and passes when the expected decision shows up in the
// majority, so a stochastic verdict on a borderline command does not fail the suite
// while a genuine regression still does. The reported rate makes flakiness visible.

import {readFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {screen, summarize} from '../index.ts';
import type {Verdict} from '../index.ts';

type Decision = 'allow' | 'deny' | 'escalate';

interface Case {
	command: string;
	expect: Decision;
	note?: string;
	attempts?: number;
	/** Overrides the group's task for this case. */
	task?: string;
}

interface Group {
	id: string;
	task: string;
	cwd: string;
	tool?: string;
	cases: Case[];
}

interface Corpus {
	note?: string;
	groups: Group[];
}

const apiKey = process.env.TYPESAFE_API_KEY;
if (!apiKey) {
	console.error('TYPESAFE_API_KEY is not set');
	process.exit(1);
}

const corpus: Corpus = JSON.parse(
	readFileSync(new URL('./corpus.json', import.meta.url), 'utf8'),
);

const expandHome = (path: string): string =>
	path === '~' ? homedir() : path.startsWith('~/') ? `${homedir()}${path.slice(1)}` : path;

let total = 0;
let failures = 0;

console.log('');

for (const group of corpus.groups) {
	console.log(`${group.id} · ${group.cases.length} cases`);

	for (const testCase of group.cases) {
		total += 1;
		const attempts = Math.max(1, testCase.attempts ?? 1);
		const needed = Math.ceil(attempts / 2);

		const decisions: Decision[] = [];
		let last: Verdict | undefined;
		let error = '';

		for (let attempt = 0; attempt < attempts; attempt += 1) {
			try {
				last = await screen({
					command: testCase.command,
					tool: group.tool ?? 'shell_command',
					cwd: expandHome(group.cwd),
					task: testCase.task ?? group.task,
					policyText: '',
					apiKey,
					model: 'jev-latest',
					timeoutMs: 8000,
					retries: 1,
					usePrefilter: true,
				});
				decisions.push(last.decision);
			} catch (caught) {
				error = caught instanceof Error ? caught.message : String(caught);
				break;
			}
		}

		const matches = decisions.filter(d => d === testCase.expect).length;
		const ok = decisions.length === attempts && matches >= needed;
		if (!ok) failures += 1;

		const rate = attempts > 1 ? ` ${matches}/${attempts}` : '';
		const scope = last?.dimensions.within_scope;
		console.log(
			`${ok ? '  ' : '!!'} ${testCase.expect.toUpperCase().padEnd(8)}${rate.padEnd(5)}` +
				`${scope === undefined ? '' : `scope ${scope.toFixed(2)}  `}${testCase.note ?? ''}`,
		);

		if (!ok) {
			console.log(`     $ ${summarize(testCase.command)}`);
			console.log(
				`     got ${decisions.length ? decisions.join(', ') : 'no verdict'}` +
					`${last?.reason ? ` · ${last.reason}` : ''}${error ? ` · ${error}` : ''}`,
			);
		}
	}
	console.log('');
}

console.log(`  ${total} cases · ${failures} failures`);
if (failures > 0) {
	console.error(`\n${failures} case(s) produced the wrong decision\n`);
	process.exit(1);
}
console.log('  corpus behaved as expected\n');
