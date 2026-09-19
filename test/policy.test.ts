// Pure unit tests for the code-owned parts of auto-mode: the prefilter and the
// allow/deny/escalate policy. No network, so these run anywhere.
//
//   node --test test/

import {test} from 'node:test';
import assert from 'node:assert/strict';

import {
	decide,
	extractTask,
	isYoloLaunch,
	prefilter,
	resolveInitialEnabled,
	DEFAULT_POLICY,
} from '../index.ts';

const policy = DEFAULT_POLICY;

/** Build a Jev-shaped answer map: nouls plus a category choice. */
function answers(
	nouls: Record<string, number>,
	category = 'read_only',
): Record<string, unknown> {
	const out: Record<string, unknown> = {
		category: {type: 'choice', choice: category, confidence: 0.9, probabilities: {}},
	};
	for (const [key, value] of Object.entries(nouls)) {
		out[key] = {type: 'noul', noul: value};
	}
	return out;
}

/** A calm, in-scope, harmless command. */
const clean = {
	within_scope: 0.95,
	destructive: 0.02,
	recoverable: 0.97,
	remote_effect: 0.01,
	secret_exposure: 0.01,
	privilege_escalation: 0.01,
	data_exfiltration: 0.01,
};

const decideWith = (nouls: Record<string, number>, category?: string) =>
	decide(answers(nouls, category), policy).decision;

test('prefilter allows only bare, argument-free safe commands', () => {
	for (const command of [
		'pwd',
		'whoami',
		'ls',
		'git status',
		'git branch --show-current',
		'node --version',
	]) {
		assert.equal(prefilter(command), true, `expected allow: ${command}`);
	}
});

test('prefilter rejects anything with arguments, paths, or metacharacters', () => {
	for (const command of [
		'',
		'ls -la',
		'ls /etc',
		'cat .env',
		'cat ~/.ssh/id_rsa',
		'git status && rm -rf /',
		'pwd; whoami',
		'ls > out.txt',
		'echo $(whoami)',
		'ls *.ts',
		'rm -rf /',
		'sudo ls',
		'git push',
		'git status | tee log',
	]) {
		assert.equal(prefilter(command), false, `expected reject: ${command}`);
	}
});

test('prefilter does not let a safe prefix smuggle a payload', () => {
	// `git status` is safe; nothing that merely starts with it is.
	assert.equal(prefilter('git status --porcelain -z'), false);
	assert.equal(prefilter('ls\nrm -rf /'), false);
});

test('allows an in-scope command that raises nothing', () => {
	// e.g. `rg "parse(" src/parser.ts` while fixing a parser test
	assert.equal(decideWith(clean, 'read_only'), 'allow');
	assert.equal(decideWith(clean, 'local_edit'), 'allow');
});

test('denies anything that touches secrets', () => {
	// e.g. `cat ~/.ssh/id_rsa`
	assert.equal(decideWith({...clean, secret_exposure: 0.93}, 'read_only'), 'deny');
});

test('denies unrecoverable destruction', () => {
	// e.g. `rm -rf /` - destructive and not recoverable
	assert.equal(
		decideWith({...clean, destructive: 0.95, recoverable: 0.04}, 'destructive'),
		'deny',
	);
});

test('escalates destruction that is recoverable', () => {
	// e.g. `rm -rf node_modules && npm install` - destructive but trivially redone
	assert.equal(
		decideWith({...clean, destructive: 0.88, recoverable: 0.92}, 'destructive'),
		'escalate',
	);
});

test('denies work outside the stated task', () => {
	// e.g. `git push --force origin main` while asked to fix one unit test
	assert.equal(decideWith({...clean, within_scope: 0.04}, 'remote_mutation'), 'deny');
});

test('out-of-scope outranks remote escalation', () => {
	assert.equal(
		decideWith({...clean, within_scope: 0.05, remote_effect: 0.9}, 'remote_mutation'),
		'deny',
	);
});

test('escalates an in-scope remote mutation to the human', () => {
	// e.g. `git push origin fix-parser` - legitimate, but visible to others
	assert.equal(decideWith({...clean, remote_effect: 0.91}, 'remote_mutation'), 'escalate');
});

test('denies privilege escalation and exfiltration', () => {
	assert.equal(
		decideWith({...clean, privilege_escalation: 0.87}, 'privileged'),
		'deny',
	);
	assert.equal(
		decideWith({...clean, data_exfiltration: 0.71}, 'data_transfer'),
		'deny',
	);
});

test('escalates when a judgement sits on the fence', () => {
	// 0.5 on a tracked dimension is not a license to run unattended
	assert.equal(decideWith({...clean, destructive: 0.5}), 'escalate');
	assert.equal(decideWith({...clean, remote_effect: 0.5}), 'escalate');
});

test('an undecided scope alone does not escalate', () => {
	// A coin-flip on scope with nothing risky raised is benign work, not a prompt -
	// driving a server or writing a scratch input should not stop for a human.
	assert.equal(decideWith({...clean, within_scope: 0.5}), 'allow');
	assert.equal(decideWith({...clean, within_scope: 0.42}), 'allow');
});

test('an undecided scope does not mask a risky dimension', () => {
	// Scope is exempt from the fence rule; risk dimensions still escalate on their own.
	assert.equal(decideWith({...clean, within_scope: 0.5, destructive: 0.5}), 'escalate');
	assert.equal(decideWith({...clean, within_scope: 0.5, remote_effect: 0.5}), 'escalate');
});

test('a confident "not a concern" does not escalate', () => {
	// 0.1 on every dimension is decisively quiet
	assert.equal(decideWith({...clean, destructive: 0.1, remote_effect: 0.1}), 'allow');
});

test('reports the reason and category alongside the decision', () => {
	const verdict = decide(
		answers({...clean, within_scope: 0.03}, 'remote_mutation'),
		policy,
	);
	assert.equal(verdict.decision, 'deny');
	assert.equal(verdict.category, 'remote_mutation');
	assert.match(verdict.reason, /scope/);
	assert.equal(verdict.dimensions.within_scope, 0.03);
});

test('extractTask reads user prompts and ignores tool results', () => {
	const state = {
		messages: [
			{role: 'user', content: 'Fix the failing parser test.'},
			{
				role: 'assistant',
				content: [{type: 'text', text: 'Looking at it.'}],
			},
			{
				role: 'user',
				content: [{type: 'tool_result', content: 'output that should not count'}],
			},
			{role: 'user', content: 'Then run the full suite.'},
		],
	};
	const task = extractTask(state);
	assert.match(task, /Fix the failing parser test\./);
	assert.match(task, /Then run the full suite\./);
	assert.doesNotMatch(task, /output that should not count/);
	// Oldest prompt first so the request reads in order.
	assert.ok(task.indexOf('Fix the failing') < task.indexOf('Then run'));
});

test('extractTask tolerates a missing or malformed transcript', () => {
	assert.equal(extractTask(undefined), '');
	assert.equal(extractTask({}), '');
	assert.equal(extractTask({messages: 'not an array'}), '');
	assert.equal(extractTask({messages: [{role: 'user', content: 42}]}), '');
});

test('isYoloLaunch matches only the bypass launch flags', () => {
	assert.equal(isYoloLaunch(['node', 'cmd', '--yolo']), true);
	assert.equal(isYoloLaunch(['node', 'cmd', '--dangerously-skip-permissions']), true);
	assert.equal(isYoloLaunch(['node', 'cmd', '-p', 'do a thing']), false);
	// A lookalike arg is not the flag, and the value form is not how it is passed.
	assert.equal(isYoloLaunch(['node', 'cmd', '--yolo-ish']), false);
	assert.equal(isYoloLaunch(['node', 'cmd', '--yolo=false']), false);
});

test('resolveInitialEnabled: an explicit flag always wins', () => {
	assert.equal(
		resolveInitialEnabled({
			flag: true,
			persisted: false,
			yolo: false,
			yoloDefault: true,
			hasApiKey: false,
		}),
		true,
	);
});

test('resolveInitialEnabled: a persisted toggle beats the yolo default', () => {
	// `/auto off` last session sticks even under --yolo.
	assert.equal(
		resolveInitialEnabled({
			flag: false,
			persisted: false,
			yolo: true,
			yoloDefault: true,
			hasApiKey: true,
		}),
		false,
	);
	assert.equal(
		resolveInitialEnabled({
			flag: false,
			persisted: true,
			yolo: false,
			yoloDefault: true,
			hasApiKey: true,
		}),
		true,
	);
});

test('resolveInitialEnabled: a fresh yolo launch starts screening on', () => {
	assert.equal(
		resolveInitialEnabled({
			flag: false,
			persisted: undefined,
			yolo: true,
			yoloDefault: true,
			hasApiKey: true,
		}),
		true,
	);
});

test('resolveInitialEnabled: yolo stays off without a key, without yolo, or when opted out', () => {
	// No key + fail-closed would block every screened call, so never default on.
	assert.equal(
		resolveInitialEnabled({
			flag: false,
			persisted: undefined,
			yolo: true,
			yoloDefault: true,
			hasApiKey: false,
		}),
		false,
	);
	assert.equal(
		resolveInitialEnabled({
			flag: false,
			persisted: undefined,
			yolo: true,
			yoloDefault: false,
			hasApiKey: true,
		}),
		false,
	);
	assert.equal(
		resolveInitialEnabled({
			flag: false,
			persisted: undefined,
			yolo: false,
			yoloDefault: true,
			hasApiKey: true,
		}),
		false,
	);
});
