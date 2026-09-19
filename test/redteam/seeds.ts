// Loading and validating the adversarial corpus.
//
// Validation is strict and loud. A suite that silently skips a malformed entry would
// report "the guard held" while testing nothing, which is the one failure mode a red
// team must not have. Two rules matter most: bypass attacks may never declare `allow`
// as their acceptable outcome, and controls may never declare `deny` as theirs.

import {readFileSync} from 'node:fs';
import {homedir} from 'node:os';
import type {Attack, Decision, Severity} from './mutations.ts';

interface RawAttack {
	id: string;
	command: string;
	expect: Decision;
	harm?: string;
	note?: string;
	task?: string;
	cwd?: string;
	tool?: string;
	severity?: Severity;
	attempts?: number;
}

interface RawGroup {
	id: string;
	kind: Attack['kind'];
	severity?: Severity;
	note?: string;
	task?: string;
	cwd?: string;
	tool?: string;
	attempts?: number;
	attacks: RawAttack[];
}

interface RawCorpus {
	note?: string;
	defaults?: {task?: string; cwd?: string; tool?: string; attempts?: number};
	groups: RawGroup[];
}

const DECISIONS: readonly string[] = ['allow', 'deny', 'escalate'];
const SEVERITIES: readonly string[] = ['critical', 'high', 'medium', 'low'];

export const expandHome = (path: string): string =>
	path === '~' ? homedir() : path.startsWith('~/') ? `${homedir()}${path.slice(1)}` : path;

export interface LoadedCorpus {
	attacks: Attack[];
	/** Non-fatal problems worth printing: duplicate commands, suspicious shapes. */
	warnings: string[];
	path: string;
}

export function loadCorpus(path = new URL('./attacks.json', import.meta.url)): LoadedCorpus {
	const raw = JSON.parse(readFileSync(path, 'utf8')) as RawCorpus;
	const defaults = raw.defaults ?? {};
	const attacks: Attack[] = [];
	const warnings: string[] = [];
	const ids = new Set<string>();
	const commands = new Map<string, string>();
	const fail = (where: string, message: string): never => {
		throw new Error(`${String(path)}: ${where}: ${message}`);
	};

	for (const group of raw.groups ?? []) {
		if (!group.id) fail('<group>', 'missing id');
		if (group.kind !== 'bypass' && group.kind !== 'control') {
			fail(group.id, `kind must be bypass or control, got ${String(group.kind)}`);
		}

		for (const attack of group.attacks ?? []) {
			const where = `${group.id}/${attack.id ?? '<attack>'}`;
			if (!attack.id) fail(group.id, 'attack missing id');
			if (ids.has(attack.id)) fail(where, 'duplicate attack id');
			ids.add(attack.id);

			if (typeof attack.command !== 'string' || attack.command.trim() === '') {
				fail(where, 'missing command');
			}
			if (!DECISIONS.includes(attack.expect)) {
				fail(where, `expect must be one of ${DECISIONS.join(', ')}, got ${String(attack.expect)}`);
			}

			const severity = attack.severity ?? group.severity ?? 'high';
			if (!SEVERITIES.includes(severity)) {
				fail(where, `unknown severity ${String(severity)}`);
			}

			// The two rules that keep the suite honest.
			const kind = group.kind;
			if (kind === 'bypass' && attack.expect === 'allow') {
				fail(where, 'a bypass attack cannot accept allow - that would make the suite vacuous');
			}
			if (kind === 'control' && attack.expect === 'deny') {
				fail(where, 'a control cannot expect deny - over-blocking is a defect, not an outcome');
			}

			// A duplicate command is only suspicious when the task matches too - the same
			// command under a different task window is a deliberate attack (judge-injection).
			const task = attack.task ?? group.task ?? defaults.task ?? '';
			const key = `${attack.command}\u0000${task}`;
			const previous = commands.get(key);
			if (previous) warnings.push(`${where}: identical command and task as ${previous}`);
			commands.set(key, where);

			const [command] = attack.command.split('\n');
			if (command.length > 400 && !attack.note) {
				warnings.push(`${where}: long single-line command with no note explaining it`);
			}

			attacks.push({
				id: attack.id,
				command: attack.command,
				task: attack.task ?? group.task ?? defaults.task ?? '',
				cwd: expandHome(attack.cwd ?? group.cwd ?? defaults.cwd ?? process.cwd()),
				tool: attack.tool ?? group.tool ?? defaults.tool ?? 'shell_command',
				kind,
				expect: attack.expect,
				severity,
				harm: attack.harm,
				note: attack.note,
				attempts: attack.attempts ?? group.attempts ?? defaults.attempts ?? 1,
				source: 'seed',
				group: group.id,
				origin: attack.id,
				transforms: [],
				verified: true,
			});
		}
	}

	if (attacks.length === 0) fail('<corpus>', 'no attacks loaded');
	return {attacks, warnings, path: String(path)};
}
