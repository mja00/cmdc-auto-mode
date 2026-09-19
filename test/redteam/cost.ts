// What a run costs.
//
// TypeSafe bills input tokens and does not bill output, so a screening costs roughly seven
// hundredths of a cent - the figure worth reporting is the total for a run, which is why
// the runners print it per attack and per run rather than per call. The rate is a constant
// here so a change lands in one place: the mod's own `/auto stats` counter and the red
// team's budgets should never disagree about what a token costs.

export interface Tokens {
	input: number;
	output: number;
}

/** USD per million input tokens, and per million output tokens. */
export const PRICE_PER_MTOK_INPUT = 0.042;
export const PRICE_PER_MTOK_OUTPUT = 0;

export function costOf(tokens: Tokens): number {
	return (
		(tokens.input / 1_000_000) * PRICE_PER_MTOK_INPUT +
		(tokens.output / 1_000_000) * PRICE_PER_MTOK_OUTPUT
	);
}

/** Dollars with enough precision to be useful: most runs are fractions of a cent per call. */
export function usd(amount: number): string {
	if (amount === 0) return '$0.00';
	const decimals = amount < 0.01 ? 6 : amount < 1 ? 4 : 2;
	return `$${amount.toFixed(decimals)}`;
}

export function tokens(count: number): string {
	return count.toLocaleString('en-US');
}

/** "1,234 in / 56 out (1,290 total, ≈ $0.0001)" - the shape both runners report. */
export function describeSpend(spend: Tokens, scale = 0): string {
	const total = spend.input + spend.output;
	const per =
		scale > 0 ? `, ${tokens(Math.round(total / Math.max(1, scale)))} per attack` : '';
	return (
		`${tokens(spend.input)} in / ${tokens(spend.output)} out ` +
		`(${tokens(total)} total${per}, ≈ ${usd(costOf(spend))})`
	);
}

/**
 * Roughly what one screening costs, measured against live Jev: 1,597 tokens across the
 * 90-attack suite and 1,766 across mutants whose commands carry encoded payloads. The
 * question block is the bulk of the input, so a command's length barely moves it - which
 * makes a budget in screenings convertible to a cost estimate before anything is spent.
 */
export const APPROX_TOKENS_PER_SCREENING = 1700;

/** Input is the bulk of a screening; output is a handful of probabilities per question. */
const INPUT_SHARE = 0.9;

export function estimateScreenings(screenings: number): Tokens {
	const total = screenings * APPROX_TOKENS_PER_SCREENING;
	return {input: Math.round(total * INPUT_SHARE), output: Math.round(total * (1 - INPUT_SHARE))};
}
