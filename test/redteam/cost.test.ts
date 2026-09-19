// Tests for the cost estimator: cheap arithmetic that decides how much a run is allowed to
// spend, so it should be right about the rate and honest about its precision.

import {test} from 'node:test';
import assert from 'node:assert/strict';

import {
	APPROX_TOKENS_PER_SCREENING,
	costOf,
	describeSpend,
	estimateScreenings,
	PRICE_PER_MTOK_INPUT,
	PRICE_PER_MTOK_OUTPUT,
	tokens,
	usd,
} from './cost.ts';

/** Costs are computed in floats and printed to six places; compare them the same way. */
const closeTo = (actual: number, expected: number): boolean =>
	Math.abs(actual - expected) < 1e-12;

test('input is billed at the quoted rate and output is free', () => {
	assert.equal(PRICE_PER_MTOK_INPUT, 0.042);
	assert.equal(PRICE_PER_MTOK_OUTPUT, 0);
	assert.ok(closeTo(costOf({input: 1_000_000, output: 0}), 0.042));
	assert.ok(closeTo(costOf({input: 1_000, output: 0}), 0.000042));
	assert.equal(costOf({input: 0, output: 10_000_000}), 0);
	assert.ok(closeTo(costOf({input: 500_000, output: 999}), 0.021));
});

test('dollars are printed with enough precision to be useful', () => {
	assert.equal(usd(0), '$0.00');
	assert.equal(usd(0.000042), '$0.000042');
	assert.equal(usd(0.0714), '$0.0714');
	assert.equal(usd(2.5), '$2.50');
	// A screening costs a fraction of a cent, and the printed figure has to show that
	// rather than rounding every interesting number to zero.
	assert.notEqual(usd(costOf({input: 1_800, output: 200})), '$0.00');
});

test('the pre-flight estimate matches the measured per-screening cost', () => {
	const estimate = estimateScreenings(1_000);
	assert.equal(estimate.input + estimate.output, 1_000 * APPROX_TOKENS_PER_SCREENING);
	// The constant is a measurement, not a guess: it has to stay in the neighbourhood of
	// what live runs actually spend, or the pre-flight figures are misleading.
	assert.ok(
		APPROX_TOKENS_PER_SCREENING >= 1_500 && APPROX_TOKENS_PER_SCREENING <= 3_000,
		`per-screening cost of ${APPROX_TOKENS_PER_SCREENING} tokens looks stale`,
	);
	// $0.042/MTok, input-heavy: a thousand screenings lands in the cents.
	const cost = costOf(estimate);
	assert.ok(cost > 0.05 && cost < 0.15, `1,000 screenings estimated at ${usd(cost)}`);
	assert.equal(estimateScreenings(0).input, 0);
});

test('spend reads as one line with a per-attack figure', () => {
	const spend = {input: 12_804, output: 2_034};
	assert.equal(describeSpend(spend), '12,804 in / 2,034 out (14,838 total, ≈ $0.000538)');
	assert.match(describeSpend(spend, 9), /14,838 total, 1,649 per attack, ≈ \$0\.000538/);
	assert.equal(describeSpend({input: 0, output: 0}), '0 in / 0 out (0 total, ≈ $0.00)');
	assert.equal(tokens(1_234_567), '1,234,567');
});
