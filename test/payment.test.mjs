// Regression test for the sandboxed payment stub (js/payment.js).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buyFullReport, PAYMENT_MODE } from '../js/payment.js';

test('payment stays in sandbox mode (no real payment provider wired)', () => {
    assert.equal(PAYMENT_MODE, 'sandbox');
});

test('buyFullReport returns a demo-checkout message in sandbox mode', () => {
    const result = buyFullReport({ totalRepos: 5 });
    assert.equal(result.ok, true);
    assert.equal(result.mode, 'sandbox');
    assert.match(result.message, /demo checkout/i);
});
