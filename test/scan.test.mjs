// Regression tests for scan orchestration logic (js/scan.js) that doesn't
// require network access: resolveRepoList's input parsing and summarize's
// aggregation math.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveRepoList, summarize } from '../js/scan.js';

test('resolveRepoList parses a comma-separated owner/repo list', async () => {
    const repos = await resolveRepoList('acme/app-1, acme/app-2');
    assert.deepEqual(repos, [
        { owner: 'acme', repo: 'app-1' },
        { owner: 'acme', repo: 'app-2' }
    ]);
});

test('resolveRepoList parses a newline-separated list and strips github.com URLs', async () => {
    const repos = await resolveRepoList('https://github.com/acme/app-1\nacme/app-2/');
    assert.deepEqual(repos, [
        { owner: 'acme', repo: 'app-1' },
        { owner: 'acme', repo: 'app-2' }
    ]);
});

test('resolveRepoList returns empty array for blank input', async () => {
    const repos = await resolveRepoList('   ');
    assert.deepEqual(repos, []);
});

test('summarize counts clean, flagged, and errored repos correctly', () => {
    const results = [
        { owner: 'a', repo: '1', error: null, findings: [] },
        { owner: 'a', repo: '2', error: null, findings: [{ severity: 'critical', checkId: 'x' }] },
        { owner: 'a', repo: '3', error: 'Could not access repo', findings: [] }
    ];
    const summary = summarize(results);
    assert.equal(summary.totalRepos, 3);
    assert.equal(summary.cleanRepos, 1);
    assert.equal(summary.erroredRepos, 1);
    assert.equal(summary.flaggedRepos, 1);
    assert.equal(summary.bySeverity.critical, 1);
});

test('summarize tallies bySeverity and byCheck across multiple findings', () => {
    const results = [
        {
            owner: 'a', repo: '1', error: null, findings: [
                { severity: 'critical', checkId: 'google-oauth-secret' },
                { severity: 'high', checkId: 'hardcoded-identity-password' },
                { severity: 'critical', checkId: 'google-oauth-secret' }
            ]
        }
    ];
    const summary = summarize(results);
    assert.equal(summary.bySeverity.critical, 2);
    assert.equal(summary.bySeverity.high, 1);
    assert.equal(summary.byCheck['google-oauth-secret'], 2);
});
