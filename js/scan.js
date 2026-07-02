// Orchestrates a cohort scan: resolve repo list -> per-repo tree -> fetch
// interesting files -> run checks -> aggregate into a report.

import { listOrgRepos, getDefaultBranch, getTree, getRawFile, INTERESTING_FILE_RE } from './github.js';
import { scanFile } from './checks.js';

const MAX_FILES_PER_REPO = 40; // rate-limit budget guard, not a quality cut

export async function resolveRepoList(input) {
    const trimmed = input.trim();
    if (!trimmed) return [];

    // Accept either "org-name" (scan every repo in the org) or a
    // comma/newline-separated list of "owner/repo" entries.
    if (!trimmed.includes('/') && !trimmed.includes(',') && !trimmed.includes('\n')) {
        const repos = await listOrgRepos(trimmed);
        return repos.map(name => ({ owner: trimmed, repo: name }));
    }

    return trimmed
        .split(/[\n,]/)
        .map(s => s.trim())
        .filter(Boolean)
        .map(entry => {
            const clean = entry.replace(/^https?:\/\/github\.com\//i, '').replace(/\/$/, '');
            const [owner, repo] = clean.split('/');
            return { owner, repo };
        })
        .filter(r => r.owner && r.repo);
}

// Config/secret-shaped files are the highest-signal, lowest-volume category
// (usually a handful per repo) — always scan them, never let a big repo's
// .cs/.js file count push them past the budget cutoff. This is the exact
// fix for a real bug found during testing: a leaked-secret appsettings.json
// sat at tree index 82 while the budget cut off at 40, so it was silently
// never fetched.
const HIGH_PRIORITY_RE = /appsettings.*\.json$|web\.config$|\.env$/i;
// This product specifically targets auth/admin vulnerability classes, so
// controllers/pages in that area are the second-highest-signal category —
// fetch them before generic (e.g. Genre/Slider/Catalog) controllers when a
// repo has more files than the scan budget allows.
const SECURITY_RELEVANT_RE = /account|admin|auth|identity|login|regist|user|role/i;

function prioritizeFiles(paths) {
    const isBuildArtifact = (p) => /\/(bin|obj|node_modules)\//i.test(p);
    const bySourceFirst = (a, b) => Number(isBuildArtifact(a)) - Number(isBuildArtifact(b));

    const configTier = paths.filter(p => HIGH_PRIORITY_RE.test(p)).sort(bySourceFirst);
    const securityTier = paths.filter(p => !HIGH_PRIORITY_RE.test(p) && SECURITY_RELEVANT_RE.test(p)).sort(bySourceFirst);
    const rest = paths.filter(p => !HIGH_PRIORITY_RE.test(p) && !SECURITY_RELEVANT_RE.test(p) && !isBuildArtifact(p));
    return [...configTier, ...securityTier, ...rest];
}

export async function scanRepo({ owner, repo }, onProgress) {
    const branch = await getDefaultBranch(owner, repo);
    if (!branch) return { owner, repo, error: 'Could not access repo (private, deleted, or renamed).', findings: [] };

    const allPaths = await getTree(owner, repo, branch);
    const candidates = allPaths.filter(p => INTERESTING_FILE_RE.test(p));
    const interesting = prioritizeFiles(candidates).slice(0, MAX_FILES_PER_REPO);

    const findings = [];
    for (const path of interesting) {
        const content = await getRawFile(owner, repo, branch, path);
        if (!content) continue;
        findings.push(...scanFile(path, content));
        if (onProgress) onProgress({ owner, repo, path });
    }

    return { owner, repo, error: null, findings, filesScanned: interesting.length };
}

export function summarize(repoResults) {
    const bySeverity = { critical: 0, high: 0, medium: 0 };
    const byCheck = {};
    let cleanRepos = 0;
    let erroredRepos = 0;

    for (const r of repoResults) {
        if (r.error) { erroredRepos++; continue; }
        if (r.findings.length === 0) { cleanRepos++; continue; }
        for (const f of r.findings) {
            bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
            byCheck[f.checkId] = (byCheck[f.checkId] || 0) + 1;
        }
    }

    return {
        totalRepos: repoResults.length,
        cleanRepos,
        erroredRepos,
        flaggedRepos: repoResults.length - cleanRepos - erroredRepos,
        bySeverity,
        byCheck
    };
}
