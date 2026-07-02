// Minimal GitHub REST API client — unauthenticated, public repos only.
// No token, no dependency. Unauthenticated requests are rate-limited to
// 60/hour per IP by GitHub, which is fine for a demo/single-cohort scan but
// is a real constraint we surface honestly in the UI rather than hiding.

const API = 'https://api.github.com';

export class RateLimitError extends Error {}

async function ghFetch(path) {
    const res = await fetch(`${API}${path}`);
    if (res.status === 403 || res.status === 429) {
        const remaining = res.headers.get('x-ratelimit-remaining');
        if (remaining === '0') {
            throw new RateLimitError('GitHub API rate limit reached (60 requests/hour for unauthenticated scans). Try again later, or scan fewer repos at once.');
        }
    }
    if (!res.ok) return null;
    return res.json();
}

export async function listOrgRepos(org) {
    const repos = [];
    let page = 1;
    while (true) {
        const batch = await ghFetch(`/orgs/${encodeURIComponent(org)}/repos?per_page=100&page=${page}`);
        if (!batch || batch.length === 0) break;
        repos.push(...batch.map(r => r.name));
        if (batch.length < 100) break;
        page++;
        if (page > 5) break; // hard safety cap (500 repos) — plenty for any real cohort
    }
    return repos;
}

export async function getDefaultBranch(owner, repo) {
    const data = await ghFetch(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`);
    return data ? data.default_branch : null;
}

export async function getTree(owner, repo, branch) {
    const data = await ghFetch(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
    if (!data || !data.tree) return [];
    return data.tree.filter(t => t.type === 'blob').map(t => t.path);
}

const MAX_FILE_BYTES = 200_000; // skip anything large (build artifacts, bundles) — not interesting for secrets

export async function getRawFile(owner, repo, branch, path) {
    const url = `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(branch)}/${path}`;
    try {
        const res = await fetch(url);
        if (!res.ok) return null;
        const contentLength = res.headers.get('content-length');
        if (contentLength && Number(contentLength) > MAX_FILE_BYTES) return null;
        return await res.text();
    } catch {
        return null;
    }
}

// Files worth fetching content for — matches the CHECKS' filePattern intent,
// kept here too so we don't waste rate-limit budget fetching irrelevant blobs.
export const INTERESTING_FILE_RE = /(appsettings.*\.json|web\.config|\.env|\.cs|\.js|\.ts)$/i;
