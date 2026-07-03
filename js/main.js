import { resolveRepoList, scanRepo, summarize } from './scan.js';
import { RateLimitError } from './github.js';
import { buyFullReport } from './payment.js';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2 };
const SEVERITY_LABEL = { critical: '🔴 Critical', high: '🟠 High', medium: '🟡 Medium' };

const el = {
    form: document.getElementById('scan-form'),
    input: document.getElementById('repo-input'),
    scanBtn: document.getElementById('btn-scan'),
    status: document.getElementById('scan-status'),
    results: document.getElementById('results'),
    summary: document.getElementById('summary'),
    repoList: document.getElementById('repo-findings'),
    buyBtn: document.getElementById('btn-buy-report'),
    buyMessage: document.getElementById('buy-message')
};

let lastResults = null;

el.form.addEventListener('submit', async (e) => {
    e.preventDefault();
    await runScan(el.input.value);
});

el.buyBtn.addEventListener('click', () => {
    if (!lastResults) return;
    const result = buyFullReport(summarize(lastResults));
    el.buyMessage.textContent = result.message;
    el.buyMessage.hidden = false;
});

async function runScan(inputValue) {
    el.scanBtn.disabled = true;
    el.scanBtn.setAttribute('aria-busy', 'true');
    el.results.hidden = true;
    el.buyMessage.hidden = true;
    el.status.hidden = false;
    el.status.textContent = 'Resolving repo list…';

    try {
        const repos = await resolveRepoList(inputValue);
        if (repos.length === 0) {
            el.status.textContent = 'Enter a GitHub org name, or a comma/newline-separated list of owner/repo.';
            el.scanBtn.disabled = false;
            el.scanBtn.removeAttribute('aria-busy');
            return;
        }

        const results = [];
        for (const [i, r] of repos.entries()) {
            el.status.textContent = `Scanning ${r.owner}/${r.repo} (${i + 1}/${repos.length})…`;
            const result = await scanRepo(r);
            results.push(result);
        }

        lastResults = results;
        renderResults(results);
    } catch (err) {
        if (err instanceof RateLimitError) {
            el.status.textContent = `⏸️ ${err.message}`;
        } else {
            el.status.textContent = `Something went wrong: ${err.message}`;
        }
        el.scanBtn.disabled = false;
        el.scanBtn.removeAttribute('aria-busy');
        return;
    }

    el.status.hidden = true;
    el.scanBtn.disabled = false;
    el.scanBtn.removeAttribute('aria-busy');
}

function renderResults(results) {
    const summary = summarize(results);
    el.summary.innerHTML = `
        <div class="summary-grid">
            <div class="summary-stat"><span class="stat-num">${summary.totalRepos}</span><span class="stat-label">repos scanned</span></div>
            <div class="summary-stat flagged"><span class="stat-num">${summary.flaggedRepos}</span><span class="stat-label">flagged</span></div>
            <div class="summary-stat clean"><span class="stat-num">${summary.cleanRepos}</span><span class="stat-label">clean</span></div>
        </div>
        <div class="severity-row">
            ${summary.bySeverity.critical ? `<span class="severity-chip critical">${summary.bySeverity.critical} critical</span>` : ''}
            ${summary.bySeverity.high ? `<span class="severity-chip high">${summary.bySeverity.high} high</span>` : ''}
            ${summary.bySeverity.medium ? `<span class="severity-chip medium">${summary.bySeverity.medium} medium</span>` : ''}
        </div>
    `;

    el.repoList.innerHTML = '';
    const flaggedRepos = results.filter(r => !r.error && r.findings.length > 0);
    const preview = flaggedRepos.slice(0, 3); // free preview shows first 3 flagged repos; full report is the paid unlock

    preview.forEach(r => {
        const card = document.createElement('div');
        card.className = 'repo-card';
        const sortedFindings = [...r.findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
        card.innerHTML = `
            <h3>${r.owner}/${r.repo}</h3>
            ${sortedFindings.map(f => `
                <div class="finding">
                    <span class="finding-severity">${SEVERITY_LABEL[f.severity]}</span>
                    <span class="finding-label">${f.label}</span>
                    <span class="finding-path">${f.path}</span>
                </div>
            `).join('')}
        `;
        el.repoList.appendChild(card);
    });

    if (flaggedRepos.length > preview.length) {
        const lockNotice = document.createElement('div');
        lockNotice.className = 'lock-notice';
        lockNotice.textContent = `+ ${flaggedRepos.length - preview.length} more flagged repo(s) in the full report.`;
        el.repoList.appendChild(lockNotice);
    }

    el.results.hidden = false;
}
