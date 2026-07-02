// Vulnerability detection rules. Each check is a real, well-known signature
// or a structural pattern found during an actual audit of a coding-bootcamp
// GitHub org — not speculative AI hand-waving. Every match redacts the
// actual secret value before display (even on already-public repos, we
// don't amplify exposure by rendering the plaintext).

function redact(match) {
    if (match.length <= 8) return '••••••••';
    return match.slice(0, 4) + '••••••••' + match.slice(-4);
}

// Each check: { id, label, severity, filePattern (regex on path), test(content) -> matches[] }
export const CHECKS = [
    {
        id: 'google-oauth-secret',
        label: 'Google OAuth client secret committed',
        severity: 'critical',
        filePattern: /\.(json|cs|js|ts|env|config)$/i,
        test(content) {
            // Google's real, fixed prefix for OAuth client secrets since 2021.
            const re = /GOCSPX-[A-Za-z0-9_-]{20,}/g;
            return [...content.matchAll(re)].map(m => redact(m[0]));
        }
    },
    {
        id: 'aws-access-key',
        label: 'AWS access key ID committed',
        severity: 'critical',
        filePattern: /\.(json|cs|js|ts|env|config|py|yml|yaml)$/i,
        test(content) {
            const re = /AKIA[0-9A-Z]{16}/g;
            return [...content.matchAll(re)].map(m => redact(m[0]));
        }
    },
    {
        id: 'smtp-plaintext-credential',
        label: 'Plaintext email/SMTP password near mail config',
        severity: 'high',
        filePattern: /appsettings.*\.json$|\.env$/i,
        test(content) {
            // Gmail app passwords are exactly 16 lowercase letters (no spaces,
            // as stored). Only flag when it's near mail/smtp-shaped keys to
            // avoid false-positiving on unrelated 16-char strings.
            const nearMail = /(mail|smtp|gmail)/i.test(content);
            if (!nearMail) return [];
            const re = /"[^"]*(?:password|pwd|pass)[^"]*"\s*:\s*"([a-z]{16}|[^"]{8,})"/gi;
            return [...content.matchAll(re)].map(m => redact(m[1]));
        }
    },
    {
        id: 'local-dev-connection-string',
        label: 'Hardcoded local/dev database connection string',
        severity: 'medium',
        filePattern: /appsettings.*\.json$|web\.config$/i,
        test(content) {
            const re = /Server\s*=\s*[.\\][^;"]*;[^"]*(?:Trusted_Connection|Integrated Security)/gi;
            return [...content.matchAll(re)].map(m => redact(m[0]));
        }
    },
    {
        id: 'allowanonymous-near-admin',
        label: 'Unauthenticated ([AllowAnonymous]) action near Admin/SuperAdmin code',
        severity: 'critical',
        filePattern: /\.cs$/i,
        test(content) {
            // ASP.NET Core actions are anonymous-accessible by DEFAULT unless
            // [Authorize] is applied somewhere — an explicit [AllowAnonymous]
            // isn't the only shape of "unauthenticated admin endpoint." This
            // check flags a file that creates a privileged user via Identity
            // AND contains no [Authorize] anywhere at all — the real shape
            // found in a live audit (an unprotected SuperAdmin-creation
            // action, no [Authorize] attribute in the whole file).
            const createsPrivilegedUser = /CreateAsync\([^,()]+,\s*"[^"]{4,}"\)/.test(content)
                && /(SuperAdmin|Admin)/.test(content);
            const hasAuthorize = /\[Authorize/.test(content);
            if (createsPrivilegedUser && !hasAuthorize) {
                return ['Identity user-creation endpoint with no [Authorize] anywhere in the file'];
            }
            return [];
        }
    },
    {
        id: 'register-action-grants-privileged-role',
        label: 'Public registration action grants Admin/SuperAdmin to every new user',
        severity: 'critical',
        filePattern: /\.cs$/i,
        test(content) {
            // Real shape found in audit: a public Register(...) action calls
            // AddToRoleAsync(user, "Admin") unconditionally — every new
            // signup becomes an admin. Look for AddToRoleAsync with a
            // privileged-role literal appearing after a Register method
            // signature in the same file.
            const registerIdx = content.search(/\bRegister\s*\(/);
            if (registerIdx === -1) return [];
            const afterRegister = content.slice(registerIdx);
            const re = /AddToRoleAsync\([^,]+,\s*"(Admin|SuperAdmin|Manager)"\)/;
            const m = afterRegister.match(re);
            return m ? [`AddToRoleAsync(..., "${m[1]}") reachable from a Register action`] : [];
        }
    },
    {
        id: 'hardcoded-identity-password',
        label: 'Hardcoded literal password passed to Identity CreateAsync',
        severity: 'high',
        filePattern: /\.cs$/i,
        test(content) {
            // The real shape: ASP.NET Identity's CreateAsync(user, password)
            // takes the password as a positional argument, not a named
            // "Password = ..." property — a hardcoded string literal there
            // is a real backdoor credential regardless of variable naming.
            const re = /CreateAsync\([^,()]+,\s*"([^"]{4,})"\)/g;
            return [...content.matchAll(re)].map(m => redact(m[1]));
        }
    }
];

export function scanFile(path, content) {
    const findings = [];
    for (const check of CHECKS) {
        if (!check.filePattern.test(path)) continue;
        const matches = check.test(content);
        if (matches.length > 0) {
            findings.push({ checkId: check.id, label: check.label, severity: check.severity, path, matches });
        }
    }
    return findings;
}
