# Cohort Autopsy 🔍

Security-vulnerability audits for coding-bootcamp cohorts. Scans an entire
cohort's GitHub repos for the security mistakes every beginner makes —
leaked secrets, unauthenticated admin panels, hardcoded backdoors — and
produces one aggregated report for the instructor or bootcamp.

▶️ **Try it:** https://emin-dev.github.io/cohort-autopsy/

## Why this exists

Built from a real, ground-truth audit: the same checks here were validated
against actual vulnerabilities found across a real coding-bootcamp GitHub
org — a live Gmail app password and Google OAuth client secret committed in
plaintext, an unauthenticated endpoint that lets anyone create a SuperAdmin
account with a hardcoded password, and a public registration action that
silently grants every new signup the Admin role. Every check in this tool
is grounded in one of those real, found bugs — not speculative pattern
guessing.

## What it checks

- Google OAuth client secrets (`GOCSPX-...`) and AWS access keys committed
  in source.
- Plaintext SMTP/email passwords near mail configuration.
- Hardcoded local/dev database connection strings.
- Identity `CreateAsync(user, "hardcoded-password")` calls — a real
  backdoor credential regardless of variable naming.
- User-creation endpoints for `Admin`/`SuperAdmin` with no `[Authorize]`
  anywhere in the file (ASP.NET Core actions are open by default without
  one — an explicit `[AllowAnonymous]` isn't the only shape of this bug).
- Public `Register(...)` actions that unconditionally grant a privileged
  role to every new user.

File-fetch budget is prioritized: config/secret files first, then
auth/admin-related controllers, then everything else — so a large repo's
file count never pushes the highest-signal files past the scan budget.

## How it's monetized

**No ads.** Scanning and a free preview (first 3 flagged repos) are free.
The full aggregated report — every flagged repo, every finding, a
downloadable instructor summary — is a one-time paid unlock, sold to the
bootcamp/instructor per cohort, not to individual students.

Payment is currently in **sandbox/test mode** (see `js/payment.js`) — no
real payment provider is connected yet. See the Studio hub's `RULES.md` for
why: creating a real payment account is a decision for the human owner, not
something built autonomously.

## Constraints (honest, by design)

- Unauthenticated GitHub API scans are limited to 60 requests/hour per IP —
  fine for one cohort, not for rapid repeated large scans.
- Static pattern-matching, not semantic analysis — it won't catch every
  vulnerability class, only the ones checked for above. It's a real,
  useful first pass, not a complete security audit.

## Tech

Vanilla JS ES modules, zero dependencies, no build step, static hosting.

```
index.html      — the scan form + results UI
style.css       — styling
js/github.js    — minimal GitHub REST API client (unauthenticated)
js/checks.js    — the vulnerability detection rules (the actual product)
js/scan.js      — orchestrates fetching + running checks + summarizing
js/payment.js   — sandboxed checkout stub
js/main.js      — wires it all to the UI
```

Made by Emin. Part of [Studio](https://emin-dev.github.io/Studio/).
