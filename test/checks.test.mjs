// Regression tests for the vulnerability detection rules (js/checks.js).
// Run with: node test/checks.test.mjs
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { scanFile } from '../js/checks.js';

test('flags a Google OAuth client secret in an .env-shaped file', () => {
    const findings = scanFile('appsettings.json', 'const secret = "GOCSPX-abcdefghijklmnopqrstuvwx";');
    assert.equal(findings.length, 1);
    assert.equal(findings[0].checkId, 'google-oauth-secret');
    assert.equal(findings[0].severity, 'critical');
});

test('does not flag an AWS-shaped key in a non-matching file extension', () => {
    const findings = scanFile('README.md', 'AKIAABCDEFGHIJKLMNOP');
    assert.equal(findings.length, 0);
});

test('flags an AWS access key ID in a matching file', () => {
    const findings = scanFile('config.js', 'const key = "AKIAABCDEFGHIJKLMNOP";');
    assert.ok(findings.some(f => f.checkId === 'aws-access-key'));
});

test('only flags SMTP-shaped password when mail/smtp context is present', () => {
    const withMail = scanFile('appsettings.json', '{"mail": {"smtp": true, "password": "abcdefghijklmnop"}}');
    const withoutMail = scanFile('appsettings.json', '{"password": "abcdefghijklmnop"}');
    assert.ok(withMail.some(f => f.checkId === 'smtp-plaintext-credential'));
    assert.equal(withoutMail.some(f => f.checkId === 'smtp-plaintext-credential'), false);
});

test('flags Identity CreateAsync with no [Authorize] anywhere in the file', () => {
    const content = `
        public async Task<IActionResult> CreateSuperAdmin() {
            await _userManager.CreateAsync(user, "hardcoded-password");
            await _userManager.AddToRoleAsync(user, "SuperAdmin");
        }
    `;
    const findings = scanFile('AdminController.cs', content);
    assert.ok(findings.some(f => f.checkId === 'allowanonymous-near-admin'));
});

test('does not flag Identity user-creation when [Authorize] is present in the file', () => {
    const content = `
        [Authorize(Roles = "SuperAdmin")]
        public async Task<IActionResult> CreateSuperAdmin() {
            await _userManager.CreateAsync(user, "hardcoded-password");
        }
    `;
    const findings = scanFile('AdminController.cs', content);
    assert.equal(findings.some(f => f.checkId === 'allowanonymous-near-admin'), false);
});

test('flags a public Register action that unconditionally grants Admin role', () => {
    const content = `
        public async Task<IActionResult> Register(RegisterModel model) {
            var user = new ApplicationUser();
            await _userManager.CreateAsync(user, model.Password);
            await _userManager.AddToRoleAsync(user, "Admin");
        }
    `;
    const findings = scanFile('AccountController.cs', content);
    assert.ok(findings.some(f => f.checkId === 'register-action-grants-privileged-role'));
});

test('redacts matched secret values (never renders plaintext)', () => {
    const findings = scanFile('appsettings.json', 'const secret = "GOCSPX-abcdefghijklmnopqrstuvwx";');
    const [match] = findings[0].matches;
    assert.ok(match.includes('••••••••'));
    assert.equal(match.includes('abcdefghijklmnopqrstuvwx'), false);
});

test('returns no findings for a clean file', () => {
    const findings = scanFile('Program.cs', 'public class Program { public static void Main() {} }');
    assert.equal(findings.length, 0);
});
