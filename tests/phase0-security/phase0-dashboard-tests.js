'use strict';
/* Phase 0 — dashboard.html client-side security tests (correction pass).
   Extracts the real shipped helpers/functions and exercises them. */
const fs = require('fs');
const { execSync } = require('child_process');
const nodePath = require('path');
const REPO = nodePath.join(__dirname, '..', '..');
const path = REPO + '/dashboard.html';
const src = fs.readFileSync(path, 'utf8');

let PASS = 0, FAIL = 0; const OUT = [];
const check = (g, n, c, d = '') => { if (c) { PASS++; OUT.push(`  PASS  [${g}] ${n}`); } else { FAIL++; OUT.push(`  FAIL  [${g}] ${n}  ${d}`); } };

function grab(name, kw) {
  const re = new RegExp('(?:' + (kw || 'function') + ')\\s+' + name + '\\s*\\([\\s\\S]*?\\n\\}', 'm');
  const m = src.match(re);
  if (!m) throw new Error('not found: ' + name);
  return m[0];
}
global.window = { location: { origin: 'https://example.org' } };
const ctx = {};
function grabConst(name) {
  // line-based: the value contains ';' inside a character class
  const m = src.match(new RegExp('^const ' + name + ' = .*$', 'm'));
  if (!m) throw new Error('const not found: ' + name);
  return m[0];
}
const helperSrc = [grabConst('MAIL_FORBIDDEN_CHARS')]
  .concat(['esc', '_esc', 'jsAttr', 'safeUrl', 'telDigits', 'safeTel', 'safeMail', 'telLink', 'mailLink'].map(n => grab(n)))
  .join('\n');
new Function('g', helperSrc + ';g.esc=esc;g._esc=_esc;g.jsAttr=jsAttr;g.safeUrl=safeUrl;g.safeTel=safeTel;g.safeMail=safeMail;g.telLink=telLink;g.mailLink=mailLink;g.telDigits=telDigits;')(ctx);

// ══ 1. Output encoding ═════════════════════════════════════════════════════
const XSS = '<img src=x onerror=alert(1)>';
check('xss', 'esc() neutralises tag characters', !/[<>]/.test(ctx.esc(XSS)));
check('xss', 'esc() neutralises double quotes', ctx.esc('a"b').includes('&quot;'));
check('xss', '_esc() neutralises tag characters', !/[<>]/.test(ctx._esc(XSS)));
check('xss', 'esc() renders a script payload inert', ctx.esc('</script><script>alert(1)</script>').indexOf('<') === -1);

// ══ 2. renderFlaggedCases (Owner-reported finding) ════════════════════════
check('flagged', 'renderFlaggedCases escapes Case Type and Court Location',
  src.includes("${esc(f(r)['Case Type']||'—')} · ${esc(f(r)['Court Location']||'No court')}"));
check('flagged', 'no unescaped Case Type/Court Location pair remains',
  !src.includes("${f(r)['Case Type']||'—'} · ${f(r)['Court Location']||'No court'}"));
check('flagged', 'avatar initials are escaped',
  src.includes("${esc((f(r)['First Name']||'?')[0])}"));

// ══ 3. Exhaustive inventory gate ══════════════════════════════════════════
let invOk = true, invOut = '';
try { invOut = execSync('node ' + JSON.stringify(nodePath.join(__dirname, 'phase0-xss-inventory.js')) + ' ' + JSON.stringify(path), { encoding: 'utf8' }); }
catch (e) { invOk = false; invOut = (e.stdout || '') + (e.stderr || ''); }
check('inventory', 'exhaustive XSS inventory reports zero unresolved findings', invOk,
  (invOut.split('\n').filter(l => /untriaged/i.test(l)).join(' | ')));

// ══ 4. jsAttr — JS-string context ═════════════════════════════════════════
const evil = "'); alert(1); //";
const enc = ctx.jsAttr(evil);
const htmlDecoded = enc.replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
let broke = false;
try { new Function("var x = '" + htmlDecoded + "'; return x;")(); } catch { broke = true; }
check('jsattr', 'jsAttr output cannot break out of a JS string literal', !broke);
check('jsattr', 'archive button uses jsAttr for the case number', src.includes("const caseNum = jsAttr("));

// ══ 5. URL scheme allowlist ═══════════════════════════════════════════════
for (const bad of ['javascript:alert(1)', 'JavaScript:alert(1)', 'data:text/html,<script>alert(1)</script>', 'vbscript:msgbox(1)', 'file:///etc/passwd'])
  check('url', `safeUrl rejects ${bad.slice(0, 20)}`, ctx.safeUrl(bad) === '');
check('url', 'safeUrl accepts https', ctx.safeUrl('https://drive.google.com/x').startsWith('https://'));

// ══ 6. Phone / email link safety ══════════════════════════════════════════
check('phone', 'safeTel requires a real digit count (7 digits rejected)', ctx.safeTel('555-1234') === '');
check('phone', 'safeTel accepts a 10-digit number', ctx.safeTel('(212) 555-0142') === '2125550142');
check('phone', 'safeTel strips a US country code', ctx.safeTel('1-212-555-0142') === '2125550142');
check('phone', 'safeTel rejects an over-long number', ctx.safeTel('1234567890123456789') === '');
for (const bad of ['javascript:alert(1)', 'abc', '', null, undefined, '###', '555', '"onmouseover="alert(1)'])
  check('phone', `safeTel rejects ${JSON.stringify(bad)}`, ctx.safeTel(bad) === '');
for (const bad of ['javascript:alert(1)', 'notanemail', 'a@b', '', null, 'a@b.co" onclick="x'])
  check('email', `safeMail rejects ${JSON.stringify(bad)}`, ctx.safeMail(bad) === '');
check('email', 'safeMail accepts a valid address', ctx.safeMail('staff@example.com') === 'staff@example.com');

// ── Stored-XSS regression: WHITESPACE-FREE attribute injection ─────────────
// The exact payload from the pre-merge report. Every one of these passes a
// naive /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/ check because it contains no space.
const MAIL_INJECTIONS = [
  'a"onmouseover=alert(1)@b.co',          // the reported payload
  'a"onfocus=alert(1)autofocus="@b.co',
  "a'onmouseover=alert(1)@b.co",          // apostrophe variant
  'a`onmouseover=alert(1)`@b.co',         // backtick variant
  'a<script>alert(1)</script>@b.co',      // angle brackets
  'a;alert(1)@b.co',                      // semicolon
  'a,alert(1)@b.co',                      // comma
  'a\\alert(1)@b.co',                     // backslash
  'a(1)@b.co',                            // parentheses
  'a[1]@b.co',                            // brackets
];
for (const p of MAIL_INJECTIONS) {
  check('xss-mail', `safeMail rejects injection ${JSON.stringify(p).slice(0, 42)}`, ctx.safeMail(p) === '', JSON.stringify(ctx.safeMail(p)));
  const out = ctx.mailLink(p);
  check('xss-mail', `mailLink renders no anchor for ${JSON.stringify(p).slice(0, 34)}`, out.indexOf('<a') === -1, out.slice(0, 90));
  check('xss-mail', `mailLink emits no href for ${JSON.stringify(p).slice(0, 34)}`, out.indexOf('href') === -1, out.slice(0, 90));
  // The decisive assertion: no attribute may survive outside the quoted href.
  check('xss-mail', `mailLink cannot break the href attribute for ${JSON.stringify(p).slice(0, 26)}`,
    !/href="[^"]*"[^>]*on[a-z]+\s*=/i.test(out) && !/<[a-z]+\s[^>]*on[a-z]+\s*=/i.test(out), out.slice(0, 110));
}
// A quote must never reach the rendered href even if a future regex lets it through.
check('xss-mail', 'mailLink output never contains a raw quote inside href',
  !/href="mailto:[^"]*"[^>]*=/.test(ctx.mailLink('a"onmouseover=alert(1)@b.co')));
// tel: equivalent — digits only, plus explicit escaping
for (const p of ['1234567890"onmouseover=alert(1)', "1234567890'onmouseover=alert(1)", '1234567890`x`']) {
  const out = ctx.telLink(p);
  check('xss-tel', `telLink cannot break the href attribute for ${JSON.stringify(p).slice(0, 30)}`,
    !/href="[^"]*"[^>]*on[a-z]+\s*=/i.test(out) && !/<[a-z]+\s[^>]*on[a-z]+\s*=/i.test(out), out.slice(0, 110));
}
// Valid destinations must still work after the tightening.
check('xss-mail', 'valid address still produces a working mailto link',
  ctx.mailLink('staff@example.com') === '<a href="mailto:staff@example.com">staff@example.com</a>', ctx.mailLink('staff@example.com'));
check('xss-tel', 'valid number still produces a working tel link',
  ctx.telLink('(212) 555-0142').indexOf('<a href="tel:2125550142"') === 0, ctx.telLink('(212) 555-0142'));
check('xss-mail', 'plus-addressing and dots still accepted', ctx.safeMail('first.last+tag@sub.example.co.uk') !== '');
check('xss-mail', 'safeMail rejects an over-long address', ctx.safeMail('a'.repeat(250) + '@b.co') === '');

// telLink / mailLink contracts
check('link', 'telLink emits an anchor for a valid number', /^<a href="tel:2125550142"/.test(ctx.telLink('(212) 555-0142')));
check('link', 'telLink emits NO anchor for an invalid number', ctx.telLink('555-1234').indexOf('<a') === -1);
check('link', 'telLink never emits an empty tel: href', !/href="tel:"/.test(ctx.telLink('abc')) && !/href="tel:"/.test(ctx.telLink('')));
check('link', 'telLink renders invalid input as escaped text', ctx.telLink(XSS).indexOf('<img') === -1 && ctx.telLink(XSS).includes('&lt;'));
check('link', 'telLink hideWhenInvalid emits nothing', ctx.telLink('555', { hideWhenInvalid: true }) === '');
check('link', 'telLink escapes its label', ctx.telLink('2125550142', { label: XSS }).indexOf('<img') === -1);
check('link', 'mailLink emits an anchor for a valid address', /^<a href="mailto:a@b\.co"/.test(ctx.mailLink('a@b.co')));
check('link', 'mailLink emits NO anchor for an invalid address', ctx.mailLink('nope').indexOf('<a') === -1);
check('link', 'mailLink never emits an empty mailto: href', !/href="mailto:"/.test(ctx.mailLink('nope')) && !/href="mailto:"/.test(ctx.mailLink('')));
check('link', 'mailLink turns a javascript: value into inert text, not a link',
  ctx.mailLink('javascript:alert(1)').indexOf('<a') === -1 && ctx.mailLink('javascript:alert(1)').indexOf('href') === -1);
check('link', 'telLink turns a javascript: value into inert text, not a link',
  ctx.telLink('javascript:alert(1)').indexOf('<a') === -1 && ctx.telLink('javascript:alert(1)').indexOf('href') === -1);

// every rendering location routed through the helpers
// exclude the two sanctioned builders inside telLink()/mailLink() themselves
const rawLinks = src.split('\n').filter(l => /href="(tel|mailto):\$\{/.test(l) && !/\$\{esc\(dest\)\}/.test(l));
check('link', 'no hand-built tel:/mailto: hrefs remain anywhere', rawLinks.length === 0, rawLinks.join(' | ').slice(0, 200));
for (const site of [
  ["case modal phone", "telLink(fd['Phone'], { label: '📞 Call'"],
  ["case modal email", "mailLink(fd['Email'], { label: '✉ Send email'"],
  ["attorney card phone", "telLink(af['Phone'], { label: '📞 '"],
  ["attorney card email", "mailLink(af['Email'], { label: '✉ '"],
  ["attorney list phone", "`<span>📞 ${telLink(fd['Phone'])}</span>`"],
  ["attorney list email", "`<span>✉️ ${mailLink(fd['Email'])}</span>`"],
]) check('link', `${site[0]} uses the validated helper`, src.includes(site[1]), site[1]);
check('link', 'financials OpenPhone button gated on a validated number', src.includes("const digits    = safeTel(phone);") && src.includes("opHref ? `<button class=\"fin-btn\""));
check('link', 'leads OpenPhone link gated on a validated number', src.includes("const digits = safeTel(phone);"));
check('link', 'leads phone cell falls back to escaped text', src.includes(": (phone ? esc(phone) : '—')"));

// ══ 7. Read Only issues no activity-log request ═══════════════════════════
{
  const fnSrc = grab('_loadActivityLog', 'async function');
  let fetches = 0, html = '';
  const el = { set innerHTML(v) { html = v; }, get innerHTML() { return html; } };
  const mk = (role) => new Function('deps', `
    const { document, hasPermission, staffHeader, _esc, fetch, formatDate, _fmtDate } = deps;
    ${fnSrc}
    return _loadActivityLog;`)({
      document: { getElementById: () => el },
      hasPermission: (min) => ({ 'Read Only': 1, Employee: 2, Manager: 3, Admin: 4 }[role] || 0) >= ({ 'Read Only': 1, Employee: 2, Manager: 3, Admin: 4 }[min] || 99),
      staffHeader: () => ({}), _esc: ctx._esc, formatDate: (x) => x, _fmtDate: (x) => x,
      fetch: async () => { fetches++; return { ok: true, json: async () => ({ records: [] }) }; },
    });
  return (async () => {
    fetches = 0; html = '';
    await mk('Read Only')('recX');
    check('readonly-log', 'Read Only issues NO get-activity-log request', fetches === 0, `fetches=${fetches}`);
    check('readonly-log', 'Read Only sees a neutral message, not an error', /available for your role/i.test(html) && !/could not|error|failed/i.test(html), html.slice(0, 90));
    fetches = 0; html = '';
    await mk('Employee')('recX');
    check('readonly-log', 'Employee still issues the case-scoped request', fetches === 1, `fetches=${fetches}`);
    fetches = 0;
    await mk('Manager')('recX');
    check('readonly-log', 'Manager still issues the request', fetches === 1, `fetches=${fetches}`);
    finish();
  })();
}

function finish() {
// ══ 8. Financial controls by role ════════════════════════════════════════
check('fin-ui', 'canEditFinancials() is defined as Manager-or-higher',
  /function canEditFinancials\(\)\s*\{\s*return hasPermission\('Manager'\);\s*\}/.test(src));
check('fin-ui', 'payment tab computes a disabled flag from the role', src.includes("const canFin = canEditFinancials();") && src.includes("const finDis = canFin ? '' : ' disabled';"));
for (const [name, needle] of [
  ['Fee Collected input', `id="ef-fee" value="${'${'}esc(fd['Client Fee Collected']||'')}" step="0.01" min="0"${'${'}finDis}`],
  ['Attorney Service Fee input', `id="ef-atty-fee" value="${'${'}esc(fd['Attorney Service Fee']||'')}" step="0.01" min="0"${'${'}finDis}`],
  ['Payment Method select', `sel(payMethods, fd['Payment Method']||'', 'ef-pay-method', finDis)`],
]) check('fin-ui', `${name} is disabled below Manager`, src.includes(needle), needle.slice(0, 60));
check('fin-ui', 'Mark Attorney Paid button is Manager-only', src.includes(": (canFin\n        ? `<button class=\"btn\" style=\"margin-top:4px;\" onclick=\"confirmAttyPaidFromEdit("));
check('fin-ui', 'financials row Record Payment button is Manager-only', src.includes("(balance > 0 && canEditFinancials())"));
check('fin-ui', 'financials row Mark Attorney Paid button is Manager-only', src.includes("(!attyPaid && attyFee > 0 && canEditFinancials())"));
check('fin-ui', 'bulk Mark Selected Paid is Manager-only', src.includes('<button class="btn primary" data-role="manager" onclick="bulkMarkPaid()">'));
check('fin-ui', 'bulk Mark Atty Paid is Manager-only', src.includes('<button class="btn" data-role="manager" onclick="bulkMarkAttyPaid()">'));
check('fin-ui', 'bulk Assign Attorney stays available to Employee', /onclick="openBulkAssignAttorney\(\)"/.test(src) && !/data-role="manager" onclick="openBulkAssignAttorney/.test(src));
check('fin-ui', 'leads Convert-to-paid button is Manager-only', src.includes('${canEditFinancials() ? `<button class="lead-btn lead-btn-convert"'));
check('fin-ui', 'leads Stripe button hidden from Read Only', src.includes("${STRIPE_ENABLED && hasPermission('Employee') ?"));
check('fin-ui', 'financial task Resolve button hidden below Manager', src.includes("(t.type === 'collect-balance' || t.type === 'pay-attorney') && !canEditFinancials() ? ''"));
for (const fn of ['markAttyPaid', 'bulkMarkAttyPaid', 'openFinPayment', 'bulkMarkPaid', 'confirmAttyPaidFromEdit', 'openConvertLead', '_resolveCollectBalance', '_resolvePayAttorney'])
  check('fin-ui', `${fn}() refuses below Manager`, new RegExp(fn + '\\([^)]*\\)\\s*\\{\\s*\\n\\s*if \\(!canEditFinancials\\(\\)\\) return showToast').test(src));
check('fin-ui', 'openTaskResolve() refuses financial task types below Manager',
  /function openTaskResolve\(taskType, caseId\) \{\s*\n\s*if \(\(taskType === 'collect-balance'/.test(src));
check('fin-ui', 'role visibility fails CLOSED when the role cannot be read',
  /catch \(e\) \{[\s\S]{0,200}querySelectorAll\('\[data-role\]'\)[\s\S]{0,80}display = 'none'/.test(src));

// Manager/Admin retain the controls (the guards are permission-based, not hard-coded off)
{
  const canFin = new Function('hasPermission', 'return ' + grab('canEditFinancials').replace('function canEditFinancials()', 'function f()') + '; ')
    ;
  const mkCan = (role) => new Function('hasPermission', grab('canEditFinancials') + ' return canEditFinancials();')(
    (min) => ({ 'Read Only': 1, Employee: 2, Manager: 3, Admin: 4 }[role] || 0) >= ({ 'Read Only': 1, Employee: 2, Manager: 3, Admin: 4 }[min] || 99));
  check('fin-ui', 'Admin retains financial controls', mkCan('Admin') === true);
  check('fin-ui', 'Manager retains financial controls', mkCan('Manager') === true);
  check('fin-ui', 'Employee is denied financial controls', mkCan('Employee') === false);
  check('fin-ui', 'Read Only is denied financial controls', mkCan('Read Only') === false);
}

// ══ 9. Auth-header coverage ══════════════════════════════════════════════
const PUBLIC = new Set(['config', 'staff-auth']);
const lines = src.split('\n');
const missing = [];
lines.forEach((l, i) => {
  const m = l.match(/\/\.netlify\/functions\/([a-z-]+)/);
  if (!m || PUBLIC.has(m[1])) return;
  if (!/staffHeader\(\)|X-Staff-Token/.test(lines.slice(i, i + 6).join('\n'))) missing.push(`${i + 1}:${m[1]}`);
});
check('headers', 'zero private dashboard requests missing X-Staff-Token', missing.length === 0, missing.join(', '));
check('headers', 'staffHeader() call count matches the audited total', (src.match(/staffHeader\(\)/g) || []).length === 27);
check('legacy', 'dashboard does not call the retired auth.js endpoint', !/\/\.netlify\/functions\/auth(?![a-z-])/.test(src));

// ── Error rendering ───────────────────────────────────────────────────────
check('errors', 'staff-list catch escapes the error before innerHTML',
  /listEl\.innerHTML = '<div[^']*'\s*\+\s*esc\(e\.message\)/.test(src));
{
  const lines = src.split('\n'); const unescaped = [];
  lines.forEach((l, i) => {
    const m = l.match(/\$\{([^}]*\b(?:e|err|error)\.message[^}]*)\}/);
    if (m && !/\b(esc|_esc)\s*\(/.test(m[1])) unescaped.push(`${i + 1}:${m[1]}`);
    const c = l.match(/innerHTML\s*=\s*[^;]*?\+\s*[A-Za-z_$][\w$.]*\.message/);
    if (c && !/esc\(/.test(l)) unescaped.push(`${i + 1}:concat`);
  });
  check('errors', 'no error message reaches innerHTML unescaped anywhere', unescaped.length === 0, unescaped.join(', '));
}
// ── Quote Status is Manager+ ─────────────────────────────────────────────
check('fin-ui', 'saveCase sends Quote Status only for Manager+',
  src.includes("fields['Quote Status']   = g('ef-quote'") && !/'Quote Status':\s+g\('ef-quote'/.test(src));
check('fin-ui', 'Quote Status select is disabled below Manager',
  src.includes("const quoteDis = canEditFinancials() ? '' : ' disabled';") && src.includes("'<select' + quoteDis + ' '"));


// ══ 11. Session tokens must never appear in a URL (pre-merge correction) ═══
{
  const authSrc = fs.readFileSync(REPO + '/auth.html', 'utf8');
  const strip   = s => s.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
  const dashCode = strip(src);
  const authCode = strip(authSrc);

  for (const [label, code] of [['dashboard.html', dashCode], ['auth.html', authCode]]) {
    // No verification URL may carry the credential.
    check('token-url', `${label} contains no staff-auth?token= verification URL`,
      !/staff-auth\?token=/.test(code));
    check('token-url', `${label} builds no URL with a token query parameter`,
      !/[?&]token=/.test(code));
    check('token-url', `${label} never concatenates the token onto a fetch URL`,
      !/fetch\(\s*['"`][^'"`]*['"`]\s*\+\s*encodeURIComponent\(\s*token/.test(code));
    // The token must never enter navigation, history or a redirect.
    check('token-url', `${label} never places a token in location.href`,
      !/location\.href\s*=\s*[^;\n]*\btoken\b/.test(code));
    check('token-url', `${label} never places a token in location.replace()`,
      !/location\.replace\(\s*[^)]*\btoken\b/.test(code));
    check('token-url', `${label} never pushes a token into history`,
      !/history\.(pushState|replaceState)\([^)]*\btoken\b/i.test(code));
    check('token-url', `${label} never logs a token value to the console`,
      ![...code.matchAll(/console\.(?:log|warn|error)\(([\s\S]*?)\);/g)]
        .some(m => /\$\{[^}]*token[^}]*\}|[,+]\s*token\b/i.test(m[1])));
    check('token-url', `${label} never renders a token into an error message`,
      !/(errEl|textContent|innerHTML)\s*=\s*[^;\n]*\btoken\b/.test(code));
  }

  // Both pages must verify using the header.
  const sendsHeader = code => /['"]X-Staff-Token['"]\s*:\s*token/.test(code);
  check('token-url', 'dashboard.html verifies the session with an X-Staff-Token header',
    sendsHeader(dashCode));
  check('token-url', 'auth.html verifies the session with an X-Staff-Token header',
    sendsHeader(authCode));
  check('token-url', 'dashboard.html still calls the staff-auth verification endpoint',
    /fetch\(\s*['"]\/\.netlify\/functions\/staff-auth['"]/.test(dashCode));
  check('token-url', 'auth.html still calls the staff-auth verification endpoint',
    /fetch\(\s*['"]\/\.netlify\/functions\/staff-auth['"]/.test(authCode));

  // Login POST and logout behaviour must be untouched.
  check('token-url', 'auth.html still POSTs credentials as a JSON body',
    /method:\s*['"]POST['"]/.test(authCode) && /JSON\.stringify\(\{\s*email/.test(authCode));
  check('token-url', 'auth.html stores the token in sessionStorage only',
    /sessionStorage\.setItem\(\s*['"]tt_auth_token['"]/.test(authCode) &&
    !/localStorage\.setItem\(\s*['"]tt_auth_token['"]/.test(authCode));
  check('token-url', 'dashboard.html keeps the token in sessionStorage only',
    !/localStorage\.(set|get)Item\(\s*['"]tt_auth_token['"]/.test(dashCode));
  check('token-url', 'signOut clears both session keys and redirects',
    /sessionStorage\.removeItem\(\s*['"]tt_auth_token['"]\s*\)/.test(dashCode) &&
    /sessionStorage\.removeItem\(\s*['"]tt_staff['"]\s*\)/.test(dashCode) &&
    /location\.replace\(\s*['"]\/auth\.html['"]\s*\)/.test(dashCode));
  check('token-url', 'every private dashboard fetch still sends X-Staff-Token',
    (dashCode.match(/X-Staff-Token/g) || []).length >= 2,
    `${(dashCode.match(/X-Staff-Token/g) || []).length} occurrences`);

  // Repo-wide sweep across every shipped HTML page.
  const htmlFiles = fs.readdirSync(REPO).filter(f => f.endsWith('.html'));
  const offenders = htmlFiles.filter(f => /[?&]token=/.test(strip(fs.readFileSync(REPO + '/' + f, 'utf8'))));
  check('token-url', 'no shipped HTML page builds a URL containing a token',
    offenders.length === 0, offenders.join(', '));
}

// ══ 10. Protected files byte-identical ═══════════════════════════════════
const PROTECTED = ['ticket-terminator-intake-form.html', 'netlify/functions/submit.js',
  'netlify/functions/stripe-webhook.js', 'netlify.toml', '_redirects', '.github/workflows/deploy.yml'];
for (const f of PROTECTED) {
  const base = execSync(`cd ${REPO} && git show c75862a:"${f}" | sha256sum | cut -d' ' -f1`, { encoding: 'utf8' }).trim();
  const now = execSync(`cd ${REPO} && sha256sum "${f}" | cut -d' ' -f1`, { encoding: 'utf8' }).trim();
  check('protected', `${f} byte-identical to base`, base === now, `${base.slice(0, 12)} vs ${now.slice(0, 12)}`);
}

console.log(OUT.join('\n'));
console.log('\n' + '─'.repeat(72));
console.log(`DASHBOARD TOTAL: ${PASS + FAIL}    PASSED: ${PASS}    FAILED: ${FAIL}`);
console.log('─'.repeat(72));
process.exit(FAIL ? 1 : 0);
}
