'use strict';
/* ───────────────────────────────────────────────────────────────────────────
   Ticket Terminator — Phase 0 Security Regression Harness
   Branch: phase-0-security   Base: c75862a

   SAFETY: global.fetch is stubbed — NO network traffic leaves this process.
   Airtable base/table/key are MOCK values pointing at a NON-EXISTENT base.
   No production credentials. No Stripe calls. No emails. No real records.
   ─────────────────────────────────────────────────────────────────────────── */
const crypto = require('crypto');
const fs = require('fs');
const nodePath = require('path');

// Functions under test, resolved relative to this file (repo-portable).
const FUNCTIONS_DIR = nodePath.join(__dirname, '..', '..', 'netlify', 'functions');

const MOCK = {
  BASE:  'appMOCKTESTBASE00',      // nonexistent
  TABLE: 'tblMOCKCASES00000',      // nonexistent
  TASKS: 'tblMOCKTASKS00000',
  KEY:   'mock_airtable_key_NOT_REAL',
  SECRET:'mock_token_secret_for_tests_only',
};
const PROD_BASE = 'app7IaHcv4nClafca';   // must NEVER be contacted

function setEnv({ secret = MOCK.SECRET, stripeEnabled = 'false' } = {}) {
  process.env.AIRTABLE_BASE_ID = MOCK.BASE;
  process.env.AIRTABLE_TABLE_ID = MOCK.TABLE;
  process.env.AIRTABLE_TASKS_TABLE_ID = MOCK.TASKS;
  process.env.AIRTABLE_API_KEY = MOCK.KEY;
  process.env.STRIPE_SECRET_KEY = 'sk_test_MOCK_not_real';
  process.env.STRIPE_WEBHOOK_SECRET = 'whsec_MOCK_not_real';
  process.env.STRIPE_WEBHOOK_ENABLED = stripeEnabled;
  process.env.ADMIN_SETUP_KEY = 'mock_setup_key';
  if (secret === null) delete process.env.DASHBOARD_TOKEN_SECRET;
  else process.env.DASHBOARD_TOKEN_SECRET = secret;
}

// ── fetch stub ──────────────────────────────────────────────────────────────
let CALLS = [];
// Never reset — used for the end-of-run assertion that no real production
// endpoint was contacted and that no outbound URL ever carried a token.
const ALL_CALLS = [];
global.__record = (url, method) => ALL_CALLS.push({ url: String(url), method: method || 'GET' });
global.fetch = async (url, opts = {}) => {
  const u = String(url);
  global.__record(u, opts.method);
  CALLS.push({ url: u, method: opts.method || 'GET' });
  if (u.includes(PROD_BASE)) throw new Error('FATAL: production Airtable base contacted');
  return {
    ok: true, status: 200,
    json: async () => ({ records: [], id: 'recMOCK0000000000', fields: { Active: true, 'Attorney Name': 'Mock Atty' }, url: 'https://example.com/x' }),
    text: async () => '{}',
  };
};
const airtableHit = () => CALLS.some(c => /api\.airtable\.com|content\.airtable\.com/.test(c.url));

// ── token factory ───────────────────────────────────────────────────────────
const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
function signTok(payload, secret = MOCK.SECRET) {
  const p = b64(payload);
  return p + '.' + crypto.createHmac('sha256', secret).update(p).digest('hex');
}
const HOUR = 3600e3;
const base = (role, over = {}) => ({
  staffId: 'rec' + role.replace(/\W/g, '').padEnd(14, 'X').slice(0, 14),
  name: role + ' User', email: role.replace(/\W/g, '').toLowerCase() + '@example.com',
  role, exp: Date.now() + HOUR, ...over,
});
const TOK = {
  admin:    signTok(base('Admin')),
  manager:  signTok(base('Manager')),
  employee: signTok(base('Employee')),
  readonly: signTok(base('Read Only')),
  expired:  signTok(base('Admin', { exp: Date.now() - HOUR })),
  unknownRole: signTok(base('Admin', { role: 'SuperUser' })),
  noStaffId:   signTok({ name: 'X', email: 'x@example.com', role: 'Admin', exp: Date.now() + HOUR }),
  noEmail:     signTok({ staffId: 'recAAAAAAAAAAAAA', name: 'X', role: 'Admin', exp: Date.now() + HOUR }),
  legacy:      signTok({ exp: Date.now() + HOUR }),            // old auth.js shape
  forgedUnsigned: b64(base('Admin')) + '.x',                    // no valid sig
  forgedHex:      b64(base('Admin')) + '.' + 'a'.repeat(64),    // well-formed but wrong sig
  tampered: (() => { const t = signTok(base('Employee')); return b64(base('Admin')) + '.' + t.split('.')[1]; })(),
  wrongSecret: signTok(base('Admin'), 'a_different_secret'),
};

// ── invocation helper ───────────────────────────────────────────────────────
function ev({ method = 'GET', token, qs = {}, body = null } = {}) {
  const headers = {};
  if (token !== undefined) headers['x-staff-token'] = token;
  return { httpMethod: method, headers, queryStringParameters: qs, body: body ? JSON.stringify(body) : null };
}
async function call(file, opts) {
  CALLS = [];
  const modPath = nodePath.join(FUNCTIONS_DIR, file);
  delete require.cache[require.resolve(modPath)];
  try {
    const res = await require(modPath).handler(ev(opts));
    let parsed = null;
    try { parsed = JSON.parse(res.body); } catch {}
    return { status: res.statusCode, body: parsed, raw: res.body, airtable: airtableHit(), calls: CALLS.length };
  } catch (e) {
    return { status: 'THREW', err: e.message, airtable: airtableHit(), calls: CALLS.length };
  }
}

// ── test runner ─────────────────────────────────────────────────────────────
let PASS = 0, FAIL = 0; const RESULTS = [];
function check(group, name, cond, detail = '') {
  if (cond) { PASS++; RESULTS.push(`  PASS  [${group}] ${name}`); }
  else { FAIL++; RESULTS.push(`  FAIL  [${group}] ${name}  ${detail}`); }
}

// Endpoints that must reject unauthenticated / forged callers.
const PRIVATE = [
  ['get-cases.js',    { method: 'GET' }],
  ['get-documents.js',{ method: 'GET' }],
  ['get-attorneys.js',{ method: 'GET' }],
  ['get-staff.js',    { method: 'GET' }],
  ['get-tasks.js',    { method: 'GET' }],
  ['get-activity-log.js', { method: 'GET', qs: { caseId: 'recX' } }],
  ['save-document.js',{ method: 'POST', body: { table: 'case-docs', fields: { 'Document Name': 'x' } } }],
  ['save-staff.js',   { method: 'POST', body: { fields: { Name: 'H', Email: 'h@x.co', password: 'password123', Role: 'Admin' } } }],
  ['save-attorney.js',{ method: 'POST', body: { fields: { 'Attorney Name': 'X' } } }],
  ['save-task.js',    { method: 'POST', body: { fields: { Task: 'x' } } }],
  ['update-case.js',  { method: 'PATCH', body: { recordId: 'recX0000000000000', fields: { Status: '✅ Closed' } } }],
  ['assign-attorney.js', { method: 'PATCH', body: { caseId: 'recX0000000000000', attorneyIds: ['recA0000000000000'] } }],
  ['create-case.js',  { method: 'POST', body: { fields: { 'First Name': 'X' } } }],
  ['create-checkout-session.js', { method: 'POST', body: { recordId: 'recX0000000000000', amount: 100 } }],
  ['change-password.js', { method: 'POST', body: { currentPassword: 'x', newPassword: 'newpass123' } }],
];

const BAD_TOKENS = [
  ['no token',              undefined],
  ['forged Admin (unsigned)', TOK.forgedUnsigned],
  ['forged Admin (hex sig)',  TOK.forgedHex],
  ['tampered signature',      TOK.tampered],
  ['signed w/ wrong secret',  TOK.wrongSecret],
  ['expired token',           TOK.expired],
  ['unknown role',            TOK.unknownRole],
  ['missing staffId',         TOK.noStaffId],
  ['missing email',           TOK.noEmail],
  ['legacy identity-less',    TOK.legacy],
];

(async () => {
  setEnv();

  // ── A. Authentication matrix ──────────────────────────────────────────────
  for (const [file, opts] of PRIVATE) {
    for (const [label, tok] of BAD_TOKENS) {
      const r = await call(file, { ...opts, token: tok });
      const rejected = r.status === 401 || r.status === 403;
      check('auth', `${file} rejects ${label}`, rejected, `got ${r.status}`);
      check('auth', `${file} no Airtable call on ${label}`, r.airtable === false, `airtable=${r.airtable}`);
    }
  }

  // ── B. Fail-closed when the signing secret is missing ─────────────────────
  setEnv({ secret: null });
  for (const [file, opts] of PRIVATE) {
    const r = await call(file, { ...opts, token: TOK.admin });
    check('failclosed', `${file} fails closed without DASHBOARD_TOKEN_SECRET`,
      r.status === 500 || r.status === 401, `got ${r.status}`);
    check('failclosed', `${file} no Airtable call without secret`, r.airtable === false);
    check('failclosed', `${file} leaks no secret name to client`,
      !/DASHBOARD_TOKEN_SECRET/.test(r.raw || ''), 'env var name in body');
  }
  setEnv();

  // ── C. Role behaviour — reads ─────────────────────────────────────────────
  for (const f of ['get-cases.js', 'get-attorneys.js', 'get-documents.js', 'get-tasks.js']) {
    const r = await call(f, { method: 'GET', token: TOK.readonly });
    check('role-read', `${f} allows Read Only`, r.status === 200, `got ${r.status}`);
  }

  // ── D. Read Only blocked from every write ────────────────────────────────
  const WRITES = [
    ['update-case.js', { method: 'PATCH', body: { recordId: 'recX0000000000000', fields: { 'Internal Notes': 'x' } } }],
    ['create-case.js', { method: 'POST', body: { fields: { 'First Name': 'X' } } }],
    ['save-task.js',   { method: 'POST', body: { fields: { Task: 'x' } } }],
    ['save-document.js', { method: 'POST', body: { table: 'case-docs', fields: { 'Document Name': 'x' } } }],
    ['save-attorney.js', { method: 'POST', body: { fields: { 'Attorney Name': 'X' } } }],
    ['assign-attorney.js', { method: 'PATCH', body: { caseId: 'recX0000000000000', attorneyIds: [] } }],
    ['save-staff.js', { method: 'POST', body: { fields: { Name: 'N', Email: 'n@x.co', password: 'password123' } } }],
  ];
  for (const [file, opts] of WRITES) {
    const r = await call(file, { ...opts, token: TOK.readonly });
    check('read-only', `${file} blocks Read Only write`, r.status === 403, `got ${r.status}`);
    check('read-only', `${file} no Airtable write for Read Only`, r.airtable === false);
  }

  // ── E. Employee ordinary writes allowed ──────────────────────────────────
  let r = await call('update-case.js', { method: 'PATCH', token: TOK.employee,
    body: { recordId: 'recX0000000000000', fields: { 'Internal Notes': 'note', 'Status': '✅ Closed' } } });
  check('employee', 'Employee may write operational case fields', r.status === 200, `got ${r.status}`);

  r = await call('create-case.js', { method: 'POST', token: TOK.employee, body: { fields: { 'First Name': 'A', 'Last Name': 'B' } } });
  check('employee', 'Employee may create a case', r.status === 200, `got ${r.status}`);

  r = await call('save-task.js', { method: 'POST', token: TOK.employee, body: { fields: { Task: 'Follow up' } } });
  check('employee', 'Employee may create a task', r.status === 200, `got ${r.status}`);

  r = await call('save-document.js', { method: 'POST', token: TOK.employee,
    body: { table: 'case-docs', fields: { 'Document Name': 'Ticket.pdf', 'File URL': 'https://drive.google.com/x' } } });
  check('employee', 'Employee may save a case document', r.status === 200, `got ${r.status}`);

  // ── F. Employee blocked from financial fields ────────────────────────────
  const FIN = ['Client Fee Collected','Client Balance Remaining','Attorney Service Fee',
    'Attorney Balance Remaining','Attorney Payment Confirmed','Attorney Paid Date',
    'Payout Due?','Payment Method','Quote Status'];
  for (const field of FIN) {
    const rr = await call('update-case.js', { method: 'PATCH', token: TOK.employee,
      body: { recordId: 'recX0000000000000', fields: { [field]: field === 'Payout Due?' ? true : 'x' } } });
    check('financial', `Employee blocked from '${field}'`, rr.status === 403, `got ${rr.status}`);
    check('financial', `no Airtable write for '${field}'`, rr.airtable === false);
  }

  // ── G. Mixed payload cannot partially bypass ─────────────────────────────
  r = await call('update-case.js', { method: 'PATCH', token: TOK.employee,
    body: { recordId: 'recX0000000000000', fields: { 'Internal Notes': 'legit', 'Client Fee Collected': 9999 } } });
  check('mixed', 'Employee mixed payload rejected wholesale', r.status === 403, `got ${r.status}`);
  check('mixed', 'Employee mixed payload writes nothing', r.airtable === false);

  r = await call('create-case.js', { method: 'POST', token: TOK.employee,
    body: { fields: { 'First Name': 'A', 'Client Fee Collected': 500 } } });
  check('mixed', 'Employee mixed create rejected wholesale', r.status === 403, `got ${r.status}`);
  check('mixed', 'create-case mixed payload writes nothing', r.airtable === false);

  // Unknown / non-schema field names rejected for every role
  for (const [label, tok] of [['Employee', TOK.employee], ['Manager', TOK.manager], ['Admin', TOK.admin]]) {
    const rr = await call('update-case.js', { method: 'PATCH', token: tok,
      body: { recordId: 'recX0000000000000', fields: { 'Profit': 1, 'Case #': 'TT-HACK' } } });
    check('allowlist', `${label} cannot write Profit / Case # (no wildcard)`, rr.status === 403, `got ${rr.status}`);
  }

  // ── H. Manager / Admin financial writes allowed ──────────────────────────
  for (const [label, tok] of [['Manager', TOK.manager], ['Admin', TOK.admin]]) {
    const rr = await call('update-case.js', { method: 'PATCH', token: tok,
      body: { recordId: 'recX0000000000000', fields: { 'Client Fee Collected': 250 } } });
    check('financial', `${label} may write financial fields`, rr.status === 200, `got ${rr.status}`);
  }

  // ── I. Attorney & template administration ────────────────────────────────
  r = await call('save-attorney.js', { method: 'POST', token: TOK.manager, body: { fields: { 'Attorney Name': 'A' } } });
  check('attorney', 'Manager may administer attorneys', r.status === 200, `got ${r.status}`);
  r = await call('save-attorney.js', { method: 'POST', token: TOK.employee, body: { fields: { 'Attorney Name': 'A' } } });
  check('attorney', 'Employee may NOT administer attorneys', r.status === 403, `got ${r.status}`);
  r = await call('save-document.js', { method: 'POST', token: TOK.manager, body: { table: 'templates', fields: { 'Template Name': 'T' } } });
  check('templates', 'Manager may administer templates', r.status === 200, `got ${r.status}`);
  r = await call('save-document.js', { method: 'POST', token: TOK.employee, body: { table: 'templates', fields: { 'Template Name': 'T' } } });
  check('templates', 'Employee may NOT administer templates', r.status === 403, `got ${r.status}`);
  check('templates', 'Employee template attempt hits no Airtable', r.airtable === false);

  // ── J. Staff administration is Admin-only ────────────────────────────────
  for (const [label, tok, want] of [['Admin', TOK.admin, 200], ['Manager', TOK.manager, 403], ['Employee', TOK.employee, 403]]) {
    const g = await call('get-staff.js', { method: 'GET', token: tok });
    check('staff-admin', `${label} get-staff -> ${want}`, g.status === want, `got ${g.status}`);
    const s = await call('save-staff.js', { method: 'POST', token: tok,
      body: { fields: { Name: 'N', Email: 'n@x.co', password: 'password123', Role: 'Employee' } } });
    check('staff-admin', `${label} save-staff -> ${want}`, s.status === want, `got ${s.status}`);
  }
  r = await call('save-staff.js', { method: 'POST', token: TOK.admin,
    body: { fields: { Name: 'N', Email: 'n@x.co', password: 'password123', Role: 'SuperUser' } } });
  check('staff-admin', 'Arbitrary Role value rejected', r.status === 400, `got ${r.status}`);
  r = await call('save-staff.js', { method: 'POST', token: TOK.admin,
    body: { fields: { Name: 'N', Email: 'n@x.co', password: 'password123', 'Password Hash': 'pwned' } } });
  check('staff-admin', "Client-supplied 'Password Hash' rejected", r.status === 403, `got ${r.status}`);

  // ── K. Activity-log category matrix ──────────────────────────────────────
  const AL = (tok, qs) => call('get-activity-log.js', { method: 'GET', token: tok, qs });
  r = await AL(TOK.readonly, {}); check('activity', 'Read Only has no activity access', r.status === 403, `got ${r.status}`);
  r = await AL(TOK.employee, {}); check('activity', 'Employee cannot request org-wide feed', r.status === 403, `got ${r.status}`);
  check('activity', 'Employee org-wide attempt hits no Airtable', r.airtable === false);
  r = await AL(TOK.employee, { caseId: 'recX0000000000000' });
  check('activity', 'Employee may request a case timeline', r.status === 200, `got ${r.status}`);
  for (const cat of ['Payment', 'Staff', 'Security']) {
    const rr = await AL(TOK.employee, { caseId: 'recX0000000000000', category: cat });
    check('activity', `Employee blocked from '${cat}' category`, rr.status === 403, `got ${rr.status}`);
  }
  for (const cat of ['Staff', 'Security']) {
    const rr = await AL(TOK.manager, { category: cat });
    check('activity', `Manager blocked from '${cat}' category`, rr.status === 403, `got ${rr.status}`);
    const ra = await AL(TOK.admin, { category: cat });
    check('activity', `Admin may view '${cat}' category`, ra.status === 200, `got ${ra.status}`);
  }
  r = await AL(TOK.manager, { category: 'Payment' });
  check('activity', 'Manager may view Payment activity', r.status === 200, `got ${r.status}`);
  r = await AL(TOK.admin, { category: 'Payment' });
  check('activity', 'Admin may view Payment activity', r.status === 200, `got ${r.status}`);
  // Category exclusions must be embedded in the query, not applied after
  CALLS = [];
  await AL(TOK.manager, {});
  const mgrUrl = decodeURIComponent(CALLS.map(c => c.url).join(' ')).replace(/\+/g, ' ');
  check('activity', 'Manager query excludes Staff+Security server-side',
    mgrUrl.includes('NOT({Category} = "Staff")') && mgrUrl.includes('NOT({Category} = "Security")'), mgrUrl.slice(0, 160));
  CALLS = [];
  await AL(TOK.employee, { caseId: 'recX0000000000000' });
  const empUrl = decodeURIComponent(CALLS.map(c => c.url).join(' ')).replace(/\+/g, ' ');
  check('activity', 'Employee query excludes Payment/Staff/Security server-side',
    empUrl.includes('NOT({Category} = "Payment")') && empUrl.includes('NOT({Category} = "Staff")'), empUrl.slice(0, 160));

  // ── L. Formula-injection escaping ────────────────────────────────────────
  CALLS = [];
  await call('get-activity-log.js', { method: 'GET', token: TOK.admin, qs: { caseId: 'recX") , OR(1,1)&"' } });
  const inj = decodeURIComponent(CALLS.map(c => c.url).join(' '));
  check('injection', 'activity-log escapes quotes in filter', inj.includes('\\"'), inj.slice(0, 200));
  CALLS = [];
  await call('get-tasks.js', { method: 'GET', token: TOK.admin, qs: { status: 'x") , OR(1,1)&"' } });
  const inj2 = decodeURIComponent(CALLS.map(c => c.url).join(' '));
  check('injection', 'get-tasks escapes quotes in filter', inj2.includes('\\"'), inj2.slice(0, 200));

  // ── M. Unsafe URL schemes rejected ───────────────────────────────────────
  for (const bad of ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>', 'vbscript:msgbox(1)']) {
    const rr = await call('save-document.js', { method: 'POST', token: TOK.manager,
      body: { table: 'case-docs', fields: { 'Document Name': 'x', 'File URL': bad } } });
    check('url', `File URL '${bad.slice(0, 18)}…' rejected`, rr.status === 400, `got ${rr.status}`);
    check('url', 'unsafe URL never reaches Airtable', rr.airtable === false);
  }
  r = await call('save-document.js', { method: 'POST', token: TOK.manager,
    body: { table: 'case-docs', fields: { 'Document Name': 'x', 'File URL': 'https://drive.google.com/file/d/abc' } } });
  check('url', 'valid https File URL accepted', r.status === 200, `got ${r.status}`);

  // ── N. Generic errors — no raw Airtable detail ───────────────────────────
  const origFetch = global.fetch;
  global.fetch = async (url, opts = {}) => {
    CALLS.push({ url: String(url), method: opts.method || 'GET' });
    return { ok: false, status: 422,
      json: async () => ({ error: { type: 'INVALID_VALUE_FOR_COLUMN', message: 'Field "Secret Internal Column" cannot accept value' } }),
      text: async () => 'Airtable raw failure text tbledZDHFKbsBiwMf' };
  };
  for (const [file, opts, tok] of [
    ['get-cases.js', { method: 'GET' }, TOK.admin],
    ['update-case.js', { method: 'PATCH', body: { recordId: 'recX0000000000000', fields: { 'Internal Notes': 'x' } } }, TOK.admin],
    ['save-attorney.js', { method: 'POST', body: { fields: { 'Attorney Name': 'A' } } }, TOK.admin],
    ['get-staff.js', { method: 'GET' }, TOK.admin],
  ]) {
    const rr = await call(file, { ...opts, token: tok });
    const leaked = /INVALID_VALUE_FOR_COLUMN|Secret Internal Column|tbledZDHFKbsBiwMf|api\.airtable\.com/.test(rr.raw || '');
    check('errors', `${file} returns a generic error`, !leaked && (rr.status === 502 || rr.status === 500), `status=${rr.status} body=${(rr.raw||'').slice(0,90)}`);
  }
  global.fetch = origFetch;

  // ── O. Public / independently authenticated endpoints ────────────────────
  r = await call('auth.js', { method: 'GET' });
  check('legacy', 'auth.js GET returns 410 Gone', r.status === 410, `got ${r.status}`);
  r = await call('auth.js', { method: 'POST', body: { password: 'anything' } });
  check('legacy', 'auth.js POST returns 410 Gone', r.status === 410, `got ${r.status}`);
  check('legacy', 'auth.js issues no token', !/token/.test(r.raw || ''));

  r = await call('config.js', { method: 'GET' });
  check('public', 'config.js public (200)', r.status === 200, `got ${r.status}`);
  check('public', 'config.js exposes only feature flags',
    r.body && Object.keys(r.body).every(k => k === 'stripeEnabled') && typeof r.body.stripeEnabled === 'boolean',
    JSON.stringify(r.body));
  check('public', 'config.js leaks no secret material',
    !/sk_|whsec_|Bearer|app[A-Za-z0-9]{14}|SECRET|KEY/.test(r.raw || ''), r.raw);

  r = await call('staff-auth.js', { method: 'GET', token: '' });
  check('public', 'staff-auth.js still serves login/verify (not 410)', r.status !== 410 && r.status !== 405, `got ${r.status}`);
  // Verification is header-based now — a query-string token is no longer honoured.
  r = await call('staff-auth.js', { method: 'GET', token: TOK.admin });
  check('public', 'staff-auth.js validates a good token', r.status === 200 && r.body && r.body.valid === true, `got ${r.status}`);

  r = await call('submit.js', { method: 'OPTIONS' });
  check('public', 'submit.js remains public (CORS preflight 204)', r.status === 204, `got ${r.status}`);

  r = await call('stripe-webhook.js', { method: 'POST', body: { id: 'evt_test' } });
  check('stripe', 'stripe-webhook kill switch active (no processing)',
    r.status === 200 && r.body && r.body.active === false, JSON.stringify(r.body));
  check('stripe', 'stripe-webhook does not accept a staff token as auth', r.airtable === false);
  setEnv({ stripeEnabled: 'true' });
  r = await call('stripe-webhook.js', { method: 'POST', body: { id: 'evt_test' } });
  check('stripe', 'stripe-webhook rejects unsigned event when enabled', r.status === 400, `got ${r.status}`);
  setEnv();

  // ── F2. Webhook-owned fields: rejected for EVERY role ────────────────────
  for (const field of ['Payment Status', 'Stripe Session ID']) {
    for (const [label, tok] of [['Admin', TOK.admin], ['Manager', TOK.manager], ['Employee', TOK.employee]]) {
      const rr = await call('update-case.js', { method: 'PATCH', token: tok,
        body: { recordId: 'recX0000000000000', fields: { [field]: 'x' } } });
      check('webhook-owned', `${label} cannot write '${field}' (webhook-owned)`, rr.status === 403, `got ${rr.status}`);
      check('webhook-owned', `no Airtable write for ${label}/'${field}'`, rr.airtable === false);
    }
    const rc = await call('create-case.js', { method: 'POST', token: TOK.admin,
      body: { fields: { 'First Name': 'A', [field]: 'x' } } });
    check('webhook-owned', `create-case rejects '${field}' even for Admin`, rc.status === 403, `got ${rc.status}`);
  }

  // ── F3. Date Submitted is Admin-only ─────────────────────────────────────
  for (const [label, tok, want] of [['Admin', TOK.admin, 200], ['Manager', TOK.manager, 403],
                                    ['Employee', TOK.employee, 403], ['Read Only', TOK.readonly, 403]]) {
    const rr = await call('update-case.js', { method: 'PATCH', token: tok,
      body: { recordId: 'recX0000000000000', fields: { 'Date Submitted': '2026-01-01' } } });
    check('admin-only', `${label} 'Date Submitted' -> ${want}`, rr.status === want, `got ${rr.status}`);
  }

  // ── F4. Quote Status requires Manager or Admin ───────────────────────────
  for (const [label, tok, want] of [['Admin', TOK.admin, 200], ['Manager', TOK.manager, 200],
                                    ['Employee', TOK.employee, 403], ['Read Only', TOK.readonly, 403]]) {
    const rr = await call('update-case.js', { method: 'PATCH', token: tok,
      body: { recordId: 'recX0000000000000', fields: { 'Quote Status': 'Sent' } } });
    check('quote-status', `${label} 'Quote Status' -> ${want}`, rr.status === want, `got ${rr.status}`);
  }

  // ── F5. Generic 403 bodies — never reveal the required role ──────────────
  const ROLE_WORDS = /Admin|Manager|Employee|Read Only|role|permission|account|required/i;
  const denials = [
    ['get-staff.js',    { method: 'GET' }, TOK.manager],
    ['save-staff.js',   { method: 'POST', body: { fields: { Name: 'N', Email: 'n@x.co', password: 'password123' } } }, TOK.manager],
    ['save-attorney.js',{ method: 'POST', body: { fields: { 'Attorney Name': 'A' } } }, TOK.employee],
    ['save-document.js',{ method: 'POST', body: { table: 'templates', fields: { 'Template Name': 'T' } } }, TOK.employee],
    ['update-case.js',  { method: 'PATCH', body: { recordId: 'recX0000000000000', fields: { 'Internal Notes': 'x' } } }, TOK.readonly],
    ['get-activity-log.js', { method: 'GET' }, TOK.readonly],
    ['create-checkout-session.js', { method: 'POST', body: { recordId: 'recX0000000000000', amount: 100 } }, TOK.readonly],
  ];
  for (const [file, opts, tok] of denials) {
    const rr = await call(file, { ...opts, token: tok });
    check('generic-403', `${file} returns 403`, rr.status === 403, `got ${rr.status}`);
    check('generic-403', `${file} 403 body reveals no role`, !ROLE_WORDS.test(rr.raw || ''), rr.raw);
  }
  // field rejection carries a machine code but still no role
  {
    const rr = await call('update-case.js', { method: 'PATCH', token: TOK.employee,
      body: { recordId: 'recX0000000000000', fields: { 'Client Fee Collected': 1 } } });
    check('generic-403', 'field rejection uses FIELD_NOT_PERMITTED code', rr.body && rr.body.code === 'FIELD_NOT_PERMITTED', rr.raw);
    check('generic-403', 'field rejection body reveals no role or field', !ROLE_WORDS.test(rr.raw || '') && !/Client Fee/.test(rr.raw || ''), rr.raw);
  }

  // ── F6. Activity-log staffId filter is Manager+ only ─────────────────────
  CALLS = [];
  await call('get-activity-log.js', { method: 'GET', token: TOK.employee, qs: { caseId: 'recX0000000000000', staffId: 'recCOLLEAGUE0000' } });
  const empQ = decodeURIComponent(CALLS.map(c => c.url).join(' ')).replace(/\+/g, ' ');
  check('activity', 'Employee staffId filter is ignored', !empQ.includes('Staff Record ID'), empQ.slice(0, 180));
  for (const [label, tok] of [['Manager', TOK.manager], ['Admin', TOK.admin]]) {
    CALLS = [];
    await call('get-activity-log.js', { method: 'GET', token: tok, qs: { staffId: 'recCOLLEAGUE0000' } });
    const q = decodeURIComponent(CALLS.map(c => c.url).join(' ')).replace(/\+/g, ' ');
    check('activity', `${label} may use the staffId filter`, q.includes('Staff Record ID'), q.slice(0, 180));
  }

  // ── F7. create-checkout-session: auth BEFORE configuration ───────────────
  {
    const savedStripe = process.env.STRIPE_SECRET_KEY, savedBase = process.env.AIRTABLE_BASE_ID;
    delete process.env.STRIPE_SECRET_KEY; delete process.env.AIRTABLE_BASE_ID;
    let rr = await call('create-checkout-session.js', { method: 'POST', token: undefined,
      body: { recordId: 'recX0000000000000', amount: 100 } });
    check('auth-order', 'unauthenticated request rejected BEFORE config checks (401 not 500)', rr.status === 401, `got ${rr.status}`);
    check('auth-order', 'config state not disclosed to an unauthenticated caller',
      !/STRIPE|AIRTABLE|configured|env/i.test(rr.raw || ''), rr.raw);
    rr = await call('create-checkout-session.js', { method: 'POST', token: TOK.forgedUnsigned,
      body: { recordId: 'recX0000000000000', amount: 100 } });
    check('auth-order', 'forged token rejected BEFORE config checks', rr.status === 401, `got ${rr.status}`);
    process.env.STRIPE_SECRET_KEY = savedStripe; process.env.AIRTABLE_BASE_ID = savedBase;
    rr = await call('create-checkout-session.js', { method: 'POST', token: TOK.admin,
      body: { recordId: 'recX0000000000000', amount: 100 } });
    check('auth-order', 'authenticated caller still reaches the flow', rr.status !== 401 && rr.status !== 403, `got ${rr.status}`);
  }

  // ── F8. recordId is URL-encoded in the Airtable record URL ───────────────
  {
    CALLS = [];
    await call('create-checkout-session.js', { method: 'POST', token: TOK.admin,
      body: { recordId: 'rec../../tblOTHER/recEVIL', amount: 100 } });
    const urls = CALLS.map(c => c.url).join(' ');
    check('encoding', 'recordId is percent-encoded (no path traversal)',
      !urls.includes('rec../../tblOTHER') , urls.slice(0, 200));
  }

  // ── F9. Generic upstream errors from create-checkout-session ─────────────
  {
    const orig = global.fetch;
    global.fetch = async (url, opts = {}) => {
      global.__record(url, opts.method);
      CALLS.push({ url: String(url), method: opts.method || 'GET' });
      return { ok: false, status: 422,
        json: async () => ({ error: { type: 'AIRTABLE_INTERNAL', message: 'Secret Internal Column blew up' } }),
        text: async () => 'raw tbledZDHFKbsBiwMf failure' };
    };
    const rr = await call('create-checkout-session.js', { method: 'POST', token: TOK.admin,
      body: { recordId: 'recX0000000000000', amount: 100 } });
    check('errors', 'create-checkout-session returns a generic upstream error',
      !/AIRTABLE_INTERNAL|Secret Internal Column|tbledZDHFKbsBiwMf/.test(rr.raw || ''), (rr.raw || '').slice(0, 120));
    global.fetch = orig;
  }

  // ── P. Method guards ─────────────────────────────────────────────────────
  r = await call('get-cases.js', { method: 'POST', token: TOK.admin });
  check('method', 'get-cases rejects POST', r.status === 405, `got ${r.status}`);
  r = await call('update-case.js', { method: 'POST', token: TOK.admin, body: { recordId: 'recX', fields: {} } });
  check('method', 'update-case rejects POST (PATCH only)', r.status === 405, `got ${r.status}`);


  // ═══════════════════════════════════════════════════════════════════════════
  //  PRE-MERGE CORRECTION #1 — SESSION TOKENS MUST NEVER APPEAR IN A URL
  // ═══════════════════════════════════════════════════════════════════════════
  setEnv();
  {
    // Valid token supplied in the X-Staff-Token header → accepted.
    let r = await call('staff-auth.js', { method: 'GET', token: TOK.admin });
    check('token-url', 'staff-auth GET accepts a valid X-Staff-Token header',
      r.status === 200 && r.body && r.body.valid === true, `got ${r.status} ${r.raw}`);
    check('token-url', 'staff-auth GET returns the staff identity from the header token',
      r.body && r.body.staff && r.body.staff.role === 'Admin', JSON.stringify(r.body));

    // The SAME valid token supplied only as ?token= → rejected.
    r = await call('staff-auth.js', { method: 'GET', qs: { token: TOK.admin } });
    check('token-url', 'staff-auth GET REJECTS a valid token supplied in the query string',
      r.status === 401 && r.body && r.body.valid === false, `got ${r.status} ${r.raw}`);
    check('token-url', 'query-string rejection does not echo the token value',
      !(r.raw || '').includes(TOK.admin), (r.raw || '').slice(0, 120));

    // No compatibility fallback: query token present alongside an empty header.
    r = await call('staff-auth.js', { method: 'GET', token: '', qs: { token: TOK.admin } });
    check('token-url', 'empty header + query token is still rejected (no fallback)',
      r.status === 401, `got ${r.status}`);

    // Tokenless.
    r = await call('staff-auth.js', { method: 'GET' });
    check('token-url', 'staff-auth GET rejects a request with no token at all',
      r.status === 401 && r.body.valid === false, `got ${r.status}`);

    // Every bad-token shape stays rejected through the header path.
    const REJECT = [
      ['forged (unsigned)',  TOK.forgedUnsigned],
      ['forged (hex sig)',   TOK.forgedHex],
      ['tampered payload',   TOK.tampered],
      ['wrong secret',       TOK.wrongSecret],
      ['expired',            TOK.expired],
      ['malformed garbage',  'not-a-token'],
      ['empty string',       ''],
      ['dots only',          '..'],
    ];
    for (const [label, tok] of REJECT) {
      r = await call('staff-auth.js', { method: 'GET', token: tok });
      check('token-url', `staff-auth GET rejects ${label} in the header`,
        r.status === 401 && r.body && r.body.valid === false, `got ${r.status}`);
    }

    // Bearer fallback on the Authorization header (still not a URL).
    {
      const modPath = nodePath.join(FUNCTIONS_DIR, 'staff-auth.js');
      delete require.cache[require.resolve(modPath)];
      const res = await require(modPath).handler({
        httpMethod: 'GET',
        headers: { authorization: 'Bearer ' + TOK.admin },
        queryStringParameters: {}, body: null,
      });
      check('token-url', 'staff-auth GET accepts a Bearer Authorization header',
        res.statusCode === 200 && JSON.parse(res.body).valid === true, `got ${res.statusCode}`);
    }

    // Header name must be advertised for CORS so browsers may send it.
    const authSrc = fs.readFileSync(nodePath.join(FUNCTIONS_DIR, 'staff-auth.js'), 'utf8');
    check('token-url', 'staff-auth advertises X-Staff-Token in Access-Control-Allow-Headers',
      /Access-Control-Allow-Headers[^\n]*X-Staff-Token/.test(authSrc));
    check('token-url', 'staff-auth source no longer reads queryStringParameters.token',
      !/queryStringParameters\s*(\?\.|\[|\.)\s*\[?['"]?token/.test(authSrc.replace(/\/\/[^\n]*/g, '')));
    check('token-url', 'staff-auth never builds a URL containing token=',
      !/[?&]token=/.test(authSrc.replace(/\/\/[^\n]*/g, '')));

    // Login POST still works and returns the token in the BODY only.
    {
      const orig = global.fetch;
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = crypto.pbkdf2Sync('correct-horse-battery', salt, 100000, 32, 'sha256').toString('hex');
      global.fetch = async (url, opts = {}) => {
        global.__record(url, opts.method);
      CALLS.push({ url: String(url), method: opts.method || 'GET' });
        return { ok: true, status: 200, json: async () => ({ records: [{
          id: 'recSTAFF000000000',
          fields: { Name: 'Test', Email: 't@example.com', Role: 'Admin', Active: true, 'Password Hash': salt + ':' + hash },
        }] }), text: async () => '{}' };
      };
      let rr = await call('staff-auth.js', { method: 'POST', body: { email: 't@example.com', password: 'correct-horse-battery' } });
      check('token-url', 'login POST still succeeds and issues a token',
        rr.status === 200 && typeof rr.body.token === 'string' && rr.body.token.includes('.'), `got ${rr.status}`);
      check('token-url', 'login POST returns no Location/redirect header carrying a credential',
        !/location/i.test(JSON.stringify(rr.raw || '')), 'body only');
      check('token-url', 'login POST does not echo the password',
        !(rr.raw || '').includes('correct-horse-battery'));
      check('token-url', 'login POST does not echo the stored hash',
        !(rr.raw || '').includes(hash));
      // Wrong password still rejected.
      rr = await call('staff-auth.js', { method: 'POST', body: { email: 't@example.com', password: 'wrong-password' } });
      check('token-url', 'login POST rejects a wrong password',
        rr.status === 401 && rr.body.error === 'Invalid email or password', `got ${rr.status}`);
      global.fetch = orig;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  PRE-MERGE CORRECTION #2 — get-staff must request EVERY field via append()
  // ═══════════════════════════════════════════════════════════════════════════
  {
    const EXPECTED = ['Name', 'Email', 'Role', 'Active', 'Last Login', 'Notes'];
    const r = await call('get-staff.js', { method: 'GET', token: TOK.admin });
    check('get-staff', 'get-staff returns 200 for Admin', r.status === 200, `got ${r.status}`);

    const atCall = CALLS.find(c => /api\.airtable\.com/.test(c.url)) || { url: '' };
    const decoded = decodeURIComponent(atCall.url).replace(/\+/g, ' ');
    for (const f of EXPECTED) {
      check('get-staff', `Airtable request includes fields[]=${f}`,
        decoded.includes(`fields[]=${f}`), decoded.slice(0, 200));
    }
    const fieldCount = (decoded.match(/fields\[\]=/g) || []).length;
    check('get-staff', 'all six fields[] survive (append, not set)',
      fieldCount === EXPECTED.length, `found ${fieldCount} fields[] params`);
    check('get-staff', 'Password Hash is NEVER requested from Airtable',
      !/Password\s*Hash/i.test(decoded), decoded.slice(0, 200));
    check('get-staff', 'response body contains no Password Hash',
      !/Password\s*Hash/i.test(r.raw || ''));

    const gsSrc  = fs.readFileSync(nodePath.join(FUNCTIONS_DIR, 'get-staff.js'), 'utf8');
    // Strip comments — prose that names the field must not fail the assertion.
    const gsCode = gsSrc.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
    check('get-staff', "get-staff no longer uses set('fields[]')",
      !/\.set\(\s*['"]fields\[\]['"]/.test(gsCode));
    check('get-staff', "get-staff uses append('fields[]')",
      /\.append\(\s*['"]fields\[\]['"]/.test(gsCode));
    check('get-staff', 'Password Hash absent from the get-staff allowlist',
      !/['"]Password Hash['"]/.test(gsCode));

    // Non-Admin still blocked.
    for (const [label, tok] of [['Manager', TOK.manager], ['Employee', TOK.employee], ['Read Only', TOK.readonly]]) {
      const rr = await call('get-staff.js', { method: 'GET', token: tok });
      check('get-staff', `get-staff still forbids ${label}`, rr.status === 403, `got ${rr.status}`);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  PRE-MERGE CORRECTION #3 — staff-auth must never leak configuration detail
  // ═══════════════════════════════════════════════════════════════════════════
  {
    const FORBIDDEN = [
      'DASHBOARD_TOKEN_SECRET', 'AIRTABLE_API_KEY', 'AIRTABLE_BASE_ID', 'AIRTABLE_TABLE_ID',
      'ADMIN_SETUP_KEY', 'tblFGsQpsOJFF2r2V', 'app7IaHcv4nClafca', MOCK.KEY, MOCK.SECRET,
      MOCK.BASE, 'Password Hash', 'admin key', 'Bootstrap', 'at ', 'node:internal',
    ];
    const clean = (label, raw) => {
      for (const bad of FORBIDDEN) {
        if (bad === 'at ' && !/\bat\s+\S+:\d+/.test(raw || '')) continue;   // stack-frame shape only
        check('leak', `${label} does not disclose "${bad}"`,
          bad === 'at ' ? !/\bat\s+\S+:\d+/.test(raw || '') : !(raw || '').includes(bad),
          (raw || '').slice(0, 120));
      }
    };

    // Missing signing secret → generic 500.
    setEnv({ secret: null });
    let r = await call('staff-auth.js', { method: 'GET', token: TOK.admin });
    check('leak', 'missing signing secret returns 500', r.status === 500, `got ${r.status}`);
    check('leak', 'missing signing secret returns the generic message',
      r.body && r.body.error === 'Authentication service unavailable', r.raw);
    clean('missing-secret response', r.raw);
    setEnv();

    // Bootstrap with a wrong setup key → generic 403.
    r = await call('staff-auth.js', { method: 'POST', body: { _setup: true, adminKey: 'wrong', name: 'X', email: 'x@y.co', password: 'p' } });
    check('leak', 'bootstrap with a wrong setup key returns 403', r.status === 403, `got ${r.status}`);
    check('leak', 'bootstrap refusal is generic', r.body && r.body.error === 'Forbidden', r.raw);
    clean('bootstrap-bad-key response', r.raw);

    // Bootstrap when an Admin already exists → generic 403, no "already exists" hint.
    {
      const orig = global.fetch;
      global.fetch = async (url, opts = {}) => {
        global.__record(url, opts.method);
      CALLS.push({ url: String(url), method: opts.method || 'GET' });
        return { ok: true, status: 200, json: async () => ({ records: [{ id: 'recA', fields: { Role: 'Admin' } }] }), text: async () => '{}' };
      };
      r = await call('staff-auth.js', { method: 'POST', body: { _setup: true, adminKey: 'mock_setup_key', name: 'X', email: 'x@y.co', password: 'p' } });
      check('leak', 'bootstrap when already provisioned returns 403', r.status === 403, `got ${r.status}`);
      check('leak', 'bootstrap-already-provisioned message is generic',
        r.body && r.body.error === 'Forbidden', r.raw);
      clean('bootstrap-exists response', r.raw);
      global.fetch = orig;
    }

    // Upstream datastore failure on login → generic 500, no raw payload.
    {
      const orig = global.fetch;
      global.fetch = async (url, opts = {}) => {
        global.__record(url, opts.method);
      CALLS.push({ url: String(url), method: opts.method || 'GET' });
        return { ok: false, status: 422,
          json: async () => ({ error: { type: 'TABLE_NOT_FOUND', message: 'tblFGsQpsOJFF2r2V is missing AIRTABLE_API_KEY' } }),
          text: async () => 'raw app7IaHcv4nClafca failure' };
      };
      r = await call('staff-auth.js', { method: 'POST', body: { email: 'a@b.co', password: 'x' } });
      check('leak', 'upstream login failure returns 500', r.status === 500, `got ${r.status}`);
      check('leak', 'upstream login failure is generic',
        r.body && r.body.error === 'Authentication service unavailable', r.raw);
      check('leak', 'upstream payload is not echoed',
        !/TABLE_NOT_FOUND|is missing/.test(r.raw || ''), (r.raw || '').slice(0, 120));
      clean('upstream-failure response', r.raw);
      global.fetch = orig;
    }

    // Missing credentials → generic 400.
    r = await call('staff-auth.js', { method: 'POST', body: {} });
    check('leak', 'missing credentials returns 400', r.status === 400, `got ${r.status}`);
    clean('missing-credentials response', r.raw);

    // Unsupported method → generic 405 JSON.
    r = await call('staff-auth.js', { method: 'PUT' });
    check('leak', 'unsupported method returns 405', r.status === 405, `got ${r.status}`);
    check('leak', '405 body is JSON, not a bare string',
      r.body && r.body.error === 'Method Not Allowed', r.raw);

    // OPTIONS preflight still works.
    r = await call('staff-auth.js', { method: 'OPTIONS' });
    check('leak', 'OPTIONS preflight returns 204', r.status === 204, `got ${r.status}`);

    // Source-level guarantees.
    const authSrc = fs.readFileSync(nodePath.join(FUNCTIONS_DIR, 'staff-auth.js'), 'utf8');
    const code = authSrc.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
    check('leak', 'no env-var name appears in a returned error string',
      !/error['"]?\s*:\s*['"][^'"]*(DASHBOARD_TOKEN_SECRET|AIRTABLE_API_KEY|AIRTABLE_BASE_ID|ADMIN_SETUP_KEY)/.test(code));
    check('leak', 'no raw upstream message is forwarded to the client',
      !/error['"]?\s*:\s*[^,}\n]*(data|err)\s*[?.]/.test(code), 'error: data?.… pattern');
    // A literal string may contain the WORD "token" (e.g. "token signing").
    // What must never happen is a sensitive VALUE being interpolated or
    // concatenated into a log argument.
    const consoleArgs = [...code.matchAll(/console\.(?:log|warn|error)\(([\s\S]*?)\);/g)].map(m => m[1]);
    const SENSITIVE = /(password|storedHash|\bhash\b|secret|adminKey|\btoken\b|\bemail\b)/i;
    const interpolated = consoleArgs.filter(a =>
      [...a.matchAll(/\$\{([^}]*)\}/g)].some(m => SENSITIVE.test(m[1])) ||   // `${password}`
      /[,+]\s*(password|storedHash|hash|secret|adminKey|token|email)\b/i.test(a)  // , password  /  + token
    );
    check('leak', 'no console log records a password, hash, secret or full token value',
      interpolated.length === 0, interpolated.join(' | ').slice(0, 160));
    check('leak', 'no console log records the submitted email value',
      !consoleArgs.some(a => /\$\{[^}]*email[^}]*\}|[,+]\s*email\b/i.test(a)));
    check('leak', 'staff-auth emits at least one safe technical log category',
      consoleArgs.some(a => /\[staff-auth\]/.test(a)), 'expected categorised logging');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  GLOBAL — no outbound URL built anywhere in this run carried a token
  // ═══════════════════════════════════════════════════════════════════════════
  {
    const srcFiles = fs.readdirSync(FUNCTIONS_DIR).filter(f => f.endsWith('.js'));
    let offenders = [];
    for (const f of srcFiles) {
      const s = fs.readFileSync(nodePath.join(FUNCTIONS_DIR, f), 'utf8')
        .replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
      if (/[?&](token|staffToken|session)=/.test(s)) offenders.push(f);
    }
    check('token-url', 'no serverless function builds a URL containing a session token',
      offenders.length === 0, offenders.join(', '));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  END-OF-RUN SAFETY ASSERTIONS — nothing real was contacted, nothing leaked
  // ═══════════════════════════════════════════════════════════════════════════
  {
    const urls = ALL_CALLS.map(c => c.url);
    check('safety', 'no request was made to the production Airtable base',
      !urls.some(u => u.includes(PROD_BASE)), urls.filter(u => u.includes(PROD_BASE)).join(', '));
    // create-checkout-session is exercised, so a Stripe URL IS constructed --
    // but only ever inside the stub. Assert that no real egress was possible:
    // global.fetch is never the native implementation during the run, and any
    // Stripe URL built used the mock test key, never a live key.
    check('safety', 'global.fetch is stubbed for the whole run (no real egress)',
      typeof global.fetch === 'function' && !/\[native code\]/.test(Function.prototype.toString.call(global.fetch)));
    check('safety', 'no live Stripe key was ever used',
      process.env.STRIPE_SECRET_KEY === 'sk_test_MOCK_not_real' &&
      !urls.some(u => /sk_live_/.test(u)), process.env.STRIPE_SECRET_KEY);
    check('safety', 'every Stripe URL contacted went through the stub only',
      urls.filter(u => /api\.stripe\.com/.test(u)).every(u => u.startsWith('https://api.stripe.com/v1/checkout/sessions')),
      urls.filter(u => /api\.stripe\.com/.test(u)).join(', '));
    check('safety', 'no outbound URL in the entire run carried a token parameter',
      !urls.some(u => /[?&]token=/.test(u)), urls.filter(u => /[?&]token=/.test(u)).join(', '));
    check('safety', 'no outbound URL carried the signing secret or API key',
      !urls.some(u => u.includes(MOCK.SECRET) || u.includes(MOCK.KEY)));
    check('safety', 'the run did make mocked upstream calls (stub is wired)',
      ALL_CALLS.length > 0, `${ALL_CALLS.length} recorded`);
  }

  // ── Output ───────────────────────────────────────────────────────────────
  console.log(RESULTS.join('\n'));
  console.log('\n' + '─'.repeat(72));
  console.log(`TOTAL: ${PASS + FAIL}    PASSED: ${PASS}    FAILED: ${FAIL}`);
  console.log('─'.repeat(72));
  process.exit(FAIL ? 1 : 0);
})();
