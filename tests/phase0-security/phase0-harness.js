'use strict';
/* ───────────────────────────────────────────────────────────────────────────
   Ticket Terminator — Phase 0 Security Regression Harness
   Branch: phase-0-security   Base: c75862a

   SAFETY: global.fetch is stubbed — NO network traffic leaves this process.
   Airtable base/table/key are MOCK values pointing at a NON-EXISTENT base.
   No production credentials. No Stripe calls. No emails. No real records.
   ─────────────────────────────────────────────────────────────────────────── */
const crypto = require('crypto');
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
global.fetch = async (url, opts = {}) => {
  const u = String(url);
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
    'Payout Due?','Payment Status','Payment Method','Stripe Session ID','Date Submitted'];
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

  r = await call('staff-auth.js', { method: 'GET', qs: { token: '' } });
  check('public', 'staff-auth.js still serves login/verify (not 410)', r.status !== 410 && r.status !== 405, `got ${r.status}`);
  r = await call('staff-auth.js', { method: 'GET', qs: { token: TOK.admin } });
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

  // ── P. Method guards ─────────────────────────────────────────────────────
  r = await call('get-cases.js', { method: 'POST', token: TOK.admin });
  check('method', 'get-cases rejects POST', r.status === 405, `got ${r.status}`);
  r = await call('update-case.js', { method: 'POST', token: TOK.admin, body: { recordId: 'recX', fields: {} } });
  check('method', 'update-case rejects POST (PATCH only)', r.status === 405, `got ${r.status}`);

  // ── Output ───────────────────────────────────────────────────────────────
  console.log(RESULTS.join('\n'));
  console.log('\n' + '─'.repeat(72));
  console.log(`TOTAL: ${PASS + FAIL}    PASSED: ${PASS}    FAILED: ${FAIL}`);
  console.log('─'.repeat(72));
  process.exit(FAIL ? 1 : 0);
})();
