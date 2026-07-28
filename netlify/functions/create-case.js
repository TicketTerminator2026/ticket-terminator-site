// Ticket Terminator — Create a Case manually
// POST { fields } → { success, caseNum, recordId, record }
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token.
//
// AUTHORIZATION (Phase 0):
//   Read Only  — blocked
//   Employee   — operational case fields only
//   Manager /
//   Admin      — operational + financial fields
// Case #, Status, Quote Status and Date Submitted are set server-side and can
// no longer be overridden by the caller (previously 'Case #' was spoofable).

'use strict';

const { log } = require('./_log');
const {
  requireAuth, canWrite, parseJsonBody, enforceFields,
  jsonResponse, forbidden, serverError, upstreamError, methodNotAllowed,
  CASE_FIELDS_BY_ROLE,
} = require('./_verify-token');

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') return methodNotAllowed();

  // ── 1. Authenticate ───────────────────────────────────────────────────────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;
  const staff = auth.staff;

  // ── 2. Read Only cannot write ─────────────────────────────────────────────
  if (!canWrite(staff)) return forbidden();

  // ── 3. Parse body ─────────────────────────────────────────────────────────
  const parsed = parseJsonBody(event);
  if (!parsed.ok) return parsed.response;

  const submitted = parsed.body.fields || {};

  // ── 4. Field allowlist — BEFORE any Airtable call ─────────────────────────
  const allowlist = CASE_FIELDS_BY_ROLE[staff.role] || [];
  const gate = enforceFields(`create-case[${staff.role}]`, submitted, allowlist, staff.staffId);
  if (!gate.ok) return gate.response;

  const base  = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_ID;
  const key   = process.env.AIRTABLE_API_KEY;
  const env   = { base, key };

  if (!base || !table || !key) {
    console.error('[create-case] Missing Airtable environment configuration.');
    return serverError();
  }

  // Server-generated identifiers — not caller-controllable.
  const year    = new Date().getFullYear();
  const seq     = Date.now().toString().slice(-5);
  const caseNum = `TT-${year}-${seq}`;

  const fields = {
    ...submitted,
    'Case #':         caseNum,
    'Status':         '🔵 Lead',
    'Quote Status':   'Not Requested',
    'Date Submitted': new Date().toISOString().split('T')[0],
  };

  const clean = {};
  Object.entries(fields).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== '') clean[k] = v;
    if (v === false || v === 0) clean[k] = v;
  });

  try {
    const res = await fetch(
      `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}`,
      {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: clean }),
      }
    );
    const data = await res.json();
    if (!res.ok) {
      console.error('[create-case] Airtable error:', res.status, data && data.error && data.error.message);
      return upstreamError();
    }

    const clientName = [clean['First Name'], clean['Last Name']].filter(Boolean).join(' ');
    await log(env, {
      staffName: staff.name, staffId: staff.staffId,
      action: `Created case${clientName ? ' for ' + clientName : ''}`,
      category: 'Case', caseNum, caseId: data.id,
      field: 'Case Created', oldVal: '', newVal: caseNum,
    });

    return jsonResponse(200, { success: true, caseNum, recordId: data.id, record: data });
  } catch (err) {
    console.error('[create-case] error:', err.message);
    return serverError();
  }
};
