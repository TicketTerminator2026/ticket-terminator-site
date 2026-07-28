// Ticket Terminator — Update a Case record in Airtable
// PATCH { recordId, fields, previousFields? } → { success, record }
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token.
//
// AUTHORIZATION (Phase 0):
//   Read Only            — blocked from all writes
//   Employee             — operational case fields only (no financial fields)
//   Manager / Admin      — operational + financial fields
// Every role uses an explicit positive allowlist; there is no Admin wildcard.
// If ANY submitted field is not permitted the entire request is rejected with
// 403 and nothing is written. Field validation happens BEFORE Airtable is
// contacted, and only field NAMES are ever logged.

'use strict';

const { log } = require('./_log');
const {
  requireAuth, canWrite, parseJsonBody, enforceFields,
  jsonResponse, forbidden, badRequest, serverError, upstreamError, methodNotAllowed,
  CASE_FIELDS_BY_ROLE,
} = require('./_verify-token');

exports.handler = async function (event) {
  if (event.httpMethod !== 'PATCH') return methodNotAllowed();

  // ── 1. Authenticate (HMAC-verified, expiry + identity + role checked) ─────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;
  const staff = auth.staff;

  // ── 2. Read Only cannot write ─────────────────────────────────────────────
  if (!canWrite(staff)) return forbidden();

  // ── 3. Parse body ─────────────────────────────────────────────────────────
  const parsed = parseJsonBody(event);
  if (!parsed.ok) return parsed.response;

  const { recordId, fields, previousFields = {} } = parsed.body;

  if (typeof recordId !== 'string' || !recordId.startsWith('rec')) {
    return badRequest('A valid record reference is required.');
  }
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
    return badRequest('No changes were supplied.');
  }

  // ── 4. Field allowlist for this role — BEFORE any Airtable call ───────────
  const allowlist = CASE_FIELDS_BY_ROLE[staff.role] || [];
  const gate = enforceFields(`update-case[${staff.role}]`, fields, allowlist, staff.staffId);
  if (!gate.ok) return gate.response;

  const base  = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_ID;
  const key   = process.env.AIRTABLE_API_KEY;
  const env   = { base, key };

  if (!base || !table || !key) {
    console.error('[update-case] Missing Airtable environment configuration.');
    return serverError();
  }

  // Valid Airtable Status singleSelect option names.
  // Add new options here AND in Airtable field settings when expanding the lifecycle.
  const VALID_AT_STATUSES = new Set([
    '🔵 Lead','🟡 Pending','🟢 Open / Active','✅ Closed',
    'Lead','Quote Sent','Waiting for Payment','Paid - Needs Attorney',
    'Attorney Assigned','Open / Active','Court Pending',
    'Waiting for Attorney Update','Outcome Received',
    'Closed - Dismissed','Closed - Reduced','Closed - Traffic School Completed',
    'Closed - Completed','Canceled','Refunded','Archived',
  ]);

  const clean = {};
  Object.entries(fields).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== '') clean[k] = v;
    // Handle explicit false/0
    if (v === false || v === 0) clean[k] = v;
  });

  // Strip Status if not a valid Airtable option (prevents "cannot create new
  // select option" error). Pre-existing behaviour, unchanged in Phase 0.
  if (clean.Status && !VALID_AT_STATUSES.has(clean.Status)) {
    delete clean.Status;
  }

  try {
    const res = await fetch(
      `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}/${encodeURIComponent(recordId)}`,
      {
        method: 'PATCH',
        headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: clean }),
      }
    );
    const data = await res.json();
    if (!res.ok) {
      console.error('[update-case] Airtable error:', res.status, data && data.error && data.error.message);
      return upstreamError();
    }

    // ── Activity Log — identity comes from the verified token, never the body.
    const caseNum = previousFields['Case #'] || recordId;
    const writes = [];
    for (const [field, newVal] of Object.entries(clean)) {
      const oldVal = previousFields[field];
      if (oldVal !== newVal) {
        writes.push(log(env, {
          staffName: staff.name, staffId: staff.staffId,
          action: `Updated ${field}`,
          category: field.includes('Payment') || field.includes('Fee') ? 'Payment' : 'Case',
          caseNum, caseId: recordId,
          field, oldVal, newVal,
        }));
      }
    }
    // Awaited so log writes are not killed when the function returns.
    await Promise.all(writes);

    return jsonResponse(200, { success: true, record: data });
  } catch (err) {
    console.error('[update-case] error:', err.message);
    return serverError();
  }
};
