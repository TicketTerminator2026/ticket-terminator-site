// Ticket Terminator — Create or update an Attorney
// POST { fields } → create | PATCH { recordId, fields } → update
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token.
// AUTHORIZATION (Phase 0): Manager or Admin only (Employee and Read Only are
// blocked). Explicit positive field allowlist for every role.

'use strict';

const { log } = require('./_log');
const {
  requireAuth, hasMinRole, parseJsonBody, enforceFields,
  jsonResponse, forbidden, badRequest, serverError, upstreamError, methodNotAllowed,
  ATTORNEY_FIELDS,
} = require('./_verify-token');

const ATTORNEYS_TABLE = 'tbl7Yj3IYYJIpFOVt';

exports.handler = async function (event) {
  const isCreate = event.httpMethod === 'POST';
  const isUpdate = event.httpMethod === 'PATCH';
  if (!isCreate && !isUpdate) return methodNotAllowed();

  // ── 1. Authenticate ───────────────────────────────────────────────────────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;
  const staff = auth.staff;

  // ── 2. Manager or higher ──────────────────────────────────────────────────
  if (!hasMinRole(staff, 'Manager')) {
    return forbidden('Attorney administration requires a Manager or Admin account.');
  }

  // ── 3. Parse body ─────────────────────────────────────────────────────────
  const parsed = parseJsonBody(event);
  if (!parsed.ok) return parsed.response;

  const fields   = parsed.body.fields || {};
  const recordId = parsed.body.recordId;

  if (isUpdate && (typeof recordId !== 'string' || !recordId.startsWith('rec'))) {
    return badRequest('A valid attorney record reference is required.');
  }

  // ── 4. Field allowlist — BEFORE any Airtable call ─────────────────────────
  const gate = enforceFields('save-attorney', fields, ATTORNEY_FIELDS);
  if (!gate.ok) return gate.response;

  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;
  const env  = { base, key };
  if (!base || !key) {
    console.error('[save-attorney] Missing Airtable environment configuration.');
    return serverError();
  }

  const clean = {};
  Object.entries(fields).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== '') clean[k] = v;
    if (v === false || v === 0) clean[k] = v;
  });

  const url = isCreate
    ? `https://api.airtable.com/v0/${base}/${ATTORNEYS_TABLE}`
    : `https://api.airtable.com/v0/${base}/${ATTORNEYS_TABLE}/${encodeURIComponent(recordId)}`;

  try {
    const res = await fetch(url, {
      method: isCreate ? 'POST' : 'PATCH',
      headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields: clean }),
    });
    const data = await res.json();
    if (!res.ok) {
      console.error('[save-attorney] Airtable error:', res.status, data && data.error && data.error.message);
      return upstreamError();
    }

    const attyName = clean['Attorney Name'] || recordId;
    await log(env, {
      staffName: staff.name, staffId: staff.staffId,
      action: isCreate ? `Added attorney ${attyName}` : `Updated attorney ${attyName}`,
      category: 'Attorney',
      field: isCreate ? 'Attorney Created' : 'Attorney Updated',
      oldVal: '', newVal: attyName,
    });

    return jsonResponse(200, { success: true, record: data });
  } catch (err) {
    console.error('[save-attorney] error:', err.message);
    return serverError();
  }
};
