// Ticket Terminator — Create or update a staff member (Admin only)
// POST  { fields: { Name, Email, Role, Notes?, password } }        → create
// PATCH { recordId, fields: { Name, Role, Active, Notes?, password? } } → update
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token with the Admin role.
//
// Hardening (Phase 0):
//   - HMAC-verified token (previously any base64 blob claiming Admin worked)
//   - Explicit field allowlist; 'Password Hash' can never be supplied directly
//   - Role must be one of the four known roles (previously arbitrary strings
//     were written straight to Airtable)

'use strict';

const crypto = require('crypto');
const {
  requireAuth, parseJsonBody, enforceFields,
  jsonResponse, forbidden, badRequest, serverError, upstreamError, methodNotAllowed,
  STAFF_FIELDS, ROLES,
} = require('./_verify-token');

const STAFF_TABLE = 'tblFGsQpsOJFF2r2V';
const MIN_PASSWORD_LENGTH = 8;

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}

function makeHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${hashPassword(password, salt)}`;
}

exports.handler = async function (event) {
  const isCreate = event.httpMethod === 'POST';
  const isUpdate = event.httpMethod === 'PATCH';
  if (!isCreate && !isUpdate) return methodNotAllowed();

  // ── 1. Authenticate ───────────────────────────────────────────────────────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;
  const staff = auth.staff;

  // ── 2. Owner/Admin only ───────────────────────────────────────────────────
  if (staff.role !== 'Admin') {
    return forbidden('Staff administration requires an Admin account.');
  }

  // ── 3. Parse body ─────────────────────────────────────────────────────────
  const parsed = parseJsonBody(event);
  if (!parsed.ok) return parsed.response;

  const { recordId } = parsed.body;
  const { password, ...rest } = parsed.body.fields || {};

  if (isUpdate && (typeof recordId !== 'string' || !recordId.startsWith('rec'))) {
    return badRequest('A valid staff record reference is required.');
  }

  // ── 4. Field allowlist — BEFORE any Airtable call ─────────────────────────
  const gate = enforceFields('save-staff', rest, STAFF_FIELDS);
  if (!gate.ok) return gate.response;

  // ── 5. Role value must be a known role ────────────────────────────────────
  if (rest.Role !== undefined && !ROLES.includes(rest.Role)) {
    return badRequest('Invalid role.');
  }

  const fields = { ...rest };

  if (isCreate) {
    if (!password || typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
      return badRequest(`A password of at least ${MIN_PASSWORD_LENGTH} characters is required.`);
    }
    if (!fields.Email) return badRequest('Email is required.');
    fields['Password Hash'] = makeHash(password);
    fields.Active = true;
  } else if (password !== undefined) {
    if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
      return badRequest(`A password of at least ${MIN_PASSWORD_LENGTH} characters is required.`);
    }
    fields['Password Hash'] = makeHash(password);
  }

  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;
  if (!base || !key) {
    console.error('[save-staff] Missing Airtable environment configuration.');
    return serverError();
  }

  const url = isCreate
    ? `https://api.airtable.com/v0/${base}/${STAFF_TABLE}`
    : `https://api.airtable.com/v0/${base}/${STAFF_TABLE}/${encodeURIComponent(recordId)}`;

  try {
    const res = await fetch(url, {
      method: isCreate ? 'POST' : 'PATCH',
      headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields }),
    });
    const data = await res.json();
    if (!res.ok) {
      console.error('[save-staff] Airtable error:', res.status, data && data.error && data.error.message);
      return upstreamError();
    }
    // Never return the password hash.
    if (data.fields) delete data.fields['Password Hash'];
    return jsonResponse(200, { success: true, record: data });
  } catch (err) {
    console.error('[save-staff] error:', err.message);
    return serverError();
  }
};
