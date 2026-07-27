// Ticket Terminator — Shared staff-token verification & authorization (Phase 0)
//
// PURPOSE
//   Single source of truth for authenticating dashboard requests. Every private
//   Netlify function must call requireAuth() before doing any other work, and
//   must validate submitted field names against an explicit positive allowlist
//   BEFORE contacting Airtable.
//
// SECURITY CONTRACT
//   - HMAC-SHA256 signature verification with timing-safe comparison
//   - Token expiry enforced
//   - Role must be one of the exact known roles (allowlist, never a deny-list)
//   - Staff identity fields (staffId, email, role) are required — legacy
//     identity-less tokens (old auth.js format) are rejected
//   - Missing DASHBOARD_TOKEN_SECRET fails CLOSED with a generic 500
//   - Client-facing errors are always generic; details go to server logs only
//   - Field allowlists are positive per role. There is no Admin wildcard.
//
// This module is NOT an HTTP handler and exposes no route of its own.

'use strict';

const crypto = require('crypto');

// ── Roles ────────────────────────────────────────────────────────────────────
const ROLES = Object.freeze(['Admin', 'Manager', 'Employee', 'Read Only']);
const ROLE_RANK = Object.freeze({ 'Read Only': 1, 'Employee': 2, 'Manager': 3, 'Admin': 4 });

// ── Responses ────────────────────────────────────────────────────────────────
const JSON_HEADERS = Object.freeze({
  'Content-Type': 'application/json',
  'Cache-Control': 'no-store',
});

function jsonResponse(statusCode, payload) {
  return { statusCode, headers: { ...JSON_HEADERS }, body: JSON.stringify(payload) };
}

// Generic, non-revealing client-facing messages.
const MSG = Object.freeze({
  AUTH: 'Authentication required.',
  FORBIDDEN: 'You do not have permission to perform this action.',
  SERVER: 'Server error. Please try again.',
  UPSTREAM: 'Unable to complete the request. Please try again.',
  BAD_REQUEST: 'Invalid request.',
  METHOD: 'Method Not Allowed',
});

const unauthorized = () => jsonResponse(401, { error: MSG.AUTH });
const forbidden = (msg) => jsonResponse(403, { error: msg || MSG.FORBIDDEN });
const serverError = () => jsonResponse(500, { error: MSG.SERVER });
const upstreamError = () => jsonResponse(502, { error: MSG.UPSTREAM });
const badRequest = (msg) => jsonResponse(400, { error: msg || MSG.BAD_REQUEST });
const methodNotAllowed = () => jsonResponse(405, { error: MSG.METHOD });

// ── Token primitives ─────────────────────────────────────────────────────────
function sign(payloadB64, secret) {
  return crypto.createHmac('sha256', secret).update(payloadB64).digest('hex');
}

/**
 * Verify a staff token. Returns the payload object, or null when the token is
 * malformed, unsigned, tampered with, expired, or missing identity fields.
 */
function verifyToken(token, secret) {
  if (!secret || typeof secret !== 'string') return null;
  if (!token || typeof token !== 'string') return null;

  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [b64, sig] = parts;
  if (!b64 || !sig) return null;

  // Signature must be lowercase hex of the correct length before we compare,
  // otherwise Buffer.from(sig,'hex') silently truncates.
  if (!/^[0-9a-f]{64}$/i.test(sig)) return null;

  const expected = sign(b64, secret);
  try {
    const a = Buffer.from(sig, 'hex');
    const b = Buffer.from(expected, 'hex');
    if (a.length !== b.length) return null;
    if (!crypto.timingSafeEqual(a, b)) return null;
  } catch {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(b64, 'base64url').toString());
  } catch {
    return null;
  }
  if (!payload || typeof payload !== 'object') return null;

  // Expiry — must be a finite number in the future.
  if (typeof payload.exp !== 'number' || !isFinite(payload.exp)) return null;
  if (Date.now() > payload.exp) return null;

  // Identity — rejects legacy {exp}-only tokens from the deprecated auth.js.
  if (!isNonEmptyString(payload.staffId)) return null;
  if (!isValidEmail(payload.email)) return null;
  if (!ROLES.includes(payload.role)) return null;

  return payload;
}

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

function isValidEmail(v) {
  return typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.trim());
}

// ── Request helpers ──────────────────────────────────────────────────────────
function getHeader(event, name) {
  const headers = (event && event.headers) || {};
  const target = String(name).toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === target) return headers[k];
  }
  return '';
}

function extractToken(event) {
  const header = getHeader(event, 'x-staff-token');
  if (isNonEmptyString(header)) return header.trim();

  // Bearer fallback — some callers may use Authorization.
  const auth = getHeader(event, 'authorization');
  if (isNonEmptyString(auth) && /^Bearer\s+/i.test(auth)) {
    return auth.replace(/^Bearer\s+/i, '').trim();
  }
  return '';
}

/**
 * Authenticate a request.
 * @returns {{ok:true, staff:object}} on success
 * @returns {{ok:false, response:object}} with a ready-to-return HTTP response
 */
function requireAuth(event) {
  const secret = process.env.DASHBOARD_TOKEN_SECRET;

  // Fail closed — never fall through to unauthenticated access.
  if (!isNonEmptyString(secret)) {
    console.error('[auth] DASHBOARD_TOKEN_SECRET is not configured — refusing all requests.');
    return { ok: false, response: serverError() };
  }

  const token = extractToken(event);
  if (!token) return { ok: false, response: unauthorized() };

  const payload = verifyToken(token, secret);
  if (!payload) return { ok: false, response: unauthorized() };

  return {
    ok: true,
    staff: {
      staffId: String(payload.staffId).trim(),
      name: isNonEmptyString(payload.name) ? String(payload.name).trim() : String(payload.email).trim(),
      email: String(payload.email).trim(),
      role: payload.role,
      exp: payload.exp,
    },
  };
}

// ── Role checks (positive) ───────────────────────────────────────────────────
function hasMinRole(staff, minRole) {
  const have = ROLE_RANK[staff && staff.role] || 0;
  const need = ROLE_RANK[minRole] || Infinity;
  return have >= need;
}

function isOneOf(staff, roles) {
  return Array.isArray(roles) && roles.includes(staff && staff.role);
}

function canWrite(staff) {
  // Read Only is never permitted to write.
  return hasMinRole(staff, 'Employee');
}

// ── Body parsing ─────────────────────────────────────────────────────────────
function parseJsonBody(event) {
  try {
    const parsed = JSON.parse((event && event.body) || '{}');
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false, response: badRequest() };
    }
    return { ok: true, body: parsed };
  } catch {
    return { ok: false, response: badRequest() };
  }
}

// ── Field allowlists ─────────────────────────────────────────────────────────
// Positive lists only. A field absent from a role's list is rejected outright.

// Cases — ordinary operational fields (Employee and above).
const CASE_FIELDS_OPERATIONAL = Object.freeze([
  'First Name', 'Last Name', 'Phone', 'Email',
  'CDL Holder', 'Traffic School Past 18 Months?',
  'Date of Violation', 'Citation / Arrest #', 'Violation Description', 'Client Statement',
  'Heard About Us', 'Referred By',
  'Status', 'Case Type', 'Priority', 'Quote Status',
  'Court Date', 'Court Location', 'Court State', 'County',
  'Court Date Status', 'Court Outcome', 'Next Court Date',
  'Outcome Received Date', 'Next Follow-Up Date',
  'Closed By', 'Closed Date',
  'Waiting For Attorney Update',
  'Ticket Received', 'Driver License Received', 'Court Notice Received',
  'Documents Complete', 'Packet Sent to Attorney',
  'Internal Notes', 'Resolution Notes',
  'Preferred Contact', 'Past Due / Collections', 'Ticket Already Paid',
]);

// Cases — financial fields. Manager and Admin only (Owner decision, Phase 0 §5).
const CASE_FIELDS_FINANCIAL = Object.freeze([
  'Client Fee Collected', 'Client Balance Remaining',
  'Attorney Service Fee', 'Attorney Balance Remaining',
  'Attorney Payment Confirmed', 'Attorney Paid Date',
  'Payout Due?', 'Payment Status', 'Payment Method',
  'Stripe Session ID', 'Date Submitted',
]);

// Never writable through the dashboard by any role:
//   Case #, Client, Attorney, Payments, Documents, Profit (formula),
//   Ticket Upload, ID Upload, SMS Consent, SMS Consent Timestamp,
//   Intake Submission ID, Preferred Language.
// (Attorney links are handled exclusively by assign-attorney.js.)

const CASE_FIELDS_BY_ROLE = Object.freeze({
  'Admin': Object.freeze([...CASE_FIELDS_OPERATIONAL, ...CASE_FIELDS_FINANCIAL]),
  'Manager': Object.freeze([...CASE_FIELDS_OPERATIONAL, ...CASE_FIELDS_FINANCIAL]),
  'Employee': CASE_FIELDS_OPERATIONAL,
  'Read Only': Object.freeze([]),
});

const TASK_FIELDS = Object.freeze([
  'Task', 'Status', 'Priority', 'Due Date',
  'Assigned To', 'Assigned Staff ID',
  'Case #', 'Case Record ID', 'Notes',
]);
// Created By / Created Date / Completed Date are set server-side only.

const ATTORNEY_FIELDS = Object.freeze([
  'Attorney Name', 'Phone', 'Email', 'Bar Number',
  'State', 'Counties Covered', 'Active', 'Internal Notes',
]);

const CASE_DOC_FIELDS = Object.freeze([
  'Document Name', 'Case', 'Document Type', 'Upload Date',
  'Uploaded By', 'Notes', 'File URL',
  'Requires Signature', 'Signed', 'Signed Date',
]);

const TEMPLATE_FIELDS = Object.freeze([
  'Template Name', 'File URL', 'Document Type', 'Attorney',
  'State', 'County', 'Court',
  'Requires Client Signature', 'Active', 'Last Updated', 'Uploaded By', 'Notes',
]);

const STAFF_FIELDS = Object.freeze(['Name', 'Email', 'Role', 'Active', 'Notes']);
// 'Password Hash' is never accepted from a client; passwords arrive as
// fields.password and are hashed server-side.

/**
 * Validate submitted field names against a positive allowlist.
 * Never inspects or logs values — field NAMES only.
 * @returns {{ok:true, fields:object}} | {{ok:false, rejected:string[]}}
 */
function checkFields(fields, allowlist) {
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
    return { ok: false, rejected: ['<invalid fields object>'] };
  }
  const allowed = new Set(allowlist || []);
  const rejected = Object.keys(fields).filter((k) => !allowed.has(k));
  if (rejected.length) return { ok: false, rejected };
  return { ok: true, fields };
}

/**
 * Enforce a field allowlist, returning a ready 403 when anything is not
 * approved. The whole request is rejected — nothing is partially written.
 */
function enforceFields(context, fields, allowlist) {
  const result = checkFields(fields, allowlist);
  if (!result.ok) {
    // Field NAMES only — never values.
    console.warn(`[authz] ${context}: rejected disallowed field name(s): ${result.rejected.join(', ')}`);
    return {
      ok: false,
      response: forbidden('One or more submitted fields are not permitted for your role.'),
    };
  }
  return { ok: true, fields: result.fields };
}

// ── Airtable helpers ─────────────────────────────────────────────────────────

/** Escape a value for safe interpolation inside an Airtable filterByFormula string literal. */
function escapeFormulaValue(value) {
  return String(value == null ? '' : value)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"');
}

/** Allow only http(s) URLs — blocks javascript:, data:, and similar schemes. */
function isSafeHttpUrl(value) {
  if (typeof value !== 'string' || !value.trim()) return false;
  try {
    const u = new URL(value.trim());
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

module.exports = {
  // constants
  ROLES,
  ROLE_RANK,
  JSON_HEADERS,
  MSG,
  // responses
  jsonResponse,
  unauthorized,
  forbidden,
  serverError,
  upstreamError,
  badRequest,
  methodNotAllowed,
  // auth
  verifyToken,
  requireAuth,
  extractToken,
  getHeader,
  hasMinRole,
  isOneOf,
  canWrite,
  parseJsonBody,
  // field policy
  CASE_FIELDS_OPERATIONAL,
  CASE_FIELDS_FINANCIAL,
  CASE_FIELDS_BY_ROLE,
  TASK_FIELDS,
  ATTORNEY_FIELDS,
  CASE_DOC_FIELDS,
  TEMPLATE_FIELDS,
  STAFF_FIELDS,
  checkFields,
  enforceFields,
  // misc
  escapeFormulaValue,
  isSafeHttpUrl,
};
