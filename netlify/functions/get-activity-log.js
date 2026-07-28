// Ticket Terminator — Fetch Activity Log
// GET ?limit=50&offset=...&category=Case&staffId=...&caseId=...&caseNum=...
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token.
//
// PHASE 0 ACCESS RULES (Owner decision):
//   Admin     — all activity, all categories (incl. Staff, Security, Payment)
//   Manager   — organisation-wide operational activity + Payment;
//               NOT Staff, NOT Security
//   Employee  — case-scoped only (caseId or caseNum REQUIRED);
//               NOT Payment, NOT Staff, NOT Security
//   Read Only — no access
//
// Category restrictions are applied BEFORE the Airtable query, both by
// rejecting an explicitly requested forbidden category and by excluding
// forbidden categories from every query so an unfiltered request cannot leak.

'use strict';

const {
  requireAuth, hasMinRole, jsonResponse, forbidden, serverError, upstreamError, methodNotAllowed,
  escapeFormulaValue,
} = require('./_verify-token');

const ACTIVITY_TABLE = 'tblHAOnm8Qu1d7iKT';

// Categories that are never visible below the stated role.
const ADMIN_ONLY_CATEGORIES   = ['Staff', 'Security'];
const MANAGER_MIN_CATEGORIES  = ['Payment'];

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') return methodNotAllowed();

  // ── Auth first — before any Airtable contact ──────────────────────────────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;
  const staff = auth.staff;
  const role  = staff.role;

  // ── Role gate ─────────────────────────────────────────────────────────────
  if (role === 'Read Only') {
    return forbidden();
  }

  const qs = event.queryStringParameters || {};
  const caseId  = qs.caseId  || '';
  const caseNum = qs.caseNum || '';

  // Employees may only request a specific case timeline.
  if (role === 'Employee' && !caseId && !caseNum) {
    return forbidden();
  }

  // Categories this caller may never see.
  const blockedCategories = [];
  if (role !== 'Admin') blockedCategories.push(...ADMIN_ONLY_CATEGORIES);
  if (role === 'Employee') blockedCategories.push(...MANAGER_MIN_CATEGORIES);

  // Explicitly requesting a forbidden category is rejected outright.
  if (qs.category && blockedCategories.includes(qs.category)) {
    return forbidden();
  }

  // ── Build query ───────────────────────────────────────────────────────────
  const parsedLimit = parseInt(qs.limit, 10);
  const pageSize = Number.isFinite(parsedLimit)
    ? Math.min(Math.max(parsedLimit, 1), 100)
    : 100;

  const params = new URLSearchParams();
  params.set('pageSize', String(pageSize));
  params.set('sort[0][field]', 'Timestamp');
  params.set('sort[0][direction]', 'desc');

  // Only Manager and Admin may filter by another staff member — Employees must
  // not be able to enumerate a colleague's actions, even within their own case.
  const effectiveStaffId = hasMinRole(staff, 'Manager') ? (qs.staffId || '') : '';

  // All interpolated values escaped — prevents Airtable formula injection.
  const filters = [];
  if (qs.category)      filters.push(`{Category} = "${escapeFormulaValue(qs.category)}"`);
  if (effectiveStaffId) filters.push(`{Staff Record ID} = "${escapeFormulaValue(effectiveStaffId)}"`);
  if (caseId)      filters.push(`{Case Record ID} = "${escapeFormulaValue(caseId)}"`);
  if (caseNum)     filters.push(`{Case #} = "${escapeFormulaValue(caseNum)}"`);

  // Hard exclusions so a category-less request cannot return restricted rows.
  for (const blocked of blockedCategories) {
    filters.push(`NOT({Category} = "${escapeFormulaValue(blocked)}")`);
  }

  if (filters.length) params.set('filterByFormula', `AND(${filters.join(',')})`);
  if (qs.offset) params.set('offset', qs.offset);

  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;
  if (!base || !key) {
    console.error('[get-activity-log] Missing Airtable environment configuration.');
    return serverError();
  }

  try {
    const res  = await fetch(`https://api.airtable.com/v0/${base}/${ACTIVITY_TABLE}?${params}`,
      { headers: { 'Authorization': `Bearer ${key}` } });
    const data = await res.json();
    if (!res.ok) {
      console.error('[get-activity-log] Airtable error:', res.status, data && data.error && data.error.message);
      return upstreamError();
    }
    return jsonResponse(200, { records: data.records || [], offset: data.offset });
  } catch (err) {
    console.error('[get-activity-log] error:', err.message);
    return serverError();
  }
};
