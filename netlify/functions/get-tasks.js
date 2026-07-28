// Ticket Terminator — Fetch Tasks
// GET ?caseId=...&staffId=...&status=Open → { records }
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token (any known role).
// NOTE: the pre-existing "Employees see their own tasks" filter is preserved
// as-is. Phase 0 deliberately does NOT add or broaden record-assignment
// filtering; proper scoping is a Dashboard V2 design item.

'use strict';

const {
  requireAuth, jsonResponse, serverError, upstreamError, methodNotAllowed,
  escapeFormulaValue,
} = require('./_verify-token');

const TASKS_TABLE = 'tblvwrl2hPjUjbUkC';

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') return methodNotAllowed();

  // ── Auth first — before any Airtable contact ──────────────────────────────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;
  const staff = auth.staff;

  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;

  if (!base || !key) {
    console.error('[get-tasks] Missing Airtable environment configuration.');
    return serverError();
  }

  const qs = event.queryStringParameters || {};
  const params = new URLSearchParams();
  params.set('pageSize', '100');
  params.set('sort[0][field]', 'Due Date');
  params.set('sort[0][direction]', 'asc');

  // All interpolated values are escaped — prevents Airtable formula injection.
  const filters = [];
  if (qs.status)  filters.push(`{Status} = "${escapeFormulaValue(qs.status)}"`);
  if (qs.caseId)  filters.push(`{Case Record ID} = "${escapeFormulaValue(qs.caseId)}"`);

  // Pre-existing behaviour retained: Employees default to their own tasks.
  // staffId now comes from a cryptographically verified token.
  if (staff.role === 'Employee' && !qs.caseId) {
    filters.push(`{Assigned Staff ID} = "${escapeFormulaValue(staff.staffId)}"`);
  } else if (qs.staffId) {
    filters.push(`{Assigned Staff ID} = "${escapeFormulaValue(qs.staffId)}"`);
  }

  if (!qs.status) filters.push(`NOT({Status} = "Cancelled")`);

  if (filters.length) params.set('filterByFormula', `AND(${filters.join(',')})`);

  try {
    const res  = await fetch(`https://api.airtable.com/v0/${base}/${TASKS_TABLE}?${params}`,
      { headers: { 'Authorization': `Bearer ${key}` } });
    const data = await res.json();
    if (!res.ok) {
      console.error('[get-tasks] Airtable error:', res.status, data && data.error && data.error.message);
      return upstreamError();
    }
    return jsonResponse(200, { records: data.records || [] });
  } catch (err) {
    console.error('[get-tasks] error:', err.message);
    return serverError();
  }
};
