// Ticket Terminator — List staff members (Admin only)
// GET → { records }
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token with the Admin role.
// Password hashes are never returned.

'use strict';

const {
  requireAuth, jsonResponse, forbidden, serverError, upstreamError, methodNotAllowed,
} = require('./_verify-token');

const STAFF_TABLE = 'tblFGsQpsOJFF2r2V';

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') return methodNotAllowed();

  // ── 1. Authenticate ───────────────────────────────────────────────────────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;

  // ── 2. Owner/Admin only ───────────────────────────────────────────────────
  if (auth.staff.role !== 'Admin') {
    return forbidden();
  }

  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;
  if (!base || !key) {
    console.error('[get-staff] Missing Airtable environment configuration.');
    return serverError();
  }

  try {
    const params = new URLSearchParams();
    params.set('sort[0][field]', 'Name');
    params.set('fields[]', 'Name');
    params.set('fields[]', 'Email');
    params.set('fields[]', 'Role');
    params.set('fields[]', 'Active');
    params.set('fields[]', 'Last Login');
    // Never return Password Hash to the frontend.

    const res  = await fetch(`https://api.airtable.com/v0/${base}/${STAFF_TABLE}?${params}`,
      { headers: { 'Authorization': `Bearer ${key}` } });
    const data = await res.json();
    if (!res.ok) {
      console.error('[get-staff] Airtable error:', res.status, data && data.error && data.error.message);
      return upstreamError();
    }
    return jsonResponse(200, { records: data.records || [] });
  } catch (err) {
    console.error('[get-staff] error:', err.message);
    return serverError();
  }
};
