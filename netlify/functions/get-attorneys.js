// Ticket Terminator — Fetch all Attorneys from Airtable
// GET → { records, total }
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token (any known role).

'use strict';

const { requireAuth, jsonResponse, serverError, upstreamError, methodNotAllowed } = require('./_verify-token');

const ATTORNEYS_TABLE = 'tbl7Yj3IYYJIpFOVt';

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') return methodNotAllowed();

  // ── Auth first — before any Airtable contact ──────────────────────────────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;

  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;

  if (!base || !key) {
    console.error('[get-attorneys] Missing Airtable environment configuration.');
    return serverError();
  }

  try {
    const params = new URLSearchParams();
    params.set('pageSize', '100');
    params.set('sort[0][field]', 'Attorney Name');
    params.set('sort[0][direction]', 'asc');

    const res = await fetch(
      `https://api.airtable.com/v0/${base}/${ATTORNEYS_TABLE}?${params}`,
      { headers: { 'Authorization': `Bearer ${key}` } }
    );
    const data = await res.json();
    if (!res.ok) {
      console.error('[get-attorneys] Airtable error:', res.status, data && data.error && data.error.message);
      return upstreamError();
    }
    return jsonResponse(200, {
      records: data.records || [],
      total: (data.records || []).length,
    });
  } catch (err) {
    console.error('[get-attorneys] error:', err.message);
    return serverError();
  }
};
