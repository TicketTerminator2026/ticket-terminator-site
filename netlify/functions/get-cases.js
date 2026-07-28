// Ticket Terminator — Fetch All Cases from Airtable
// GET → { records, total, truncated }
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token (any known role, including
// Read Only). Paginates through ALL records (Airtable max 100/page), newest
// first. Caps at 2,000 records for dashboard performance.

'use strict';

const { requireAuth, jsonResponse, serverError, upstreamError, methodNotAllowed } = require('./_verify-token');

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') return methodNotAllowed();

  // ── Auth first — before any Airtable contact ──────────────────────────────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;

  const base  = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_ID;
  const key   = process.env.AIRTABLE_API_KEY;

  if (!base || !table || !key) {
    console.error('[get-cases] Missing Airtable environment configuration.');
    return serverError();
  }

  const atHeaders = { 'Authorization': `Bearer ${key}` };
  const MAX_RECORDS = 2000; // safety cap for dashboard perf

  const allRecords = [];
  let offset = null;

  try {
    do {
      const params = new URLSearchParams();
      params.set('pageSize', '100');
      params.set('sort[0][field]',     'Date Submitted');
      params.set('sort[0][direction]', 'desc');
      if (offset) params.set('offset', offset);

      const url = `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}?${params}`;
      const res = await fetch(url, { headers: atHeaders });

      if (!res.ok) {
        const errText = await res.text();
        console.error('[get-cases] Airtable fetch error:', res.status, errText);
        return upstreamError();
      }

      const page = await res.json();
      allRecords.push(...(page.records || []));
      offset = page.offset || null;

    } while (offset && allRecords.length < MAX_RECORDS);

    const truncated = !!(offset && allRecords.length >= MAX_RECORDS);

    return jsonResponse(200, {
      records:   allRecords,
      total:     allRecords.length,
      truncated, // true when more than 2,000 records exist
    });

  } catch (err) {
    console.error('[get-cases] error:', err.message);
    return serverError();
  }
};
