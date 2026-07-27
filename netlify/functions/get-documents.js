// Ticket Terminator — get-documents.js
// GET ?type=all|case-docs|templates&caseId=recXXX → { caseDocs?, templates? }
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token (any known role).

'use strict';

const {
  requireAuth, jsonResponse, serverError, upstreamError, methodNotAllowed,
  escapeFormulaValue,
} = require('./_verify-token');

const CASE_DOCS_TABLE = 'tblfYr2UCNJSikhjp';
const TEMPLATES_TABLE = 'tblKlrzPFTVmmGDCa';
const MAX_RECORDS = 2000; // bound the paginated fetch

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') return methodNotAllowed();

  // ── Auth first — before any Airtable contact ──────────────────────────────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;

  const baseId = process.env.AIRTABLE_BASE_ID;
  const apiKey = process.env.AIRTABLE_API_KEY;

  if (!baseId || !apiKey) {
    console.error('[get-documents] Missing Airtable environment configuration.');
    return serverError();
  }

  const headers = { 'Authorization': `Bearer ${apiKey}` };
  const params  = event.queryStringParameters || {};
  const type    = params.type   || 'all';    // 'all' | 'case-docs' | 'templates'
  const caseId  = params.caseId || '';       // optional — filter case docs by case record ID

  // ── Paginated fetch helper ───────────────────────────
  async function fetchAll(tableId, filterFormula) {
    const records = [];
    let offset = '';
    do {
      let url = `https://api.airtable.com/v0/${baseId}/${tableId}?pageSize=100`;
      if (filterFormula) url += `&filterByFormula=${encodeURIComponent(filterFormula)}`;
      if (offset)        url += `&offset=${encodeURIComponent(offset)}`;
      const res = await fetch(url, { headers });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        console.error('[get-documents] Airtable error:', res.status, errData && errData.error && errData.error.message);
        throw new Error('UPSTREAM');
      }
      const data = await res.json();
      records.push(...(data.records || []));
      offset = data.offset || '';
    } while (offset && records.length < MAX_RECORDS);
    return records;
  }

  try {
    const result = {};

    if (type === 'case-docs' || type === 'all') {
      // Escaped to prevent Airtable formula injection.
      const filter = caseId
        ? `FIND("${escapeFormulaValue(caseId)}",ARRAYJOIN({Case})) > 0`
        : '';
      result.caseDocs = await fetchAll(CASE_DOCS_TABLE, filter);
    }

    if (type === 'templates' || type === 'all') {
      result.templates = await fetchAll(TEMPLATES_TABLE, '');
    }

    return jsonResponse(200, result);
  } catch (e) {
    if (e.message === 'UPSTREAM') return upstreamError();
    console.error('[get-documents]', e.message);
    return serverError();
  }
};
