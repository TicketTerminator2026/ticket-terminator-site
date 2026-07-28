// Ticket Terminator — save-document.js
// POST { table: 'case-docs'|'templates', recordId?, fields } → { success, record }
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token.
//
// AUTHORIZATION (Phase 0):
//   Read Only          — blocked from all document writes
//   Employee           — may create/update ordinary CASE documents only
//   Manager / Admin    — may manage case documents AND global templates
// Explicit positive field allowlist per table. File URL values must be http(s)
// so javascript:/data: URLs can never be stored and later rendered.

'use strict';

const {
  requireAuth, canWrite, hasMinRole, parseJsonBody, enforceFields,
  jsonResponse, forbidden, badRequest, serverError, upstreamError, methodNotAllowed,
  CASE_DOC_FIELDS, TEMPLATE_FIELDS, isSafeHttpUrl,
} = require('./_verify-token');

const TABLE_IDS = {
  'case-docs': 'tblfYr2UCNJSikhjp',
  'templates': 'tblKlrzPFTVmmGDCa',
};

const FIELD_POLICY = {
  'case-docs': CASE_DOC_FIELDS,
  'templates': TEMPLATE_FIELDS,
};

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') return methodNotAllowed();

  // ── 1. Authenticate ───────────────────────────────────────────────────────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;
  const staff = auth.staff;

  // ── 2. Read Only cannot write ─────────────────────────────────────────────
  if (!canWrite(staff)) return forbidden();

  // ── 3. Parse body ─────────────────────────────────────────────────────────
  const parsed = parseJsonBody(event);
  if (!parsed.ok) return parsed.response;

  const { table, recordId, fields } = parsed.body;

  if (!table || !TABLE_IDS[table]) {
    return badRequest('Unknown document type.');
  }

  // ── 4. Template administration is Manager or higher ───────────────────────
  if (table === 'templates' && !hasMinRole(staff, 'Manager')) {
    return forbidden();
  }

  if (recordId !== undefined && (typeof recordId !== 'string' || !recordId.startsWith('rec'))) {
    return badRequest('A valid document reference is required.');
  }

  // ── 5. Field allowlist — BEFORE any Airtable call ─────────────────────────
  const gate = enforceFields(`save-document[${table}]`, fields, FIELD_POLICY[table], staff.staffId);
  if (!gate.ok) return gate.response;

  // ── 6. Reject unsafe URL schemes ──────────────────────────────────────────
  const url = fields['File URL'];
  if (url !== undefined && url !== null && url !== '' && !isSafeHttpUrl(url)) {
    return badRequest('File URL must be a valid http or https link.');
  }

  const baseId = process.env.AIRTABLE_BASE_ID;
  const apiKey = process.env.AIRTABLE_API_KEY;
  if (!baseId || !apiKey) {
    console.error('[save-document] Missing Airtable environment configuration.');
    return serverError();
  }

  const tableId = TABLE_IDS[table];
  const target  = recordId
    ? `https://api.airtable.com/v0/${baseId}/${tableId}/${encodeURIComponent(recordId)}`
    : `https://api.airtable.com/v0/${baseId}/${tableId}`;
  const method  = recordId ? 'PATCH' : 'POST';

  try {
    const res = await fetch(target, {
      method,
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type':  'application/json',
      },
      body: JSON.stringify({ fields }),
    });

    const data = await res.json();
    if (!res.ok) {
      console.error('[save-document] Airtable error:', res.status, data && data.error && data.error.message);
      return upstreamError();
    }

    return jsonResponse(200, { success: true, record: data, ...data });
  } catch (e) {
    console.error('[save-document]', e.message);
    return serverError();
  }
};
