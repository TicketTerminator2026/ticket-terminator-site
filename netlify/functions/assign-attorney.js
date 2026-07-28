// Ticket Terminator — Assign attorney(s) to a case
// PATCH { caseId, attorneyIds: [id], caseNum, previousAttorneyName } → { success, record, attorneyName }
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token.
// AUTHORIZATION (Phase 0): Employee, Manager and Admin may assign; Read Only is
// blocked.
//
// Phase 1 rules (unchanged):
//   - Exactly 0 or 1 attorney IDs accepted (single-assignment only)
//   - Attorney must exist in Airtable and be Active
//   - When assigning: sets Attorney + Status = "Attorney Assigned"
//   - When removing: clears Attorney only — Status NOT automatically changed
//   - Activity Log written with server-resolved attorney name (never relies on caller)

'use strict';

const { log } = require('./_log');
const {
  requireAuth, canWrite, parseJsonBody,
  jsonResponse, forbidden, badRequest, serverError, upstreamError, methodNotAllowed,
} = require('./_verify-token');

// Hardcoded to match get-attorneys.js — no separate env var used
const ATTORNEYS_TABLE = 'tbl7Yj3IYYJIpFOVt';

exports.handler = async function (event) {
  if (event.httpMethod !== 'PATCH') return methodNotAllowed();

  // ── 1. Authenticate (HMAC-verified) ───────────────────────────────────────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;
  const staff = auth.staff;

  if (!canWrite(staff)) return forbidden();

  const base  = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_ID;
  const key   = process.env.AIRTABLE_API_KEY;
  const env   = { base, key };

  if (!base || !table || !key) {
    console.error('[assign-attorney] Missing Airtable environment configuration.');
    return serverError();
  }

  // ── 2. Parse body ─────────────────────────────────────────────────────────
  const parsed = parseJsonBody(event);
  if (!parsed.ok) return parsed.response;

  const { caseId, attorneyIds = [], caseNum = '', previousAttorneyName = '' } = parsed.body;

  // ── 3. Validate caseId ────────────────────────────────────────────────────
  if (typeof caseId !== 'string' || !caseId.startsWith('rec')) {
    return badRequest('A valid case reference is required.');
  }

  // ── 4. Validate attorneyIds — exactly 0 or 1 ─────────────────────────────
  if (!Array.isArray(attorneyIds)) {
    return badRequest('attorneyIds must be an array.');
  }
  if (attorneyIds.length > 1) {
    return badRequest('Only one attorney can be assigned in Phase 1.');
  }
  if (attorneyIds.length === 1 &&
      (typeof attorneyIds[0] !== 'string' || !attorneyIds[0].startsWith('rec'))) {
    return badRequest('A valid attorney reference is required.');
  }

  const isAssigning = attorneyIds.length === 1;
  let resolvedAttorneyName = '';

  // ── 5–7. Fetch attorney, confirm it exists and is Active ─────────────────
  if (isAssigning) {
    const attyId = attorneyIds[0];
    let attyData;
    try {
      const attyRes = await fetch(
        `https://api.airtable.com/v0/${base}/${ATTORNEYS_TABLE}/${encodeURIComponent(attyId)}`,
        { headers: { Authorization: `Bearer ${key}` } }
      );
      attyData = await attyRes.json();
      if (!attyRes.ok) {
        console.error('[assign-attorney] Attorney lookup failed:', attyRes.status);
        return badRequest('Attorney not found.');
      }
    } catch (err) {
      console.error('[assign-attorney] Attorney lookup error:', err.message);
      return serverError();
    }

    if (attyData.fields?.Active !== true) {
      return badRequest('Cannot assign an inactive attorney.');
    }

    // Resolve name server-side so Activity Log is always accurate
    resolvedAttorneyName = attyData.fields?.['Attorney Name'] || attyId;
  }

  // ── 8. Build PATCH payload ────────────────────────────────────────────────
  const linkedIds   = isAssigning ? [attorneyIds[0]] : [];
  const patchFields = { Attorney: linkedIds };

  // Only set Status when assigning — never roll it back on removal
  if (isAssigning) {
    patchFields['Status'] = 'Attorney Assigned';
  }

  try {
    const res = await fetch(
      `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}/${encodeURIComponent(caseId)}`,
      {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: patchFields }),
      }
    );
    const data = await res.json();
    if (!res.ok) {
      console.error('[assign-attorney] Airtable error:', res.status, data && data.error && data.error.message);
      return upstreamError();
    }

    // ── 9. Write Activity Log (awaited; identity from verified token) ─────
    await log(env, {
      staffName: staff.name,
      staffId:   staff.staffId,
      action:    isAssigning
        ? `Assigned attorney ${resolvedAttorneyName}`
        : 'Removed attorney assignment',
      category:  'Case',
      caseNum,
      caseId,
      field:     'Attorney',
      oldVal:    previousAttorneyName,
      newVal:    resolvedAttorneyName,
    });

    // ── 10. Return updated record ─────────────────────────────────────────
    return jsonResponse(200, {
      success:      true,
      record:       data,
      attorneyName: resolvedAttorneyName,
    });

  } catch (err) {
    console.error('[assign-attorney] error:', err.message);
    return serverError();
  }
};
