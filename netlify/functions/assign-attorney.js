// Ticket Terminator — Assign attorney(s) to a case
// PATCH { caseId, attorneyIds: [id], caseNum, previousAttorneyName } → { success, record, attorneyName }
//
// Phase 1 rules:
//   - Exactly 0 or 1 attorney IDs accepted (Phase 1: single-assignment only)
//   - Attorney must exist in Airtable and be Active
//   - When assigning: sets Attorney + Status = "Attorney Assigned"
//   - When removing: clears Attorney only — Status NOT automatically changed
//   - Activity Log written with server-resolved attorney name (never relies on caller)
//   - Returns full updated Airtable record in response

const { log } = require('./_log');

// Hardcoded to match get-attorneys.js — no separate env var used
const ATTORNEYS_TABLE = 'tbl7Yj3IYYJIpFOVt';

function decodeToken(token) {
  try { return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString()); } catch { return null; }
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'PATCH') return { statusCode: 405, body: 'Method Not Allowed' };

  const base  = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_ID;
  const key   = process.env.AIRTABLE_API_KEY;
  const env   = { base, key };

  // ── 1. Validate staff token ───────────────────────────────────────────────
  const tokenHeader = event.headers['x-staff-token'] || event.headers['X-Staff-Token'] || '';
  const staff = decodeToken(tokenHeader) || { name: 'Unknown', staffId: '' };
  if (staff.role === 'Read Only') {
    return { statusCode: 403, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Permission denied' }) };
  }

  // ── 2. Parse body ─────────────────────────────────────────────────────────
  let body;
  try { body = JSON.parse(event.body); } catch {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const { caseId, attorneyIds = [], caseNum = '', previousAttorneyName = '' } = body;

  // ── 3. Validate caseId ────────────────────────────────────────────────────
  if (!caseId) {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'caseId required' }) };
  }

  // ── 4. Validate attorneyIds — Phase 1: exactly 0 or 1 ───────────────────
  if (!Array.isArray(attorneyIds)) {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'attorneyIds must be an array' }) };
  }
  if (attorneyIds.length > 1) {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Only one attorney can be assigned in Phase 1.' }) };
  }

  const isAssigning = attorneyIds.length === 1;
  let resolvedAttorneyName = '';

  // ── 5–7. Fetch attorney, confirm it exists and is Active ─────────────────
  if (isAssigning) {
    const attyId = attorneyIds[0];
    let attyData;
    try {
      const attyRes = await fetch(
        `https://api.airtable.com/v0/${base}/${ATTORNEYS_TABLE}/${attyId}`,
        { headers: { Authorization: `Bearer ${key}` } }
      );
      attyData = await attyRes.json();
      if (!attyRes.ok) {
        return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: `Attorney not found: ${attyData.error?.message || attyId}` }) };
      }
    } catch (err) {
      return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: `Failed to fetch attorney: ${err.message}` }) };
    }

    if (attyData.fields?.Active !== true) {
      return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Cannot assign an inactive attorney.' }) };
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
      `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}/${caseId}`,
      {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: patchFields }),
      }
    );
    const data = await res.json();
    if (!res.ok) {
      return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: data.error?.message || JSON.stringify(data) }) };
    }

    // ── 9. Write Activity Log (awaited; errors non-fatal) ────────────────
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
    }).catch(logErr =>
      console.error('[assign-attorney] Activity Log write failed:', logErr.message)
    );

    // ── 10. Return updated record ─────────────────────────────────────────
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        success:      true,
        record:       data,
        attorneyName: resolvedAttorneyName,
      }),
    };

  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message }) };
  }
};
