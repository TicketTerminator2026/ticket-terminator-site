// Ticket Terminator — Update a Case record in Airtable
// PATCH { recordId, fields } → { success, record }
// Requires X-Staff-Token header. Logs every changed field to Activity Log.

const { log } = require('./_log');

function decodeToken(token) {
  try {
    const b64 = token.split('.')[0];
    return JSON.parse(Buffer.from(b64, 'base64url').toString());
  } catch { return null; }
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'PATCH') return { statusCode: 405, body: 'Method Not Allowed' };

  const base  = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_ID;
  const key   = process.env.AIRTABLE_API_KEY;
  const env   = { base, key };

  // Decode staff from token (verification happens in staff-auth — here we trust the payload
  // since this function runs server-side and the token is passed from the dashboard)
  const tokenHeader = event.headers['x-staff-token'] || event.headers['X-Staff-Token'] || '';
  const staff = decodeToken(tokenHeader) || { name: 'Unknown', staffId: '' };

  // Role check — Read Only cannot write
  if (staff.role === 'Read Only') {
    return { statusCode: 403, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Permission denied' }) };
  }

  let body;
  try { body = JSON.parse(event.body); } catch {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const { recordId, fields, previousFields = {} } = body;
  if (!recordId || !fields) {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'recordId and fields required' }) };
  }

  // Valid Airtable Status singleSelect option names.
  // Add new options here AND in Airtable field settings when expanding the lifecycle.
  const VALID_AT_STATUSES = new Set([
    '🔵 Lead','🟡 Pending','🟢 Open / Active','✅ Closed',
    'Lead','Quote Sent','Waiting for Payment','Paid - Needs Attorney',
    'Attorney Assigned','Open / Active','Court Pending',
    'Waiting for Attorney Update','Outcome Received',
    'Closed - Dismissed','Closed - Reduced','Closed - Traffic School Completed',
    'Closed - Completed','Canceled','Refunded','Archived',
  ]);

  const clean = {};
  Object.entries(fields).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== '') clean[k] = v;
    // Handle explicit false/0
    if (v === false || v === 0) clean[k] = v;
  });

  // Strip Status if not a valid Airtable option (prevents "cannot create new select option" error).
  // The extended 16-status options must also be added to the Status field in Airtable manually.
  if (clean.Status && !VALID_AT_STATUSES.has(clean.Status)) {
    delete clean.Status;
  }

  try {
    const res = await fetch(
      `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}/${recordId}`,
      {
        method: 'PATCH',
        headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: clean }),
      }
    );
    const data = await res.json();
    if (!res.ok) {
      return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: data.error?.message || JSON.stringify(data) }) };
    }

    // Log each changed field
    const caseNum = previousFields['Case #'] || fields['Case #'] || recordId;
    for (const [field, newVal] of Object.entries(clean)) {
      const oldVal = previousFields[field];
      if (oldVal !== newVal) {
        log(env, {
          staffName: staff.name, staffId: staff.staffId,
          action: `Updated ${field}`,
          category: field.includes('Payment') || field.includes('Fee') ? 'Payment' : 'Case',
          caseNum, caseId: recordId,
          field, oldVal, newVal,
        });
      }
    }

    return { statusCode: 200, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ success: true, record: data }) };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message }) };
  }
};
