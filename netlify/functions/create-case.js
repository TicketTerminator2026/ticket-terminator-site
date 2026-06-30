// Ticket Terminator — Create a Case manually
// POST { fields } → { success, caseNum, recordId }

const { log } = require('./_log');

function decodeToken(token) {
  try { return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString()); } catch { return null; }
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };

  const base  = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_ID;
  const key   = process.env.AIRTABLE_API_KEY;
  const env   = { base, key };

  const tokenHeader = event.headers['x-staff-token'] || event.headers['X-Staff-Token'] || '';
  const staff = decodeToken(tokenHeader) || { name: 'Unknown', staffId: '' };

  if (staff.role === 'Read Only') {
    return { statusCode: 403, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Permission denied' }) };
  }

  let body;
  try { body = JSON.parse(event.body); } catch {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const year    = new Date().getFullYear();
  const seq     = Date.now().toString().slice(-5);
  const caseNum = body.fields?.['Case #'] || `TT-${year}-${seq}`;

  const fields = {
    'Case #':         caseNum,
    'Status':         '🔵 Lead',
    'Quote Status':   'Not Requested',
    'Date Submitted': new Date().toISOString().split('T')[0],
    ...body.fields,
  };
  fields['Case #'] = caseNum;

  const clean = {};
  Object.entries(fields).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== '') clean[k] = v;
  });

  try {
    const res = await fetch(
      `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}`,
      {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: clean }),
      }
    );
    const data = await res.json();
    if (!res.ok) {
      return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: data.error?.message || JSON.stringify(data) }) };
    }

    const clientName = [clean['First Name'], clean['Last Name']].filter(Boolean).join(' ');
    log(env, {
      staffName: staff.name, staffId: staff.staffId,
      action: `Created case${clientName ? ' for ' + clientName : ''}`,
      category: 'Case', caseNum, caseId: data.id,
      field: 'Case Created', oldVal: '', newVal: caseNum,
    });

    return { statusCode: 200, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ success: true, caseNum, recordId: data.id, record: data }) };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message }) };
  }
};
