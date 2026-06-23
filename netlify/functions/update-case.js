// Ticket Terminator — Update a Case record
// PATCH { recordId, fields, previousFields } — requires X-Staff-Token

const { log } = require('./_log');
function decodeToken(t) { try { return JSON.parse(Buffer.from(t.split('.')[0], 'base64url').toString()); } catch { return null; } }

exports.handler = async function (event) {
  if (event.httpMethod !== 'PATCH') return { statusCode: 405, body: 'Method Not Allowed' };
  const base  = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_ID;
  const key   = process.env.AIRTABLE_API_KEY;
  const env   = { base, key };
  const staff = decodeToken(event.headers['x-staff-token'] || '') || { name: 'Unknown', staffId: '', role: '' };
  if (staff.role === 'Read Only')
    return { statusCode: 403, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Permission denied' }) };
  let body;
  try { body = JSON.parse(event.body); } catch {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }
  const { recordId, fields, previousFields = {} } = body;
  if (!recordId || !fields)
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'recordId and fields required' }) };
  const clean = {};
  Object.entries(fields).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== '') clean[k] = v;
    if (v === false || v === 0) clean[k] = v;
  });
  try {
    const res = await fetch('https://api.airtable.com/v0/' + base + '/' + encodeURIComponent(table) + '/' + recordId, {
      method: 'PATCH',
      headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields: clean }),
    });
    const data = await res.json();
    if (!res.ok)
      return { statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: data.error?.message || JSON.stringify(data) }) };
    const caseNum = previousFields['Case #'] || fields['Case #'] || recordId;
    for (const [field, newVal] of Object.entries(clean)) {
      const oldVal = previousFields[field];
      if (oldVal !== newVal) {
        log(env, {
          staffName: staff.name, staffId: staff.staffId,
          action: 'Updated ' + field,
          category: (field.includes('Payment') || field.includes('Fee')) ? 'Payment' : 'Case',
          caseNum, caseId: recordId, field, oldVal, newVal,
        });
      }
    }
    return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ success: true, record: data }) };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: err.message }) };
  }
};
