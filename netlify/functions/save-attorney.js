// Ticket Terminator — Create or update an Attorney (Manager/Admin only)
// POST { fields } | PATCH { recordId, fields }

const { log } = require('./_log');
const ATTORNEYS_TABLE = 'tbl7Yj3IYYJIpFOVt';
function decodeToken(t) { try { return JSON.parse(Buffer.from(t.split('.')[0], 'base64url').toString()); } catch { return null; } }

exports.handler = async function (event) {
  const isCreate = event.httpMethod === 'POST';
  const isUpdate = event.httpMethod === 'PATCH';
  if (!isCreate && !isUpdate) return { statusCode: 405, body: 'Method Not Allowed' };
  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;
  const env  = { base, key };
  const staff = decodeToken(event.headers['x-staff-token'] || '') || { name: 'Unknown', staffId: '', role: '' };
  if (staff.role === 'Read Only' || staff.role === 'Employee')
    return { statusCode: 403, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Manager or Admin required' }) };
  let body;
  try { body = JSON.parse(event.body); } catch {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }
  const fields   = body.fields || {};
  const recordId = body.recordId;
  if (isUpdate && !recordId)
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'recordId required for update' }) };
  const clean = {};
  Object.entries(fields).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== '') clean[k] = v;
    if (v === false) clean[k] = v;
  });
  const url = isCreate
    ? 'https://api.airtable.com/v0/' + base + '/' + ATTORNEYS_TABLE
    : 'https://api.airtable.com/v0/' + base + '/' + ATTORNEYS_TABLE + '/' + recordId;
  try {
    const res = await fetch(url, {
      method: isCreate ? 'POST' : 'PATCH',
      headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields: clean }),
    });
    const data = await res.json();
    if (!res.ok)
      return { statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: data.error?.message || JSON.stringify(data) }) };
    const attyName = clean['Attorney Name'] || recordId;
    log(env, {
      staffName: staff.name, staffId: staff.staffId,
      action: isCreate ? 'Added attorney ' + attyName : 'Updated attorney ' + attyName,
      category: 'Attorney', field: isCreate ? 'Attorney Created' : 'Attorney Updated',
      oldVal: '', newVal: attyName,
    });
    return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ success: true, record: data }) };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: err.message }) };
  }
};
