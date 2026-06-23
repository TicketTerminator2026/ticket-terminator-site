// Ticket Terminator — Create or update an Attorney record
// POST { fields }               → create
// PATCH { recordId, fields }    → update

const ATTORNEYS_TABLE = 'tbl7Yj3IYYJIpFOVt';

exports.handler = async function (event) {
  const isCreate = event.httpMethod === 'POST';
  const isUpdate = event.httpMethod === 'PATCH';
  if (!isCreate && !isUpdate) {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;

  let body;
  try { body = JSON.parse(event.body); } catch {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const fields   = body.fields || {};
  const recordId = body.recordId;

  if (isUpdate && !recordId) {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'recordId required for update' }) };
  }

  const clean = {};
  Object.entries(fields).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== '') clean[k] = v;
  });

  const url = isCreate
    ? `https://api.airtable.com/v0/${base}/${ATTORNEYS_TABLE}`
    : `https://api.airtable.com/v0/${base}/${ATTORNEYS_TABLE}/${recordId}`;

  try {
    const res = await fetch(url, {
      method: isCreate ? 'POST' : 'PATCH',
      headers: {
        'Authorization': `Bearer ${key}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ fields: clean }),
    });
    const data = await res.json();
    if (!res.ok) {
      return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: data.error?.message || JSON.stringify(data) }) };
    }
    return { statusCode: 200, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ success: true, record: data }) };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message }) };
  }
};
