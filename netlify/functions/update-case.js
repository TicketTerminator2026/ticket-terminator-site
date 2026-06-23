// Ticket Terminator — Update a Case record in Airtable
// PATCH { recordId, fields } → { success, record }

exports.handler = async function (event) {
  if (event.httpMethod !== 'PATCH') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const base  = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_ID;
  const key   = process.env.AIRTABLE_API_KEY;

  let body;
  try { body = JSON.parse(event.body); } catch {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const { recordId, fields } = body;
  if (!recordId || !fields) {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'recordId and fields required' }) };
  }

  // Strip undefined/null/empty-string values so Airtable doesn't complain
  const clean = {};
  Object.entries(fields).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== '') clean[k] = v;
  });

  try {
    const res = await fetch(
      `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}/${recordId}`,
      {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${key}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ fields: clean }),
      }
    );
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
