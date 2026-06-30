// Ticket Terminator — List staff members (Admin only)
// GET → { records }
// POST { _setup: true, ... } → create first admin (see staff-auth.js)

const STAFF_TABLE = 'tblFGsQpsOJFF2r2V';

function decodeToken(token) {
  try { return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString()); } catch { return null; }
}

exports.handler = async function (event) {
  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;

  const tokenHeader = event.headers['x-staff-token'] || event.headers['X-Staff-Token'] || '';
  const staff = decodeToken(tokenHeader) || { role: '' };

  if (staff.role !== 'Admin') {
    return { statusCode: 403, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Admin only' }) };
  }

  if (event.httpMethod !== 'GET') return { statusCode: 405, body: 'Method Not Allowed' };

  try {
    const params = new URLSearchParams();
    params.set('sort[0][field]', 'Name');
    params.set('fields[]', 'Name');
    params.set('fields[]', 'Email');
    params.set('fields[]', 'Role');
    params.set('fields[]', 'Active');
    params.set('fields[]', 'Last Login');
    // Never return Password Hash to frontend

    const res  = await fetch(`https://api.airtable.com/v0/${base}/${STAFF_TABLE}?${params}`,
      { headers: { 'Authorization': `Bearer ${key}` } });
    const data = await res.json();
    if (!res.ok) {
      return { statusCode: 502, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: data.error?.message }) };
    }
    return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
      body: JSON.stringify({ records: data.records || [] }) };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message }) };
  }
};
