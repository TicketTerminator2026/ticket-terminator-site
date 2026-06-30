// Ticket Terminator — Fetch Activity Log
// GET ?limit=50&offset=0&category=Case&staffId=...&caseId=...

const ACTIVITY_TABLE = 'tblHAOnm8Qu1d7iKT';

function decodeToken(token) {
  try { return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString()); } catch { return null; }
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') return { statusCode: 405, body: 'Method Not Allowed' };

  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;

  const tokenHeader = event.headers['x-staff-token'] || event.headers['X-Staff-Token'] || '';
  const staff = decodeToken(tokenHeader) || { role: '' };

  // Only Admin and Manager can see full activity log
  if (!['Admin', 'Manager'].includes(staff.role)) {
    return { statusCode: 403, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Permission denied — Manager or Admin required' }) };
  }

  const qs = event.queryStringParameters || {};
  const pageSize = Math.min(parseInt(qs.limit || '100'), 100);

  const params = new URLSearchParams();
  params.set('pageSize', String(pageSize));
  params.set('sort[0][field]', 'Timestamp');
  params.set('sort[0][direction]', 'desc');

  const filters = [];
  if (qs.category) filters.push(`{Category} = "${qs.category}"`);
  if (qs.staffId) filters.push(`{Staff Record ID} = "${qs.staffId}"`);
  if (qs.caseId)  filters.push(`{Case Record ID} = "${qs.caseId}"`);
  if (qs.caseNum) filters.push(`{Case #} = "${qs.caseNum}"`);
  if (filters.length) params.set('filterByFormula', `AND(${filters.join(',')})`);
  if (qs.offset)  params.set('offset', qs.offset);

  try {
    const res  = await fetch(`https://api.airtable.com/v0/${base}/${ACTIVITY_TABLE}?${params}`,
      { headers: { 'Authorization': `Bearer ${key}` } });
    const data = await res.json();
    if (!res.ok) {
      return { statusCode: 502, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: data.error?.message }) };
    }
    return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
      body: JSON.stringify({ records: data.records || [], offset: data.offset }) };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message }) };
  }
};
