// Ticket Terminator — Fetch Tasks
// GET ?status=Open&caseId=...&staffId=...

const TASKS_TABLE = 'tblvwrl2hPjUjbUkC';
function decodeToken(t) { try { return JSON.parse(Buffer.from(t.split('.')[0], 'base64url').toString()); } catch { return null; } }

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') return { statusCode: 405, body: 'Method Not Allowed' };
  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;
  const staff = decodeToken(event.headers['x-staff-token'] || '') || { role: '', staffId: '' };
  if (!staff.role)
    return { statusCode: 401, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Authentication required' }) };
  const qs = event.queryStringParameters || {};
  const params = new URLSearchParams();
  params.set('pageSize', '100');
  params.set('sort[0][field]', 'Due Date');
  params.set('sort[0][direction]', 'asc');
  const filters = [];
  if (qs.status)  filters.push('{Status} = "' + qs.status + '"');
  if (qs.caseId)  filters.push('{Case Record ID} = "' + qs.caseId + '"');
  if (staff.role === 'Employee' && !qs.caseId)
    filters.push('{Assigned Staff ID} = "' + staff.staffId + '"');
  else if (qs.staffId)
    filters.push('{Assigned Staff ID} = "' + qs.staffId + '"');
  if (!qs.status) filters.push('NOT({Status} = "Cancelled")');
  if (filters.length) params.set('filterByFormula', 'AND(' + filters.join(',') + ')');
  try {
    const res  = await fetch('https://api.airtable.com/v0/' + base + '/' + TASKS_TABLE + '?' + params,
      { headers: { Authorization: 'Bearer ' + key } });
    const data = await res.json();
    if (!res.ok)
      return { statusCode: 502, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: data.error?.message }) };
    return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
      body: JSON.stringify({ records: data.records || [] }) };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: err.message }) };
  }
};
