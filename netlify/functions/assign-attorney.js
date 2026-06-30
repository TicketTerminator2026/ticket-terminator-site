// Ticket Terminator — Assign attorney(s) to a case
// PATCH { caseId, attorneyIds: [id, ...], previousAttorneyName } → { success }

const { log } = require('./_log');

function decodeToken(token) {
  try { return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString()); } catch { return null; }
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'PATCH') return { statusCode: 405, body: 'Method Not Allowed' };

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

  const { caseId, attorneyIds = [], caseNum = '', previousAttorneyName = '', newAttorneyName = '' } = body;
  if (!caseId) {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'caseId required' }) };
  }

  // Attorney field in Cases is multipleRecordLinks — send array of {id} objects
  const linkedIds = attorneyIds.map(id => ({ id }));

  try {
    const res = await fetch(
      `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}/${caseId}`,
      {
        method: 'PATCH',
        headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { Attorney: linkedIds } }),
      }
    );
    const data = await res.json();
    if (!res.ok) {
      return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: data.error?.message || JSON.stringify(data) }) };
    }

    log(env, {
      staffName: staff.name, staffId: staff.staffId,
      action: newAttorneyName
        ? `Assigned attorney ${newAttorneyName}`
        : attorneyIds.length === 0 ? 'Removed attorney assignment' : 'Assigned attorney',
      category: 'Case', caseNum, caseId,
      field: 'Attorney', oldVal: previousAttorneyName, newVal: newAttorneyName,
    });

    return { statusCode: 200, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ success: true, record: data }) };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message }) };
  }
};
