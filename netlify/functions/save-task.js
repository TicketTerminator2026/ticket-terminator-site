// Ticket Terminator — Create or update a Task
// POST { fields } | PATCH { recordId, fields }

const { log } = require('./_log');
const TASKS_TABLE = 'tblvwrl2hPjUjbUkC';
function decodeToken(t) { try { return JSON.parse(Buffer.from(t.split('.')[0], 'base64url').toString()); } catch { return null; } }

exports.handler = async function (event) {
  const isCreate = event.httpMethod === 'POST';
  const isUpdate = event.httpMethod === 'PATCH';
  if (!isCreate && !isUpdate) return { statusCode: 405, body: 'Method Not Allowed' };
  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;
  const env  = { base, key };
  const staff = decodeToken(event.headers['x-staff-token'] || '') || { name: 'Unknown', staffId: '', role: '' };
  if (staff.role === 'Read Only')
    return { statusCode: 403, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Permission denied' }) };
  let body;
  try { body = JSON.parse(event.body); } catch {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }
  const { recordId } = body;
  const fields = { ...(body.fields || {}) };
  if (isCreate) {
    fields['Created By']   = staff.name;
    fields['Created Date'] = new Date().toISOString();
    if (!fields['Status']) fields['Status'] = 'Open';
  }
  if (fields['Status'] === 'Done' && !fields['Completed Date'])
    fields['Completed Date'] = new Date().toISOString();
  const clean = {};
  Object.entries(fields).forEach(([k, v]) => { if (v !== null && v !== undefined && v !== '') clean[k] = v; });
  const url = isCreate
    ? 'https://api.airtable.com/v0/' + base + '/' + TASKS_TABLE
    : 'https://api.airtable.com/v0/' + base + '/' + TASKS_TABLE + '/' + recordId;
  try {
    const res = await fetch(url, {
      method: isCreate ? 'POST' : 'PATCH',
      headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields: clean }),
    });
    const data = await res.json();
    if (!res.ok)
      return { statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: data.error?.message }) };
    log(env, {
      staffName: staff.name, staffId: staff.staffId,
      action: isCreate ? 'Created task: ' + (clean['Task'] || '') : 'Updated task: ' + (clean['Task'] || recordId),
      category: 'Task', caseNum: clean['Case #'], caseId: clean['Case Record ID'],
      field: isCreate ? 'Task Created' : 'Task Updated', oldVal: '', newVal: clean['Status'] || '',
    });
    return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ success: true, record: data }) };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: err.message }) };
  }
};
