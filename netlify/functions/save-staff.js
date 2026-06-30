// Ticket Terminator — Create or update a staff member (Admin only)
// POST { fields: { Name, Email, password, Role } } → create
// PATCH { recordId, fields: { Name, Role, Active, password? } } → update

const crypto = require('crypto');
const STAFF_TABLE = 'tblFGsQpsOJFF2r2V';

function decodeToken(token) {
  try { return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString()); } catch { return null; }
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}

function makeHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  return `${salt}:${hash}`;
}

exports.handler = async function (event) {
  const isCreate = event.httpMethod === 'POST';
  const isUpdate = event.httpMethod === 'PATCH';
  if (!isCreate && !isUpdate) return { statusCode: 405, body: 'Method Not Allowed' };

  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;

  const tokenHeader = event.headers['x-staff-token'] || event.headers['X-Staff-Token'] || '';
  const staff = decodeToken(tokenHeader) || { role: '' };

  if (staff.role !== 'Admin') {
    return { statusCode: 403, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Admin only' }) };
  }

  let body;
  try { body = JSON.parse(event.body); } catch {
    return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const { recordId } = body;
  const { password, ...rest } = body.fields || {};

  const fields = { ...rest };
  if (isCreate) {
    if (!password) return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Password required for new staff' }) };
    if (!fields.Email) return { statusCode: 400, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Email required' }) };
    fields['Password Hash'] = makeHash(password);
    fields.Active = true;
  } else if (password) {
    // Changing password
    fields['Password Hash'] = makeHash(password);
  }

  const url = isCreate
    ? `https://api.airtable.com/v0/${base}/${STAFF_TABLE}`
    : `https://api.airtable.com/v0/${base}/${STAFF_TABLE}/${recordId}`;

  try {
    const res = await fetch(url, {
      method: isCreate ? 'POST' : 'PATCH',
      headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields }),
    });
    const data = await res.json();
    if (!res.ok) {
      return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: data.error?.message || JSON.stringify(data) }) };
    }
    // Strip password hash from response
    if (data.fields) delete data.fields['Password Hash'];
    return { statusCode: 200, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ success: true, record: data }) };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message }) };
  }
};
