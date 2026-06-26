// Ticket Terminator — Change Password
// POST { token, currentPassword, newPassword }
// Verifies the current password, hashes the new one, updates Airtable.

const crypto = require('crypto');
const STAFF_TABLE = 'tblFGsQpsOJFF2r2V';

const cors = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function verifyToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  const expected = sign(b64, secret);
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
  } catch { return null; }
  try {
    const payload = JSON.parse(Buffer.from(b64, 'base64url').toString());
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}

function makeHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + hashPassword(password, salt);
}

function checkPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const attempt = hashPassword(password, salt);
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex'));
  } catch { return false; }
}

exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: cors, body: 'Method Not Allowed' };

  const base   = process.env.AIRTABLE_BASE_ID;
  const key    = process.env.AIRTABLE_API_KEY;
  const secret = process.env.DASHBOARD_TOKEN_SECRET;

  if (!secret) return { statusCode: 500, headers: cors, body: JSON.stringify({ error: 'Server misconfiguration' }) };

  let body;
  try { body = JSON.parse(event.body || '{}'); } catch { body = {}; }

  const { token, currentPassword, newPassword } = body;

  if (!token || !currentPassword || !newPassword) {
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'token, currentPassword, and newPassword are required' }) };
  }

  if (newPassword.length < 8) {
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'New password must be at least 8 characters' }) };
  }

  const payload = verifyToken(token, secret);
  if (!payload) {
    return { statusCode: 401, headers: cors, body: JSON.stringify({ error: 'Invalid or expired session. Please log in again.' }) };
  }

  const lookup = await fetch(
    'https://api.airtable.com/v0/' + base + '/' + STAFF_TABLE + '/' + payload.staffId,
    { headers: { 'Authorization': 'Bearer ' + key } }
  );
  if (!lookup.ok) {
    return { statusCode: 404, headers: cors, body: JSON.stringify({ error: 'Staff record not found' }) };
  }
  const staffRecord = await lookup.json();
  const storedHash = staffRecord.fields && staffRecord.fields['Password Hash'] || '';

  if (!storedHash || !checkPassword(currentPassword, storedHash)) {
    await new Promise(r => setTimeout(r, 500));
    return { statusCode: 401, headers: cors, body: JSON.stringify({ error: 'Current password is incorrect' }) };
  }

  const newHash = makeHash(newPassword);
  const update = await fetch(
    'https://api.airtable.com/v0/' + base + '/' + STAFF_TABLE + '/' + payload.staffId,
    {
      method:  'PATCH',
      headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
      body:    JSON.stringify({ fields: { 'Password Hash': newHash } }),
    }
  );

  if (!update.ok) {
    const err = await update.json();
    return { statusCode: 500, headers: cors, body: JSON.stringify({ error: (err.error && err.error.message) || 'Failed to update password' }) };
  }

  return { statusCode: 200, headers: cors, body: JSON.stringify({ success: true }) };
};
