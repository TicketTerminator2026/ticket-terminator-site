// Ticket Terminator — Staff Authentication
// POST { email, password } → { token, staff: { name, email, role, staffId } }
// GET  ?token=...          → { valid, staff: { name, email, role, staffId } }

const crypto = require('crypto');
const STAFF_TABLE = 'tblFGsQpsOJFF2r2V';
const TOKEN_TTL_MS = 10 * 60 * 60 * 1000;

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}
function makeToken(payload, secret) {
  const b64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = sign(b64, secret);
  return b64 + '.' + sig;
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
  try { return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex')); }
  catch { return false; }
}

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors, body: '' };
  const base   = process.env.AIRTABLE_BASE_ID;
  const key    = process.env.AIRTABLE_API_KEY;
  const secret = process.env.DASHBOARD_TOKEN_SECRET;
  if (!secret) return { statusCode: 500, headers: cors, body: JSON.stringify({ error: 'DASHBOARD_TOKEN_SECRET not set' }) };

  if (event.httpMethod === 'GET') {
    const token = event.queryStringParameters?.token || '';
    const payload = verifyToken(token, secret);
    if (!payload) return { statusCode: 401, headers: cors, body: JSON.stringify({ valid: false }) };
    return { statusCode: 200, headers: cors, body: JSON.stringify({ valid: true, staff: {
      staffId: payload.staffId, name: payload.name, email: payload.email, role: payload.role
    }}) };
  }

  if (event.httpMethod === 'POST') {
    let body;
    try { body = JSON.parse(event.body || '{}'); } catch { body = {}; }

    if (body._setup) {
      if (body.adminKey !== process.env.ADMIN_SETUP_KEY)
        return { statusCode: 403, headers: cors, body: JSON.stringify({ error: 'Invalid admin key' }) };
      const hash = makeHash(body.password);
      const res = await fetch('https://api.airtable.com/v0/' + base + '/' + STAFF_TABLE, {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { Name: body.name, Email: body.email, 'Password Hash': hash, Role: body.role || 'Admin', Active: true } }),
      });
      const data = await res.json();
      if (!res.ok) return { statusCode: 500, headers: cors, body: JSON.stringify({ error: data.error?.message }) };
      return { statusCode: 200, headers: cors, body: JSON.stringify({ success: true, staffId: data.id }) };
    }

    const { email, password } = body;
    if (!email || !password)
      return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'Email and password required' }) };

    const params = new URLSearchParams();
    params.set('filterByFormula', 'LOWER({Email}) = "' + email.toLowerCase().replace(/"/g, '') + '"');
    params.set('maxRecords', '1');
    const lookup = await fetch('https://api.airtable.com/v0/' + base + '/' + STAFF_TABLE + '?' + params,
      { headers: { Authorization: 'Bearer ' + key } });
    const staffData = await lookup.json();
    const staffRecord = staffData.records?.[0];

    if (!staffRecord) {
      await new Promise(r => setTimeout(r, 500));
      return { statusCode: 401, headers: cors, body: JSON.stringify({ error: 'Invalid email or password' }) };
    }
    const sf = staffRecord.fields;
    if (!sf.Active)
      return { statusCode: 403, headers: cors, body: JSON.stringify({ error: 'Account is inactive. Contact your admin.' }) };

    const storedHash = sf['Password Hash'] || '';
    if (!storedHash || !checkPassword(password, storedHash)) {
      await new Promise(r => setTimeout(r, 500));
      return { statusCode: 401, headers: cors, body: JSON.stringify({ error: 'Invalid email or password' }) };
    }

    await fetch('https://api.airtable.com/v0/' + base + '/' + STAFF_TABLE + '/' + staffRecord.id, {
      method: 'PATCH',
      headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields: { 'Last Login': new Date().toISOString() } }),
    });

    const tokenPayload = { staffId: staffRecord.id, name: sf.Name, email: sf.Email, role: sf.Role, exp: Date.now() + TOKEN_TTL_MS };
    const token = makeToken(tokenPayload, secret);
    return { statusCode: 200, headers: cors, body: JSON.stringify({
      token, staff: { staffId: staffRecord.id, name: sf.Name, email: sf.Email, role: sf.Role },
    }) };
  }

  return { statusCode: 405, headers: cors, body: 'Method Not Allowed' };
};
exports.makeHash = makeHash;
