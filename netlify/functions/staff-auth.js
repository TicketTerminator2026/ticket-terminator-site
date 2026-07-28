// Ticket Terminator — Staff Authentication
// POST { email, password }        → { token, staff: { name, email, role, staffId } }
// GET  X-Staff-Token: <token>     → { valid, staff: { name, email, role, staffId } }
//
// Passwords stored as PBKDF2-SHA256 hash+salt in Airtable Staff table.
// Token: base64url(JSON.stringify({exp, staffId, name, email, role})).HMAC-SHA256
//
// SESSION TOKENS ARE NEVER ACCEPTED IN A URL.
// The GET verification route reads the token from the X-Staff-Token request
// header only. A credential placed in a query string is recorded by the CDN
// access log, the browser's history, the Referer header and every intermediate
// proxy, so the previous `?token=` route has been removed outright — there is
// deliberately no compatibility fallback.
//
// CLIENT-FACING ERRORS ARE GENERIC.
// No response ever names an environment variable, configuration key, Airtable
// table ID or field, and no raw upstream payload or stack trace is echoed.
// Server-side logs record a short technical category only — never a secret, a
// password, a submitted credential, or a token value.

const crypto = require('crypto');
const STAFF_TABLE = 'tblFGsQpsOJFF2r2V';
const TOKEN_TTL_MS = 10 * 60 * 60 * 1000; // 10 hours

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function makeToken(payload, secret) {
  const b64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = sign(b64, secret);
  return `${b64}.${sig}`;
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
  const hash = hashPassword(password, salt);
  return `${salt}:${hash}`;
}

function checkPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const attempt = hashPassword(password, salt);
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex'));
  } catch { return false; }
}

const cors = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Staff-Token',
  'Content-Type': 'application/json',
};

// Generic client-facing messages. These are the ONLY strings this function
// returns in an `error` field — none of them reveal configuration detail.
const MSG = Object.freeze({
  UNAVAILABLE:  'Authentication service unavailable',
  CREDENTIALS:  'Invalid email or password',
  MISSING:      'Email and password required',
  INACTIVE:     'Account is inactive. Contact your admin.',
  FORBIDDEN:    'Forbidden',
  METHOD:       'Method Not Allowed',
});

const json = (statusCode, obj) => ({ statusCode, headers: cors, body: JSON.stringify(obj) });

// Case-insensitive header read — Netlify lower-cases, but local harnesses and
// some proxies do not.
function getHeader(event, name) {
  const headers = (event && event.headers) || {};
  const target  = String(name).toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === target) return headers[key];
  }
  return '';
}

// Reads the session token from the X-Staff-Token header ONLY.
// Query-string and path tokens are never consulted.
function extractToken(event) {
  const header = getHeader(event, 'x-staff-token');
  if (typeof header === 'string' && header.trim()) return header.trim();

  const auth = getHeader(event, 'authorization');
  if (typeof auth === 'string' && /^Bearer\s+/i.test(auth)) {
    return auth.replace(/^Bearer\s+/i, '').trim();
  }
  return '';
}

exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors, body: '' };

  const base   = process.env.AIRTABLE_BASE_ID;
  const key    = process.env.AIRTABLE_API_KEY;
  const secret = process.env.DASHBOARD_TOKEN_SECRET;

  if (!secret) {
    // Log a category, never the variable name or its value.
    console.error('[staff-auth] configuration incomplete: token signing');
    return json(500, { error: MSG.UNAVAILABLE });
  }

  // ── GET: verify token (header only — never a query parameter) ──────────────
  if (event.httpMethod === 'GET') {
    // A token supplied as ?token=... is ignored outright. There is no fallback:
    // the query string is not read, so such a request is treated as tokenless
    // and rejected exactly like a missing token.
    const token   = extractToken(event);
    const payload = verifyToken(token, secret);
    if (!payload) return json(401, { valid: false });
    return json(200, { valid: true, staff: {
      staffId: payload.staffId, name: payload.name, email: payload.email, role: payload.role
    }});
  }

  // ── POST: login ────────────────────────────────────────────────────────────
  if (event.httpMethod === 'POST') {
    let body;
    try { body = JSON.parse(event.body || '{}'); } catch { body = {}; }

    // Special bootstrap: if body has { _setup: true, email, name, password, adminKey }
    // Allows creating the FIRST Admin account only — refuses if any Admin already exists.
    if (body._setup) {
      // Generic 403 for every bootstrap refusal — the response must not reveal
      // that a setup key exists, nor whether an Admin account is already present.
      if (!process.env.ADMIN_SETUP_KEY || body.adminKey !== process.env.ADMIN_SETUP_KEY) {
        console.warn('[staff-auth] bootstrap refused: setup credential');
        return json(403, { error: MSG.FORBIDDEN });
      }
      if (!base || !key) {
        console.error('[staff-auth] configuration incomplete: datastore');
        return json(500, { error: MSG.UNAVAILABLE });
      }
      // Refuse if an Admin account already exists.
      let checkData;
      try {
        const checkParams = new URLSearchParams();
        checkParams.set('filterByFormula', `{Role} = "Admin"`);
        checkParams.set('maxRecords', '1');
        const checkRes = await fetch(`https://api.airtable.com/v0/${base}/${STAFF_TABLE}?${checkParams}`, {
          headers: { 'Authorization': `Bearer ${key}` },
        });
        if (!checkRes.ok) throw new Error('upstream');
        checkData = await checkRes.json();
      } catch {
        console.error('[staff-auth] bootstrap: datastore lookup failed');
        return json(500, { error: MSG.UNAVAILABLE });
      }
      if (checkData.records && checkData.records.length > 0) {
        console.warn('[staff-auth] bootstrap refused: already provisioned');
        return json(403, { error: MSG.FORBIDDEN });
      }
      if (!body.name || !body.email || !body.password) {
        return json(400, { error: MSG.MISSING });
      }
      const hash = makeHash(body.password);
      try {
        const res = await fetch(`https://api.airtable.com/v0/${base}/${STAFF_TABLE}`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: {
            Name: body.name, Email: body.email,
            'Password Hash': hash, Role: 'Admin', Active: true,
          }}),
        });
        if (!res.ok) throw new Error('upstream');
        const data = await res.json();
        return json(200, { success: true, staffId: data.id });
      } catch {
        // Never echo the upstream payload or a stack trace.
        console.error('[staff-auth] bootstrap: datastore write failed');
        return json(500, { error: MSG.UNAVAILABLE });
      }
    }

    const { email, password } = body;
    if (!email || !password) {
      return json(400, { error: MSG.MISSING });
    }

    if (!base || !key) {
      console.error('[staff-auth] configuration incomplete: datastore');
      return json(500, { error: MSG.UNAVAILABLE });
    }

    // Lookup staff by email. Never log the submitted address or password.
    let staffRecord;
    try {
      const params = new URLSearchParams();
      params.set('filterByFormula', `LOWER({Email}) = "${email.toLowerCase().replace(/"/g, '')}"`);
      params.set('maxRecords', '1');
      const lookup = await fetch(`https://api.airtable.com/v0/${base}/${STAFF_TABLE}?${params}`, {
        headers: { 'Authorization': `Bearer ${key}` },
      });
      if (!lookup.ok) throw new Error('upstream');
      const staffData = await lookup.json();
      staffRecord = staffData.records?.[0];
    } catch {
      console.error('[staff-auth] login: datastore lookup failed');
      return json(500, { error: MSG.UNAVAILABLE });
    }

    if (!staffRecord) {
      await new Promise(r => setTimeout(r, 500));
      return json(401, { error: MSG.CREDENTIALS });
    }

    const sf = staffRecord.fields;
    if (!sf.Active) {
      return json(403, { error: MSG.INACTIVE });
    }

    const storedHash = sf['Password Hash'] || '';
    if (!storedHash || !checkPassword(password, storedHash)) {
      await new Promise(r => setTimeout(r, 500));
      return json(401, { error: MSG.CREDENTIALS });
    }

    // Update last login. A failure here must not block a valid sign-in, and
    // must not surface upstream detail to the caller.
    try {
      await fetch(`https://api.airtable.com/v0/${base}/${STAFF_TABLE}/${staffRecord.id}`, {
        method: 'PATCH',
        headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { 'Last Login': new Date().toISOString() } }),
      });
    } catch {
      console.warn('[staff-auth] login: last-login update failed');
    }

    const tokenPayload = {
      staffId: staffRecord.id,
      name:    sf.Name,
      email:   sf.Email,
      role:    sf.Role,
      exp:     Date.now() + TOKEN_TTL_MS,
    };
    const token = makeToken(tokenPayload, secret);
    // The token is returned in the response BODY only — never in a redirect,
    // a Location header, or any URL.
    return json(200, {
      token,
      staff: { staffId: staffRecord.id, name: sf.Name, email: sf.Email, role: sf.Role },
    });
  }

  return json(405, { error: MSG.METHOD });
};

// Export hash utility for setup scripts
exports.makeHash = makeHash;
