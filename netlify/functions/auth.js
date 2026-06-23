// Ticket Terminator — Dashboard Authentication
// POST { password } → { token, expires } on success
// GET  ?token=...   → { valid: true/false }
// Token: HMAC-SHA256 signed payload, expires in 10 hours.
// Required env vars: DASHBOARD_PASSWORD, DASHBOARD_TOKEN_SECRET

const crypto = require('crypto');

const TOKEN_TTL_MS = 10 * 60 * 60 * 1000; // 10 hours

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function makeToken(secret) {
  const exp     = Date.now() + TOKEN_TTL_MS;
  const payload = Buffer.from(JSON.stringify({ exp })).toString('base64url');
  const sig     = sign(payload, secret);
  return `${payload}.${sig}`;
}

function verifyToken(token, secret) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [payload, sig] = parts;
  // Constant-time comparison to prevent timing attacks
  const expected = sign(payload, secret);
  if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return false;
  try {
    const { exp } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return Date.now() < exp;
  } catch {
    return false;
  }
}

exports.handler = async function (event) {
  const password = process.env.DASHBOARD_PASSWORD;
  const secret   = process.env.DASHBOARD_TOKEN_SECRET;

  const corsHeaders = {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: corsHeaders, body: '' };
  }

  if (!password || !secret) {
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Auth not configured. Set DASHBOARD_PASSWORD and DASHBOARD_TOKEN_SECRET in Netlify env vars.' }),
    };
  }

  // ── GET: verify a token ────────────────────────────────────────────────────
  if (event.httpMethod === 'GET') {
    const token = event.queryStringParameters?.token || '';
    const valid = verifyToken(token, secret);
    return {
      statusCode: valid ? 200 : 401,
      headers: corsHeaders,
      body: JSON.stringify({ valid }),
    };
  }

  // ── POST: exchange password for token ─────────────────────────────────────
  if (event.httpMethod === 'POST') {
    let body;
    try { body = JSON.parse(event.body || '{}'); } catch { body = {}; }

    const submitted = body.password || '';
    // Constant-time comparison
    const pwBuf = Buffer.from(password);
    const subBuf = Buffer.alloc(pwBuf.length);
    Buffer.from(submitted).copy(subBuf);
    const match = submitted.length === password.length &&
      crypto.timingSafeEqual(pwBuf, subBuf);

    if (!match) {
      // 500ms delay on wrong password to slow brute force
      await new Promise(r => setTimeout(r, 500));
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Incorrect password' }),
      };
    }

    const token   = makeToken(secret);
    const expires = new Date(Date.now() + TOKEN_TTL_MS).toISOString();
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify({ token, expires }),
    };
  }

  return { statusCode: 405, headers: corsHeaders, body: 'Method Not Allowed' };
};
