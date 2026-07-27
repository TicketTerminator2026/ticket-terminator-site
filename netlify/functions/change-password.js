// Ticket Terminator — Change Password
// POST { currentPassword, newPassword } with X-Staff-Token header
//      (legacy: { token, currentPassword, newPassword } in the body)
//
// Verifies the current password, hashes the new one, updates Airtable.
// Token verification now uses the shared HMAC verifier, which also requires
// staff identity fields — legacy identity-less tokens are rejected.

'use strict';

const crypto = require('crypto');
const {
  verifyToken, extractToken, jsonResponse, badRequest, serverError, unauthorized,
} = require('./_verify-token');

const STAFF_TABLE = 'tblFGsQpsOJFF2r2V';
const MIN_PASSWORD_LENGTH = 8;

const cors = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Staff-Token',
  'Content-Type': 'application/json',
  'Cache-Control': 'no-store',
};

const corsJson = (statusCode, payload) => ({
  statusCode, headers: cors, body: JSON.stringify(payload),
});

// ── Password helpers (mirrors staff-auth.js) ──────────────────────────────────
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}

function makeHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${hashPassword(password, salt)}`;
}

function checkPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const attempt = hashPassword(password, salt);
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex'));
  } catch { return false; }
}

// ── Handler ───────────────────────────────────────────────────────────────────
exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors, body: '' };
  if (event.httpMethod !== 'POST') return corsJson(405, { error: 'Method Not Allowed' });

  const base   = process.env.AIRTABLE_BASE_ID;
  const key    = process.env.AIRTABLE_API_KEY;
  const secret = process.env.DASHBOARD_TOKEN_SECRET;

  // Fail closed if the signing secret is not configured.
  if (!secret) {
    console.error('[change-password] DASHBOARD_TOKEN_SECRET is not configured.');
    return corsJson(500, { error: 'Server error. Please try again.' });
  }
  if (!base || !key) {
    console.error('[change-password] Missing Airtable environment configuration.');
    return corsJson(500, { error: 'Server error. Please try again.' });
  }

  let body;
  try { body = JSON.parse(event.body || '{}'); } catch { body = {}; }
  if (!body || typeof body !== 'object' || Array.isArray(body)) body = {};

  const { currentPassword, newPassword } = body;

  // Header is preferred; body token retained for backwards compatibility.
  const token = extractToken(event) || body.token || '';

  // Authentication is evaluated before request-shape validation.
  if (!token) return corsJson(401, { error: 'Authentication required.' });

  if (!currentPassword || !newPassword) {
    return corsJson(400, { error: 'Current and new password are required.' });
  }

  if (typeof newPassword !== 'string' || newPassword.length < MIN_PASSWORD_LENGTH) {
    return corsJson(400, { error: `New password must be at least ${MIN_PASSWORD_LENGTH} characters` });
  }

  // 1. Verify the session token (HMAC + expiry + identity fields)
  const payload = verifyToken(token, secret);
  if (!payload) {
    return corsJson(401, { error: 'Invalid or expired session. Please log in again.' });
  }

  try {
    // 2. Fetch the staff record from Airtable
    const lookup = await fetch(
      `https://api.airtable.com/v0/${base}/${STAFF_TABLE}/${encodeURIComponent(payload.staffId)}`,
      { headers: { 'Authorization': `Bearer ${key}` } }
    );
    if (!lookup.ok) {
      console.error('[change-password] Staff lookup failed:', lookup.status);
      return corsJson(404, { error: 'Staff record not found' });
    }
    const staffRecord = await lookup.json();
    const storedHash = staffRecord.fields?.['Password Hash'] || '';

    // 3. Verify the current password
    if (!storedHash || !checkPassword(currentPassword, storedHash)) {
      await new Promise(r => setTimeout(r, 500)); // brute-force delay
      return corsJson(401, { error: 'Current password is incorrect' });
    }

    // 4. Hash the new password and update Airtable
    const newHash = makeHash(newPassword);
    const update = await fetch(
      `https://api.airtable.com/v0/${base}/${STAFF_TABLE}/${encodeURIComponent(payload.staffId)}`,
      {
        method:  'PATCH',
        headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
        body:    JSON.stringify({ fields: { 'Password Hash': newHash } }),
      }
    );

    if (!update.ok) {
      console.error('[change-password] Airtable update failed:', update.status);
      return corsJson(500, { error: 'Failed to update password' });
    }

    return corsJson(200, { success: true });
  } catch (err) {
    console.error('[change-password] error:', err.message);
    return corsJson(500, { error: 'Server error. Please try again.' });
  }
};
