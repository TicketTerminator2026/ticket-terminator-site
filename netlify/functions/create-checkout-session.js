// Ticket Terminator — Create Stripe Checkout Session
// POST { recordId, amount? } → { checkoutUrl, sessionId }
//
// Called from the dashboard "Send Payment Link" button on a Lead.
// Creates a per-case Stripe Checkout Session with full metadata so the
// stripe-webhook.js can look up the exact Airtable record via airtable_record_id.
//
// Required Netlify env vars:
//   STRIPE_SECRET_KEY       — sk_live_... or sk_test_...
//   AIRTABLE_BASE_ID        — app7IaHcv4nClafca
//   AIRTABLE_TABLE_ID       — tbledZDHFKbsBiwMf (Cases table)
//   AIRTABLE_API_KEY        — Airtable personal access token
//   DASHBOARD_TOKEN_SECRET  — for staff auth verification
//
// Auth: X-Staff-Token header (HMAC-SHA256 token from staff-auth.js)

'use strict';

const crypto = require('crypto');

const CASES_TABLE = process.env.AIRTABLE_TABLE_ID || 'tbledZDHFKbsBiwMf';
const SITE_URL    = 'https://ticket-terminator-intake.netlify.app';

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Staff-Token',
  'Content-Type': 'application/json',
};

// ─────────────────────────────────────────────────────────────────────────────
//  Staff token verification (mirrors staff-auth.js verifyToken)
// ─────────────────────────────────────────────────────────────────────────────
function verifyToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  const expected   = crypto.createHmac('sha256', secret).update(b64).digest('hex');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
  } catch { return null; }
  try {
    const payload = JSON.parse(Buffer.from(b64, 'base64url').toString());
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stripe API call (no SDK — direct HTTPS, form-encoded per Stripe spec)
// ─────────────────────────────────────────────────────────────────────────────
async function createStripeSession({ stripeKey, amountCents, caseFields, recordId }) {
  const fd = caseFields;

  const clientName  = `${fd['First Name'] || ''} ${fd['Last Name'] || ''}`.trim() || 'Client';
  const caseNum     = fd['Case #']               || '';
  const citationNum = fd['Citation / Arrest #']  || '';
  const caseType    = fd['Case Type']?.name || fd['Case Type'] || 'Traffic Citation';
  const clientEmail = fd['Email']                || '';
  const clientPhone = fd['Phone']                || '';

  // Build form-encoded body per Stripe Checkout Session API
  // https://stripe.com/docs/api/checkout/sessions/create
  const params = new URLSearchParams();

  params.set('mode', 'payment');

  // Line item
  params.set('line_items[0][quantity]', '1');
  params.set('line_items[0][price_data][currency]', 'usd');
  params.set('line_items[0][price_data][unit_amount]', String(amountCents));
  params.set('line_items[0][price_data][product_data][name]', 'Ticket Terminator Legal Services');
  params.set(
    'line_items[0][price_data][product_data][description]',
    `Case ${caseNum} — ${caseType}${citationNum ? ` (Citation: ${citationNum})` : ''}`
  );

  // Pre-fill customer email
  if (clientEmail) {
    params.set('customer_email', clientEmail);
  }

  // Metadata — airtable_record_id is the primary webhook lookup key
  params.set('metadata[airtable_record_id]', recordId);
  params.set('metadata[tt_case_number]',     caseNum);
  params.set('metadata[citation_number]',    citationNum);
  params.set('metadata[client_email]',       clientEmail);
  params.set('metadata[client_phone]',       clientPhone);

  // Redirect URLs
  params.set('success_url', `${SITE_URL}/dashboard.html?payment=success&case=${encodeURIComponent(caseNum)}`);
  params.set('cancel_url',  `${SITE_URL}/dashboard.html?payment=cancelled`);

  const res = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST',
    headers: {
      'Authorization':  `Bearer ${stripeKey}`,
      'Content-Type':   'application/x-www-form-urlencoded',
      'Stripe-Version': '2024-06-20',
    },
    body: params.toString(),
  });

  const data = await res.json();
  if (!res.ok) {
    const msg = data?.error?.message || JSON.stringify(data);
    throw new Error(`Stripe API error: ${msg}`);
  }

  return { checkoutUrl: data.url, sessionId: data.id };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Main handler
// ─────────────────────────────────────────────────────────────────────────────
exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: 'Method Not Allowed' }) };
  }

  // ── Env var checks ───────────────────────────────────────────────────────────
  const stripeKey    = process.env.STRIPE_SECRET_KEY;
  const base         = process.env.AIRTABLE_BASE_ID;
  const atKey        = process.env.AIRTABLE_API_KEY;
  const tokenSecret  = process.env.DASHBOARD_TOKEN_SECRET;

  if (!stripeKey) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'STRIPE_SECRET_KEY not configured.' }) };
  }
  if (!base || !atKey) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'Airtable env vars not configured.' }) };
  }
  if (!tokenSecret) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'DASHBOARD_TOKEN_SECRET not configured.' }) };
  }

  // ── Staff auth ───────────────────────────────────────────────────────────────
  const tokenHeader = event.headers['x-staff-token'] || event.headers['X-Staff-Token'] || '';
  const staff = verifyToken(tokenHeader, tokenSecret);
  if (!staff) {
    return { statusCode: 401, headers: CORS, body: JSON.stringify({ error: 'Unauthorized — valid staff token required.' }) };
  }
  if (staff.role === 'Read Only') {
    return { statusCode: 403, headers: CORS, body: JSON.stringify({ error: 'Permission denied — Read Only role cannot generate payment links.' }) };
  }

  // ── Parse body ───────────────────────────────────────────────────────────────
  let body;
  try { body = JSON.parse(event.body || '{}'); } catch {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Invalid JSON body.' }) };
  }

  const { recordId, amount } = body;
  if (!recordId || typeof recordId !== 'string' || !recordId.startsWith('rec')) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'recordId is required (must be an Airtable record ID starting with "rec").' }) };
  }

  const amountDollars = parseFloat(amount);
  if (!amountDollars || amountDollars <= 0 || !isFinite(amountDollars)) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'amount is required and must be a positive number (in dollars).' }) };
  }
  const amountCents = Math.round(amountDollars * 100);

  // ── Fetch case from Airtable ─────────────────────────────────────────────────
  const caseUrl = `https://api.airtable.com/v0/${base}/${encodeURIComponent(CASES_TABLE)}/${recordId}`;
  const atHdrs  = { 'Authorization': `Bearer ${atKey}`, 'Content-Type': 'application/json' };

  let caseRecord;
  try {
    const res = await fetch(caseUrl, { headers: atHdrs });
    if (!res.ok) {
      if (res.status === 404) {
        return { statusCode: 404, headers: CORS, body: JSON.stringify({ error: 'Case not found in Airtable.' }) };
      }
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData?.error?.message || `Airtable ${res.status}`);
    }
    caseRecord = await res.json();
  } catch (err) {
    console.error('[create-checkout-session] Airtable fetch error:', err.message);
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: `Failed to fetch case: ${err.message}` }) };
  }

  const fd      = caseRecord.fields || {};
  const caseNum = fd['Case #'] || recordId;
  const status  = (typeof fd['Status'] === 'object' ? fd['Status']?.name : fd['Status']) || '';

  // ── Validate case is eligible for payment ────────────────────────────────────
  // Refuse to generate a link if the case has already been paid
  const alreadyPaid = fd['Payment Status'] === 'Paid' || fd['Stripe Session ID'];
  if (alreadyPaid) {
    return {
      statusCode: 409,
      headers: CORS,
      body: JSON.stringify({
        error:   `Case ${caseNum} already has a recorded payment (Payment Status: ${fd['Payment Status'] || 'set'}).`,
        alreadyPaid: true,
        stripeSessionId: fd['Stripe Session ID'] || null,
      }),
    };
  }

  // ── Create Stripe Checkout Session ───────────────────────────────────────────
  let checkoutUrl, sessionId;
  try {
    ({ checkoutUrl, sessionId } = await createStripeSession({
      stripeKey,
      amountCents,
      caseFields: fd,
      recordId,
    }));
  } catch (err) {
    console.error('[create-checkout-session] Stripe error:', err.message);
    return { statusCode: 502, headers: CORS, body: JSON.stringify({ error: err.message }) };
  }

  console.log(`[create-checkout-session] ✅ Created session ${sessionId} for ${caseNum} | $${amountDollars.toFixed(2)} | staff: ${staff.name}`);

  return {
    statusCode: 200,
    headers: CORS,
    body: JSON.stringify({
      success:     true,
      checkoutUrl,
      sessionId,
      caseNum,
      amountDollars,
    }),
  };
};
