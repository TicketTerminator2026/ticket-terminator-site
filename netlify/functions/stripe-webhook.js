// Ticket Terminator — Stripe Webhook Handler
// Primary event: checkout.session.completed
// Secondary:     invoice.payment_succeeded (skipped safely — future path)
//
// Setup in Stripe Dashboard → Webhooks:
//   Endpoint URL: https://ticket-terminator-intake.netlify.app/.netlify/functions/stripe-webhook
//   Events:       checkout.session.completed
//   Signing secret → STRIPE_WEBHOOK_SECRET in Netlify env vars
//
// Required Netlify env vars:
//   STRIPE_WEBHOOK_SECRET   — signing secret from Stripe Dashboard
//   STRIPE_WEBHOOK_ENABLED  — must be exactly "true" to process events
//   AIRTABLE_BASE_ID        — app7IaHcv4nClafca
//   AIRTABLE_TABLE_ID       — tbledZDHFKbsBiwMf (Cases table)
//   AIRTABLE_API_KEY        — Airtable personal access token

'use strict';

const crypto  = require('crypto');
const { log } = require('./_log');

const CASES_TABLE = process.env.AIRTABLE_TABLE_ID || 'tbledZDHFKbsBiwMf';

// ─────────────────────────────────────────────────────────────────────────────
//  Stripe signature verification (manual — no Stripe SDK required)
//  Implements Stripe's HMAC-SHA256 spec exactly.
// ─────────────────────────────────────────────────────────────────────────────
function verifyStripeSignature(rawBody, sigHeader, secret) {
  try {
    const parts  = sigHeader.split(',');
    const tPart  = parts.find(p => p.startsWith('t='));
    const v1Part = parts.find(p => p.startsWith('v1='));
    if (!tPart || !v1Part) return false;

    const timestamp     = tPart.slice(2);
    const receivedSig   = v1Part.slice(3);
    const signedPayload = `${timestamp}.${rawBody}`;
    const expected      = crypto
      .createHmac('sha256', secret)
      .update(signedPayload, 'utf8')
      .digest('hex');

    // Timing-safe compare — prevents timing attacks
    if (expected.length !== receivedSig.length) return false;
    return crypto.timingSafeEqual(
      Buffer.from(expected,     'hex'),
      Buffer.from(receivedSig,  'hex')
    );
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Airtable lookup helpers
// ─────────────────────────────────────────────────────────────────────────────

// 1. Direct fetch by record ID (fastest — used when metadata.airtable_record_id is present)
async function fetchRecordById(baseUrl, headers, recordId) {
  try {
    const res = await fetch(`${baseUrl}/${recordId}`, { headers });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

// 2. Find by tt_case_number (Case # field)
async function findByCaseNumber(baseUrl, headers, caseNumber) {
  try {
    const filter = encodeURIComponent(`{Case #} = "${caseNumber.replace(/"/g, '')}"`);
    const res    = await fetch(`${baseUrl}?filterByFormula=${filter}&maxRecords=1`, { headers });
    if (!res.ok) return null;
    const d = await res.json();
    return d.records?.[0] || null;
  } catch {
    return null;
  }
}

// 3. Find by email (only lead-status records)
async function findByEmail(baseUrl, headers, email) {
  try {
    const safeEmail = email.replace(/"/g, '');
    // Match email AND status still contains "Lead" (avoids matching already-converted cases)
    const filter = encodeURIComponent(
      `AND(LOWER({Email}) = "${safeEmail.toLowerCase()}", OR(FIND("Lead",{Status})>0, {Status}="Waiting for Payment", {Status}="Quote Sent"))`
    );
    const res = await fetch(`${baseUrl}?filterByFormula=${filter}&maxRecords=1`, { headers });
    if (!res.ok) return null;
    const d = await res.json();
    return d.records?.[0] || null;
  } catch {
    return null;
  }
}

// 4. Find by phone (last 10 digits)
async function findByPhone(baseUrl, headers, phone) {
  try {
    const digits  = phone.replace(/\D/g, '');
    if (digits.length < 10) return null;
    const local10 = digits.slice(-10);
    const filter  = encodeURIComponent(
      `AND(RIGHT(SUBSTITUTE(SUBSTITUTE(SUBSTITUTE(SUBSTITUTE(SUBSTITUTE({Phone},"+",""),"-","")," ",""),"(",""),")",""),10)="${local10}", OR(FIND("Lead",{Status})>0, {Status}="Waiting for Payment"))`
    );
    const res = await fetch(`${baseUrl}?filterByFormula=${filter}&maxRecords=1`, { headers });
    if (!res.ok) return null;
    const d = await res.json();
    return d.records?.[0] || null;
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Main handler
// ─────────────────────────────────────────────────────────────────────────────
exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  // ── Kill switch ──────────────────────────────────────────────────────────────
  if (process.env.STRIPE_WEBHOOK_ENABLED !== 'true') {
    console.log('[stripe-webhook] Disabled — set STRIPE_WEBHOOK_ENABLED=true in Netlify env to activate.');
    return { statusCode: 200, body: JSON.stringify({ received: true, active: false }) };
  }

  // ── Hard-require webhook secret ──────────────────────────────────────────────
  const whSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!whSecret) {
    console.error('[stripe-webhook] STRIPE_WEBHOOK_SECRET is not set — refusing to process event.');
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Webhook secret not configured. Set STRIPE_WEBHOOK_SECRET.' }),
    };
  }

  // ── Verify Stripe signature ──────────────────────────────────────────────────
  const sigHeader = event.headers['stripe-signature'];
  if (!sigHeader) {
    console.warn('[stripe-webhook] Missing Stripe-Signature header — rejecting.');
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing Stripe-Signature header' }) };
  }
  if (!verifyStripeSignature(event.body || '', sigHeader, whSecret)) {
    console.error('[stripe-webhook] Signature verification failed — possible replay or forgery.');
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid signature' }) };
  }

  // ── Parse event ──────────────────────────────────────────────────────────────
  let stripeEvent;
  try {
    stripeEvent = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid JSON body' }) };
  }

  const eventType = stripeEvent.type;
  console.log(`[stripe-webhook] Received event: ${eventType} (${stripeEvent.id})`);

  // ── Route events ─────────────────────────────────────────────────────────────
  if (eventType === 'checkout.session.completed') {
    return await handleCheckoutSessionCompleted(stripeEvent);
  }

  // All other events: acknowledge without processing
  // invoice.payment_succeeded is intentionally skipped (subscription/invoicing path — not in use)
  console.log(`[stripe-webhook] Skipping event type: ${eventType}`);
  return { statusCode: 200, body: JSON.stringify({ received: true, skipped: true, type: eventType }) };
};

// ─────────────────────────────────────────────────────────────────────────────
//  Handle checkout.session.completed
// ─────────────────────────────────────────────────────────────────────────────
async function handleCheckoutSessionCompleted(stripeEvent) {
  const session = stripeEvent.data?.object;
  if (!session) {
    return { statusCode: 400, body: JSON.stringify({ error: 'No session object in event' }) };
  }

  const sessionId   = session.id;                              // cs_test_...
  const amountPaid  = (session.amount_total || 0) / 100;      // cents → dollars
  const metadata    = session.metadata || {};
  const email       = (session.customer_email || metadata.client_email || '').trim();
  const phone       = metadata.client_phone || '';

  // Stripe metadata fields (set by create-checkout-session.js)
  const metaRecordId   = metadata.airtable_record_id || '';
  const metaCaseNumber = metadata.tt_case_number     || '';

  console.log(`[stripe-webhook] Session ${sessionId} | $${amountPaid} | rec: ${metaRecordId} | case: ${metaCaseNumber} | email: ${email}`);

  // ── Airtable env ────────────────────────────────────────────────────────────
  const base    = process.env.AIRTABLE_BASE_ID;
  const atKey   = process.env.AIRTABLE_API_KEY;
  const env     = { base, key: atKey };
  const baseUrl = `https://api.airtable.com/v0/${base}/${encodeURIComponent(CASES_TABLE)}`;
  const atHdrs  = { 'Authorization': `Bearer ${atKey}`, 'Content-Type': 'application/json' };

  // ── Find the Airtable case (priority: record ID → case # → email → phone) ──
  let record = null;
  let lookupMethod = '';

  if (metaRecordId) {
    record = await fetchRecordById(baseUrl, atHdrs, metaRecordId);
    if (record) lookupMethod = 'metadata:airtable_record_id';
  }

  if (!record && metaCaseNumber) {
    record = await findByCaseNumber(baseUrl, atHdrs, metaCaseNumber);
    if (record) lookupMethod = 'metadata:tt_case_number';
  }

  if (!record && email) {
    record = await findByEmail(baseUrl, atHdrs, email);
    if (record) lookupMethod = 'fallback:email';
  }

  if (!record && phone) {
    record = await findByPhone(baseUrl, atHdrs, phone);
    if (record) lookupMethod = 'fallback:phone';
  }

  // ── No match — log and acknowledge ─────────────────────────────────────────
  if (!record) {
    console.warn(`[stripe-webhook] No case matched — session ${sessionId}`);
    await log(env, {
      staffName: 'Stripe',
      action:    'Payment received — no matching case found',
      category:  'Payment',
      notes:     `Session ${sessionId} | Amount: $${amountPaid.toFixed(2)} | Email: ${email} | metadata.airtable_record_id: ${metaRecordId || 'none'} | metadata.tt_case_number: ${metaCaseNumber || 'none'}`,
    });
    return { statusCode: 200, body: JSON.stringify({ received: true, matched: false }) };
  }

  const recordId  = record.id;
  const prevFlds  = record.fields || {};
  const caseNum   = prevFlds['Case #'] || recordId;

  // ── Idempotency check — prevent double-processing on Stripe retries ─────────
  if (prevFlds['Stripe Session ID'] === sessionId) {
    console.log(`[stripe-webhook] Duplicate event — session ${sessionId} already processed for ${caseNum}. Ignoring.`);
    return {
      statusCode: 200,
      body: JSON.stringify({ received: true, duplicate: true, sessionId, caseNum }),
    };
  }

  // ── Build update fields ──────────────────────────────────────────────────────
  const updateFields = {
    'Client Fee Collected':  amountPaid,
    'Client Balance Remaining': 0,          // Phase 1: treat session as full payment
    'Payment Method':        'Stripe',
    'Payment Status':        'Paid',
    'Status':                'Paid - Needs Attorney',
    'Stripe Session ID':     sessionId,
  };

  // ── PATCH Airtable ───────────────────────────────────────────────────────────
  const updateRes = await fetch(`${baseUrl}/${recordId}`, {
    method:  'PATCH',
    headers: atHdrs,
    body:    JSON.stringify({ fields: updateFields }),
  });

  if (!updateRes.ok) {
    const errData = await updateRes.json().catch(() => ({}));
    const errMsg  = errData?.error?.message || JSON.stringify(errData);
    console.error(`[stripe-webhook] Airtable update failed for ${recordId}: ${errMsg}`);
    // Return 500 so Stripe retries — idempotency guard above will catch the retry
    return { statusCode: 500, body: JSON.stringify({ error: errMsg }) };
  }

  console.log(`[stripe-webhook] ✅ Converted ${caseNum} (${recordId}) via ${lookupMethod} | $${amountPaid.toFixed(2)}`);

  // ── Activity Log (4 entries — awaited so writes complete before function returns) ──
  const logBase = { staffName: 'Stripe', caseNum, caseId: recordId };

  await Promise.all([
    // 1. Payment received
    log(env, {
      ...logBase,
      action:   `Stripe payment received — $${amountPaid.toFixed(2)}`,
      category: 'Payment',
      field:    'Client Fee Collected',
      oldVal:   prevFlds['Client Fee Collected'] || 0,
      newVal:   amountPaid,
      notes:    `Session ${sessionId} | Lookup: ${lookupMethod}`,
    }),

    // 2. Status changed
    log(env, {
      ...logBase,
      action:   'Status auto-converted via Stripe payment',
      category: 'Case',
      field:    'Status',
      oldVal:   prevFlds['Status'] || '🔵 Lead',
      newVal:   'Paid - Needs Attorney',
    }),

    // 3. Payment Method set
    log(env, {
      ...logBase,
      action:   'Payment Method set to Stripe',
      category: 'Payment',
      field:    'Payment Method',
      oldVal:   prevFlds['Payment Method'] || '',
      newVal:   'Stripe',
    }),

    // 4. Payment Status set
    log(env, {
      ...logBase,
      action:   'Payment Status set to Paid',
      category: 'Payment',
      field:    'Payment Status',
      oldVal:   prevFlds['Payment Status'] || '',
      newVal:   'Paid',
    }),
  ]);

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      received:     true,
      matched:      true,
      lookupMethod,
      recordId,
      caseNum,
      amountPaid,
      sessionId,
    }),
  };
}
