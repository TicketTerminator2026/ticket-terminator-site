// Ticket Terminator — Stripe Webhook Handler
// Listens for invoice.payment_succeeded → finds matching Airtable Lead → updates to Pending
//
// Setup in Stripe Dashboard → Webhooks:
//   Endpoint URL: https://YOUR-NETLIFY-SITE/.netlify/functions/stripe-webhook
//   Events: invoice.payment_succeeded
//   Copy "Signing secret" → set as STRIPE_WEBHOOK_SECRET in Netlify env vars

const crypto  = require('crypto');
const { log } = require('./_log');

// ── Stripe signature verification ─────────────────────
function verifyStripeSignature(rawBody, sigHeader, secret) {
  try {
    const parts   = sigHeader.split(',');
    const tPart   = parts.find(p => p.startsWith('t='));
    const v1Part  = parts.find(p => p.startsWith('v1='));
    if (!tPart || !v1Part) return false;

    const timestamp    = tPart.slice(2);
    const receivedSig  = v1Part.slice(3);
    const signedPayload = `${timestamp}.${rawBody}`;
    const expected     = crypto.createHmac('sha256', secret).update(signedPayload, 'utf8').digest('hex');

    // Timing-safe compare
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(receivedSig, 'hex'));
  } catch { return false; }
}

// ── Airtable search helper ────────────────────────────
async function findLeadRecord(baseUrl, headers, email, phone) {
  // 1. Try by email
  if (email) {
    const filter = encodeURIComponent(`AND({Email} = "${email.replace(/"/g, '')}",FIND("Lead",{Status}) > 0)`);
    const res    = await fetch(`${baseUrl}?filterByFormula=${filter}&maxRecords=1`, { headers });
    if (res.ok) {
      const d = await res.json();
      if (d.records?.length > 0) return d.records[0];
    }
  }

  // 2. Fallback — match by phone digits
  if (phone) {
    const digits = phone.replace(/\D/g, '');
    if (digits.length >= 10) {
      // Strip country code for matching (last 10 digits)
      const local10 = digits.slice(-10);
      // Airtable formula: strip non-digits from Phone field and compare
      const filter = encodeURIComponent(
        `AND(RIGHT(SUBSTITUTE(SUBSTITUTE(SUBSTITUTE(SUBSTITUTE(SUBSTITUTE({Phone},"+",""),"-","")," ",""),"(",""),")",""),10) = "${local10}",FIND("Lead",{Status}) > 0)`
      );
      const res = await fetch(`${baseUrl}?filterByFormula=${filter}&maxRecords=1`, { headers });
      if (res.ok) {
        const d = await res.json();
        if (d.records?.length > 0) return d.records[0];
      }
    }
  }

  return null;
}

// ── Main handler ──────────────────────────────────────
exports.handler = async function(event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  // ── Kill switch — set STRIPE_WEBHOOK_ENABLED=true in Netlify env vars to activate ──
  if (process.env.STRIPE_WEBHOOK_ENABLED !== 'true') {
    console.log('[stripe-webhook] Disabled — STRIPE_WEBHOOK_ENABLED is not set to true. Ignoring event.');
    return { statusCode: 200, body: JSON.stringify({ received: true, active: false }) };
  }

  const base     = process.env.AIRTABLE_BASE_ID;
  const table    = process.env.AIRTABLE_TABLE_ID;
  const atKey    = process.env.AIRTABLE_API_KEY;
  const whSecret = process.env.STRIPE_WEBHOOK_SECRET;
  const env      = { base, key: atKey };

  // ── Verify Stripe signature ──
  const sigHeader = event.headers['stripe-signature'];
  if (whSecret && sigHeader) {
    if (!verifyStripeSignature(event.body || '', sigHeader, whSecret)) {
      console.error('[stripe-webhook] Signature verification failed');
      return { statusCode: 400, body: JSON.stringify({ error: 'Invalid signature' }) };
    }
  } else if (whSecret && !sigHeader) {
    console.warn('[stripe-webhook] No Stripe-Signature header — rejecting');
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing signature' }) };
  }

  // ── Parse event ──
  let stripeEvent;
  try { stripeEvent = JSON.parse(event.body); }
  catch {
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  // ── Only process invoice.payment_succeeded ──
  if (stripeEvent.type !== 'invoice.payment_succeeded') {
    return { statusCode: 200, body: JSON.stringify({ received: true, skipped: true, type: stripeEvent.type }) };
  }

  const invoice = stripeEvent.data?.object;
  if (!invoice) {
    return { statusCode: 400, body: JSON.stringify({ error: 'No invoice object in event' }) };
  }

  const email      = (invoice.customer_email || '').trim();
  const phone      = invoice.customer_phone || '';
  const amountPaid = (invoice.amount_paid || 0) / 100;    // cents → dollars
  const invoiceId  = invoice.id;

  if (!email && !phone) {
    return { statusCode: 200, body: JSON.stringify({ received: true, skipped: 'No email or phone on invoice' }) };
  }

  // ── Search Airtable ──
  const atHeaders = { 'Authorization': `Bearer ${atKey}`, 'Content-Type': 'application/json' };
  const baseUrl   = `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}`;

  const record = await findLeadRecord(baseUrl, atHeaders, email, phone);

  if (!record) {
    // Payment received but no matching Lead found — log it so staff can manually handle
    log(env, {
      staffName: 'Stripe',
      action:    'Payment received — no matching lead found',
      category:  'Payment',
      notes:     `Invoice ${invoiceId} | Email: ${email} | Phone: ${phone} | Amount: $${amountPaid.toFixed(2)}`,
    });
    console.log(`[stripe-webhook] No lead matched — invoice ${invoiceId}`);
    return { statusCode: 200, body: JSON.stringify({ received: true, matched: false }) };
  }

  const recordId   = record.id;
  const prevFields = record.fields || {};
  const caseNum    = prevFields['Case #'] || recordId;

  // ── Update Airtable record ──
  const updateFields = {
    'Client Fee Collected': amountPaid,
    'Status':               '🟡 Pending',
    'Payment Method':       'Stripe',
  };

  const updateRes = await fetch(`${baseUrl}/${recordId}`, {
    method:  'PATCH',
    headers: atHeaders,
    body:    JSON.stringify({ fields: updateFields }),
  });

  if (!updateRes.ok) {
    const errData = await updateRes.json().catch(() => ({}));
    console.error('[stripe-webhook] Airtable update failed', errData);
    return { statusCode: 500, body: JSON.stringify({ error: errData.error?.message || 'Airtable update failed' }) };
  }

  // ── Activity log entries ──
  log(env, {
    staffName: 'Stripe',
    action:    `Invoice paid — $${amountPaid.toFixed(2)} received`,
    category:  'Payment',
    caseNum,
    caseId:    recordId,
    field:     'Client Fee Collected',
    oldVal:    prevFields['Client Fee Collected'] || 0,
    newVal:    amountPaid,
    notes:     `Stripe invoice ${invoiceId} — auto-converted to Pending`,
  });
  log(env, {
    staffName: 'Stripe',
    action:    'Status auto-updated via Stripe payment',
    category:  'Case',
    caseNum,
    caseId:    recordId,
    field:     'Status',
    oldVal:    prevFields['Status'] || '🔵 Lead',
    newVal:    '🟡 Pending',
  });

  console.log(`[stripe-webhook] Converted lead ${recordId} — $${amountPaid.toFixed(2)} | Case ${caseNum}`);

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ received: true, matched: true, recordId, caseNum, amountPaid }),
  };
};
