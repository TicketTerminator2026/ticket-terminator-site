// Ticket Terminator — Secure Form → Airtable Function
// Commit 2 (v2): idempotency via Netlify Blobs — lease + ETag compare-and-set
// API key lives in Netlify env vars, never in the HTML.

'use strict';

const { randomUUID, createHash } = require('crypto');
const { getStore, connectLambda } = require('@netlify/blobs');

// ── Constants ──────────────────────────────────────────────────────────────
const CORS_HEADERS = {
  'Content-Type':                'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods':'POST, OPTIONS',
  'Access-Control-Allow-Headers':'Content-Type',
};

// UUID v4 validation — reject anything that doesn't match the canonical format
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Lease duration: 90 s exceeds Netlify's 60 s synchronous function timeout, so
// a normally-running function's lease never expires mid-execution. Abandoned
// executions (crash, kill) are recoverable after 90 s.
const LEASE_MS         = 90_000;
const POLL_INTERVAL_MS =    600; // how often duplicates poll for state changes
const MAX_POLL_MS      = 12_000; // max time a duplicate request will wait
const RECOVERY_WAIT_MS =  1_500; // pause between two-pass crash-window search passes

const delay = ms => new Promise(r => setTimeout(r, ms));

// ── Ownership-lost sentinel ────────────────────────────────────────────────
// Thrown by etagTransition / renewLease when the ETag CAS fails, meaning
// another request has taken over this submission. All callers hard-stop and
// return 503 — no further Airtable mutations may be made.
class OwnershipLostError extends Error {
  constructor() {
    super('Ownership lost — another request has taken over this submission.');
    this.name = 'OwnershipLostError';
  }
}

// ── Handler ────────────────────────────────────────────────────────────────
exports.handler = async function (event) {

  // ── CORS preflight ──────────────────────────────────────────────────
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS_HEADERS, body: '' };
  }
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: CORS_HEADERS, body: JSON.stringify({ error: 'Method Not Allowed' }) };
  }

  // ── Body size guard (Commit 1: Buffer.byteLength, not .length) ───────
  const bodyLen = Buffer.byteLength(event.body || '', 'utf8');
  if (bodyLen > 5 * 1024 * 1024) {
    return {
      statusCode: 413,
      headers: CORS_HEADERS,
      body: JSON.stringify({ error: 'Request too large. Please upload smaller photos (compress to under 4MB each).' }),
    };
  }

  // ── Parse body ────────────────────────────────────────────────────
  let data;
  try {
    data = JSON.parse(event.body);
  } catch (e) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: 'Invalid request body' }) };
  }

  // ── Server-side validation ────────────────────────────────────────
  if (!data.firstName || !data.lastName) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: 'First and last name are required' }) };
  }
  if (!data.phone || data.phone.replace(/\D/g, '').length < 10) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: 'A valid phone number is required' }) };
  }
  if (!data.email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(data.email)) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: 'A valid email address is required' }) };
  }

  // ── Validate submissionId ────────────────────────────────────────
  // Every Case must be protected by idempotency. Missing or malformed IDs
  // are rejected — we never fall back to unprotected Case creation.
  const submissionId = typeof data.submissionId === 'string' ? data.submissionId.trim() : '';
  if (!UUID_V4_RE.test(submissionId)) {
    return {
      statusCode: 400,
      headers: CORS_HEADERS,
      body: JSON.stringify({
        error: 'Missing or invalid submissionId. Please reload and try again.',
        retryable: false,
      }),
    };
  }

  // ── Compute request fingerprint ───────────────────────────────────
  // SHA-256 of the canonical payload (all keys sorted).
  // Excluded from hash (volatile / auto-generated — must not affect fingerprint stability):
  //   submissionId     — the key being looked up; circular if included
  //   consentTimestamp — changes on every Submit click; would break reload / lost-response retry
  // Normalization applied before hashing (must match client):
  //   - null / undefined / '' treated as absent (key omitted)
  //   - String values trimmed
  //   - Booleans kept as-is
  // Included (material user data whose change should produce a new Case):
  //   smsConsent, all form fields, Base64 document data, lang.
  // Stored in the Blob claim so a reused submissionId with a different payload
  // is detected and rejected with 409 before any Airtable mutation.
  function _fpNorm(v) {
    if (v === null || v === undefined || v === '') return undefined;
    if (typeof v === 'string') return v.trim() === '' ? undefined : v.trim();
    return v;
  }
  const { submissionId: _sid, consentTimestamp: _cts, ...hashableData } = data;
  const fpEntries = Object.keys(hashableData).sort().reduce((acc, k) => {
    const v = _fpNorm(hashableData[k]);
    if (v !== undefined) acc.push([k, v]);
    return acc;
  }, []);
  const canonicalPayload = JSON.stringify(Object.fromEntries(fpEntries));
  const requestHash = createHash('sha256').update(canonicalPayload).digest('hex');

  // ── Environment / Airtable config ────────────────────────────────
  const BASE_ID       = process.env.AIRTABLE_BASE_ID;
  const CASES_TABLE   = process.env.AIRTABLE_TABLE_ID;
  const CLIENTS_TABLE = 'tblqNIl5A1QUQqrus';
  const API_KEY       = process.env.AIRTABLE_API_KEY;

  const atHeaders = {
    'Authorization': `Bearer ${API_KEY}`,
    'Content-Type':  'application/json',
  };

  // ── Violation type → Airtable Case Type ─────────────────────────
  const caseTypeMap = {
    'Speeding':      '🚗 Traffic Citation',
    'Red Light':     '🚗 Traffic Citation',
    'Stop Sign':     '🚗 Traffic Citation',
    'Reckless':      '🚗 Traffic Citation',
    'Cell Phone':    '🚗 Traffic Citation',
    'Fix-It Ticket': '🚗 Traffic Citation',
    'Other':         '🚗 Traffic Citation',
    'DUI/DWI':       '🚨 DUI / DWI',
    'DUI / DWI':     '🚨 DUI / DWI',
  };

  // ── Priority ─────────────────────────────────────────────────────
  const isDUI     = (data.violationType || '').toUpperCase().includes('DUI');
  const hasCDL    = data.cdl === 'yes';
  const isPastDue = data.pastDue === 'yes';
  const hasCourt  = !!(data.courtDate);
  let priority;
  if (isDUI || hasCDL || isPastDue)  priority = '🔴 High';
  else if (hasCourt)                  priority = '🟡 Medium';
  else                                priority = '🟢 Low';

  // ── Label maps ───────────────────────────────────────────────────
  const contactMap = { phone: 'Phone Call', text: 'Text / SMS', email: 'Email' };
  const pastDueMap = { yes: 'Yes', no: 'No', unsure: 'Not Sure' };
  const paidMap    = { yes: 'Yes — Paid', no: 'Not Yet' };
  const bacMap     = {
    yes_breathalyzer: 'Yes — Breathalyzer',
    yes_blood:        'Yes — Blood Test',
    refused:          'Refused',
    no:               'No Test Given',
  };
  const fstMap = { yes: 'Yes', no: 'No', refused: 'Refused' };

  const preferredContact = contactMap[data.preferredContact] || null;
  const pastDueVal       = pastDueMap[data.pastDue]          || null;
  const paidVal          = paidMap[data.alreadyPaid]         || null;
  const bacVal           = bacMap[data.bac]                  || null;
  const fstVal           = fstMap[data.fst]                  || null;

  // ── DUI / Speeding notes ─────────────────────────────────────────
  let duiNotes = '';
  if (isDUI) {
    const parts = [];
    if (bacVal)         parts.push(`BAC Test: ${bacVal}`);
    if (data.bacResult) parts.push(`BAC Result: ${data.bacResult}`);
    if (fstVal)         parts.push(`Field Sobriety Test: ${fstVal}`);
    if (parts.length)   duiNotes = parts.join(' | ');
  }

  let speedNotes = '';
  if ((data.violationType || '').toLowerCase() === 'speeding') {
    const parts = [];
    if (data.speedAlleged) parts.push(`Alleged: ${data.speedAlleged} mph`);
    if (data.speedLimit)   parts.push(`Posted limit: ${data.speedLimit} mph`);
    if (parts.length)      speedNotes = parts.join(' | ');
  }

  const clientStatementParts = [];
  if (data.story)   clientStatementParts.push(data.story);
  if (duiNotes)     clientStatementParts.push(`[DUI Details] ${duiNotes}`);
  if (speedNotes)   clientStatementParts.push(`[Speed Details] ${speedNotes}`);
  const clientStatement = clientStatementParts.join('\n\n');

  // ── Generate Case Number BEFORE the atomic Blob claim ────────────
  // This caseNum is stored in the initial claim so crash-window recovery
  // can search Airtable by the exact number that was (or will be) used,
  // even if the function died before writing a Blob checkpoint.
  const year         = new Date().getFullYear();
  const seq          = Date.now().toString().slice(-5);
  const draftCaseNum = `TT-${year}-${seq}`;

  // ═══════════════════════════════════════════════════════════════════
  // IDEMPOTENCY — Netlify Blobs atomic claim
  // ═══════════════════════════════════════════════════════════════════
  // For Functions v1 (exports.handler), the Blobs client context is passed
  // through the Lambda event object. connectLambda() must be called before
  // getStore() to initialise the siteID/token/edgeURL from event.blobs.
  try { connectLambda(event); } catch (_) { /* no-op if already initialised */ }
  const store   = getStore('tt-submissions');
  const ownerId = randomUUID();
  const nowMs   = Date.now();

  // Initial state stored in the Blob. No PII — only operational metadata.
  // requestHash binds this submissionId to one specific payload; a reuse with
  // a different payload is rejected with 409 before any Airtable mutation.
  const initialState = {
    state:          'processing',
    ownerId,
    caseNum:        draftCaseNum,
    requestHash,
    leaseExpiresAt: new Date(nowMs + LEASE_MS).toISOString(),
    createdAt:      new Date(nowMs).toISOString(),
    updatedAt:      new Date(nowMs).toISOString(),
  };

  // Mutable owner state — updated by etagTransition() and renewLease()
  let myEtag;
  let currentEntry;

  // Recovery flags: set when we take over an existing in-flight submission
  let isRecovery        = false;
  let recoveredRecordId = null; // set when taking over a case_created state

  // ── Atomic claim ─────────────────────────────────────────────────
  // modified=true  → we own the claim; proceed as new owner
  // modified=false → key existed; read state and follow state machine below
  // throws         → storage unreachable; fail closed (never create Case without protection)
  let claimResult;
  try {
    // Use set() not setJSON() — setJSON v10 has a bug where it spreads conditions
    // into makeRequest instead of passing them as a named param, so onlyIfNew/
    // onlyIfMatch headers are silently dropped and every write appears to succeed.
    claimResult = await store.set(submissionId, JSON.stringify(initialState), { onlyIfNew: true });
  } catch (blobErr) {
    console.error('Idempotency store unavailable (claim):', blobErr.message);
    return {
      statusCode: 503,
      headers: CORS_HEADERS,
      body: JSON.stringify({
        error: 'Service temporarily unavailable — please try again in a moment.',
        retryable: true,
      }),
    };
  }

  if (claimResult.modified) {
    // ── New owner ────────────────────────────────────────────────
    myEtag       = claimResult.etag;
    currentEntry = initialState;

  } else {
    // ── Duplicate request — follow state machine ──────────────────
    let readResult;
    try {
      readResult = await store.getWithMetadata(submissionId, { type: 'json' });
    } catch (readErr) {
      console.error('Idempotency store unavailable (read):', readErr.message);
      return {
        statusCode: 503,
        headers: CORS_HEADERS,
        body: JSON.stringify({ error: 'Service temporarily unavailable — please try again.', retryable: true }),
      };
    }

    if (!readResult || !readResult.data) {
      return {
        statusCode: 503,
        headers: CORS_HEADERS,
        body: JSON.stringify({ error: 'Service temporarily unavailable — please try again.', retryable: true }),
      };
    }

    let existing     = readResult.data;
    let existingEtag = readResult.etag;

    // ── Hash mismatch → 409 IDEMPOTENCY_KEY_REUSED ────────────────
    // The submissionId is bound to the payload that first claimed it.
    // A different payload with the same submissionId is a client error:
    // no Airtable reads, creates, PATCHes, or uploads may proceed.
    if (existing.requestHash && existing.requestHash !== requestHash) {
      console.warn('Idempotency key reused with different payload for submission', submissionId);
      return {
        statusCode: 409,
        headers: CORS_HEADERS,
        body: JSON.stringify({
          error: 'This submission ID was already used for a different request. Please reload and try again.',
          code:  'IDEMPOTENCY_KEY_REUSED',
          retryable: false,
        }),
      };
    }

    // Completed → return the stored sanitized success response immediately
    if (existing.state === 'completed' && existing.successResponse) {
      return {
        statusCode: 200,
        headers: CORS_HEADERS,
        body: JSON.stringify(existing.successResponse),
      };
    }

    // ── Poll while another owner holds a valid lease ───────────────
    const leaseValid = () =>
      existing.leaseExpiresAt && new Date(existing.leaseExpiresAt) > new Date();

    if (leaseValid()) {
      const pollDeadline = Date.now() + MAX_POLL_MS;

      while (Date.now() < pollDeadline) {
        await delay(POLL_INTERVAL_MS);

        let pollResult;
        try {
          pollResult = await store.getWithMetadata(submissionId, { type: 'json' });
        } catch (e) {
          break; // storage error during poll — fall through to takeover
        }
        if (!pollResult || !pollResult.data) break;

        existingEtag = pollResult.etag;
        existing     = pollResult.data;

        if (existing.state === 'completed' && existing.successResponse) {
          return {
            statusCode: 200,
            headers: CORS_HEADERS,
            body: JSON.stringify(existing.successResponse),
          };
        }

        if (!leaseValid()) break; // lease expired during polling — attempt takeover
      }

      // Re-read for freshest ETag before takeover CAS
      try {
        const reread = await store.getWithMetadata(submissionId, { type: 'json' });
        if (reread && reread.data) {
          existing     = reread.data;
          existingEtag = reread.etag;
        }
      } catch (e) { /* use last known values */ }

      if (existing.state === 'completed' && existing.successResponse) {
        return {
          statusCode: 200,
          headers: CORS_HEADERS,
          body: JSON.stringify(existing.successResponse),
        };
      }
    }

    // ── Expired-lease takeover via ETag compare-and-set ───────────
    // Only one racing request wins the CAS; all others get 503.
    const takenEntry = {
      ...existing,
      ownerId,
      leaseExpiresAt: new Date(Date.now() + LEASE_MS).toISOString(),
      updatedAt:      new Date().toISOString(),
    };

    let takeoverResult;
    try {
      takeoverResult = await store.set(submissionId, JSON.stringify(takenEntry), { onlyIfMatch: existingEtag });
    } catch (e) {
      console.error('Idempotency store unavailable (takeover):', e.message);
      return {
        statusCode: 503,
        headers: CORS_HEADERS,
        body: JSON.stringify({ error: 'Service temporarily unavailable — please try again.', retryable: true }),
      };
    }

    if (!takeoverResult.modified) {
      // Lost the takeover race — another duplicate won
      return {
        statusCode: 503,
        headers: CORS_HEADERS,
        body: JSON.stringify({
          error: 'Another submission is in progress — please wait and try again.',
          retryable: true,
        }),
      };
    }

    myEtag       = takeoverResult.etag;
    currentEntry = takenEntry;

    // Classify recovery type
    if (existing.state === 'case_created') {
      isRecovery        = true;
      recoveredRecordId = existing.recordId || null;
    } else {
      // processing or failed_before_case — will search Airtable before Case creation
      isRecovery = true;
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // ETag helpers — both throw OwnershipLostError on CAS miss
  // ═══════════════════════════════════════════════════════════════════

  // etagTransition: advance the state machine. Throws OwnershipLostError
  // if the ETag is stale (another owner took over). Callers must stop
  // immediately on failure — no further Airtable mutations permitted.
  async function etagTransition(partial) {
    const newData = { ...currentEntry, ...partial, updatedAt: new Date().toISOString() };
    let result;
    try {
      result = await store.set(submissionId, JSON.stringify(newData), { onlyIfMatch: myEtag });
    } catch (e) {
      console.error('Blob state transition storage error:', e.message);
      throw e; // storage failure — propagate to top-level catch
    }
    if (!result.modified) {
      throw new OwnershipLostError();
    }
    myEtag       = result.etag;
    currentEntry = newData;
  }

  // renewLease: extend leaseExpiresAt and verify ownership via ETag.
  // Called before every group of Airtable mutations to confirm we still
  // own the lease. Throws OwnershipLostError if another owner took over.
  async function renewLease() {
    const renewed = {
      ...currentEntry,
      leaseExpiresAt: new Date(Date.now() + LEASE_MS).toISOString(),
      updatedAt:      new Date().toISOString(),
    };
    let result;
    try {
      result = await store.set(submissionId, JSON.stringify(renewed), { onlyIfMatch: myEtag });
    } catch (e) {
      console.error('Lease renewal storage error:', e.message);
      throw e;
    }
    if (!result.modified) {
      throw new OwnershipLostError();
    }
    myEtag       = result.etag;
    currentEntry = renewed;
  }

  // ── Effective Case Number ─────────────────────────────────────────
  // Always use the caseNum stored in the original claim — never generate
  // a new one during recovery. This ensures all paths use the same display
  // identifier. Recovery lookups use Intake Submission ID, not Case #.
  const effectiveCaseNum = (currentEntry && currentEntry.caseNum) || draftCaseNum;

  // ── Build Cases fields object ─────────────────────────────────────
  // Intake Submission ID is the authoritative recovery key stored in Airtable.
  // Document receipt checkboxes (Ticket Received, Driver License Received,
  // Documents Complete) are set via PATCH after upload outcomes are known.
  const caseFields = {
    'Case #':               effectiveCaseNum,
    'Intake Submission ID': submissionId,
    'Status':               '🔵 Lead',
    'Quote Status':         'Not Requested',
    'Case Type':            caseTypeMap[data.violationType] || '🚗 Traffic Citation',
    'Priority':             priority,
    'Date Submitted':       new Date().toISOString().split('T')[0],
    'Citation / Arrest #':  data.citationNum || '',

    'First Name':  data.firstName || '',
    'Last Name':   data.lastName  || '',
    'Phone':       data.phone     || '',
    'Email':       data.email     || '',
    'CDL Holder':  data.cdl === 'yes',

    'Violation Description':          data.violationDesc   || '',
    'Traffic School Past 18 Months?': data.trafficSchool === 'yes',
    'Client Statement':               clientStatement,

    'Court Location': data.courtLocation || '',
    'Court State':    data.state         || '',
    'County':         data.county        || '',

    ...(preferredContact ? { 'Preferred Contact':      preferredContact } : {}),
    ...(pastDueVal        ? { 'Past Due / Collections': pastDueVal       } : {}),
    ...(paidVal           ? { 'Ticket Already Paid':    paidVal          } : {}),

    'Heard About Us':        data.heardAbout || '',
    'Referred By':           data.referredBy || '',
    'SMS Consent':           data.smsConsent === true,
    'SMS Consent Timestamp': data.consentTimestamp || new Date().toISOString(),
    'Preferred Language':    data.lang === 'es' ? 'Spanish' : 'English',
  };

  if (data.violationDate) caseFields['Date of Violation'] = data.violationDate;
  if (data.courtDate)     caseFields['Court Date']        = data.courtDate;

  Object.keys(caseFields).forEach(k => {
    if (caseFields[k] === '' || caseFields[k] === null || caseFields[k] === undefined) {
      delete caseFields[k];
    }
  });

  // ═══════════════════════════════════════════════════════════════════
  // OWNERSHIP-PROTECTED PROCESSING
  // All OwnershipLostErrors and storage errors propagate to this catch.
  // No Airtable mutations may occur after an ownership loss.
  // ═══════════════════════════════════════════════════════════════════
  try {

    // ── Step 1: Find or create Client record ────────────────────────
    // Client search is a read — no ownership renewal required.
    // renewLease() is called only if a new Client record must be created.
    let clientId = null;
    try {
      const rawPhone = (data.phone || '').replace(/\D/g, '');
      const rawEmail = (data.email || '').toLowerCase().trim();

      let searchFilter;
      if (rawEmail && rawPhone) {
        searchFilter = `OR(LOWER({Email})="${rawEmail}",REGEX_REPLACE({Phone},"[^0-9]","")="${rawPhone}")`;
      } else if (rawEmail) {
        searchFilter = `LOWER({Email})="${rawEmail}"`;
      } else if (rawPhone) {
        searchFilter = `REGEX_REPLACE({Phone},"[^0-9]","")="${rawPhone}"`;
      }

      if (searchFilter) {
        const searchRes  = await fetch(
          `https://api.airtable.com/v0/${BASE_ID}/${CLIENTS_TABLE}` +
          `?filterByFormula=${encodeURIComponent(searchFilter)}&maxRecords=1`,
          { headers: atHeaders }
        );
        const searchData = await searchRes.json();
        console.log('Client search result:', JSON.stringify(searchData).substring(0, 200));

        if (searchData.records && searchData.records.length > 0) {
          clientId = searchData.records[0].id;
          console.log('Existing client found:', clientId);
        } else {
          // Creating a new Client is a mutation — verify ownership first
          await renewLease();

          const clientFields = {
            'Client Name': `${data.firstName || ''} ${data.lastName || ''}`.trim() || 'Unknown',
          };
          if (data.phone) clientFields['Phone'] = data.phone;
          if (data.email) clientFields['Email'] = data.email;

          const clientRes  = await fetch(
            `https://api.airtable.com/v0/${BASE_ID}/${CLIENTS_TABLE}`,
            { method: 'POST', headers: atHeaders, body: JSON.stringify({ fields: clientFields }) }
          );
          const clientData = await clientRes.json();
          console.log('Client create result:', JSON.stringify(clientData).substring(0, 200));
          if (clientData.id && typeof clientData.id === 'string') clientId = clientData.id;
        }
      }
    } catch (e) {
      if (e instanceof OwnershipLostError) throw e; // propagate hard-stop
      console.warn('Client lookup/create failed:', e.message);
    }

    if (clientId && typeof clientId === 'string' && clientId.startsWith('rec')) {
      caseFields['Client'] = [clientId];
    }

    // ── Step 2: Obtain a Case record ────────────────────────────────
    let recordId = recoveredRecordId;

    if (!recordId) {
      // ── 2a. Crash-window search (recovery from processing / failed_before_case)
      // The earlier request may have created the Case and then crashed before
      // writing the case_created checkpoint.
      //
      // NOTE: The Blob lease plus this recovery search minimises the cross-system
      // crash window. We do NOT rely on Airtable enforcing unique Case Numbers —
      // no confirmed unique index exists on that field in production.
      //
      // Search protocol:
      //   - Two passes separated by RECOVERY_WAIT_MS.
      //   - Any network or HTTP error → fail closed (503) — do not create a Case.
      //   - Only after TWO successful zero-result passes may a new Case be created.
      //   - Search by Intake Submission ID (the authoritative recovery key), not Case #.

      if (isRecovery) {
        let foundInAirtable = false;

        for (let pass = 1; pass <= 2; pass++) {
          if (pass === 2) await delay(RECOVERY_WAIT_MS);

          let searchRes;
          try {
            // Search by Intake Submission ID — the unique, authoritative recovery key.
            // Never use Case # for recovery: it may not be unique and was not designed
            // as a lookup key.
            const filter = encodeURIComponent(`{Intake Submission ID}="${submissionId}"`);
            // maxRecords=2: fetch one more than needed so we can detect duplicates
            searchRes = await fetch(
              `https://api.airtable.com/v0/${BASE_ID}/${CASES_TABLE}` +
              `?filterByFormula=${filter}&maxRecords=2&fields%5B%5D=Intake%20Submission%20ID`,
              { headers: atHeaders }
            );
          } catch (fetchErr) {
            // Network error on Airtable search — fail closed; cannot safely proceed
            console.error(`Crash-window search network error (pass ${pass}):`, fetchErr.message);
            // Best-effort: try to mark failed state; ignore transition errors here
            try { await etagTransition({ state: 'failed_before_case' }); } catch (_) {}
            return {
              statusCode: 503,
              headers: CORS_HEADERS,
              body: JSON.stringify({
                error: 'Could not verify prior submission state — please try again.',
                retryable: true,
              }),
            };
          }

          if (!searchRes.ok) {
            console.error(`Crash-window search HTTP error (pass ${pass}):`, searchRes.status);
            try { await etagTransition({ state: 'failed_before_case' }); } catch (_) {}
            return {
              statusCode: 503,
              headers: CORS_HEADERS,
              body: JSON.stringify({
                error: 'Could not verify prior submission state — please try again.',
                retryable: true,
              }),
            };
          }

          const searchData = await searchRes.json();

          if (searchData.records && searchData.records.length > 1) {
            // Multiple Cases share this Intake Submission ID — integrity violation.
            // Stop immediately so a human can investigate; do not mutate state.
            console.error('Crash-window recovery: multiple Cases found for Intake Submission ID', submissionId,
              '— halting to prevent incorrect recovery');
            return {
              statusCode: 503,
              headers: CORS_HEADERS,
              body: JSON.stringify({
                error: 'Multiple records found for this submission — please contact support at 877-873-3187.',
                retryable: false,
              }),
            };
          }

          if (searchData.records && searchData.records.length === 1) {
            recordId        = searchData.records[0].id;
            foundInAirtable = true;
            console.log('Crash-window recovery: found existing Case by Intake Submission ID', submissionId, recordId);
            // Checkpoint: advance state machine to case_created
            // This throws OwnershipLostError if we've been superseded → hard stop
            await etagTransition({ state: 'case_created', recordId });
            break;
          }
          // Zero records this pass — loop continues for second pass
        }

        // If found, skip Case creation below
        if (foundInAirtable) {
          // recordId is set; fall through to attachment section
        }
        // If two clean zero-result passes: safe to create a new Case
      }

      // ── 2b. Create Case (new submission, or recovery with zero search results)
      if (!recordId) {
        // Verify ownership before the Case creation mutation
        await renewLease();

        let caseRes, caseResult;
        try {
          caseRes    = await fetch(
            `https://api.airtable.com/v0/${BASE_ID}/${CASES_TABLE}`,
            { method: 'POST', headers: atHeaders, body: JSON.stringify({ fields: caseFields }) }
          );
          caseResult = await caseRes.json();
        } catch (fetchErr) {
          console.error('Network error during Case create:', fetchErr.message);
          try { await etagTransition({ state: 'failed_before_case' }); } catch (_) {}
          return {
            statusCode: 503,
            headers: CORS_HEADERS,
            body: JSON.stringify({
              error: 'Network error — please try again. Your form data is saved locally.',
              retryable: true,
            }),
          };
        }

        if (!caseRes.ok) {
          console.error('Airtable Case create error:', JSON.stringify(caseResult));
          try { await etagTransition({ state: 'failed_before_case' }); } catch (_) {}
          return {
            statusCode: 502,
            headers: CORS_HEADERS,
            body: JSON.stringify({
              error: 'Case could not be created — please try again or text us at 877-873-3187.',
              detail: caseResult.error?.message || '',
              retryable: true,
            }),
          };
        }

        recordId = caseResult.id;

        // Checkpoint: transition to case_created BEFORE uploads.
        // If this throws OwnershipLostError, the outer catch returns 503 —
        // uploads do not proceed, preventing orphaned attachments on the Case.
        await etagTransition({ state: 'case_created', recordId });
      }
    }

    // ── Step 3: Inspect existing attachments (recovery only) ────────
    // When resuming an existing Case, read the current attachment fields
    // before uploading to avoid creating duplicate attachments.
    // On any read failure: expire the lease (preserving case_created) and
    // return a retryable 503 — never assume populated or empty.
    let existingTicketUpload = false;
    let existingIdUpload     = false;

    if (isRecovery && recordId) {
      let attachReadFailed = false;

      try {
        const caseReadRes = await fetch(
          `https://api.airtable.com/v0/${BASE_ID}/${CASES_TABLE}/${recordId}` +
          `?fields%5B%5D=Ticket%20Upload&fields%5B%5D=ID%20Upload`,
          { headers: atHeaders }
        );
        if (caseReadRes.ok) {
          const caseData = await caseReadRes.json();
          existingTicketUpload =
            Array.isArray(caseData.fields?.['Ticket Upload']) &&
            caseData.fields['Ticket Upload'].length > 0;
          existingIdUpload =
            Array.isArray(caseData.fields?.['ID Upload']) &&
            caseData.fields['ID Upload'].length > 0;
          console.log('Recovery: existing attachments —',
            'ticket:', existingTicketUpload, 'id:', existingIdUpload);
        } else {
          // HTTP error — cannot safely determine attachment state; must retry
          console.warn('Could not read Case attachments (HTTP', caseReadRes.status, ') — expiring lease for retry');
          attachReadFailed = true;
        }
      } catch (e) {
        if (e instanceof OwnershipLostError) throw e; // propagate hard-stop
        // Network error — same safe behavior: must retry
        console.warn('Could not read Case attachments:', e.message, '— expiring lease for retry');
        attachReadFailed = true;
      }

      if (attachReadFailed) {
        // Atomically expire lease (preserving case_created) so the next retry
        // can reacquire ownership and re-read attachment state cleanly.
        // No uploads, no PATCH, no Task decision based on unknown state.
        try { await etagTransition({ leaseExpiresAt: new Date(0).toISOString() }); } catch (_) {}
        return {
          statusCode: 503,
          headers: CORS_HEADERS,
          body: JSON.stringify({
            error: 'Could not verify existing document state — please try again.',
            retryable: true,
          }),
        };
      }
    }

    // ── Step 4: Upload attachments in parallel ───────────────────────
    // Verify ownership before the upload mutations.
    await renewLease();

    const attachmentFields = [
      {
        dataKey:          'ticketPhotoBase64',
        fileName:         data.ticketPhotoName || 'ticket-photo.jpg',
        fieldName:        'Ticket Upload',
        skipForRecovery:  existingTicketUpload,
      },
      {
        dataKey:          'idPhotoBase64',
        fileName:         data.idPhotoName || 'id-photo.jpg',
        fieldName:        'ID Upload',
        skipForRecovery:  existingIdUpload,
      },
    ];

    const uploadTasks = attachmentFields
      .filter(({ dataKey, skipForRecovery }) => !!data[dataKey] && !skipForRecovery)
      .map(({ dataKey, fileName, fieldName }) =>
        (async () => {
          const base64      = data[dataKey];
          const fileData    = base64.includes(',') ? base64.split(',')[1] : base64;
          const contentType = base64.includes('data:')
            ? base64.split(';')[0].replace('data:', '')
            : 'application/octet-stream';
          try {
            const uploadRes = await fetch(
              `https://content.airtable.com/v0/${BASE_ID}/${recordId}` +
              `/${encodeURIComponent(fieldName)}/uploadAttachment`,
              {
                method:  'POST',
                headers: atHeaders,
                body:    JSON.stringify({ contentType, filename: fileName, file: fileData }),
              }
            );
            if (!uploadRes.ok) {
              const errBody = await uploadRes.text();
              console.error(`Attachment upload failed for ${fieldName}:`, errBody);
              throw new Error(fieldName);
            }
          } catch (err) {
            if (err.message !== fieldName) {
              console.error(`Attachment upload error for ${fieldName}:`, err.message);
            }
            throw new Error(fieldName);
          }
        })()
      );

    const uploadResults = await Promise.allSettled(uploadTasks);
    const uploadErrors  = uploadResults
      .filter(r => r.status === 'rejected')
      .map(r => (r.reason && r.reason.message) || String(r.reason));

    // ── Step 4b: Compute final attachment state ─────────────────────
    // For fresh Cases: field is populated only if the upload succeeded.
    // For recovery: field is populated if it already existed OR upload succeeded.
    const hasTicket =
      existingTicketUpload ||
      (!!data.ticketPhotoBase64 && !uploadErrors.includes('Ticket Upload'));
    const hasId =
      existingIdUpload ||
      (!!data.idPhotoBase64 && !uploadErrors.includes('ID Upload'));

    // ── Step 5: PATCH Case with document receipt status ──────────────
    // Verify ownership before the PATCH mutation.
    await renewLease();

    const patchFields = {
      'Ticket Received':         hasTicket,
      'Driver License Received': hasId,
      'Documents Complete':      hasTicket && hasId,
    };

    async function patchDocStatus() {
      const patchRes = await fetch(
        `https://api.airtable.com/v0/${BASE_ID}/${CASES_TABLE}/${recordId}`,
        { method: 'PATCH', headers: atHeaders, body: JSON.stringify({ fields: patchFields }) }
      );
      return patchRes.ok;
    }

    let statusUpdateWarning;
    try {
      const patchOk = await patchDocStatus();
      if (!patchOk) {
        await delay(500);
        const retryOk = await patchDocStatus();
        if (!retryOk) {
          console.warn('Document status PATCH failed after retry for case', effectiveCaseNum);
          statusUpdateWarning = 'Document status could not be updated on the case record — please verify manually.';
        }
      }
    } catch (patchErr) {
      console.warn('Document status PATCH error for case', effectiveCaseNum, '—', patchErr.message);
      statusUpdateWarning = 'Document status could not be updated on the case record — please verify manually.';
    }

    // ── Step 6: Create "Missing Documents" task ──────────────────────
    let taskUpdateWarning;

    if (!hasTicket || !hasId) {
      const tasksTable = process.env.AIRTABLE_TASKS_TABLE_ID;

      if (tasksTable) {
        const missing  = [];
        if (!hasTicket) missing.push('Traffic Ticket');
        if (!hasId)     missing.push('Driver License');

        const todayStr = new Date().toISOString().split('T')[0];

        const taskFields = {
          'Task':           `📄 Missing Documents — ${effectiveCaseNum}`,
          'Status':         'Open',
          'Priority':       priority,
          'Case #':         effectiveCaseNum,
          'Case Record ID': recordId,
          'Notes':          `Missing: ${missing.join(' & ')}. Request from client before processing.`,
          'Created By':     'System (Intake Form)',
          'Created Date':   todayStr,
        };

        // Verify ownership before the Task mutation group
        await renewLease();

        let shouldCreateTask = true;

        if (isRecovery) {
          // Dedup check: search for existing active Missing Documents task.
          // If the search fails for any reason, do NOT create a potentially
          // duplicate task. Surface a taskUpdateWarning instead.
          try {
            const taskFilter    = encodeURIComponent(
              `AND({Case Record ID}="${recordId}",` +
              `{Task}="📄 Missing Documents — ${effectiveCaseNum}",` +
              `{Status}="Open")`
            );
            const taskSearchRes = await fetch(
              `https://api.airtable.com/v0/${BASE_ID}/${tasksTable}` +
              `?filterByFormula=${taskFilter}&maxRecords=1&fields%5B%5D=Task`,
              { headers: atHeaders }
            );

            if (taskSearchRes.ok) {
              const taskSearchData = await taskSearchRes.json();
              if (taskSearchData.records && taskSearchData.records.length > 0) {
                console.log('Recovery: existing Missing Documents task found for', effectiveCaseNum, '— skipping');
                shouldCreateTask = false;
              }
            } else {
              // HTTP error on dedup search — skip creation to avoid duplicates
              console.warn('Task dedup search HTTP error:', taskSearchRes.status, '— skipping task creation');
              shouldCreateTask  = false;
              taskUpdateWarning = 'Missing Documents task dedup check failed — verify the task exists manually.';
            }
          } catch (taskSearchErr) {
            // Network error on dedup search — skip creation to avoid duplicates
            console.warn('Task dedup search error:', taskSearchErr.message, '— skipping task creation');
            shouldCreateTask  = false;
            taskUpdateWarning = 'Missing Documents task dedup check failed — verify the task exists manually.';
          }
        }

        if (shouldCreateTask) {
          try {
            const taskRes = await fetch(
              `https://api.airtable.com/v0/${BASE_ID}/${tasksTable}`,
              { method: 'POST', headers: atHeaders, body: JSON.stringify({ fields: taskFields }) }
            );
            if (!taskRes.ok) {
              const errBody = await taskRes.text();
              console.error('Missing Documents task create failed:', errBody);
            } else {
              console.log('Missing Documents task created for', effectiveCaseNum);
            }
          } catch (taskErr) {
            console.warn('Missing Documents task creation error:', taskErr.message);
          }
        }

      } else {
        console.warn('AIRTABLE_TASKS_TABLE_ID not set — Missing Documents task skipped');
      }
    }

    // ── Step 7: Transition to completed ─────────────────────────────
    // Store only sanitized, non-PII fields in the success response.
    // The taskUpdateWarning is included so staff can act on it without
    // the duplicate request receiving a false "all-clear".
    const successResponse = {
      success:  true,
      caseNum:  effectiveCaseNum,
      recordId,
      ...(uploadErrors.length
        ? { attachmentWarning: `Could not upload: ${uploadErrors.join(', ')}` }
        : {}),
      ...(statusUpdateWarning ? { statusUpdateWarning } : {}),
      ...(taskUpdateWarning   ? { taskUpdateWarning }   : {}),
    };

    // If this throws OwnershipLostError, the outer catch returns 503.
    // All work was completed, but the idempotency record was not finalized.
    // A subsequent retry will take over, read the existing Case/attachments,
    // skip redundant work, and re-attempt the completed transition.
    await etagTransition({ state: 'completed', successResponse });

    return {
      statusCode: 200,
      headers:    CORS_HEADERS,
      body:       JSON.stringify(successResponse),
    };

  } catch (err) {
    // ── Ownership lost — hard stop ─────────────────────────────────
    if (err instanceof OwnershipLostError) {
      console.warn('Ownership lost mid-processing for submission', submissionId, '— stopping');
      return {
        statusCode: 503,
        headers: CORS_HEADERS,
        body: JSON.stringify({
          error: 'Submission was superseded by another request — please try again.',
          retryable: true,
        }),
      };
    }
    // Re-throw unexpected errors (Netlify returns 500 for unhandled rejections)
    throw err;
  }
};
