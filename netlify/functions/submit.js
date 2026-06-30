// Ticket Terminator — Secure Form → Airtable Function
// API key lives in Netlify env vars, never in the HTML.
// Updated: CORS headers, retry-safe responses, DUI/speeding fields, input validation.

const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

exports.handler = async function (event) {
  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS_HEADERS, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: CORS_HEADERS, body: JSON.stringify({ error: 'Method Not Allowed' }) };
  }

  // ── Request body size guard (Netlify limit is 6MB, base64 photos can be large)
  const bodyLen = event.body ? event.body.length : 0;
  if (bodyLen > 5 * 1024 * 1024) {
    return {
      statusCode: 413,
      headers: CORS_HEADERS,
      body: JSON.stringify({ error: 'Request too large. Please upload smaller photos (compress to under 4MB each).' }),
    };
  }

  let data;
  try {
    data = JSON.parse(event.body);
  } catch (e) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: 'Invalid request body' }) };
  }

  // ── Basic server-side validation ─────────────────────────────────────────
  if (!data.firstName || !data.lastName) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: 'First and last name are required' }) };
  }
  if (!data.phone || data.phone.replace(/\D/g,'').length < 10) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: 'A valid phone number is required' }) };
  }
  if (!data.email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(data.email)) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: 'A valid email address is required' }) };
  }

  const BASE_ID       = process.env.AIRTABLE_BASE_ID;
  const CASES_TABLE   = process.env.AIRTABLE_TABLE_ID; // Cases table ID or name
  const CLIENTS_TABLE = 'tblqNIl5A1QUQqrus';           // Clients table (hard-coded stable ID)
  const API_KEY       = process.env.AIRTABLE_API_KEY;

  const atHeaders = {
    'Authorization': `Bearer ${API_KEY}`,
    'Content-Type':  'application/json',
  };

  // ── Case number: TT-YYYY-NNNNN ───────────────────────────────────────────
  const year    = new Date().getFullYear();
  const seq     = Date.now().toString().slice(-5);
  const caseNum = `TT-${year}-${seq}`;

  // ── Violation type → Airtable Case Type ──────────────────────────────────
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

  // ── Auto-set Priority ────────────────────────────────────────────────────
  const isDUI     = (data.violationType || '').toUpperCase().includes('DUI');
  const hasCDL    = data.cdl === 'yes';
  const isPastDue = data.pastDue === 'yes';
  const hasCourt  = !!(data.courtDate);
  let priority;
  if (isDUI || hasCDL || isPastDue) {
    priority = '🔴 High';
  } else if (hasCourt) {
    priority = '🟡 Medium';
  } else {
    priority = '🟢 Low';
  }

  // ── Label maps ───────────────────────────────────────────────────────────
  const contactMap = { phone: 'Phone Call', text: 'Text / SMS', email: 'Email' };
  const pastDueMap = { yes: 'Yes', no: 'No', unsure: 'Not Sure' };
  const paidMap    = { yes: 'Yes — Paid', no: 'Not Yet' };
  const bacMap     = {
    yes_breathalyzer: 'Yes — Breathalyzer',
    yes_blood:        'Yes — Blood Test',
    refused:          'Refused',
    no:               'No Test Given',
  };
  const fstMap     = { yes: 'Yes', no: 'No', refused: 'Refused' };

  const preferredContact = contactMap[data.preferredContact] || null;
  const pastDueVal       = pastDueMap[data.pastDue] || null;
  const paidVal          = paidMap[data.alreadyPaid] || null;
  const bacVal           = bacMap[data.bac] || null;
  const fstVal           = fstMap[data.fst] || null;

  // ── Build DUI-specific notes block ──────────────────────────────────────
  let duiNotes = '';
  if (isDUI) {
    const parts = [];
    if (bacVal)          parts.push(`BAC Test: ${bacVal}`);
    if (data.bacResult)  parts.push(`BAC Result: ${data.bacResult}`);
    if (fstVal)          parts.push(`Field Sobriety Test: ${fstVal}`);
    if (parts.length)    duiNotes = parts.join(' | ');
  }

  // ── Build Speeding notes block ───────────────────────────────────────────
  let speedNotes = '';
  if ((data.violationType || '').toLowerCase() === 'speeding') {
    const parts = [];
    if (data.speedAlleged) parts.push(`Alleged: ${data.speedAlleged} mph`);
    if (data.speedLimit)   parts.push(`Posted limit: ${data.speedLimit} mph`);
    if (parts.length)      speedNotes = parts.join(' | ');
  }

  // ── Combine statement with violation-specific notes ──────────────────────
  const clientStatementParts = [];
  if (data.story)    clientStatementParts.push(data.story);
  if (duiNotes)      clientStatementParts.push(`[DUI Details] ${duiNotes}`);
  if (speedNotes)    clientStatementParts.push(`[Speed Details] ${speedNotes}`);
  const clientStatement = clientStatementParts.join('\n\n');

  // ── Build Cases fields object ────────────────────────────────────────────
  const caseFields = {
    'Case #':            caseNum,
    'Status':            '🔵 Lead',
    'Quote Status':      'Not Requested',
    'Case Type':         caseTypeMap[data.violationType] || '🚗 Traffic Citation',
    'Priority':          priority,
    'Date Submitted':    new Date().toISOString().split('T')[0],
    'Citation / Arrest #': data.citationNum || '',

    // Client contact (denormalized on Case for quick access)
    'First Name':  data.firstName || '',
    'Last Name':   data.lastName  || '',
    'Phone':       data.phone     || '',
    'Email':       data.email     || '',
    'CDL Holder':  data.cdl === 'yes',

    // Violation
    'Violation Description':          data.violationDesc   || '',
    'Traffic School Past 18 Months?': data.trafficSchool === 'yes',
    'Client Statement':               clientStatement,

    // Location
    'Court Location': data.courtLocation || '',
    'Court State':    data.state         || '',
    'County':         data.county        || '',

    // Contact/financial
    ...(preferredContact ? { 'Preferred Contact':      preferredContact } : {}),
    ...(pastDueVal        ? { 'Past Due / Collections': pastDueVal       } : {}),
    ...(paidVal           ? { 'Ticket Already Paid':    paidVal          } : {}),

    // Source
    'Heard About Us': data.heardAbout || '',
    'Referred By':    data.referredBy || '',

    // Document tracking (checkbox fields in Airtable)
    // Set to true only when the upload was actually provided
    'Ticket Received':         !!(data.ticketPhotoBase64),
    'Driver License Received': !!(data.idPhotoBase64),
    'Documents Complete':      !!(data.ticketPhotoBase64) && !!(data.idPhotoBase64),
  };

  // Optional dates — Airtable rejects empty strings on date fields
  if (data.violationDate) caseFields['Date of Violation'] = data.violationDate;
  if (data.courtDate)     caseFields['Court Date']        = data.courtDate;

  // Strip empty strings / nulls
  Object.keys(caseFields).forEach(k => {
    if (caseFields[k] === '' || caseFields[k] === null || caseFields[k] === undefined) {
      delete caseFields[k];
    }
  });

  // ── Step 1: Find or create Client record (dedup by phone + email) ────────
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
      const searchRes = await fetch(
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
        const clientFields = {
          'Client Name': `${data.firstName || ''} ${data.lastName || ''}`.trim() || 'Unknown',
        };
        if (data.phone) clientFields['Phone'] = data.phone;
        if (data.email) clientFields['Email'] = data.email;

        const clientRes = await fetch(
          `https://api.airtable.com/v0/${BASE_ID}/${CLIENTS_TABLE}`,
          {
            method: 'POST',
            headers: atHeaders,
            body: JSON.stringify({ fields: clientFields }),
          }
        );
        const clientData = await clientRes.json();
        console.log('Client create result:', JSON.stringify(clientData).substring(0, 200));
        if (clientData.id && typeof clientData.id === 'string') clientId = clientData.id;
      }
    }
  } catch (e) {
    // Non-fatal — case is still created, just without client link
    console.warn('Client lookup/create failed:', e.message);
  }

  // Link client to case — Airtable v0 requires plain string array
  if (clientId && typeof clientId === 'string' && clientId.startsWith('rec')) {
    caseFields['Client'] = [clientId];
  }

  // ── Step 2: Create the Case record ───────────────────────────────────────
  let recordId;
  try {
    const res = await fetch(
      `https://api.airtable.com/v0/${BASE_ID}/${CASES_TABLE}`,
      {
        method: 'POST',
        headers: atHeaders,
        body: JSON.stringify({ fields: caseFields }),
      }
    );
    const result = await res.json();

    if (!res.ok) {
      console.error('Airtable create error:', JSON.stringify(result));
      return {
        statusCode: 502,
        headers: CORS_HEADERS,
        body: JSON.stringify({
          error: 'Case could not be created — please try again or text us at 877-873-3187.',
          detail: result.error?.message || JSON.stringify(result),
          retryable: true,
        }),
      };
    }

    recordId = result.id;

  } catch (err) {
    console.error('Network error:', err.message);
    return {
      statusCode: 503,
      headers: CORS_HEADERS,
      body: JSON.stringify({
        error: 'Network error — please try again. Your form data is saved locally.',
        retryable: true,
      }),
    };
  }

  // ── Step 3: Upload attachments ────────────────────────────────────────────
  const attachmentFields = [
    { dataKey: 'ticketPhotoBase64', fileName: data.ticketPhotoName || 'ticket-photo.jpg', fieldName: 'Ticket Upload' },
    { dataKey: 'idPhotoBase64',     fileName: data.idPhotoName     || 'id-photo.jpg',     fieldName: 'ID Upload'     },
  ];
  const uploadErrors = [];

  for (const { dataKey, fileName, fieldName } of attachmentFields) {
    const base64 = data[dataKey];
    if (!base64) continue;

    const fileData    = base64.includes(',') ? base64.split(',')[1] : base64;
    const contentType = base64.includes('data:')
      ? base64.split(';')[0].replace('data:', '')
      : 'application/octet-stream';

    try {
      const uploadRes = await fetch(
        `https://content.airtable.com/v0/${BASE_ID}/${recordId}` +
        `/${encodeURIComponent(fieldName)}/uploadAttachment`,
        {
          method: 'POST',
          headers: atHeaders,
          body: JSON.stringify({ contentType, filename: fileName, file: fileData }),
        }
      );
      if (!uploadRes.ok) {
        const errBody = await uploadRes.text();
        console.error(`Attachment upload failed for ${fieldName}:`, errBody);
        uploadErrors.push(fieldName);
      }
    } catch (err) {
      console.error(`Attachment upload error for ${fieldName}:`, err.message);
      uploadErrors.push(fieldName);
    }
  }

  // ── Return success ────────────────────────────────────────────────────────
  return {
    statusCode: 200,
    headers: CORS_HEADERS,
    body: JSON.stringify({
      success: true,
      caseNum,
      recordId,
      ...(uploadErrors.length
        ? { attachmentWarning: `Could not upload: ${uploadErrors.join(', ')}` }
        : {}),
    }),
  };
};
