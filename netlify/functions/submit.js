// Ticket Terminator — Secure Form → Airtable Function
// API key lives in Netlify env vars, never in the HTML.
// Updated: client dedup, priority auto-set, all form fields mapped.

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  let data;
  try {
    data = JSON.parse(event.body);
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid request body' }) };
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
  // Uses last 5 digits of timestamp to avoid collisions while staying readable
  const year    = new Date().getFullYear();
  const seq     = Date.now().toString().slice(-5);
  const caseNum = `TT-${year}-${seq}`;

  // ── Violation type → Airtable Case Type ──────────────────────────────────
  // NOTE: form value is 'DUI/DWI' (no spaces), Airtable option is '🚨 DUI / DWI'
  const caseTypeMap = {
    'Speeding':      '🚗 Traffic Citation',
    'Red Light':     '🚗 Traffic Citation',
    'Stop Sign':     '🚗 Traffic Citation',
    'Reckless':      '🚗 Traffic Citation',
    'Cell Phone':    '🚗 Traffic Citation',
    'Fix-It Ticket': '🚗 Traffic Citation',
    'Other':         '🚗 Traffic Citation',
    'DUI/DWI':       '🚨 DUI / DWI',   // Fixed: was '🍺 DUI' which doesn't match Airtable
    'DUI / DWI':     '🚨 DUI / DWI',   // Fallback for any variant
  };

  // ── Auto-set Priority ────────────────────────────────────────────────────
  const isDUI      = (data.violationType || '').toUpperCase().includes('DUI');
  const hasCDL     = data.cdl === 'yes';
  const isPastDue  = data.pastDue === 'yes';
  const hasCourt   = !!(data.courtDate);
  let priority;
  if (isDUI || hasCDL || isPastDue) {
    priority = '🔴 High';
  } else if (hasCourt) {
    priority = '🟡 Medium';
  } else {
    priority = '🟢 Low';
  }

  // ── Preferred contact label ──────────────────────────────────────────────
  const contactMap = { phone: 'Phone Call', text: 'Text / SMS', email: 'Email' };
  const preferredContact = contactMap[data.preferredContact] || null;

  // ── Past due / already paid labels ───────────────────────────────────────
  const pastDueMap = { yes: 'Yes', no: 'No', unsure: 'Not Sure' };
  const paidMap    = { yes: 'Yes — Paid', no: 'Not Yet' };
  const pastDueVal = pastDueMap[data.pastDue]  || null;
  const paidVal    = paidMap[data.alreadyPaid] || null;

  // ── Build Cases fields object ─────────────────────────────────────────────
  const caseFields = {
    'Case #':           caseNum,
    'Status':           '🔵 Lead',
    'Quote Status':     'Not Requested',
    'Case Type':        caseTypeMap[data.violationType] || '🚗 Traffic Citation',
    'Priority':         priority,
    'Date Submitted':   new Date().toISOString().split('T')[0],
    'Citation / Arrest #': data.citationNum || '',

    // Client contact (kept denormalized on Case for quick access)
    'First Name':  data.firstName || '',
    'Last Name':   data.lastName  || '',
    'Phone':       data.phone     || '',
    'Email':       data.email     || '',
    'CDL Holder':  data.cdl === 'yes',

    // Violation
    'Violation Description':         data.violationDesc    || '',
    'Traffic School Past 18 Months?': data.trafficSchool === 'yes',
    'Client Statement':              data.story            || '',

    // Location
    'Court Location': data.courtLocation || '',
    'Court State':    data.state         || '',
    'County':         data.county        || '',

    // New intake fields
    ...(preferredContact ? { 'Preferred Contact':      preferredContact } : {}),
    ...(pastDueVal        ? { 'Past Due / Collections': pastDueVal       } : {}),
    ...(paidVal           ? { 'Ticket Already Paid':    paidVal          } : {}),

    // Source
    'Heard About Us': data.heardAbout || '',
    'Referred By':    data.referredBy || '',
  };

  // Optional dates — Airtable rejects empty strings on date fields
  if (data.violationDate) caseFields['Date of Violation'] = data.violationDate;
  if (data.courtDate)     caseFields['Court Date']        = data.courtDate;

  // Strip empty strings / nulls so Airtable doesn't complain
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
      searchFilter = `OR(LOWER({Email})="${rawEmail}", REGEX_REPLACE(REGEX_REPLACE({Phone},"[^0-9]",""),"","")="${rawPhone}")`;
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

      if (searchData.records && searchData.records.length > 0) {
        // Existing client found — reuse
        clientId = searchData.records[0].id;
      } else {
        // New client — create
        const clientRes = await fetch(
          `https://api.airtable.com/v0/${BASE_ID}/${CLIENTS_TABLE}`,
          {
            method: 'POST',
            headers: atHeaders,
            body: JSON.stringify({
              fields: {
                'Client Name': `${data.firstName || ''} ${data.lastName || ''}`.trim(),
                'Phone': data.phone || '',
                'Email': data.email || '',
              },
            }),
          }
        );
        const clientData = await clientRes.json();
        if (clientData.id) clientId = clientData.id;
      }
    }
  } catch (e) {
    // Non-fatal: case is still created, just without client link
    console.warn('Client lookup/create failed:', e.message);
  }

  // Link client to case
  if (clientId) {
    caseFields['Client'] = [clientId];  }

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
        statusCode: 500,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          error: 'Airtable rejected the record',
          detail: result.error?.message || JSON.stringify(result),
        }),
      };
    }

    recordId = result.id;

  } catch (err) {
    console.error('Network error:', err.message);
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Server error — please try again' }),
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
    headers: { 'Content-Type': 'application/json' },
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
