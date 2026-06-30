// Ticket Terminator — save-document.js
// Creates or updates a record in Case Documents or Document Templates
//
// POST /.netlify/functions/save-document
// Body: {
//   table:    'case-docs' | 'templates'
//   recordId: string (optional — omit to create, include to update)
//   fields:   { [fieldName]: value }
// }

const TABLE_IDS = {
  'case-docs': 'tblfYr2UCNJSikhjp',
  'templates': 'tblKlrzPFTVmmGDCa',
};

exports.handler = async function(event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const baseId = process.env.AIRTABLE_BASE_ID;
  const apiKey = process.env.AIRTABLE_API_KEY;

  // ── Parse body ──────────────────────────────────────
  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return { statusCode: 400, body: JSON.stringify({ error: 'Invalid JSON body' }) }; }

  const { table, recordId, fields } = body;

  if (!table || !TABLE_IDS[table]) {
    return { statusCode: 400, body: JSON.stringify({ error: `Invalid table: "${table}". Use "case-docs" or "templates".` }) };
  }
  if (!fields || typeof fields !== 'object') {
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing or invalid fields object' }) };
  }

  const tableId = TABLE_IDS[table];
  const url     = recordId
    ? `https://api.airtable.com/v0/${baseId}/${tableId}/${recordId}`
    : `https://api.airtable.com/v0/${baseId}/${tableId}`;
  const method  = recordId ? 'PATCH' : 'POST';

  // ── Call Airtable ────────────────────────────────────
  try {
    const res = await fetch(url, {
      method,
      headers: {
        'Authorization':  `Bearer ${apiKey}`,
        'Content-Type':   'application/json',
      },
      body: JSON.stringify({ fields }),
    });

    const data = await res.json();
    if (!res.ok) {
      console.error('[save-document] Airtable error:', data);
      return { statusCode: res.status, body: JSON.stringify(data) };
    }

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    };
  } catch(e) {
    console.error('[save-document]', e.message);
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
