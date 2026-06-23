// Ticket Terminator — Fetch All Cases from Airtable
// Paginates through ALL records (Airtable max 100/page), sorted newest first.
// Caps at 2,000 records for dashboard performance; returns truncated:true if more exist.

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const base  = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_ID;
  const key   = process.env.AIRTABLE_API_KEY;

  if (!base || !table || !key) {
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Missing Airtable env vars (AIRTABLE_BASE_ID / AIRTABLE_TABLE_ID / AIRTABLE_API_KEY)' }),
    };
  }

  const atHeaders = { 'Authorization': `Bearer ${key}` };
  const MAX_RECORDS = 2000; // safety cap for dashboard perf

  const allRecords = [];
  let offset = null;

  try {
    do {
      // Build query params
      const params = new URLSearchParams();
      params.set('pageSize', '100');
      params.set('sort[0][field]',     'Date Submitted');
      params.set('sort[0][direction]', 'desc');
      if (offset) params.set('offset', offset);

      const url = `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}?${params}`;
      const res = await fetch(url, { headers: atHeaders });

      if (!res.ok) {
        const errText = await res.text();
        console.error('Airtable fetch error:', errText);
        return {
          statusCode: 502,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'Airtable fetch failed', detail: errText }),
        };
      }

      const page = await res.json();
      allRecords.push(...(page.records || []));
      offset = page.offset || null;

    } while (offset && allRecords.length < MAX_RECORDS);

    const truncated = !!(offset && allRecords.length >= MAX_RECORDS);

    return {
      statusCode: 200,
      headers: {
        'Content-Type':  'application/json',
        'Cache-Control': 'no-cache, no-store',
      },
      body: JSON.stringify({
        records:   allRecords,
        total:     allRecords.length,
        truncated, // true when more than 2,000 records exist
      }),
    };

  } catch (err) {
    console.error('get-cases error:', err.message);
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message }),
    };
  }
};
