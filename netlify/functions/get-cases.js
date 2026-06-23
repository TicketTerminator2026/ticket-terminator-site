// Ticket Terminator — Secure Airtable GET proxy
// API key lives in Netlify env vars, never exposed to the browser.

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const base  = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_ID;
  const key   = process.env.AIRTABLE_API_KEY;

  const headers = {
    'Authorization': `Bearer ${key}`,
  };

  // Fetch all pages (Airtable returns max 100 per page)
  let allRecords = [];
  let offset = null;

  try {
    do {
      const params = new URLSearchParams({ maxRecords: '500' });
      if (offset) params.set('offset', offset);

      const res = await fetch(
        `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}?${params}`,
        { headers }
      );

      if (!res.ok) {
        const err = await res.text();
        console.error('Airtable GET error:', err);
        return {
          statusCode: 500,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'Airtable fetch failed', detail: err }),
        };
      }

      const data = await res.json();
      allRecords = allRecords.concat(data.records || []);
      offset = data.offset || null;

    } while (offset);

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache',
      },
      body: JSON.stringify({ records: allRecords, total: allRecords.length }),
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
