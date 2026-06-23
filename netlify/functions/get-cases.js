exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }
  const base  = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_ID;
  const key   = process.env.AIRTABLE_API_KEY;

  // Debug: show partial values to diagnose
  const debug = {
    base_prefix: base ? base.slice(0, 8) + '...' : 'MISSING',
    table_value: table || 'MISSING',
    key_prefix:  key  ? key.slice(0, 8) + '...' : 'MISSING',
  };

  const headers = { 'Authorization': `Bearer ${key}` };
  const params = new URLSearchParams({ maxRecords: '100' });
  const url = `https://api.airtable.com/v0/${base}/${encodeURIComponent(table)}?${params}`;

  try {
    const res = await fetch(url, { headers });
    if (!res.ok) {
      const err = await res.text();
      return {
        statusCode: 500,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Airtable fetch failed', detail: err, debug, url_called: url.replace(key || '', '[KEY]') }),
      };
    }
    const data = await res.json();
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
      body: JSON.stringify({ records: data.records || [], total: (data.records || []).length }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message, debug }),
    };
  }
};
