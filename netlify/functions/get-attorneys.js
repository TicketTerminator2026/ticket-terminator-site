// Ticket Terminator — Fetch all Attorneys from Airtable

const ATTORNEYS_TABLE = 'tbl7Yj3IYYJIpFOVt';

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;

  try {
    const params = new URLSearchParams();
    params.set('pageSize', '100');
    params.set('sort[0][field]', 'Attorney Name');
    params.set('sort[0][direction]', 'asc');

    const res = await fetch(
      `https://api.airtable.com/v0/${base}/${ATTORNEYS_TABLE}?${params}`,
      { headers: { 'Authorization': `Bearer ${key}` } }
    );
    const data = await res.json();
    if (!res.ok) {
      return { statusCode: 502, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: data.error?.message || 'Airtable error' }) };
    }
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
      body: JSON.stringify({ records: data.records || [], total: (data.records || []).length }),
    };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message }) };
  }
};
