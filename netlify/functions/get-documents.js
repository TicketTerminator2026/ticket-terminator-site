// Ticket Terminator — get-documents.js
// Returns case documents and/or document templates from Airtable
// GET /.netlify/functions/get-documents?type=all|case-docs|templates&caseId=recXXX

exports.handler = async function(event) {
  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const baseId  = process.env.AIRTABLE_BASE_ID;
  const apiKey  = process.env.AIRTABLE_API_KEY;
  const headers = { 'Authorization': `Bearer ${apiKey}` };

  const params  = event.queryStringParameters || {};
  const type    = params.type   || 'all';    // 'all' | 'case-docs' | 'templates'
  const caseId  = params.caseId || '';       // optional — filter case docs by case record ID

  // ── Paginated fetch helper ───────────────────────────
  async function fetchAll(tableId, filterFormula) {
    const records = [];
    let offset = '';
    do {
      let url = `https://api.airtable.com/v0/${baseId}/${tableId}?pageSize=100`;
      if (filterFormula) url += `&filterByFormula=${encodeURIComponent(filterFormula)}`;
      if (offset)        url += `&offset=${encodeURIComponent(offset)}`;
      const res = await fetch(url, { headers });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(`Airtable ${res.status}: ${errData.error?.message || res.statusText}`);
      }
      const data = await res.json();
      records.push(...(data.records || []));
      offset = data.offset || '';
    } while (offset);
    return records;
  }

  try {
    const result = {};

    // ── Case Documents (tblfYr2UCNJSikhjp) ──
    if (type === 'case-docs' || type === 'all') {
      const filter = caseId
        ? `FIND("${caseId.replace(/"/g, '')}",ARRAYJOIN({Case})) > 0`
        : '';
      result.caseDocs = await fetchAll('tblfYr2UCNJSikhjp', filter);
    }

    // ── Document Templates (tblKlrzPFTVmmGDCa) ──
    if (type === 'templates' || type === 'all') {
      result.templates = await fetchAll('tblKlrzPFTVmmGDCa', '');
    }

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      body: JSON.stringify(result),
    };
  } catch(e) {
    console.error('[get-documents]', e.message);
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
