// Ticket Terminator — Secure Form → Airtable Function
// API key lives in Netlify env vars, never in the HTML.

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

  const year = new Date().getFullYear();
  const rand = String(Math.floor(Math.random() * 9000) + 1000);
  const caseNum = `TT-${year}-${rand}`;

  const caseTypeMap = {
    'Speeding':         '🚗 Traffic Citation',
    'Red Light':        '🚗 Traffic Citation',
    'Stop Sign':        '🚗 Traffic Citation',
    'Reckless Driving': '🚗 Traffic Citation',
    'No Insurance':     '🚗 Traffic Citation',
    'Cell Phone':       '🚗 Traffic Citation',
    'DUI / DWI':        '🍺 DUI',
    'Other':            '🚗 Traffic Citation',
  };

  const fields = {
    'Case #':                        caseNum,
    'Status':                        'Lead',
    'Case Type':                     caseTypeMap[data.violationType] || '🚗 Traffic Citation',
    'Date of Intake':                new Date().toISOString().split('T')[0],
    'First Name':                    data.firstName  || '',
    'Last Name':                     data.lastName   || '',
    'Phone':                         data.phone      || '',
    'Email':                         data.email      || '',
    'Client State':                  data.state      || '',
    'CDL Holder':                    data.cdl === 'yes',
    'Violation Code':                data.violationDesc || data.violationType || '',
    'Court Location':                data.courtLocation || '',
    'Court State':                   data.state || '',
    'County':                        data.county || '',
    'Traffic School Past 18 Months?': data.trafficSchool === 'yes',
    'Client Statement':              data.story || '',
    'Heard About Us':                data.heardAbout  || '',
    'Referred By':                   data.referredBy  || '',
  };

  if (data.violationDate) fields['Date of Violation'] = data.violationDate;
  if (data.courtDate)     fields['Court Date']        = data.courtDate;

  Object.keys(fields).forEach(k => { if (fields[k] === '' || fields[k] === null) delete fields[k]; });

  let recordId;
  try {
    const res = await fetch(
      `https://api.airtable.com/v0/${process.env.AIRTABLE_BASE_ID}/${process.env.AIRTABLE_TABLE_ID}`,
      {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${process.env.AIRTABLE_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields }),
      }
    );
    const result = await res.json();
    if (!res.ok) {
      console.error('Airtable error:', JSON.stringify(result));
      return { statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Airtable rejected the record', detail: result.error?.message }) };
    }
    recordId = result.id;
  } catch (err) {
    console.error('Network error:', err.message);
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Server error — please try again' }) };
  }

  const attachmentFields = [
    { dataKey: 'ticketPhotoBase64', fileName: data.ticketPhotoName || 'ticket-photo.jpg', fieldName: 'Ticket Upload' },
    { dataKey: 'idPhotoBase64',     fileName: data.idPhotoName     || 'id-photo.jpg',     fieldName: 'ID Upload'     },
  ];
  const uploadErrors = [];
  for (const { dataKey, fileName, fieldName } of attachmentFields) {
    const base64 = data[dataKey];
    if (!base64) continue;
    const fileData = base64.includes(',') ? base64.split(',')[1] : base64;
    const contentType = base64.includes('data:') ? base64.split(';')[0].replace('data:', '') : 'application/octet-stream';
    try {
      const uploadRes = await fetch(
        `https://content.airtable.com/v0/${process.env.AIRTABLE_BASE_ID}/${recordId}/${encodeURIComponent(fieldName)}/uploadAttachment`,
        { method: 'POST', headers: { 'Authorization': `Bearer ${process.env.AIRTABLE_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ contentType, filename: fileName, file: fileData }) }
      );
      if (!uploadRes.ok) { const e = await uploadRes.text(); console.error(`Upload failed for ${fieldName}:`, e); uploadErrors.push(fieldName); }
    } catch (err) { console.error(`Upload error for ${fieldName}:`, err.message); uploadErrors.push(fieldName); }
  }

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ success: true, caseNum, recordId, ...(uploadErrors.length ? { attachmentWarning: `Could not upload: ${uploadErrors.join(', ')}` } : {}) }),
  };
};
