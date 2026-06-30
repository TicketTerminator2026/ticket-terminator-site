// Shared activity logger — imported by other functions
// Usage: await log(env, { staffName, staffId, action, category, caseNum, caseId, field, oldVal, newVal, notes })
// Returns the fetch promise so callers can await it (prevents write being killed when function returns).

const ACTIVITY_TABLE = 'tblHAOnm8Qu1d7iKT';

async function log(env, opts) {
  const { base, key } = env;
  const fields = {
    'Action':          opts.action || '',
    'Staff Name':      opts.staffName || 'System',
    'Case #':          opts.caseNum || '',
    'Field Changed':   opts.field || '',
    'Old Value':       opts.oldVal != null ? String(opts.oldVal) : '',
    'New Value':       opts.newVal != null ? String(opts.newVal) : '',
    'Timestamp':       new Date().toISOString(),
    'Category':        opts.category || 'Case',
    'Notes':           opts.notes || '',
    'Staff Record ID': opts.staffId || '',
    'Case Record ID':  opts.caseId || '',
  };
  // Return the promise so callers can await it — do NOT fire-and-forget.
  // Errors are swallowed so logging never throws and breaks the main operation.
  return fetch(`https://api.airtable.com/v0/${base}/${ACTIVITY_TABLE}`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields }),
  }).catch(() => {}); // swallow errors silently
}

module.exports = { log };
