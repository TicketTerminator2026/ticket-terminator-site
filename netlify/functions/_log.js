// Shared activity logger — required by other functions
// Usage: const { log } = require('./_log');

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
  // Fire-and-forget — never blocks main response
  fetch('https://api.airtable.com/v0/' + base + '/' + ACTIVITY_TABLE, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields }),
  }).catch(() => {});
}

module.exports = { log };
