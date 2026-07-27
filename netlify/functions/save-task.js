// Ticket Terminator — Create or update a Task
// POST { fields } → create | PATCH { recordId, fields } → update
//
// PRIVATE ENDPOINT — requires a valid X-Staff-Token.
// AUTHORIZATION (Phase 0): Employee, Manager and Admin may write; Read Only is
// blocked. Explicit positive field allowlist. Created By / Created Date /
// Completed Date are set server-side and cannot be supplied by the caller.

'use strict';

const { log } = require('./_log');
const {
  requireAuth, canWrite, parseJsonBody, enforceFields,
  jsonResponse, forbidden, badRequest, serverError, upstreamError, methodNotAllowed,
  TASK_FIELDS,
} = require('./_verify-token');

const TASKS_TABLE = 'tblvwrl2hPjUjbUkC';

exports.handler = async function (event) {
  const isCreate = event.httpMethod === 'POST';
  const isUpdate = event.httpMethod === 'PATCH';
  if (!isCreate && !isUpdate) return methodNotAllowed();

  // ── 1. Authenticate ───────────────────────────────────────────────────────
  const auth = requireAuth(event);
  if (!auth.ok) return auth.response;
  const staff = auth.staff;

  // ── 2. Read Only cannot write ─────────────────────────────────────────────
  if (!canWrite(staff)) return forbidden('Your role does not permit changes.');

  // ── 3. Parse body ─────────────────────────────────────────────────────────
  const parsed = parseJsonBody(event);
  if (!parsed.ok) return parsed.response;

  const { recordId } = parsed.body;
  const submitted = parsed.body.fields || {};

  if (isUpdate && (typeof recordId !== 'string' || !recordId.startsWith('rec'))) {
    return badRequest('A valid task record reference is required.');
  }

  // ── 4. Field allowlist — BEFORE any Airtable call ─────────────────────────
  const gate = enforceFields('save-task', submitted, TASK_FIELDS);
  if (!gate.ok) return gate.response;

  const fields = { ...submitted };

  // Server-controlled metadata.
  if (isCreate) {
    fields['Created By']   = staff.name;
    fields['Created Date'] = new Date().toISOString();
    if (!fields['Status']) fields['Status'] = 'Open';
  }
  if (fields['Status'] === 'Done' && !fields['Completed Date']) {
    fields['Completed Date'] = new Date().toISOString();
  }

  const base = process.env.AIRTABLE_BASE_ID;
  const key  = process.env.AIRTABLE_API_KEY;
  const env  = { base, key };
  if (!base || !key) {
    console.error('[save-task] Missing Airtable environment configuration.');
    return serverError();
  }

  const clean = {};
  Object.entries(fields).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== '') clean[k] = v;
    if (v === false || v === 0) clean[k] = v;
  });

  const url = isCreate
    ? `https://api.airtable.com/v0/${base}/${TASKS_TABLE}`
    : `https://api.airtable.com/v0/${base}/${TASKS_TABLE}/${encodeURIComponent(recordId)}`;

  try {
    const res = await fetch(url, {
      method: isCreate ? 'POST' : 'PATCH',
      headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields: clean }),
    });
    const data = await res.json();
    if (!res.ok) {
      console.error('[save-task] Airtable error:', res.status, data && data.error && data.error.message);
      return upstreamError();
    }

    await log(env, {
      staffName: staff.name, staffId: staff.staffId,
      action: isCreate ? `Created task: ${clean['Task'] || ''}` : `Updated task: ${clean['Task'] || recordId}`,
      category: 'Task',
      caseNum: clean['Case #'], caseId: clean['Case Record ID'],
      field: isCreate ? 'Task Created' : 'Task Updated',
      oldVal: '', newVal: clean['Status'] || '',
    });

    return jsonResponse(200, { success: true, record: data });
  } catch (err) {
    console.error('[save-task] error:', err.message);
    return serverError();
  }
};
