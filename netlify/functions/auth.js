// Ticket Terminator — DEPRECATED legacy dashboard authentication
//
// This endpoint previously exchanged a single shared DASHBOARD_PASSWORD for a
// token that carried no staff identity. It has been retired in favour of
// staff-auth.js, which issues per-user, identity-bearing tokens backed by
// per-account PBKDF2 password hashes.
//
// Phase 0: the endpoint is neutralised — it no longer accepts DASHBOARD_PASSWORD
// and no longer issues or verifies tokens. Every method returns 410 Gone.
//
// The file is intentionally retained (not deleted) so the route resolves with a
// clear, deliberate response instead of a 404, and so the change is auditable.
// Legacy identity-less tokens are additionally rejected by _verify-token.js,
// which requires staffId, email and a known role on every private endpoint.

'use strict';

const GONE_HEADERS = {
  'Content-Type': 'application/json',
  'Cache-Control': 'no-store',
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: GONE_HEADERS, body: '' };
  }

  return {
    statusCode: 410,
    headers: GONE_HEADERS,
    body: JSON.stringify({
      error: 'This endpoint has been retired. Please sign in through the staff login page.',
    }),
  };
};
