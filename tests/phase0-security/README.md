# Phase 0 Security Tests

Automated security regression suite for the Ticket Terminator staff dashboard and
its private Netlify functions. Added with the `phase-0-security` work that
introduced `netlify/functions/_verify-token.js` and closed the unauthenticated /
forgeable-token endpoints.

These tests exist so the Phase 0 guarantees cannot silently regress.

---

## ⚠️ Never run these against production

- They use **mock credentials only** and a **non-existent Airtable base**
  (`appMOCKTESTBASE00` / `tblMOCKCASES00000`) with a throwaway HMAC secret.
- `global.fetch` is **stubbed**, so no HTTP request ever leaves the process.
- The stub **throws** if the real production base ID is referenced, which is
  itself one of the assertions.
- **Do not** supply real `AIRTABLE_API_KEY`, `DASHBOARD_TOKEN_SECRET`,
  `STRIPE_SECRET_KEY` or any other production value when running them.
- They create no records, send no email or SMS, and open no Stripe session.

Everything the suite needs is generated at runtime. There are no secrets,
tokens, API keys, environment values, client data or Airtable exports in this
folder, and none should ever be added.

---

## What each file checks

### `phase0-harness.js` — server-side function security (453 tests)

Loads each Netlify function directly and asserts, for every private endpoint:

- **Authentication** — rejects: no token, forged "Admin" tokens (both unsigned
  and well-formed-hex), tampered signatures, tokens signed with the wrong
  secret, expired tokens, unknown roles, tokens missing `staffId` or `email`,
  and legacy identity-less tokens from the retired `auth.js`.
- **Auth precedes data access** — asserts that no Airtable request is issued on
  any rejection path.
- **Fail-closed** — with `DASHBOARD_TOKEN_SECRET` absent, every endpoint fails
  closed and never names the environment variable in its response.
- **Roles** — Read Only may read but never write; Employee may do ordinary
  operational writes but not financial ones; Manager administers attorneys and
  document templates but not staff; Admin administers staff.
- **Field allowlists** — unapproved field names reject the *whole* request with
  403 before Airtable is contacted, mixed payloads cannot partially bypass, and
  no role (including Admin) has a wildcard.
- **Activity-log scoping** — Read Only denied; Employee case-scoped only and
  blocked from Payment/Staff/Security; Manager blocked from Staff/Security;
  category exclusions are embedded in the Airtable query itself.
- **Injection & URLs** — Airtable formula values are escaped; `File URL` must be
  `http(s)`.
- **Error hygiene** — raw Airtable messages, table IDs and internal detail never
  reach the client.
- **Public surface unchanged** — `submit.js` still public, `config.js` exposes
  only feature flags, `staff-auth.js` still serves login, `stripe-webhook.js`
  stays signature-authenticated and kill-switched, and `auth.js` returns 410.

### `phase0-dashboard-tests.js` — client-side security (97 tests)

Extracts the real shipped helpers and functions from `dashboard.html` and
exercises them:

- **Output encoding** — `esc()` / `_esc()` neutralise HTML; `jsAttr()` output
  cannot break out of a single-quoted JS string in an inline handler.
- **URL scheme allowlist** — `safeUrl()` rejects `javascript:`, `data:`,
  `vbscript:`, `file:`.
- **Phone / email links** — `safeTel()` requires a real digit count after
  normalisation (not just character deletion); `telLink()` / `mailLink()` emit an
  anchor **only** for a valid destination and otherwise render escaped plain
  text, so `href="tel:"` and `href="mailto:"` are never produced empty or
  malformed. All nine link locations are asserted.
- **Read Only activity log** — the real `_loadActivityLog` is executed against a
  stubbed fetch/DOM: Read Only issues **zero** requests and sees a neutral
  message; Employee and Manager still issue the case-scoped request.
- **Financial controls by role** — fee inputs, Payment Method, Mark Attorney
  Paid, Record Payment, bulk paid actions, lead conversion and financial task
  resolvers are hidden or disabled below Manager; attorney assignment stays
  available; nine action functions refuse below Manager; role visibility fails
  closed.
- **Auth headers** — zero private `fetch` calls missing `X-Staff-Token`.
- **Protected files** — six files byte-identical to base commit `c75862a`.

### `phase0-xss-inventory.js` — exhaustive XSS inventory (regression gate)

Parses the **whole** `dashboard.html`, enumerates every `${…}` inside every
template literal, classifies each by sink context (HTML text, attribute,
inline-handler JS string, `href`/`src`, `tel:`, `mailto:`) and requires the
correct encoder for that context. It judges each interpolation on its own — a
value is never treated as safe because its surrounding function escapes
elsewhere.

Two tiers: **Tier 1** is a direct record accessor reaching a sink unencoded;
**Tier 2** is a local variable carrying unencoded record data, resolved by
nearest-preceding assignment. Reviewed non-issues are listed in the tool's
triage table with a recorded reason. It exits non-zero if anything appears that
is **not** triaged.

---

## How to run

From the repository root:

```bash
npm install                                  # once — provides @netlify/blobs

node tests/phase0-security/phase0-harness.js
node tests/phase0-security/phase0-dashboard-tests.js
node tests/phase0-security/phase0-xss-inventory.js
```

Each exits `0` on success and non-zero on failure, so they can be wired into CI
as-is. They can be run from any working directory — all paths resolve relative
to the test files themselves.

---

## Expected current result

```
phase0-harness.js            TOTAL: 453    PASSED: 453    FAILED: 0
phase0-dashboard-tests.js    TOTAL:  97    PASSED:  97    FAILED: 0
                             ─────────────────────────────────────
                             TOTAL: 550    PASSED: 550    FAILED: 0

phase0-xss-inventory.js      Tier 1 untriaged: 0
                             Tier 2 untriaged: 0
```

**550 passed, 0 failed, zero unresolved XSS findings.**

Any deviation means a Phase 0 guarantee has regressed — investigate before
merging or deploying.

---

## Notes

- `phase0-harness.js` needs `@netlify/blobs` because `submit.js` requires it at
  module load; it is already a project dependency.
- The dashboard tests read `dashboard.html` as text and evaluate individual
  extracted functions. They do not need a browser or a DOM library.
- The protected-file assertions shell out to `git show c75862a:<path>`, so they
  require the base commit to be present in the local clone.
