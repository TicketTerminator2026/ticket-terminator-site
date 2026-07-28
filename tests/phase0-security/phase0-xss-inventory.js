'use strict';
/* Exhaustive HTML-sink interpolation inventory for dashboard.html (final branch).
   TIER 1 — a direct Airtable/user accessor reaching a sink without the encoder
            required for that context. These are true findings.
   TIER 2 — local variables that carry UNENCODED record data, plus every sink
            they flow into. Reviewed manually and triaged below. */
const fs = require('fs');
const FILE = process.argv[2] || require('path').join(__dirname, '..', '..', 'dashboard.html');
const src = fs.readFileSync(FILE, 'utf8');
const lines = src.split('\n');

// Direct accessors for Airtable / user-entered values.
const DIRECT = /\bf\(r\)\s*\[|\bfd\s*\[|\bflds\s*\[|\baf\s*\[|\.fields\s*\[|\.fields\.[A-Za-z_]|\bclientName\s*\(|\b_resolveAttyNames\s*\(|\ba\.url\b|\ba\.filename\b|\bt\.(?:client|caseNum|status|notes|title|sub)\b/;
// Airtable record identifiers are system-generated (rec…) — not user content.
const SAFE_ID = /^(?:[A-Za-z_$][\w$]*\.)?id$|^rid$|^caseId$|^recordId$|^attyId$|^r\.id$|^a\.id$|^t\.id$/;

const ENCODERS = ['esc','_esc','jsAttr','safeUrl','safeTel','safeMail','telLink','mailLink',
  'encodeURIComponent','Number','parseFloat','parseInt','currency','formatDate','formatDateShort',
  'daysUntil','toFixed','statusBadge','priorityBadge','typeBadge','quoteStatusBadge',
  'statusBadgeClass','normalizePhone','sel','selE','selEmpty','_fmtDate','telDigits'];
const ENC_RE = new RegExp('\\b(' + ENCODERS.join('|') + ')\\s*\\(');

function stripEncoded(s) {
  let out = s, guard = 0;
  while (guard++ < 50) {
    const mm = out.match(ENC_RE);
    if (!mm) break;
    const idx = out.indexOf(mm[0]);
    let depth = 0, k = idx + mm[0].length - 1;
    for (; k < out.length; k++) {
      if (out[k] === '(') depth++;
      else if (out[k] === ')') { depth--; if (depth === 0) break; }
    }
    out = out.slice(0, idx) + ' ENC ' + out.slice(k + 1);
  }
  return out;
}
// A ternary CONDITION is never emitted — analyse only the branches.
function stripTernaryConds(s) {
  let out = s, guard = 0;
  while (guard++ < 20) {
    let depth = 0, cut = -1;
    for (let i = 0; i < out.length; i++) {
      const c = out[i];
      if ('([{'.includes(c)) depth++;
      else if (')]}'.includes(c)) depth--;
      else if (c === '?' && depth === 0 && out[i + 1] !== '.' && out[i + 1] !== '?' && out[i - 1] !== '?') { cut = i; break; }
    }
    if (cut === -1) break;
    out = out.slice(cut + 1);
  }
  return out;
}
const hasRawDirect = (expr) => DIRECT.test(stripTernaryConds(stripEncoded(expr)));

// Only template literals that actually build HTML are XSS sinks.
function buildsHtml(span) {
  const b = src.lastIndexOf('`', span.start);
  const a = src.indexOf('`', span.end);
  if (b === -1 || a === -1) return true;
  return /<[a-zA-Z\/!]/.test(src.slice(b, a));
}

// ── Enumerate ${...} spans ────────────────────────────────────────────────
const spans = [];
for (let i = 0; i < src.length - 1; i++) {
  if (src[i] === '$' && src[i + 1] === '{') {
    let depth = 1, j = i + 2;
    while (j < src.length && depth > 0) {
      if (src[j] === '{') depth++;
      else if (src[j] === '}') { depth--; if (depth === 0) break; }
      j++;
    }
    spans.push({ start: i, end: j, expr: src.slice(i + 2, j), line: src.slice(0, i).split('\n').length });
    i = j;
  }
}

function sinkOf(span) {
  const before = src.slice(Math.max(0, span.start - 300), span.start);
  const handler = before.match(/\bon[a-z]+\s*=\s*(["'])((?:(?!\1).)*)$/is);
  if (handler) return /'[^']*$/.test(handler[2]) ? 'inline-handler-jsstring' : 'inline-handler';
  const attr = before.match(/\b([a-zA-Z-]+)\s*=\s*(["'])((?:(?!\2).)*)$/s);
  if (attr) {
    const n = attr[1].toLowerCase();
    if (n === 'href' || n === 'src') {
      if (/tel:$/i.test(attr[3])) return 'href-tel';
      if (/mailto:$/i.test(attr[3])) return 'href-mailto';
      return 'href-src';
    }
    return 'attribute:' + n;
  }
  const lo = before.lastIndexOf('<'), lc = before.lastIndexOf('>');
  return lo > lc ? 'tag-internal' : 'text';
}
const REQUIRED = {
  'inline-handler-jsstring': /\bjsAttr\s*\(/,
  'inline-handler': /\b(jsAttr|esc|_esc)\s*\(/,
  'href-src': /\b(safeUrl|encodeURIComponent)\s*\(/,
  'href-tel': /\bsafeTel\s*\(/,
  'href-mailto': /\bsafeMail\s*\(/,
};

// ── TIER 1 ────────────────────────────────────────────────────────────────
const tier1 = [];
for (const s of spans) {
  if (!buildsHtml(s)) continue;
  const sink = sinkOf(s);
  const kind = sink.startsWith('attribute') ? 'attribute' : sink;
  if (REQUIRED[kind]) {
    // context-specific encoder required whenever ANY record value is present
    if (DIRECT.test(stripTernaryConds(s.expr)) && !REQUIRED[kind].test(s.expr)) {
      if (SAFE_ID.test(s.expr.trim())) continue;
      tier1.push({ line: s.line, sink, expr: s.expr.replace(/\s+/g, ' ').trim().slice(0, 140) });
    }
    continue;
  }
  if (hasRawDirect(s.expr)) {
    tier1.push({ line: s.line, sink, expr: s.expr.replace(/\s+/g, ' ').trim().slice(0, 140) });
  }
}

// ── TIER 2: nearest-preceding-assignment analysis (approximates block scope) ──
// For each local name we record EVERY assignment with whether the record data in
// it was encoded. A sink use is flagged only when the assignment that most
// closely precedes it left the value unencoded.
const assigns = new Map();               // name -> [{line, unencoded}]
const ASSIGN = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*((?:[^;\n]|\n\s{6,})+)/g;
let m2;
while ((m2 = ASSIGN.exec(src))) {
  const [, name, rhs] = m2;
  if (SAFE_ID.test(name)) continue;
  if (!DIRECT.test(rhs)) continue;       // assignment carries no record data at all
  const line = src.slice(0, m2.index).split('\n').length;
  if (!assigns.has(name)) assigns.set(name, []);
  assigns.get(name).push({ line, unencoded: hasRawDirect(rhs) });
}
const tier2 = [];
for (const [name, defs] of assigns) {
  if (!defs.some(d => d.unencoded)) continue;          // every definition is encoded
  const re = new RegExp('(^|[^\\w$.\\-])' + name.replace(/\$/g, '\\$') + '(?![\\w$\\-])');
  const uses = [];
  for (const sp of spans) {
    if (!buildsHtml(sp)) continue;
    if (!re.test(stripTernaryConds(sp.expr))) continue;
    const shadow = new RegExp('(\\(\\s*|,\\s*)' + name.replace(/\$/g,'\\$') + '\\s*(,[^)]*)?\\)\\s*=>');
    if (shadow.test(sp.expr)) continue;
    // nearest preceding assignment governs
    let gov = null;
    for (const d of defs) if (d.line <= sp.line && (!gov || d.line > gov.line)) gov = d;
    if (!gov || !gov.unencoded) continue;
    const sink = sinkOf(sp);
    const kind = sink.startsWith('attribute') ? 'attribute' : sink;
    const bare = stripEncoded(stripTernaryConds(sp.expr));
    const encoded = REQUIRED[kind] ? REQUIRED[kind].test(sp.expr) : !re.test(bare);
    if (!encoded) uses.push({ line: sp.line, sink, expr: sp.expr.replace(/\s+/g, ' ').trim().slice(0, 120), def: gov.line });
  }
  if (uses.length) tier2.push({ name, defLines: defs.filter(d => d.unencoded).map(d => d.line), uses });
}


// ── TRIAGE ──────────────────────────────────────────────────────────────────
// Reviewed by hand; each entry records why the finding is not exploitable.
// Anything NOT listed here is reported as unresolved and fails the check.
const TIER1_TRIAGE = [
  ["fd['Waiting For Attorney Update'] ?", "ternary CONDITION only; the branch escapes its content (formatDate)"],
  ["(fd['Court Outcome'] || fd['Resolution Notes']) ?", "ternary CONDITION only; every branch value uses _esc()/formatDate()"],
  ["fd['Notes'] ?", "branch escapes with _esc(); the second use is .length (numeric)"],
  ["isEdit ? (fd['Active'] ? 'checked' : '') : 'checked'", "boolean -> fixed 'checked' literal; no record text emitted"],
];
const TIER2_TRIAGE = {
  s: "scope collision - local search-index strings and hardcoded option lists, not these sinks",
  a: "scope collision - attorney/record objects; the flagged uses emit record ids only",
  text: "local inside telLink()/mailLink(); already esc()'d at assignment",
  fd: "flagged uses are boolean conditions, nested already-escaped content, or a colour-map lookup",
  t: "modal TABS array is hardcoded; task objects carry literal labels, numeric amounts and record ids",
  bal: "numeric (.toFixed)", attyBal: "numeric (.toFixed)", withAtty: "numeric count",
  quoteSent: "numeric count", accepted: "numeric count", todayCount: "numeric count",
  caseCount: "numeric count (array length)", active: "boolean",
  cardsHtml: "pre-rendered HTML; its interpolations are scanned separately",
  evHtml: "pre-rendered HTML; its interpolations are scanned separately",
  attyPaidHtml: "pre-rendered HTML; its interpolations are scanned separately",
  courtDateDisp: "formatDate() output plus literal markup",
  upDate: "_fmtDate() output", signedDt: "_fmtDate() output", lastUpd: "_fmtDate() output",
  ts: "toLocaleString() output", last: "toLocaleDateString() output",
};
const t1Untriaged = tier1.filter(f => !TIER1_TRIAGE.some(([sig]) => f.expr.indexOf(sig.slice(0, 40)) !== -1));
const t2Untriaged = tier2.filter(v => !TIER2_TRIAGE[v.name]);

const stats = {
  'innerHTML assignments': (src.match(/\.innerHTML\s*=/g) || []).length,
  'insertAdjacentHTML calls': (src.match(/insertAdjacentHTML/g) || []).length,
  'outerHTML assignments': (src.match(/\.outerHTML\s*=/g) || []).length,
  'document.write calls': (src.match(/document\.write/g) || []).length,
  'template interpolations scanned': spans.length,
};
const out = { stats, tier1, tier2, t1Untriaged, t2Untriaged };
if (process.env.JSON_OUT) { console.log(JSON.stringify(out, null, 1)); process.exit(0); }
console.log('=== SINKS PRESENT IN FILE ===');
for (const [k, v] of Object.entries(stats)) console.log(`  ${k}: ${v}`);
console.log(`\n=== TIER 1 — direct record accessor without required encoder: ${tier1.length} ===`);
tier1.forEach(f => console.log(`  L${f.line} [${f.sink}] ${f.expr}\n       ${(lines[f.line-1]||'').trim().slice(0,160)}`));
console.log(`\n=== TIER 2 — locals carrying unencoded record data, used unencoded in a sink: ${tier2.length} ===`);
tier2.forEach(v => {
  console.log(`  ${v.name}  (assigned L${v.defLines.join(', L')})`);
  v.uses.forEach(u => console.log(`      -> L${u.line} [${u.sink}] ${u.expr}`));
});
console.log(`\n=== TRIAGE ===`);
TIER1_TRIAGE.forEach(([sig, why]) => console.log(`  T1 ${sig.slice(0,58)} -> ${why}`));
Object.entries(TIER2_TRIAGE).forEach(([n, why]) => console.log(`  T2 ${n} -> ${why}`));
console.log(`\n=== UNRESOLVED (must be zero) ===`);
console.log(`  Tier 1 untriaged: ${t1Untriaged.length}`);
t1Untriaged.forEach(f => console.log(`     L${f.line} [${f.sink}] ${f.expr}`));
console.log(`  Tier 2 untriaged: ${t2Untriaged.length}`);
t2Untriaged.forEach(v => console.log(`     ${v.name} (L${v.defLines.join(', L')})`));
process.exit((t1Untriaged.length + t2Untriaged.length) ? 1 : 0);
