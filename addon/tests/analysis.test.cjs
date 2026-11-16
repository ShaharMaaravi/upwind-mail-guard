const assert = require('node:assert/strict');
const { test } = require('node:test');
const { harness, event } = require('./helpers.cjs');

function payload() {
  return { schema_version: '1', request_id: '00000000-0000-4000-8000-000000000001',
    message: { from_address: 'sender@example.com', reply_to: '', subject: 'Synthetic <b>subject</b>',
      plain_text: '', html: '', authentication_results: '' }, attachments: [], truncated_fields: [] };
}
function response(context, p = payload()) {
  const names = Array.from(context.ANALYSIS_FIELDS);
  const available = names.filter(k => (k === 'attachments' ? p.attachments : p.message[k]) !== null);
  const missing = names.filter(k => !available.includes(k));
  return { schema_version: '1', request_id: p.request_id, policy_version: 'heuristic-v2',
    normalization_version: 'normalize-v2', analysis_status: missing.length || p.truncated_fields.length ? 'partial' : 'complete',
    score: 0, verdict: missing.length || p.truncated_fields.length ? 'inconclusive' : 'low_observed_risk', findings: [],
    scoring: { requested_points: 0, category_suppressed_points: 0, global_suppressed_points: 0, duplicates_removed: 0 },
    checks_run: Object.keys(context.RULE_LABELS), checks_skipped: [],
    coverage: { available_fields: available, unavailable_fields: missing, truncated_fields: [...p.truncated_fields],
      issues: [], links_considered: 0, unique_links: 0, attachment_records: (p.attachments || []).length,
      limitations: Array.from(context.ANALYSIS_LIMITATIONS) } };
}
function finding() {
  return { finding_id: 'a'.repeat(64), rule_id: 'url.display_mismatch', category: 'url', severity: 'high',
    field: 'html', evidence: '<a href="https://example.net">example.com</a>', explanation: 'Example <script>alert(1)</script>',
    requested_points: 40, awarded_points: 40, category_suppressed_points: 0, global_suppressed_points: 0 };
}
function suspicious(context, p = payload()) {
  const r = response(context, p);
  r.score = 40; r.verdict = 'suspicious'; r.findings = [finding()]; r.scoring.requested_points = 40;
  return r;
}
function metadataResponse(data, status = 200) {
  return { getResponseCode: () => status, getContentText: () => JSON.stringify(data) };
}

test('metadata fetch uses exact Google path, both Google tokens, field mask, and no redirects', () => {
  let observed;
  const { context } = harness({ UrlFetchApp: { fetch(url, options) {
    observed = { url, options };
    return metadataResponse({ payload: { mimeType: 'multipart/mixed', parts: [
      { mimeType: 'text/plain', filename: '' },
      { mimeType: 'text/plain', filename: 'note.txt', body: { size: 12 } }
    ] } });
  } } });
  const p = context.extractAnalysis(event);
  assert.deepEqual(JSON.parse(JSON.stringify(p.attachments)), [{ filename: 'note.txt', content_type: 'text/plain', size_bytes: 12 }]);
  const url = new URL(observed.url);
  assert.equal(url.origin, 'https://gmail.googleapis.com');
  assert.equal(url.pathname, '/gmail/v1/users/me/messages/selected-message');
  assert.equal(url.searchParams.get('format'), 'full');
  assert.ok(!url.searchParams.get('fields').includes('data'));
  assert.ok(!url.searchParams.get('fields').includes('attachmentId'));
  assert.equal(observed.options.headers.Authorization, 'Bearer synthetic-google-oauth-token');
  assert.equal(observed.options.headers['X-Goog-Gmail-Access-Token'], event.gmail.accessToken);
  assert.equal(observed.options.followRedirects, false);
  assert.equal(observed.options.validateHttpsCertificates, true);
  for (const secret of [event.gmail.accessToken, event.gmail.messageId, 'synthetic-google-oauth-token']) {
    assert.ok(!JSON.stringify(p).includes(secret));
  }
});

test('metadata absence and genuinely empty attachment list remain distinct', () => {
  const denied = harness({ UrlFetchApp: { fetch: () => metadataResponse({ error: 'private provider error' }, 403) } });
  assert.equal(denied.context.extractAnalysis(event).attachments, null);
  const empty = harness({ UrlFetchApp: { fetch: () => metadataResponse({ payload: { mimeType: 'text/plain' } }) } });
  assert.equal(empty.context.extractAnalysis(event).attachments.length, 0);
});

for (const value of [{}, { payload: {} }, { payload: { mimeType: 'text/plain', filename: 42 } },
  { payload: { mimeType: 'text/plain', body: { data: 'must-not-request-bytes' } } },
  { payload: { mimeType: 'text/plain', filename: 'x', body: { size: -1 } } }]) {
  test('malformed or unexpected metadata fails to unavailable', () => {
    const { context } = harness({ UrlFetchApp: { fetch: () => metadataResponse(value) } });
    assert.equal(context.extractAnalysis(event).attachments, null);
  });
}

test('metadata bounds count, filename, MIME depth and part traversal with truncation', () => {
  const { context } = harness();
  const part = { mimeType: 'application/test', filename: 'x'.repeat(600), body: { size: 0 } };
  const count = context.parseAttachmentMetadata({ payload: { mimeType: 'multipart/mixed', parts: Array(21).fill(part) } });
  assert.equal(count.attachments.length, 20);
  assert.equal(count.attachments[0].filename.length, 512);
  assert.equal(count.truncated, true);
  let nested = { partId: 'omitted-deep-part' };
  for (let i = 0; i < 5; i++) nested = { mimeType: 'multipart/mixed', parts: [nested] };
  assert.equal(context.parseAttachmentMetadata({ payload: nested }).truncated, true);
  const many = { payload: { mimeType: 'multipart/mixed', parts: Array(201).fill({ mimeType: 'text/plain' }) } };
  assert.equal(context.parseAttachmentMetadata(many).truncated, true);
});

test('metadata response byte limit rejects large Unicode even below character ceiling', () => {
  const { context } = harness({ UrlFetchApp: { fetch: () => metadataResponse({ payload: { mimeType: 'text/plain', filename: 'א'.repeat(70000) } }) } });
  assert.equal(context.extractAnalysis(event).attachments, null);
});

test('analysis client pins endpoint, validates response and keeps the demo token separate', () => {
  let observed;
  const { context } = harness({ UrlFetchApp: { fetch(url, options) {
    observed = { url, options };
    return metadataResponse(response(context, JSON.parse(options.payload)));
  } } });
  assert.equal(context.callAnalysis(payload()).score, 0);
  assert.equal(observed.url, 'https://mail-guard.demo-host.dev/v1/analyze');
  assert.equal(observed.options.headers.Authorization, 'Bearer ' + 'x'.repeat(43));
  assert.equal(observed.options.followRedirects, false);
  assert.ok(!JSON.stringify(observed).includes('synthetic-google-oauth-token'));
});

for (const [name, mutate] of [
  ['wrong correlation', r => r.request_id = 'wrong'], ['unknown policy', r => r.policy_version = 'future'],
  ['unknown normalizer', r => r.normalization_version = 'future'], ['unexpected field', r => r.safe = true],
  ['string score', r => r.score = '40'], ['wrong sum', r => r.score = 41],
  ['wrong verdict', r => r.verdict = 'low_observed_risk'], ['fake complete', r => r.coverage.issues.push({ field: 'html', code: 'invalid_url' })],
  ['missing input hidden', r => r.coverage.unavailable_fields.push('html')], ['truncation forged', r => r.coverage.truncated_fields.push('html')],
  ['bad link counts', r => r.coverage.unique_links = 101], ['wrong attachments', r => r.coverage.attachment_records = 1],
  ['unknown issue', r => r.coverage.issues.push({ field: 'html', code: '<b>injected</b>' })],
  ['missing limitations', r => r.coverage.limitations = []], ['unknown rule', r => r.findings[0].rule_id = 'sender.trusted'],
  ['invalid source field', r => r.findings[0].field = 'token'], ['wrong category', r => r.findings[0].category = 'sender'],
  ['invalid severity', r => r.findings[0].severity = '<b>safe</b>'], ['bad finding ID', r => r.findings[0].finding_id = 'x'],
  ['oversized evidence', r => r.findings[0].evidence = 'x'.repeat(257)], ['oversized explanation', r => r.findings[0].explanation = 'x'.repeat(401)],
  ['negative award', r => r.findings[0].awarded_points = -1], ['inconsistent cap', r => r.findings[0].category_suppressed_points = 5],
  ['wrong aggregate', r => r.scoring.requested_points = 0], ['duplicate checks', r => r.checks_run.push('url.ip_host')],
  ['unaccounted check', r => r.checks_run.pop()], ['run and skipped', r => r.checks_skipped.push({ rule_id: 'url.ip_host', reason: 'missing_fields', fields: ['html'] })],
  ['empty skip reason fields', r => { const id = r.checks_run.pop(); r.checks_skipped.push({ rule_id: id, reason: 'missing_fields', fields: [] }); }],
  ['duplicate finding', r => r.findings.push(r.findings[0])]
]) {
  test(`analysis rejects ${name}`, () => {
    const { context } = harness();
    const r = suspicious(context); mutate(r);
    assert.throws(() => context.validateAnalysis(r, payload()), /invalid_response/);
  });
}

test('valid unavailable result has no score and explains skipped checks', () => {
  const { context, calls } = harness();
  const p = payload();
  Object.keys(p.message).forEach(k => { p.message[k] = null; });
  p.message.authentication_results = 'untrusted'; p.attachments = null;
  const r = response(context, p);
  r.analysis_status = 'unavailable'; r.score = null; r.verdict = 'analysis_unavailable'; r.scoring = null;
  r.checks_skipped = r.checks_run.map(rule_id => ({ rule_id, reason: 'missing_fields', fields: ['html'] })); r.checks_run = [];
  context.validateAnalysis(r, p); context.analysisCard(r, p);
  const display = JSON.stringify(calls);
  assert.ok(display.includes('No score available'));
  assert.ok(display.includes('Skipped checks'));
  assert.ok(!display.includes('Risk score: 0'));
});

test('card escapes subject, explanations and evidence; does not create links from evidence', () => {
  const { context, calls } = harness();
  const r = suspicious(context); context.validateAnalysis(r, payload()); context.analysisCard(r, payload());
  const display = JSON.stringify(calls);
  assert.ok(display.includes('Risk score: 40 / 100'));
  assert.ok(display.includes('&lt;b&gt;subject&lt;/b&gt;'));
  assert.ok(display.includes('&lt;a href='));
  assert.ok(display.includes('&lt;script&gt;'));
  assert.ok(!display.includes('<script>') && !display.includes('<a href='));
  assert.ok(!calls.some(c => ['setUrl', 'setOpenLink'].includes(c[0])));
  assert.ok(display.includes('Requested 40; awarded 40'));
});

test('partial zero displays inconclusive and missing data, never a safe verdict', () => {
  const { context, calls } = harness();
  const p = payload(); p.attachments = null;
  const r = response(context, p);
  r.checks_run = r.checks_run.filter(id => !id.startsWith('attachment.'));
  r.checks_skipped = ['attachment.executable', 'attachment.double_extension'].map(rule_id => ({ rule_id, reason: 'missing_fields', fields: ['attachments'] }));
  context.validateAnalysis(r, p); context.analysisCard(r, p);
  const display = JSON.stringify(calls);
  assert.ok(display.includes('Inconclusive') && display.includes('Partial analysis'));
  assert.ok(display.includes('Attachment metadata: unavailable'));
  assert.ok(!display.includes('Low observed risk'));
});

test('large finding list has a bounded card and accounts for omitted points', () => {
  const { context, calls } = harness();
  const r = response(context);
  r.findings = Array.from({ length: 10 }, (_, i) => ({ ...finding(), finding_id: i.toString(16).padStart(64, '0'),
    requested_points: 40, awarded_points: 6, category_suppressed_points: 34 }));
  r.score = 60; r.verdict = 'high_risk'; r.scoring.requested_points = 400; r.scoring.category_suppressed_points = 340;
  context.validateAnalysis(r, payload()); context.analysisCard(r, payload());
  const display = JSON.stringify(calls);
  assert.ok(display.includes('Showing 8 of 10 findings. Additional findings contribute 12 points.'));
  assert.ok(calls.filter(c => c[0] === 'addWidget').length < 40);
});

for (const status of [301, 401, 403, 429, 500]) {
  test(`analysis action shows an unavailable card for backend HTTP ${status}`, () => {
    const { context, calls } = harness({ UrlFetchApp: { fetch(url) {
      return url.startsWith('https://gmail.googleapis.com') ? metadataResponse({ payload: { mimeType: 'text/plain' } }) : metadataResponse({ private: 'do not echo' }, status);
    } } });
    context.onAnalyzeEmail(event);
    const display = JSON.stringify(calls);
    assert.ok(display.includes('Analysis unavailable'));
    assert.ok(!display.includes('Risk score:') && !display.includes('do not echo'));
  });
}

test('analysis action with expired authorization stops before any HTTP request', () => {
  let network = false;
  const { context, calls } = harness({ GmailApp: { setCurrentMessageAccessToken() { throw new Error('private auth error'); } },
    UrlFetchApp: { fetch() { network = true; } } });
  context.onAnalyzeEmail(event);
  assert.equal(network, false);
  assert.ok(JSON.stringify(calls).includes('Analysis unavailable'));
  assert.ok(!JSON.stringify(calls).includes('private auth error'));
});

test('analysis client rejects byte-oversized responses before parsing', () => {
  const { context } = harness({ UrlFetchApp: { fetch: () => ({ getResponseCode: () => 200,
    getContentText: () => 'א'.repeat(300000) }) } });
  assert.throws(() => context.callAnalysis(payload()), /invalid_response/);
});

module.exports = { payload, response };
