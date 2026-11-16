const assert = require('node:assert/strict');
const { test } = require('node:test');
const { harness, responseFor, event } = require('./helpers.cjs');

test('reads selected event message, keeps Gmail token and ID out of payload', () => {
  const { context, messages } = harness();
  const payload = context.extractDiagnostic(event);
  assert.deepEqual(messages, [['token', event.gmail.accessToken], ['message', event.gmail.messageId]]);
  assert.ok(!JSON.stringify(payload).includes(event.gmail.accessToken));
  assert.ok(!JSON.stringify(payload).includes(event.gmail.messageId));
});

for (const e of [undefined, {}, { gmail: {} }, { gmail: { messageId: 'id' } }]) {
  test('missing Gmail context fails without extraction', () => {
    const { context, messages } = harness();
    assert.throws(() => context.extractDiagnostic(e), /message_unavailable/);
    assert.equal(messages.length, 0);
  });
}

test('partial extraction preserves empty versus unavailable and Unicode truncation', () => {
  const { context } = harness({ GmailApp: {
    setCurrentMessageAccessToken() {},
    getMessageById: () => ({
      getFrom: () => '', getReplyTo: () => { throw new Error('permission denied'); },
      getSubject: () => 'x'.repeat(2047) + '🔒', getPlainBody: () => 'א'.repeat(20000),
      getBody: () => '', getHeader: () => ''
    })
  } });
  const payload = context.extractDiagnostic(event);
  assert.equal(payload.message.from_address, '');
  assert.equal(payload.message.reply_to, null);
  assert.equal(payload.message.subject, 'x'.repeat(2047));
  assert.equal(payload.message.plain_text.length, 16000);
  assert.deepEqual(Array.from(payload.truncated_fields), ['subject', 'plain_text']);
  assert.ok(Buffer.byteLength(JSON.stringify(payload)) < 256 * 1024);
});

test('expired authorization never reaches backend and never shows success', () => {
  const { context, calls } = harness({ GmailApp: {
    setCurrentMessageAccessToken() { throw new Error('secret-provider-error'); }
  } });
  context.onTestConnection(event);
  const output = JSON.stringify(calls);
  assert.ok(output.includes('Analysis unavailable'));
  assert.ok(output.includes('Reopen the email and authorize'));
  assert.ok(!output.includes('secret-provider-error'));
  assert.ok(!output.includes('Backend connected'));
});

test('all fields unavailable is an extraction failure', () => {
  const { context } = harness({ GmailApp: {
    setCurrentMessageAccessToken() {}, getMessageById: () => ({})
  } });
  assert.throws(() => context.extractDiagnostic(event), /message_unavailable/);
});

test('client sends authenticated JSON only to pinned origin without redirects', () => {
  let observed;
  const { context } = harness({ UrlFetchApp: { fetch(url, options) {
    observed = { url, options };
    return { getResponseCode: () => 200, getContentText: () => JSON.stringify(responseFor(JSON.parse(options.payload))) };
  } } });
  const payload = context.extractDiagnostic(event);
  assert.equal(context.callDiagnostic(payload).status, 'diagnostic_only');
  assert.equal(observed.url, 'https://mail-guard.demo-host.dev/v1/diagnose');
  assert.equal(observed.options.headers.Authorization, 'Bearer ' + 'x'.repeat(43));
  assert.equal(observed.options.followRedirects, false);
  assert.equal(observed.options.validateHttpsCertificates, true);
  assert.equal(observed.options.muteHttpExceptions, true);
  assert.equal(observed.options.contentType, 'application/json');
});

for (const [status, code] of [[301, 'backend_unavailable'], [307, 'backend_unavailable'],
  [401, 'backend_unauthorized'], [403, 'backend_unauthorized'], [429, 'rate_limited'], [500, 'backend_unavailable']]) {
  test(`HTTP ${status} produces a safe error`, () => {
    const { context } = harness({ UrlFetchApp: { fetch: () => ({
      getResponseCode: () => status, getContentText: () => 'sensitive server error'
    }) } });
    assert.throws(() => context.callDiagnostic(context.extractDiagnostic(event)), new RegExp(code));
  });
}

test('missing secret stops before network', () => {
  const { context } = harness({ PropertiesService: {
    getScriptProperties: () => ({ getProperty: () => null })
  } });
  assert.throws(() => context.callDiagnostic(context.extractDiagnostic(event)), /configuration_error/);
});

test('transport exception is redacted', () => {
  const { context } = harness();
  assert.throws(() => context.callDiagnostic(context.extractDiagnostic(event)), /backend_unavailable/);
});

for (const raw of ['not-json', 'null', '{}', 'x'.repeat(8193)]) {
  test('malformed or oversized backend response is rejected', () => {
    const { context } = harness({ UrlFetchApp: { fetch: () => ({
      getResponseCode: () => 200, getContentText: () => raw
    }) } });
    assert.throws(() => context.callDiagnostic(context.extractDiagnostic(event)), /invalid_response/);
  });
}

for (const mutate of [
  r => r.request_id = '00000000-0000-4000-8000-000000000002',
  r => r.field_characters.subject = '<img>',
  r => r.field_characters.subject = -1,
  r => r.field_characters.extra = 0,
  r => delete r.field_characters.subject,
  r => r.status = 'safe',
  r => r.authentication_status = 'verified',
  r => r.truncated_fields = ['html']
]) {
  test('untrusted or mismatched response fails validation', () => {
    const { context } = harness();
    const payload = context.extractDiagnostic(event);
    const result = responseFor(payload);
    mutate(result);
    assert.throws(() => context.validateDiagnostic(result, payload), /invalid_response/);
  });
}

test('success card escapes the subject and labels missing coverage', () => {
  const { context, calls } = harness();
  const payload = context.extractDiagnostic(event);
  payload.message.html = null;
  context.diagnosticCard(responseFor(payload), payload);
  const output = JSON.stringify(calls);
  assert.ok(output.includes('&lt;b&gt;subject&lt;/b&gt;'));
  assert.ok(!output.includes('Synthetic <b>'));
  assert.ok(output.includes('HTML: unavailable'));
  assert.ok(output.includes('No threat analysis was performed'));
  assert.ok(output.includes('Attachments: not inspected'));
});

test('opening a different message resets to a fresh start card without reading mail', () => {
  const { context, calls, messages } = harness();
  context.onGmailMessage(event);
  context.onGmailMessage({ gmail: { messageId: 'different-message' } });
  assert.equal(messages.length, 0);
  assert.equal(calls.filter(c => c[0] === 'setText' && c[1] === 'Analyze this email').length, 2);
  assert.ok(!JSON.stringify(calls).includes('Backend connected'));
});

test('homepage does not offer a test without a message', () => {
  const { context, calls } = harness();
  context.onHomepage();
  assert.ok(JSON.stringify(calls).includes('Open an email'));
  assert.ok(!calls.some(c => c[0] === 'setOnClickAction'));
});
