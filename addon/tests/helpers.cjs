const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function harness(overrides = {}) {
  const messages = [];
  const calls = [];
  const widget = () => new Proxy({}, {
    get(target, key) {
      if (key === 'build') return () => target;
      return (...args) => { calls.push([key, ...args]); return new Proxy(target, this); };
    }
  });
  const context = vm.createContext({
    BACKEND_ORIGIN: 'https://mail-guard.demo-host.dev',
    PropertiesService: { getScriptProperties: () => ({ getProperty: () => 'x'.repeat(43) }) },
    Utilities: {
      getUuid: () => '00000000-0000-4000-8000-000000000001',
      newBlob: text => ({ getBytes: () => Buffer.from(text) })
    },
    GmailApp: {
      setCurrentMessageAccessToken: token => messages.push(['token', token]),
      getMessageById: id => {
        messages.push(['message', id]);
        return {
          getFrom: () => 'sender@example.test', getReplyTo: () => '',
          getSubject: () => 'Synthetic <b>subject</b>', getPlainBody: () => 'Hello 🔒 שלום',
          getBody: () => '<p>Hello</p>', getHeader: () => ''
        };
      }
    },
    CardService: new Proxy({}, { get: () => widget }),
    UrlFetchApp: { fetch: () => { throw new Error('unexpected_network_call'); } },
    ...overrides
  });
  for (const filename of ['Extraction.js', 'ApiClient.js', 'Cards.js', 'Handlers.js']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../src', filename), 'utf8'), context, { filename });
  }
  return { context, messages, calls };
}

function responseFor(payload) {
  return {
    schema_version: '1', request_id: payload.request_id, status: 'diagnostic_only',
    field_characters: Object.fromEntries(Object.entries(payload.message).map(
      ([key, value]) => [key, value === null ? null : Array.from(value).length]
    )),
    truncated_fields: Array.from(payload.truncated_fields),
    attachments_status: 'not_inspected', authentication_status: 'unverified'
  };
}

const event = { gmail: { messageId: 'selected-message', accessToken: 'synthetic-gmail-token' } };
module.exports = { harness, responseFor, event };
