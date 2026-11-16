/** Gmail tokens and message IDs remain inside Apps Script. */
var FIELD_LIMITS = Object.freeze({
  from_address: 2048, reply_to: 2048, subject: 2048,
  plain_text: 16000, html: 16000, authentication_results: 4096
});

function extractDiagnostic(e) {
  if (!e || !e.gmail || !e.gmail.accessToken || !e.gmail.messageId) {
    throw new Error('message_unavailable');
  }
  var message;
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    message = GmailApp.getMessageById(e.gmail.messageId);
  } catch (_) {
    throw new Error('message_unavailable');
  }
  var readers = {
    from_address: function () { return message.getFrom(); },
    reply_to: function () { return message.getReplyTo(); },
    subject: function () { return message.getSubject(); },
    plain_text: function () { return message.getPlainBody(); },
    html: function () { return message.getBody(); },
    authentication_results: function () { return message.getHeader('Authentication-Results'); }
  };
  var fields = {};
  var truncated = [];
  Object.keys(readers).forEach(function (name) {
    try {
      var value = readers[name]();
      if (typeof value !== 'string') throw new Error('field_unavailable');
      if (value.length > FIELD_LIMITS[name]) {
        truncated.push(name);
        value = value.slice(0, FIELD_LIMITS[name]);
        // Avoid splitting a UTF-16 surrogate pair at the truncation boundary.
        if (/[\uD800-\uDBFF]$/.test(value)) value = value.slice(0, -1);
      }
      fields[name] = value;
    } catch (_) {
      fields[name] = null;
    }
  });
  if (Object.keys(fields).every(function (name) { return fields[name] === null; })) {
    throw new Error('message_unavailable');
  }
  return {
    schema_version: '1', request_id: Utilities.getUuid(), message: fields,
    truncated_fields: truncated
  };
}
