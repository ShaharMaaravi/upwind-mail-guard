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

function extractAnalysis(e) {
  var payload = extractDiagnostic(e);
  var metadata = readAttachmentMetadata(e);
  payload.attachments = metadata.attachments;
  if (metadata.truncated) payload.truncated_fields.push('attachments');
  return payload;
}

/** Partial-response mask deliberately excludes body.data and attachment download IDs. */
function attachmentFieldMask(depth) {
  var fields = 'filename,mimeType,body(size)';
  return fields + (depth > 0 ? ',parts(' + attachmentFieldMask(depth - 1) + ')' : ',parts(partId)');
}

function readAttachmentMetadata(e) {
  try {
    var url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/' +
      encodeURIComponent(e.gmail.messageId) + '?format=full&fields=' +
      encodeURIComponent('payload(' + attachmentFieldMask(4) + ')');
    var response = UrlFetchApp.fetch(url, {
      headers: { Authorization: 'Bearer ' + ScriptApp.getOAuthToken(),
        'X-Goog-Gmail-Access-Token': e.gmail.accessToken },
      followRedirects: false, validateHttpsCertificates: true, muteHttpExceptions: true
    });
    if (response.getResponseCode() !== 200) throw new Error('metadata_unavailable');
    var raw = response.getContentText();
    if (raw.length > 128 * 1024 || Utilities.newBlob(raw).getBytes().length > 128 * 1024) {
      throw new Error('metadata_unavailable');
    }
    return parseAttachmentMetadata(JSON.parse(raw));
  } catch (_) {
    // Google tokens, message IDs, and provider errors never enter logs or the backend payload.
    return { attachments: null, truncated: false };
  }
}

function parseAttachmentMetadata(data) {
  var attachments = [], truncated = false, visited = 0;
  function bounded(value, limit) {
    if (value.length <= limit) return value;
    truncated = true;
    var result = value.slice(0, limit);
    return /[\uD800-\uDBFF]$/.test(result) ? result.slice(0, -1) : result;
  }
  function visit(part, depth) {
    if (++visited > 200) { truncated = true; return; }
    if (!part || typeof part !== 'object' || typeof part.mimeType !== 'string' ||
        (part.filename !== undefined && typeof part.filename !== 'string') ||
        (part.parts !== undefined && !Array.isArray(part.parts)) ||
        (part.body && ('data' in part.body || 'attachmentId' in part.body))) {
      throw new Error('metadata_unavailable');
    }
    if (part.filename) {
      if (attachments.length >= 20) { truncated = true; }
      else {
        var size = part.body && part.body.size;
        if (size !== undefined && (!Number.isSafeInteger(size) || size < 0 || size > 1e12)) {
          throw new Error('metadata_unavailable');
        }
        attachments.push({ filename: bounded(part.filename, 512),
          content_type: bounded(part.mimeType, 128), size_bytes: size === undefined ? null : size });
      }
    }
    if (part.parts && part.parts.length) {
      if (depth >= 4) { truncated = true; return; }
      for (var i = 0; i < part.parts.length; i++) {
        if (visited >= 200) { truncated = true; break; }
        visit(part.parts[i], depth + 1);
      }
    }
  }
  visit(data && data.payload, 0);
  return { attachments: attachments, truncated: truncated };
}
