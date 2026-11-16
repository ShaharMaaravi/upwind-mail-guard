/** The build pins the HTTPS origin in Deployment.js and the manifest allowlist. */
function callDiagnostic(payload) {
  var result = backendRequest('/v1/diagnose', payload, 8192);
  validateDiagnostic(result, payload);
  return result;
}

function callAnalysis(payload) {
  var result = backendRequest('/v1/analyze', payload, 512 * 1024);
  validateAnalysis(result, payload);
  return result;
}

function backendRequest(path, payload, responseLimit) {
  var token = PropertiesService.getScriptProperties().getProperty('MAIL_GUARD_API_TOKEN');
  if (!token || !/^[A-Za-z0-9_-]{43,128}$/.test(token)) throw new Error('configuration_error');
  var json = JSON.stringify(payload);
  if (Utilities.newBlob(json).getBytes().length > 256 * 1024) throw new Error('request_too_large');
  var response;
  try {
    response = UrlFetchApp.fetch(BACKEND_ORIGIN + path, {
      method: 'post', contentType: 'application/json',
      headers: { Authorization: 'Bearer ' + token }, payload: json,
      followRedirects: false, validateHttpsCertificates: true, muteHttpExceptions: true
    });
  } catch (_) {
    throw new Error('backend_unavailable');
  }
  var status = response.getResponseCode();
  if (status === 401 || status === 403) throw new Error('backend_unauthorized');
  if (status === 429) throw new Error('rate_limited');
  if (status !== 200) throw new Error('backend_unavailable');
  var raw = response.getContentText();
  if (raw.length > responseLimit || Utilities.newBlob(raw).getBytes().length > responseLimit) {
    throw new Error('invalid_response');
  }
  var result;
  try { result = JSON.parse(raw); } catch (_) { throw new Error('invalid_response'); }
  return result;
}

function validateDiagnostic(result, payload) {
  if (!result || result.schema_version !== '1' || result.status !== 'diagnostic_only' ||
      result.request_id !== payload.request_id || result.attachments_status !== 'not_inspected' ||
      result.authentication_status !== 'unverified' || !result.field_characters ||
      typeof result.field_characters !== 'object' || Array.isArray(result.field_characters) ||
      !Array.isArray(result.truncated_fields)) throw new Error('invalid_response');
  var names = Object.keys(FIELD_LIMITS);
  if (Object.keys(result.field_characters).length !== names.length) throw new Error('invalid_response');
  names.forEach(function (name) {
    var expected = payload.message[name] === null ? null : Array.from(payload.message[name]).length;
    if (result.field_characters[name] !== expected) throw new Error('invalid_response');
  });
  if (JSON.stringify(result.truncated_fields) !== JSON.stringify(payload.truncated_fields)) {
    throw new Error('invalid_response');
  }
}
