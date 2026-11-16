/** Fail closed on inconsistent findings, coverage, policy versions, or score accounting. */
var ANALYSIS_FIELDS = Object.keys(FIELD_LIMITS).concat(['attachments']);
var RULE_LABELS = Object.freeze({
  'url.display_mismatch': 'Link destination differs',
  'url.userinfo': 'Misleading link address',
  'url.ip_host': 'Link uses an IP address',
  'sender.reply_to_mismatch': 'Replies go to another domain',
  'content.credentials_pressure': 'Urgent credential request',
  'content.payment_pressure': 'Payment request with urgency',
  'attachment.executable': 'Executable file name',
  'attachment.double_extension': 'Disguised file extension'
});
var COVERAGE_ISSUES = Object.freeze({
  invalid_address: 'Address could not be interpreted', unknown_domain_boundary: 'Unknown domain boundary',
  invalid_url: 'URL could not be interpreted', unsupported_url_scheme: 'Unsupported URL scheme',
  relative_url: 'Relative URL could not be resolved', link_limit_reached: 'Link limit reached',
  url_too_long: 'URL exceeded the length limit', ambiguous_html: 'Ambiguous HTML',
  invalid_text: 'Invalid text characters', normalized_text_limit_reached: 'Text expansion limit reached',
  ambiguous_filename: 'Ambiguous filename', display_url_unresolved: 'Displayed URL could not be resolved'
});
var ANALYSIS_LIMITATIONS = ['authentication_unverified', 'urls_not_fetched',
  'attachment_bytes_not_inspected', 'html_not_rendered', 'quoted_content_not_separated', 'english_content_rules'];

function validateAnalysis(result, payload) {
  function fail() { throw new Error('invalid_response'); }
  function object(value, keys) {
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        Object.keys(value).sort().join('|') !== keys.slice().sort().join('|')) fail();
  }
  function text(value, limit) {
    if (typeof value !== 'string' || Array.from(value).length > limit) fail();
  }
  function integer(value, max) {
    if (!Number.isSafeInteger(value) || value < 0 || value > max) fail();
  }
  function unique(values, allowed) {
    if (!Array.isArray(values) || values.length > allowed.length ||
        values.some(function (v, i) { return allowed.indexOf(v) < 0 || values.indexOf(v) !== i; })) fail();
  }
  function same(a, b) { if (a.slice().sort().join('|') !== b.slice().sort().join('|')) fail(); }
  var rules = Object.keys(RULE_LABELS);
  object(result, ['schema_version', 'request_id', 'policy_version', 'normalization_version',
    'analysis_status', 'score', 'verdict', 'findings', 'scoring', 'checks_run', 'checks_skipped', 'coverage']);
  if (result.schema_version !== '1' || result.request_id !== payload.request_id ||
      result.policy_version !== 'heuristic-v2' || result.normalization_version !== 'normalize-v2') fail();
  unique(result.checks_run, rules);
  if (!Array.isArray(result.checks_skipped) || result.checks_skipped.length > rules.length) fail();
  var skippedIds = [];
  result.checks_skipped.forEach(function (check) {
    object(check, ['rule_id', 'reason', 'fields']);
    if (['missing_fields', 'invalid_fields', 'unknown_domain_boundary'].indexOf(check.reason) < 0) fail();
    unique(check.fields, ANALYSIS_FIELDS);
    if (!check.fields.length) fail();
    skippedIds.push(check.rule_id);
  });
  unique(result.checks_run.concat(skippedIds), rules);
  same(result.checks_run.concat(skippedIds), rules);
  var coverage = result.coverage;
  object(coverage, ['available_fields', 'unavailable_fields', 'truncated_fields', 'issues',
    'links_considered', 'unique_links', 'attachment_records', 'limitations']);
  ['available_fields', 'unavailable_fields', 'truncated_fields'].forEach(function (key) {
    unique(coverage[key], ANALYSIS_FIELDS);
  });
  var available = ANALYSIS_FIELDS.filter(function (field) {
    return field === 'attachments' ? payload.attachments != null : payload.message[field] !== null;
  });
  same(coverage.available_fields, available);
  same(coverage.unavailable_fields, ANALYSIS_FIELDS.filter(function (f) { return available.indexOf(f) < 0; }));
  same(coverage.truncated_fields, payload.truncated_fields);
  integer(coverage.links_considered, 100);
  integer(coverage.unique_links, coverage.links_considered);
  integer(coverage.attachment_records, 20);
  if (coverage.attachment_records !== (payload.attachments || []).length) fail();
  unique(coverage.limitations, ANALYSIS_LIMITATIONS);
  same(coverage.limitations, ANALYSIS_LIMITATIONS);
  if (!Array.isArray(coverage.issues) || coverage.issues.length > 7 * Object.keys(COVERAGE_ISSUES).length) fail();
  var issueKeys = [];
  coverage.issues.forEach(function (issue) {
    object(issue, ['field', 'code']);
    if (available.indexOf(issue.field) < 0 || !Object.prototype.hasOwnProperty.call(COVERAGE_ISSUES, issue.code)) fail();
    var key = issue.field + ':' + issue.code;
    if (issueKeys.indexOf(key) >= 0) fail();
    issueKeys.push(key);
  });
  if (!Array.isArray(result.findings) || result.findings.length > 343) fail();
  if (result.analysis_status === 'unavailable') {
    if (result.score !== null || result.verdict !== 'analysis_unavailable' ||
        result.findings.length || result.scoring !== null || result.checks_run.length) fail();
    return;
  }
  if (!result.checks_run.length || ['complete', 'partial'].indexOf(result.analysis_status) < 0) fail();
  var incomplete = coverage.unavailable_fields.length || coverage.truncated_fields.length ||
    coverage.issues.length || result.checks_skipped.length;
  if ((result.analysis_status === 'partial') !== Boolean(incomplete)) fail();
  integer(result.score, 100);
  var expectedVerdict = result.score >= 60 ? 'high_risk' : result.score >= 25 ? 'suspicious' :
    incomplete ? 'inconclusive' : 'low_observed_risk';
  if (result.verdict !== expectedVerdict) fail();
  object(result.scoring, ['requested_points', 'category_suppressed_points', 'global_suppressed_points', 'duplicates_removed']);
  var sums = { requested_points: 0, awarded_points: 0, category_suppressed_points: 0, global_suppressed_points: 0 };
  var ids = [], categoryPoints = { url: 0, sender: 0, content: 0, attachment: 0 };
  result.findings.forEach(function (finding) {
    object(finding, ['finding_id', 'rule_id', 'category', 'severity', 'field', 'evidence', 'explanation',
      'requested_points', 'awarded_points', 'category_suppressed_points', 'global_suppressed_points']);
    if (typeof finding.finding_id !== 'string' || !/^[0-9a-f]{64}$/.test(finding.finding_id) ||
        ids.indexOf(finding.finding_id) >= 0 || result.checks_run.indexOf(finding.rule_id) < 0 ||
        finding.category !== finding.rule_id.split('.')[0] || available.indexOf(finding.field) < 0 ||
        ['low', 'medium', 'high'].indexOf(finding.severity) < 0) fail();
    ids.push(finding.finding_id);
    text(finding.evidence, 256); text(finding.explanation, 400);
    if (!finding.explanation) fail();
    Object.keys(sums).forEach(function (key) { integer(finding[key], 100); sums[key] += finding[key]; });
    if (finding.requested_points !== finding.awarded_points + finding.category_suppressed_points +
        finding.global_suppressed_points) fail();
    categoryPoints[finding.category] += finding.awarded_points;
  });
  if (sums.awarded_points !== result.score) fail();
  Object.keys(result.scoring).forEach(function (key) {
    integer(result.scoring[key], key === 'duplicates_removed' ? 512 : 51200);
    if (key !== 'duplicates_removed' && result.scoring[key] !== sums[key]) fail();
  });
  var caps = { url: 60, sender: 20, content: 35, attachment: 40 };
  Object.keys(caps).forEach(function (key) { if (categoryPoints[key] > caps[key]) fail(); });
}
