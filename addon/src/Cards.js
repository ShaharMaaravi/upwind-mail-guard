/** Fixed labels, validated counts, and escaped subject/evidence enter card markup. */
function escapeCardText(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function paragraph(text) {
  return CardService.newTextParagraph().setText(text);
}

function baseCard(section, extraSections) {
  var builder = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle('Upwind Mail Guard').setSubtitle('Email risk analysis')
  ).addSection(section);
  (extraSections || []).forEach(function (extra) { builder.addSection(extra); });
  return builder.build();
}

function startCard(hasMessage) {
  var section = CardService.newCardSection().addWidget(paragraph(
    'Check this email for warning signs and see the evidence behind its risk score.'
  ));
  if (hasMessage) {
    section.addWidget(paragraph(
      'Analyze sends limited sender, Reply-To, subject, body, authentication-header text and ' +
      'available attachment names/types/sizes to your configured backend. Content is not stored. ' +
      'Links are not visited and attachment contents are not opened.'
    ));
    section.addWidget(paragraph('In a conversation, expand the message you want to check before analyzing. Each result covers one message.'));
    section.addWidget(CardService.newTextButton().setText('Analyze this email')
      .setOnClickAction(CardService.newAction().setFunctionName('onAnalyzeEmail')));
  } else {
    section.addWidget(paragraph('Open an email, then choose Analyze this email.'));
  }
  return baseCard(section);
}

function diagnosticCard(result, payload) {
  var section = CardService.newCardSection().addWidget(paragraph(
    '<b>Backend connected — diagnostic only</b><br>No threat analysis was performed.'
  ));
  section.addWidget(paragraph('Selected subject: ' + escapeCardText(
    payload.message.subject === null ? '(unavailable)' : payload.message.subject.slice(0, 120)
  )));
  var labels = {
    from_address: 'Sender', reply_to: 'Reply-To', subject: 'Subject',
    plain_text: 'Plain text', html: 'HTML', authentication_results: 'Authentication header'
  };
  Object.keys(labels).forEach(function (name) {
    var count = result.field_characters[name];
    section.addWidget(paragraph(labels[name] + ': ' + (count === null ? 'unavailable' : count + ' characters') +
      (result.truncated_fields.indexOf(name) >= 0 ? ' (truncated)' : '')));
  });
  section.addWidget(paragraph('Attachments: not inspected. Authentication claims: unverified.'));
  section.addWidget(paragraph('Test reference: ' + escapeCardText(result.request_id)));
  return baseCard(section);
}

function errorCard(code) {
  var messages = {
    configuration_error: 'The add-on is not configured. Check its backend settings.',
    message_unavailable: 'Reopen the email and authorize the add-on, then try again.',
    request_too_large: 'The message could not be sent within the request limit.',
    backend_unauthorized: 'Backend authentication failed. Check the configured token.',
    rate_limited: 'Too many requests. Wait one minute before trying again.',
    invalid_response: 'The backend returned an inconsistent or oversized analysis response.',
    backend_unavailable: 'The backend could not complete the request. Check the service and retry.'
  };
  var message = Object.prototype.hasOwnProperty.call(messages, code) ? messages[code] : messages.backend_unavailable;
  return baseCard(CardService.newCardSection().addWidget(paragraph(
    '<b>Analysis unavailable</b><br>' + message +
    '<br>No safety verdict was produced. Reopen the add-on to retry.'
  )));
}

var FIELD_LABELS = { from_address: 'Sender', reply_to: 'Reply-To', subject: 'Subject',
  plain_text: 'Plain text', html: 'HTML', authentication_results: 'Authentication header', attachments: 'Attachment metadata' };

function analysisCard(result, payload) {
  var verdicts = { low_observed_risk: 'Low observed risk', suspicious: 'Suspicious',
    high_risk: 'High risk', inconclusive: 'Inconclusive', analysis_unavailable: 'Analysis unavailable' };
  var actions = {
    low_observed_risk: 'Few implemented warning signs were found. Verify unexpected requests independently.',
    suspicious: 'Pause before acting. Verify the sender and request through a channel you already trust.',
    high_risk: 'Avoid the message links and attachments. Verify the request through a known, independent channel.',
    inconclusive: 'Coverage is incomplete. Verify the message independently before acting.',
    analysis_unavailable: 'The available information could not support any check. Reopen the message and retry.'
  };
  var summary = CardService.newCardSection();
  summary.addWidget(paragraph('<b>' + verdicts[result.verdict] + '</b>' +
    (result.score === null ? '<br>No score available.' : '<br><b>Risk score: ' + result.score + ' / 100</b>')));
  summary.addWidget(paragraph('Selected subject: ' + escapeCardText(
    payload.message.subject === null ? '(unavailable)' : payload.message.subject.slice(0, 160))));
  var preview = payload.message.plain_text === null ? null :
    Array.from(payload.message.plain_text.replace(/\s+/g, ' ').trim());
  summary.addWidget(paragraph('Analyzed text: ' + escapeCardText(preview === null ? '(unavailable)' :
    preview.length ? preview.slice(0, 120).join('') + (preview.length > 120 ? '…' : '') : '(empty)')));
  summary.addWidget(paragraph(result.analysis_status === 'partial' ?
    '<b>Partial analysis — some evidence was unavailable or limited.</b>' :
    result.analysis_status === 'complete' ? 'All implemented checks ran on the supplied fields.' :
    'No check could run on the supplied fields.'));
  summary.addWidget(paragraph(actions[result.verdict] + '<br>A heuristic score is not a probability or a guarantee of safety.'));

  var evidence = CardService.newCardSection().setHeader('Why this score');
  var shown = result.findings.slice().sort(function (a, b) { return b.awarded_points - a.awarded_points; }).slice(0, 8);
  var visiblePoints = 0;
  shown.forEach(function (finding) {
    visiblePoints += finding.awarded_points;
    evidence.addWidget(paragraph('<b>' + RULE_LABELS[finding.rule_id] + ' · +' + finding.awarded_points +
      '</b><br>' + escapeCardText(finding.explanation) + '<br>Evidence (' + FIELD_LABELS[finding.field] +
      '): ' + escapeCardText(finding.evidence)));
    evidence.addWidget(paragraph('Requested ' + finding.requested_points + '; awarded ' + finding.awarded_points +
      '; removed by category cap ' + finding.category_suppressed_points +
      '; removed by total cap ' + finding.global_suppressed_points + '.'));
  });
  if (!shown.length) evidence.addWidget(paragraph(result.score === null ?
    'No findings are available.' : 'No implemented warning patterns matched the available evidence.'));
  if (result.findings.length > shown.length) evidence.addWidget(paragraph(
    'Showing ' + shown.length + ' of ' + result.findings.length + ' findings. Additional findings contribute ' +
    (result.score - visiblePoints) + ' points.'));
  if (result.scoring) evidence.addWidget(paragraph('Total: ' + result.scoring.requested_points +
    ' requested − ' + result.scoring.category_suppressed_points + ' category-capped − ' +
    result.scoring.global_suppressed_points + ' total-capped = <b>' + result.score + ' points</b>. ' +
    result.scoring.duplicates_removed + ' duplicate signals removed.'));

  var coverage = CardService.newCardSection().setHeader('Coverage and limits');
  coverage.addWidget(paragraph('Checks run: ' + result.checks_run.length + ' / ' + Object.keys(RULE_LABELS).length +
    '. Links considered: ' + result.coverage.links_considered + ' (unique evidence: ' + result.coverage.unique_links + ').'));
  if (result.checks_run.length) coverage.addWidget(paragraph(result.checks_run.map(function (id) { return RULE_LABELS[id]; }).join('<br>')));
  if (result.checks_skipped.length) coverage.addWidget(paragraph('<b>Skipped checks:</b><br>' + result.checks_skipped.map(function (check) {
    var reasons = { missing_fields: 'missing input', invalid_fields: 'invalid input', unknown_domain_boundary: 'unknown domain boundary' };
    return RULE_LABELS[check.rule_id] + ': ' + reasons[check.reason] + ' (' +
      check.fields.map(function (f) { return FIELD_LABELS[f]; }).join(', ') + ')';
  }).join('<br>')));
  ['unavailable_fields', 'truncated_fields'].forEach(function (key) {
    if (result.coverage[key].length) coverage.addWidget(paragraph(
      (key === 'unavailable_fields' ? 'Unavailable: ' : 'Truncated: ') + result.coverage[key].map(function (f) { return FIELD_LABELS[f]; }).join(', ')));
  });
  if (result.coverage.issues.length) coverage.addWidget(paragraph('<b>Evidence limitations:</b><br>' +
    result.coverage.issues.slice(0, 6).map(function (issue) { return FIELD_LABELS[issue.field] + ': ' + COVERAGE_ISSUES[issue.code]; }).join('<br>') +
    (result.coverage.issues.length > 6 ? '<br>' + (result.coverage.issues.length - 6) + ' additional parsing/limit issues.' : '')));
  coverage.addWidget(paragraph('Attachment metadata: ' + (payload.attachments === null ? 'unavailable' : result.coverage.attachment_records + ' records') +
    '. Attachment contents are not inspected. Authentication claims are unverified. URLs are not visited.'));
  coverage.addWidget(paragraph('Content checks use English patterns. HTML is not visually rendered, and quoted or forwarded content is not separated. Legitimate messages can trigger warnings.'));
  coverage.addWidget(paragraph('Analysis reference: ' + escapeCardText(result.request_id)));
  coverage.addWidget(CardService.newTextButton().setText('Analyze again')
    .setOnClickAction(CardService.newAction().setFunctionName('onAnalyzeEmail')));
  return baseCard(summary, [evidence, coverage]);
}
