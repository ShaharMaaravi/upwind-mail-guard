/** Fixed labels, validated counts, and escaped subject/evidence enter card markup. */
function escapeCardText(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function paragraph(text) {
  return CardService.newTextParagraph().setText(text);
}

function baseCard(section, extraSections, actionLabel) {
  var builder = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle('Email analysis')
  ).addSection(section);
  (extraSections || []).forEach(function (extra) { builder.addSection(extra); });
  if (actionLabel) builder.setFixedFooter(CardService.newFixedFooter().setPrimaryButton(
    CardService.newTextButton().setText(actionLabel).setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setOnClickAction(CardService.newAction().setFunctionName('onAnalyzeEmail'))));
  return builder.build();
}

function startCard(hasMessage) {
  var section = CardService.newCardSection().addWidget(paragraph(
    '<b>Understand this email’s warning signs.</b><br>Get a risk score, clear reasons, and a suggested next step.'
  ));
  if (hasMessage) {
    section.addWidget(paragraph(
      'Analyze sends bounded sender, Reply-To, subject, body, authentication-header text and ' +
      'attachment names/types/sizes to your backend. Content is not stored. Links and attachment contents are not opened.'
    ));
    section.addWidget(paragraph('In a conversation, expand the message you want to check first.'));

  } else {
    section.addWidget(paragraph('Open an email, then choose Analyze this email.'));
  }
  return baseCard(section, [], hasMessage ? 'Analyze this email' : null);
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
    '<br>No safety verdict was produced. Return to the message list and reopen the email to retry.'
  )));
}

var FIELD_LABELS = { from_address: 'Sender', reply_to: 'Reply-To', subject: 'Subject',
  plain_text: 'Plain text', html: 'HTML', authentication_results: 'Authentication header', attachments: 'Attachment metadata' };

/** Native collapse controls keep details available without retaining email state. */
function detailSection(title, visibleWidgets) {
  return CardService.newCardSection().setHeader(title).setCollapsible(true)
    .setNumUncollapsibleWidgets(visibleWidgets);
}

function messagePreview(value, limit) {
  if (value === null) return '(unavailable)';
  var chars = Array.from(value.replace(/\s+/g, ' ').trim());
  return chars.length ? chars.slice(0, limit).join('') + (chars.length > limit ? '…' : '') : '(empty)';
}

function analysisCard(result, payload) {
  var verdicts = { low_observed_risk: 'Low observed risk', suspicious: 'Suspicious',
    high_risk: 'High risk', inconclusive: 'Inconclusive', analysis_unavailable: 'Analysis unavailable' };
  var colors = { low_observed_risk: '#17463D', suspicious: '#8A4B00', high_risk: '#B3261E',
    inconclusive: '#8A4B00', analysis_unavailable: '#5F6368' };
  var actions = {
    low_observed_risk: 'Verify unexpected requests independently before acting.',
    suspicious: 'Pause. Verify the sender and request through a trusted channel.',
    high_risk: 'Avoid links and attachments. Verify the request independently.',
    inconclusive: 'Coverage is incomplete. Verify the message independently.',
    analysis_unavailable: 'No check could run. Reopen the message and try again.'
  };
  var summary = CardService.newCardSection();
  summary.addWidget(paragraph('<font color="' + colors[result.verdict] + '"><b>' +
    verdicts[result.verdict] + '</b></font>' +
    (result.score === null ? '<br>No score available.' : '<br><b>Risk score: ' + result.score + ' / 100</b>')));
  summary.addWidget(paragraph(actions[result.verdict]));
  var coverageText = result.analysis_status === 'partial' ? '<b>Partial analysis</b>' :
    result.analysis_status === 'complete' ? 'All implemented checks ran' : 'Analysis unavailable';
  coverageText += ' · ' + result.checks_run.length + ' / ' + Object.keys(RULE_LABELS).length + ' checks';
  ['unavailable_fields', 'truncated_fields'].forEach(function (key) {
    if (result.coverage[key].length) coverageText += '<br>' +
      (key === 'unavailable_fields' ? 'Unavailable: ' : 'Truncated: ') +
      result.coverage[key].map(function (f) { return FIELD_LABELS[f]; }).join(', ');
  });
  if (result.coverage.issues.length) coverageText += '<br>' + result.coverage.issues.length + ' parsing or evidence limitations';
  if (result.checks_skipped.length) coverageText += '<br>' + result.checks_skipped.length + ' checks skipped';
  summary.addWidget(paragraph(coverageText));
  summary.addWidget(paragraph('<b>' + escapeCardText(messagePreview(payload.message.subject, 100)) +
    '</b><br>Analyzed text: ' + escapeCardText(messagePreview(payload.message.plain_text, 120))));

  var shown = result.findings.slice().sort(function (a, b) { return b.awarded_points - a.awarded_points; }).slice(0, 8);
  var evidence = shown.length ? detailSection('Why this score', 1) : CardService.newCardSection().setHeader('Why this score');
  if (shown.length) {
    var headlines = shown.slice(0, 3).map(function (finding) {
      return '<b>+' + finding.awarded_points + '</b> · ' + RULE_LABELS[finding.rule_id];
    }).join('<br>');
    if (result.findings.length > 3) headlines += '<br>Top 3 of ' + result.findings.length + ' findings. Expand for evidence.';
    evidence.addWidget(paragraph(headlines));
  } else evidence.addWidget(paragraph(result.score === null ? 'No findings are available.' : 'No implemented warning signs were found.'));
  var visiblePoints = 0;
  shown.forEach(function (finding) {
    visiblePoints += finding.awarded_points;
    evidence.addWidget(paragraph('<b>' + RULE_LABELS[finding.rule_id] + ' · +' + finding.awarded_points +
      '</b><br>' + escapeCardText(finding.explanation) + '<br>Evidence (' + FIELD_LABELS[finding.field] +
      '): ' + escapeCardText(finding.evidence) + '<br>Requested ' + finding.requested_points +
      '; awarded ' + finding.awarded_points + '; removed by category cap ' + finding.category_suppressed_points +
      '; removed by total cap ' + finding.global_suppressed_points + '.'));
  });
  if (result.findings.length > shown.length) evidence.addWidget(paragraph(
    'Showing ' + shown.length + ' of ' + result.findings.length + ' findings. Additional findings contribute ' +
    (result.score - visiblePoints) + ' points.'));
  if (result.scoring && shown.length) evidence.addWidget(paragraph('<b>Score calculation</b><br>Total: ' + result.scoring.requested_points +
    ' requested − ' + result.scoring.category_suppressed_points + ' category-capped − ' +
    result.scoring.global_suppressed_points + ' total-capped = <b>' + result.score + ' points</b>. ' +
    result.scoring.duplicates_removed + ' duplicate signals removed.'));

  var coverage = detailSection('Checks and limitations', 0);
  coverage.addWidget(paragraph('Checks run: ' + result.checks_run.length + ' / ' + Object.keys(RULE_LABELS).length +
    '. Links considered: ' + result.coverage.links_considered + ' (unique evidence: ' + result.coverage.unique_links + ').'));
  if (result.checks_run.length) coverage.addWidget(paragraph(result.checks_run.map(function (id) { return RULE_LABELS[id]; }).join('<br>')));
  if (result.checks_skipped.length) coverage.addWidget(paragraph('<b>Skipped checks:</b><br>' + result.checks_skipped.map(function (check) {
    var reasons = { missing_fields: 'missing input', invalid_fields: 'invalid input', unknown_domain_boundary: 'unknown domain boundary' };
    return RULE_LABELS[check.rule_id] + ': ' + reasons[check.reason] + ' (' +
      check.fields.map(function (f) { return FIELD_LABELS[f]; }).join(', ') + ')';
  }).join('<br>')));
  if (result.coverage.issues.length) coverage.addWidget(paragraph('<b>Evidence limitations:</b><br>' +
    result.coverage.issues.slice(0, 6).map(function (issue) { return FIELD_LABELS[issue.field] + ': ' + COVERAGE_ISSUES[issue.code]; }).join('<br>') +
    (result.coverage.issues.length > 6 ? '<br>' + (result.coverage.issues.length - 6) + ' additional parsing/limit issues.' : '')));
  coverage.addWidget(paragraph('Attachment metadata: ' + (payload.attachments === null ? 'unavailable' : result.coverage.attachment_records + ' records') +
    '. Attachment contents are not inspected. Authentication claims are unverified. URLs are not visited.'));
  coverage.addWidget(paragraph('Content checks use English patterns. HTML is not visually rendered, and quoted or forwarded content is not separated. Legitimate messages can trigger warnings.'));
  coverage.addWidget(paragraph('A heuristic score is not a probability. Analysis reference: ' + escapeCardText(result.request_id)));
  var note = CardService.newCardSection().addWidget(paragraph('A low score does not guarantee safety.'));
  return baseCard(summary, [evidence, coverage, note], 'Analyze again');
}
