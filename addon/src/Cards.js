/** Only fixed labels, validated counts and escaped local subject text enter card markup. */
function escapeCardText(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function paragraph(text) {
  return CardService.newTextParagraph().setText(text);
}

function baseCard(section) {
  return CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle('Upwind Mail Guard').setSubtitle('Integration diagnostic')
  ).addSection(section).build();
}

function startCard(hasMessage) {
  var section = CardService.newCardSection().addWidget(paragraph(
    'Milestone 0: connection test only. No maliciousness score or safety verdict is produced.'
  ));
  if (hasMessage) {
    section.addWidget(paragraph(
      'Clicking Test connection sends bounded sender, Reply-To, subject, body and authentication ' +
      'header text to your configured backend. Content is not stored. Use a synthetic test email.'
    ));
    section.addWidget(CardService.newTextButton().setText('Test connection')
      .setOnClickAction(CardService.newAction().setFunctionName('onTestConnection')));
  } else {
    section.addWidget(paragraph('Open an email to test the connection.'));
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
    configuration_error: 'Set the backend token in Script Properties before testing.',
    message_unavailable: 'Reopen the email and authorize the add-on, then try again.',
    request_too_large: 'The message could not be sent within the request limit.',
    backend_unauthorized: 'Backend authentication failed. Check the configured token.',
    rate_limited: 'Too many requests. Wait one minute before trying again.',
    invalid_response: 'The backend returned an invalid diagnostic response.',
    backend_unavailable: 'The backend could not complete the request. Check the service and retry.'
  };
  var message = Object.prototype.hasOwnProperty.call(messages, code) ? messages[code] : messages.backend_unavailable;
  return baseCard(CardService.newCardSection().addWidget(paragraph(
    '<b>Analysis unavailable</b><br>' + message +
    '<br>No safety verdict was produced. Reopen the add-on to retry.'
  )));
}
