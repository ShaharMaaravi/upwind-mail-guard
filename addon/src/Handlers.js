function onHomepage() {
  return startCard(false);
}

function onGmailMessage(e) {
  // A fresh root card for every message; no cached results or stored message IDs.
  return startCard(Boolean(e && e.gmail && e.gmail.messageId));
}

function onTestConnection(e) {
  var card;
  try {
    var payload = extractDiagnostic(e);
    card = diagnosticCard(callDiagnostic(payload), payload);
  } catch (error) {
    card = errorCard(error && error.message);
  }
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card)).build();
}

function onAnalyzeEmail(e) {
  var card;
  try {
    var payload = extractAnalysis(e);
    card = analysisCard(callAnalysis(payload), payload);
  } catch (error) {
    card = errorCard(error && error.message);
  }
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card)).build();
}
