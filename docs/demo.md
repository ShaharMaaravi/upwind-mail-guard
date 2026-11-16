# Gmail demonstration

Use a demonstration account and synthetic messages only. Keep the backend and HTTPS tunnel running,
confirm `/healthz`, and check that the deployed add-on uses the current HTTPS origin and matching
token. See [installation](gmail-setup.md); a restarted temporary tunnel may require rebuilding and
uploading the add-on. This walkthrough describes the tested milestone 3 behavior.

1. Open the existing benign synthetic test message. Open Upwind Mail Guard and explain the
   transmission notice before choosing **Analyze this email**. Show **0 / low observed risk**,
   no findings, all eight checks run, and the limitations. Zero is not a guarantee of safety.
2. Open the existing suspicious synthetic message with the literal HTML-like subject and harmless
   text attachment. Analyze it. Show **75 / high risk**, evidence, and the contribution arithmetic:
   credential pressure 25 + URL user-info 25 + IP host 15 + payment pressure 10 = 75. Payment
   requested 25 but lost 15 to the 35-point content cap. Do not visit the example URL.
3. Show coverage: one attachment metadata record, all eight checks, attachment contents not inspected,
   authentication unverified, URLs not visited, English-only content patterns, and HTML/quoted-content limits.
4. Switch back to the benign message. The add-on must present a fresh action before analysis and
   return the benign result, not a stale 75.
5. For the failure demonstration, stop only the identified development backend process. Choose
   **Analyze again** and show **Analysis unavailable**, without a score. Restart the backend with
   the same secret, return to the message list, reopen the message, and analyze again to show recovery.

The already-sent suspicious fixture combines urgent credential/payment wording with a user-info
URL targeting a documentation IP address; its harmless attachment contributes zero points. The
fixture is intentionally conspicuous. Do not describe these two examples as accuracy evaluation.

For a separate reproducible API example, `fixtures/analysis-request.json` scores **95**. It has
different signals: displayed/target domain mismatch, Reply-To mismatch, and executable/double-extension
filename metadata. `npm run test:integration` verifies that example and all 20 detection-corpus cases
against a local backend, with Google services mocked.

Outstanding final rehearsal items are tracked in [live verification](live-verification.md).
