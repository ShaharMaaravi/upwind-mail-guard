# Milestone 0 live verification

**Core integration gate passed on 2026-11-16.** This record distinguishes observed Gmail behavior
from automated coverage and broader cases still pending before final submission.

Environment: personal Gmail account, unpublished Apps Script test deployment, local FastAPI
backend behind a temporary Cloudflare HTTPS tunnel. Scope:
`https://www.googleapis.com/auth/gmail.addons.current.message.action`.
No broad mailbox scope was added. The author explicitly approved authorization, storing the demo
token in Script Properties, and sending one synthetic email to the same account.

## Observed in Gmail

- [x] Install the test deployment and authorize the intended current-message action scope.
- [x] Outside an opened message, the add-on asks the user to open an email.
- [x] A synthetic message displays the explicit Test connection action and transmission notice.
- [x] Clicking the action displays a real backend-connected diagnostic card in Gmail.
- [x] All implemented getters worked: sender 43 characters; Reply-To 0; subject 27; plain text 39;
      HTML 64; authentication header 0. Counts reflect Gmail's representation, including its
      formatting. Zero-length fields remained distinct from unavailable fields.
- [x] The synthetic body included emoji and Hebrew and completed the full round trip.
- [x] Attachments are explicitly not inspected; authentication claims remain unverified.
- [x] Stopping the backend produced Analysis unavailable, with no score or safe verdict.
- [x] Restarting the backend and reopening the message produced a successful result with a new
      request reference. Returning to search results reset to the homepage, and reopening the
      message produced a fresh action card.
- [x] Local backend/tunnel logs were checked for the demo token and synthetic body text; neither
      was present. No real email content was submitted to the backend.

The outage test used an unavailable origin, which returned promptly through the tunnel. It does
not prove behavior at Google's hard execution deadline. For reliable retries in this test, return
to the message list and reopen the message; simply closing/reopening the sidebar may retain a card.

## Broader live cases still pending

- [ ] Two messages within one thread: verify the selected message, not the prior message, is read.
- [ ] Switch between different messages and check for stale results.
- [ ] Long synthetic message: observe truncation and elapsed time.
- [ ] HTML-like subject: verify escaping in actual CardService rendering.
- [ ] Metadata-only attachment retrieval feasibility before implementing attachment rules.
- [ ] Wrong backend token in the live add-on. API rejection/client error handling are already
      covered by automated tests, and unauthorized public HTTPS requests were rejected.
- [ ] Slow/hanging backend near Google's hard execution deadline.
- [ ] Inspect Google execution logs for accidental content/token retention.
- [ ] Container build, durable hosting, remote CI, and fresh-checkout reviewer rehearsal.

Do not commit email bodies, addresses, credentials, or private screenshots as evidence.
