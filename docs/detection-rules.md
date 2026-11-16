# Detection rules and fixture evidence

Milestone 2 implements eight pure rules in `backend/app/rules.py`. No message URL, remote image,
attachment body, or external reputation service is accessed. The rules produce signals; the scorer
deduplicates and caps them. A finding indicates a warning pattern, not proof of malicious intent.

## Implemented checks

| Rule | Trigger | Important boundary |
| --- | --- | --- |
| `url.display_mismatch` | A whole HTTP(S)/`www.`/protocol-relative URL or bare domain label identifies a different registrable domain/IP from its target | Ordinary prose and common filename labels are ignored. Subdomains of the same registrable domain match; private PSL tenants remain distinct. Unresolved explicit URL labels produce coverage issues. Legitimate tracking can trigger it. |
| `url.userinfo` | Target contains user-info before `@` | The actual parsed host is reported; credentials/query strings are not echoed by URL findings. Some legitimate legacy URLs use user-info. |
| `url.ip_host` | Target uses an ordinary IPv4/IPv6 literal after IDNA normalization | An IP destination is weak evidence and receives 15 points. Browser-specific integer/octal/short IPv4 repairs are not emulated. |
| `sender.reply_to_mismatch` | Valid From and nonempty Reply-To have different registrable domains | Empty Reply-To is normal. Missing, ambiguous, or unknown-boundary addresses skip the comparison. Different support/mailing-service domains can be legitimate. |
| `content.credentials_pressure` | An English request verb near a credential term plus pressure within a bounded context | Request verbs include enter/provide/send/share/confirm/verify/submit/update; terms include password/passcode/OTP/one-time code/login credentials. A credential mention or urgency alone does not suffice. |
| `content.payment_pressure` | An English payment/gift-card request plus nearby pressure | Patterns include pay/settle invoice, send/wire/transfer funds, and buy/purchase gift cards. Ordinary invoices due today can trigger it. |
| `attachment.executable` | Normalized final filename suffix belongs to the screening list | Metadata only: no malware scan, archive inspection, MIME/type verification, or file execution. |
| `attachment.double_extension` | A document/archive suffix immediately precedes an executable suffix | `invoice.pdf.exe` triggers both attachment rules; `report.final.docx`, `source.tar.gz`, and `invoice.exe.txt` do not. Correlated findings share the 40-point attachment cap. |

Content matching examines subject, plain text, and extracted HTML independently. It requires a request
and pressure in the same field, within 100 characters before/after the matched request. It recognizes
urgency, immediately/today, final notices, short hour/minute deadlines, and account suspension language.
Simple nearby negations such as “never share” or “do not pay” suppress the match. It does not implement
semantic negation, cross-field reasoning, language detection, or translation. A request in the body
with urgency only in the subject can be missed. Each content rule awards at most once per message.

Filename matching uses NFKC/case folding, removes control/format characters for matching, takes the
final path segment, and ignores trailing spaces/dots. Ambiguous original names remain coverage issues,
and their controls are made visible in evidence. Screening suffixes:

`exe, msi, msix, com, bat, cmd, ps1, vbs, vbe, js, jse, mjs, scr, pif, lnk, hta, cpl, dll, jar, wsf, wsh, sh, py`

The preceding document/archive suffix set is defined next to it in the module. This limited policy is
not a complete executable inventory. Gmail itself blocks many potentially unsafe attachment types,
so executable-name tests use synthetic JSON metadata and do not require sending executable files.
[Google's blocked attachment documentation](https://support.google.com/mail/answer/6590?hl=en-GB).

## Coverage and verdicts

All eight rules appear exactly once in `checks_run` or `checks_skipped`. A missing field is not an empty
field. Skipped checks explain whether prerequisites are missing, invalid, or lack a known domain
boundary. When another supported field is available, usable checks still run and their findings remain
visible. A check that runs over limited evidence does not make that evidence complete.

- No evaluable checks: unavailable, null score, no findings.
- Any missing/truncated field, normalization issue, or skipped check: partial analysis.
- Partial score below 25: inconclusive. Scores 25–59 remain suspicious; 60–100 remain high risk.
- Complete coverage means the implemented checks had their supplied inputs; it does not mean
  authentication was verified, attachments were scanned, or all possible threats were assessed.

Authentication headers never add or subtract points. A forged SPF/DKIM/DMARC pass does not cancel
a URL finding. Always-present limitations disclose English content rules, unverified authentication,
unvisited URLs, uninspected attachment bytes, unrendered HTML, and unseparated quoted content.

## Synthetic corpus

`fixtures/detection-cases.json` provides a complete base request and 20 explicit message/metadata
variants. Each specifies expected rule IDs, exact score, verdict, and analysis status. The test suite
checks these through HTTP and compares them to direct core results. The corpus is deliberately small
and authored alongside the rules; it is regression evidence, not an independent accuracy benchmark.

| Fixture group | Expected behavior |
| --- | --- |
| Team update, marketing prose, same-site subdomains, Unicode/punycode equivalence, security guidance, ordinary multi-extension files | No findings; score 0 with complete supplied coverage |
| Credential request with urgency; payment request with urgency | One content finding, score 25 |
| Display mismatch, different private hosting tenants | URL mismatch, score 40 |
| URL with deceptive display, user-info, and literal IP | Requested 80; URL cap awards 60 |
| Reply-To mismatch | One weak sender signal, score 15 |
| `invoice.PDF.EXE` with a claimed PDF MIME type | Two filename signals; attachment cap awards 40 |
| Forged authentication pass with URL mismatch | Score stays 40 |
| Unknown destination domain or missing attachment metadata | Score 0, partial/inconclusive |
| Authentication header as the only readable input | No supported check can run; unavailable/null score |
| Quoted phishing example, legitimate displayed-domain tracking link, ordinary invoice due today | Explicit known false positives: 25, 40, and 25 respectively |

Additional tests cover duplicate links across plain/HTML, private suffixes, IDNs, IPs, malformed input,
unresolved labels, Unicode filenames, redaction, no network access, truncation, and the 100-link /
20-attachment combined budget. The maximum current signal count is 343; the stress case reconciles
every suppressed point and keeps the serialized response below 256 KiB for that fixture. That test
is not a universal response byte-limit guarantee; the Gmail client must enforce its own bound.

## Concrete trace

`fixtures/analysis-request.json` yields:

| Finding | Requested | Awarded | Category-suppressed |
| --- | ---: | ---: | ---: |
| Displayed `example.com` → target `example.net` | 40 | 40 | 0 |
| Executable filename `invoice.pdf.exe` | 35 | 35 | 0 |
| Misleading double extension | 20 | 5 | 15 |
| From `example.com` → Reply-To `example.net` | 15 | 15 | 0 |
| Total | 110 | **95** | 15 |

No global suppression is needed. All eight rules ran, four found warning signals, and authentication
data was unavailable, so the result is **high risk / partial analysis**. The same case passes through
a real localhost HTTP server in `npm run test:integration`, including add-on response validation
and card rendering. Gmail now displays analysis results; its separate live synthetic case scores
75 as recorded in [live verification](live-verification.md).

Useful interview questions: why a legitimate tracking link can score 40, why a weak mismatch can
appear in a low-score result, how missing metadata changes the verdict, why the same link is awarded
once, and why a forged authentication pass has no effect.
