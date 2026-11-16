# Analysis contract and scoring foundation

Milestone 2 enables eight deterministic detection rules on the milestone 1 foundation. The live
Gmail adapter still calls `/v1/diagnose`; result cards will move to `/v1/analyze` in milestone 3.

## Request and coverage

`POST /v1/analyze` requires the same bearer authentication and JSON transport as `/v1/diagnose`.
Both routes share the 256 KiB body limit, five-second upload deadline, and 30/minute process-local
authenticated rate limit. Invalid input returns a redacted `{"error":"invalid_request"}` response.
See [the complete synthetic request](../fixtures/analysis-request.json).

| Field | Meaning and limit |
| --- | --- |
| `schema_version` | Literal string `1` |
| `request_id` | Lowercase UUID-shaped correlation string; no Gmail identifier |
| `message.from_address`, `reply_to`, `subject` | Required keys, nullable strings, at most 2,048 characters each |
| `message.plain_text`, `html` | Required keys, nullable strings, at most 16,000 characters each |
| `message.authentication_results` | Required key, nullable string, at most 4,096 characters; always unverified |
| `attachments` | Optional nullable list, at most 20 metadata records; omission means unavailable |
| `attachments[].filename` | Required string, at most 512 characters |
| `attachments[].content_type` | Required nullable string, at most 128 characters |
| `attachments[].size_bytes` | Required nullable integer from 0 through 10^12; booleans/strings rejected |
| `truncated_fields` | Required unique list of available field names; includes `attachments` |

Unknown fields are rejected. Attachment bytes and caller-generated findings/scores are not accepted.
`null` means unavailable; `""` or `[]` means read successfully but empty. Entirely unavailable requests
are rejected. Clients truncate before sending and identify each truncated field; oversized input is
rejected rather than silently shortened by schema validation.

The synthetic request produces this response excerpt:

```json
{
  "schema_version": "1",
  "request_id": "00000000-0000-4000-8000-000000000002",
  "policy_version": "heuristic-v2",
  "normalization_version": "normalize-v2",
  "analysis_status": "partial",
  "score": 95,
  "verdict": "high_risk",
  "scoring": {
    "requested_points": 110,
    "category_suppressed_points": 15,
    "global_suppressed_points": 0,
    "duplicates_removed": 0
  },
  "checks_skipped": []
}
```

The excerpt omits `findings`, `checks_run`, and `coverage`. Coverage lists available, unavailable,
and truncated fields; bounded issue codes; raw/unique link counts; attachment record count; and
limitations. Issues identify failure types without echoing rejected content. Findings include a
stable ID, rule ID, category, severity, source field, evidence up to 256 characters, explanation,
and requested/awarded/category-suppressed/globally-suppressed points. Evidence is untrusted text;
the Gmail renderer must escape it and keep URLs inert. The backend does not log message content.

`checks_run` identifies evaluated rules, including checks that found nothing. `checks_skipped`
identifies each unevaluated rule with its missing/invalid fields or unknown-domain reason. All
eight rules are accounted for exactly once. A check can run on a truncated or partially parsed
field; its coverage issues still make the overall result partial. No evaluable rules means
`analysis_status: unavailable`, a null score/accounting, no findings, and explicit skipped checks.

## Normalization behavior

1. Parse one sender and at most one Reply-To mailbox with `email.headerregistry`. Reject ambiguous
   lists, header injection, groups, malformed addresses, and address literals. An empty Reply-To is
   normal; an empty From cannot identify a sender.
2. Normalize domain names with IDNA, identify ordinary IPv4/IPv6 literals, and determine registrable
   boundaries with the offline PSL, including private suffixes. Unknown suffixes remain unknown.
3. Extract text and anchor targets/labels with `HTMLParser`; exclude head/script/style/template
   content. Decode entities but do not render CSS, execute code, load images, or resolve relative URLs.
4. Consider up to 100 raw links, HTML anchors first then plain-text HTTP(S)/`www.` URLs. Duplicates
   still consume this extraction budget. Record overflow and unsupported/invalid targets as issues.
5. Canonicalize HTTP(S) scheme, host, default port, and absent path; remove fragments. Keep user-info,
   path, and query, preserving evidence of deceptive structure. Distinct anchor labels survive
   deduplication. Unusual browser numeric-IP forms and browser-specific URL repairs are not emulated.
6. Normalize matching text with NFKC and collapsed whitespace. Replace invalid control/surrogate text
   and report issues. Bound each normalized body representation to 16,000 characters after expansion.
   Parse URLs from original text, so text normalization cannot erase their deceptive syntax.
7. Preserve attachment filename metadata with NFC, normalize MIME-type casing, and never access bytes.
   Empty names, controls, bidi/format characters, or path separators produce an ambiguity issue.

Limitations always disclose unverified authentication, unvisited URLs, uninspected attachment bytes,
unrendered HTML, and unseparated quoted content. Recognized ambiguous markup is reported; this is not
a complete browser grammar validator. Content rules explicitly disclose their English-only matching.
No DNS lookup, HTTP request, cache write, or PSL download occurs
during normalization. Tests forbid network access even for the first domain lookup.

## Provisional scoring policy

All eight rules below are enabled. Their exact behavior, prerequisites, and known limitations are
documented in [Detection rules](detection-rules.md). `heuristic-v2` activates the rules and extends
display comparison to IP identities; weights and caps remain the provisional milestone 1 values.
`normalize-v2` adds source-specific text parts and filename ambiguity reporting.

| Rule ID | Requested points | Category cap |
| --- | ---: | ---: |
| `url.display_mismatch` | 40 | URL: 60 |
| `url.userinfo` | 25 | URL: 60 |
| `url.ip_host` | 15 | URL: 60 |
| `sender.reply_to_mismatch` | 15 | Sender: 20 |
| `content.credentials_pressure` | 25 | Content: 35 |
| `content.payment_pressure` | 25 | Content: 35 |
| `attachment.executable` | 35 | Attachment: 40 |
| `attachment.double_extension` | 20 | Attachment: 40 |

The scorer accepts at most 512 internal signals; the current extraction/rule budgets emit at most
343. It deduplicates `(rule_id, evidence_key)`, selects a
stable evidence representative, and orders unique signals by descending requested weight then
rule ID/evidence key. Finding IDs are SHA-256 hashes of the rule/evidence key pair. Detectors hash
canonical identity tuples into bounded evidence keys. Content rules use one key per message/rule;
attachment rules use the normalized filename. Repeated occurrences do not inflate scores.

Apply the category budget first, then the global 100-point budget. Category usage includes points
subsequently suppressed by the global cap. Every finding satisfies:

`requested = awarded + category_suppressed + global_suppressed`

The response score equals the sum of awarded points, and aggregate accounting equals the findings.
Zero-point findings remain visible. Example: URL signals worth 40, 25, and 15 receive 40, 20, and 0;
the score is 60 and 20 points are suppressed by the URL cap. Reordering the inputs changes nothing.

The response contract reserves score bands 0–24 low observed risk, 25–59 suspicious, and 60–100 high
risk. A partial analysis scoring below 25 is inconclusive. A scored response requires nonempty
`checks_run`, reconciled findings, and accounting. An unavailable analysis cannot contain a score.
Missing/truncated/invalid fields or skipped checks cannot accompany a `complete` status. Complete
means the implemented checks ran on the supplied fields, not that every threat was checked or
authentication was trusted. These rules do not make a
heuristic score a probability, a malware verdict, or proof that an email is safe.

## PSL maintenance

`tldextract==5.4.0` packages `.tld_set_snapshot`. Its reviewed SHA-256 is:

`b69315c085d53972724b8f2df111ffc329b0c84fe0a47d62c8c91655cc774a38`

The extractor uses `cache_dir=None`, `suffix_list_urls=()`, `fallback_to_snapshot=True`, and
`include_psl_private_domains=True`. To update, deliberately select a new dependency version in a
development environment, inspect its snapshot/version changes, update the dependency pins and hash
in `domains.py`, rerun domain/normalization fixtures, and increment the normalization version if
results change. Record the reviewed update in this file. Never repair an integrity failure by enabling
runtime downloads. Pinning makes results reproducible but requires manual freshness maintenance.

Primary references: [tldextract configuration](https://github.com/john-kurkowski/tldextract),
[Python address headers](https://docs.python.org/3.12/library/email.headerregistry.html),
[HTMLParser](https://docs.python.org/3.12/library/html.parser.html), and
[URL parsing cautions](https://docs.python.org/3.12/library/urllib.parse.html#url-parsing-security).

## Review and later interview discussion

The code separates API validation, normalization, rule policy, and orchestration because each has
a different trust boundary. Scoring tests inject signals to isolate arithmetic; the 20-case message
corpus and adversarial tests also exercise actual detectors through the core and HTTP route.
Useful questions to revisit afterward:
why private suffixes matter, why risk and coverage are separate, why repeated evidence is capped,
what a browser parser would change, and why an authentication header cannot cancel a dangerous link.
