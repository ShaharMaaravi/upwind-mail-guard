"""Small deterministic heuristics. No network, Gmail APIs, or file-content access."""

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass

from app.analysis_schemas import AnalysisField, CoverageIssue, SkippedCheck
from app.domains import Domain
from app.normalization import NormalizedMessage, normalize_url
from app.scoring import Signal

URL_RULES = ("url.display_mismatch", "url.userinfo", "url.ip_host")
CONTENT_RULES = ("content.credentials_pressure", "content.payment_pressure")
ATTACHMENT_RULES = ("attachment.executable", "attachment.double_extension")
SENDER_RULE = "sender.reply_to_mismatch"

# A deliberately limited screening list, not a malware/type detector.
EXECUTABLE_EXTENSIONS = frozenset(
    {
        "exe",
        "msi",
        "msix",
        "com",
        "bat",
        "cmd",
        "ps1",
        "vbs",
        "vbe",
        "js",
        "jse",
        "mjs",
        "scr",
        "pif",
        "lnk",
        "hta",
        "cpl",
        "dll",
        "jar",
        "wsf",
        "wsh",
        "sh",
        "py",
    }
)
DOCUMENT_EXTENSIONS = frozenset(
    {
        "pdf",
        "txt",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "jpg",
        "jpeg",
        "png",
        "gif",
        "csv",
        "zip",
        "gz",
        "tar",
    }
)
PRESSURE = re.compile(
    r"\b(?:urgent(?:ly)?|immediately|today|final (?:notice|warning)|"
    r"within \d{1,3} (?:minutes?|hours?)|account (?:will be |has been |is )?"
    r"(?:suspended|closed|locked))\b",
    re.IGNORECASE,
)
CREDENTIAL_REQUEST = re.compile(
    r"\b(?:enter|provide|send|share|confirm|verify|submit|update)\b[^.!?\n]{0,32}?"
    r"\b(?:password|passcode|otp|one[- ]time (?:code|password)|login credentials|"
    r"account credentials)\b",
    re.IGNORECASE,
)
PAYMENT_REQUEST = re.compile(
    r"\b(?:(?:pay|settle)\b[^.!?\n]{0,24}?\b(?:invoice|balance|fee|payment)|"
    r"(?:send|wire|transfer)\b[^.!?\n]{0,24}?\b(?:money|funds|payment)|"
    r"(?:buy|purchase)\b[^.!?\n]{0,24}?\bgift cards?)\b",
    re.IGNORECASE,
)
NEGATED_PREFIX = re.compile(
    r"\b(?:do not|don't|never|avoid|will not|won't|must not|should not)"
    r"(?:[\s,]+[\w'-]+){0,3}[\s,]+$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RuleEvaluation:
    signals: tuple[Signal, ...]
    checks_run: tuple[str, ...]
    checks_skipped: tuple[SkippedCheck, ...]
    issues: tuple[CoverageIssue, ...]


def evidence_text(value: str, limit: int = 256) -> str:
    """Make control/bidi/surrogate characters visible; keep both ends of long filenames."""
    visible = "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c) in {"Cc", "Cf", "Cs"} else c for c in value
    )
    if len(visible) <= limit:
        return visible
    half = (limit - 1) // 2
    return visible[:half] + "…" + visible[-(limit - half - 1) :]


def signal(rule: str, field: AnalysisField, evidence: str, *key_parts: str) -> Signal:
    # Hashing bounds keys even when IDNA expansion makes a canonical URL longer than its input.
    key = hashlib.sha256(json.dumps(key_parts, ensure_ascii=True).encode()).hexdigest()
    return Signal(rule, key, field, evidence_text(evidence))


def site_identity(domain: Domain) -> str | None:
    return domain.host if domain.is_ip else domain.registrable


def displayed_site(label: str) -> tuple[str | None, bool]:
    """Only a whole URL/domain label is a claim; arbitrary anchor prose is not."""
    explicit = label.lower().startswith(("https://", "http://", "www.", "//"))
    if not label or any(c.isspace() for c in label):
        return None, explicit
    if not explicit:
        if "." not in label or any(c in label for c in "/:@?#"):
            return None, False
        if label.rsplit(".", 1)[-1].lower() in DOCUMENT_EXTENSIONS:
            return None, False
    try:
        parsed = normalize_url(label if explicit else "https://" + label)
    except ValueError:
        return None, explicit
    identity = site_identity(parsed.domain)
    return identity, identity is None


def url_signals(message: NormalizedMessage) -> tuple[list[Signal], list[CoverageIssue]]:
    found: list[Signal] = []
    issues: list[CoverageIssue] = []
    for link in message.links:
        url = link.url
        if url.has_userinfo:
            found.append(
                signal(
                    "url.userinfo",
                    link.field,
                    "User-info before @; destination host: " + url.domain.host,
                    url.canonical,
                )
            )
        if url.domain.is_ip:
            found.append(
                signal(
                    "url.ip_host", link.field, "IP destination: " + url.domain.host, url.canonical
                )
            )
        if link.field != "html":
            continue
        shown, unresolved = displayed_site(link.label)
        if unresolved:
            issues.append(CoverageIssue(field="html", code="display_url_unresolved"))
        actual = site_identity(url.domain)
        if shown and actual and shown != actual:
            found.append(
                signal(
                    "url.display_mismatch",
                    "html",
                    "Displayed site: "
                    + evidence_text(shown, 100)
                    + "; destination site: "
                    + evidence_text(actual, 100),
                    url.canonical,
                    shown,
                )
            )
    return found, issues


def content_signal(message: NormalizedMessage, rule: str, pattern: re.Pattern) -> Signal | None:
    # One finding per content rule, even if plain/HTML versions or multiple sentences repeat it.
    for part in message.text_parts:
        for request in pattern.finditer(part.text):
            if NEGATED_PREFIX.search(part.text[max(0, request.start() - 80) : request.start()]):
                continue
            start, end = max(0, request.start() - 100), request.end() + 100
            window = part.text[start:end]
            if PRESSURE.search(window):
                return signal(rule, part.field, window, "message")
    return None


def attachment_signals(message: NormalizedMessage) -> list[Signal]:
    found = []
    for item in message.attachments or ():
        name = unicodedata.normalize("NFKC", item.filename).casefold()
        name = "".join(c for c in name if unicodedata.category(c) not in {"Cc", "Cf", "Cs"})
        name = re.split(r"[/\\]", name)[-1].rstrip(" .")
        parts = name.split(".")
        if len(parts) < 2 or parts[-1] not in EXECUTABLE_EXTENSIONS:
            continue
        found.append(signal("attachment.executable", "attachments", item.filename, name))
        if len(parts) >= 3 and parts[-2] in DOCUMENT_EXTENSIONS:
            found.append(signal("attachment.double_extension", "attachments", item.filename, name))
    return found


def run_rules(message: NormalizedMessage) -> RuleEvaluation:
    available = set(message.coverage.available_fields)
    found: list[Signal] = []
    ran: list[str] = []
    skipped: list[SkippedCheck] = []
    issues: list[CoverageIssue] = []

    def skip(rules, reason, fields):
        skipped.extend(SkippedCheck(rule_id=rule, reason=reason, fields=fields) for rule in rules)

    if {"plain_text", "html"} & available:
        ran.extend(URL_RULES[1:])
        if "html" in available:
            ran.append(URL_RULES[0])
        else:
            skip(URL_RULES[:1], "missing_fields", ["html"])
        links, link_issues = url_signals(message)
        found.extend(links)
        issues.extend(link_issues)
    else:
        skip(URL_RULES, "missing_fields", ["html", "plain_text"])

    sender_fields = ["from_address", "reply_to"]
    missing = [field for field in sender_fields if field not in available]
    address_issues = [issue for issue in message.coverage.issues if issue.field in sender_fields]
    if missing:
        skip([SENDER_RULE], "missing_fields", missing)
    elif address_issues or message.sender is None:
        reason = (
            "unknown_domain_boundary"
            if address_issues
            and all(issue.code == "unknown_domain_boundary" for issue in address_issues)
            else "invalid_fields"
        )
        skip([SENDER_RULE], reason, sorted({i.field for i in address_issues}) or ["from_address"])
    else:
        ran.append(SENDER_RULE)
        if (
            message.reply_to
            and message.sender.domain.registrable != message.reply_to.domain.registrable
        ):
            origin, reply = message.sender.domain.registrable, message.reply_to.domain.registrable
            found.append(
                signal(
                    SENDER_RULE,
                    "reply_to",
                    "From site: "
                    + evidence_text(origin, 100)
                    + "; Reply-To site: "
                    + evidence_text(reply, 100),
                    origin,
                    reply,
                )
            )

    if message.text_parts:
        ran.extend(CONTENT_RULES)
        for rule, pattern in zip(CONTENT_RULES, (CREDENTIAL_REQUEST, PAYMENT_REQUEST), strict=True):
            match = content_signal(message, rule, pattern)
            if match:
                found.append(match)
    else:
        skip(CONTENT_RULES, "missing_fields", ["subject", "plain_text", "html"])

    if message.attachments is not None:
        ran.extend(ATTACHMENT_RULES)
        found.extend(attachment_signals(message))
    else:
        skip(ATTACHMENT_RULES, "missing_fields", ["attachments"])
    return RuleEvaluation(
        tuple(found),
        tuple(sorted(ran)),
        tuple(sorted(skipped, key=lambda check: check.rule_id)),
        tuple(issues),
    )
