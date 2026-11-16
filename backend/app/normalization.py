"""Bounded, inert extraction. No DNS, URL fetching, HTML rendering, or attachment reads."""

import re
import unicodedata
from dataclasses import dataclass
from email.headerregistry import HeaderRegistry
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

from app.analysis_schemas import AnalysisField, AnalysisRequest, Coverage, CoverageIssue
from app.domains import Domain, normalize_domain

NORMALIZATION_VERSION = "normalize-v1"
MAX_LINKS = 100
MAX_URL_LENGTH = 2048
TEXT_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)


@dataclass(frozen=True)
class Address:
    display_name: str
    mailbox: str
    domain: Domain


@dataclass(frozen=True)
class Url:
    original: str
    canonical: str
    scheme: str
    domain: Domain
    has_userinfo: bool


@dataclass(frozen=True)
class Link:
    url: Url
    label: str
    field: AnalysisField


@dataclass(frozen=True)
class Attachment:
    filename: str
    content_type: str | None
    size_bytes: int | None


@dataclass(frozen=True)
class NormalizedMessage:
    sender: Address | None
    reply_to: Address | None
    subject: str | None
    body_text: str | None
    links: tuple[Link, ...]
    attachments: tuple[Attachment, ...] | None
    coverage: Coverage


def normalize_address(value: str) -> Address:
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError("Invalid address")
    try:
        header = HeaderRegistry()("From", value)
        if header.defects or len(header.addresses) != 1:
            raise ValueError("Ambiguous address")
        if any(group.display_name is not None for group in header.groups):
            raise ValueError("Address groups are unsupported")
        address = header.addresses[0]
        if not address.username or not address.domain:
            raise ValueError("Incomplete address")
        domain = normalize_domain(address.domain)
        if domain.is_ip:
            raise ValueError("Address literals are unsupported")
        return Address(address.display_name, address.username + "@" + domain.host, domain)
    except (ValueError, IndexError, TypeError, RecursionError) as error:
        raise ValueError("Invalid address") from error


def normalize_url(value: str) -> Url:
    if len(value) > MAX_URL_LENGTH:
        raise ValueError("url_too_long")
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError("invalid_url")
    original = value.strip(" ")
    if not original or "\\" in original or any(c.isspace() for c in original):
        raise ValueError("invalid_url")
    candidate = original
    if candidate.startswith("//"):
        candidate = "https:" + candidate
    elif candidate.lower().startswith("www."):
        candidate = "https://" + candidate
    try:
        parts = urlsplit(candidate)
        if not parts.scheme:
            raise ValueError("relative_url")
        if parts.scheme.lower() not in {"http", "https"}:
            raise ValueError("unsupported_url_scheme")
        if not parts.hostname or parts.port == 0:
            raise ValueError("invalid_url")
        domain = normalize_domain(parts.hostname)
        netloc = "[" + domain.host + "]" if ":" in domain.host else domain.host
        port = parts.port
        scheme = parts.scheme.lower()
        if port is not None and (scheme, port) not in {("https", 443), ("http", 80)}:
            netloc += ":" + str(port)
        has_userinfo = "@" in parts.netloc
        if has_userinfo:
            netloc = parts.netloc.rsplit("@", 1)[0] + "@" + netloc
        canonical = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
        return Url(original, canonical, scheme, domain, has_userinfo)
    except ValueError as error:
        if str(error) in {"relative_url", "unsupported_url_scheme", "invalid_url"}:
            raise
        raise ValueError("invalid_url") from error


class _HtmlEvidence(HTMLParser):
    """Tolerant HTML parsing is not browser rendering; ambiguity stays in coverage."""

    IGNORED = {"script", "style", "template", "head"}
    BLOCKS = {"p", "div", "br", "li", "tr", "td", "h1", "h2", "h3", "section"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ignored: list[str] = []
        self.text: list[str] = []
        self.links: list[tuple[str, str]] = []
        self.href: str | None = None
        self.label: list[str] = []
        self.ambiguous = False
        self.link_limit = False

    def _finish_link(self) -> None:
        if self.href is not None:
            if len(self.links) < MAX_LINKS:
                self.links.append((self.href, "".join(self.label)))
            else:
                self.link_limit = True
        self.href = None
        self.label = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.IGNORED:
            self.ignored.append(tag)
        if self.ignored:
            return
        if tag in self.BLOCKS:
            self.text.append(" ")
        if tag != "a":
            return
        if self.href is not None:
            self.ambiguous = True
            self._finish_link()
        hrefs = [value for name, value in attrs if name == "href"]
        if len(hrefs) > 1:
            self.ambiguous = True
        self.href = hrefs[0] if hrefs else None
        self.label = []

    def handle_endtag(self, tag: str) -> None:
        if self.ignored:
            if tag == self.ignored[-1]:
                self.ignored.pop()
            return
        if tag == "a":
            self._finish_link()
        if tag in self.BLOCKS:
            self.text.append(" ")

    def handle_data(self, data: str) -> None:
        if not self.ignored:
            self.text.append(data)
            if self.href is not None:
                self.label.append(data)

    def close(self) -> None:
        super().close()
        if self.href is not None or self.ignored:
            self.ambiguous = True
        self._finish_link()


def normalize_message(payload: AnalysisRequest) -> NormalizedMessage:
    values = {**payload.message.model_dump(), "attachments": payload.attachments}
    issues: dict[tuple[str, str], CoverageIssue] = {}

    def issue(field: AnalysisField, code: str) -> None:
        issues[(field, code)] = CoverageIssue(field=field, code=code)

    def text(value: str | None, field: AnalysisField) -> str | None:
        if value is None:
            return None

        def invalid(c: str) -> bool:
            return (
                (ord(c) < 32 and c not in "\r\n\t") or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF
            )

        if any(invalid(c) for c in value):
            issue(field, "invalid_text")
        value = "".join("\ufffd" if invalid(c) else c for c in value)
        value = " ".join(unicodedata.normalize("NFKC", value).split())
        if len(value) > 16000:
            issue(field, "normalized_text_limit_reached")
            value = value[:16000]
        return value

    def address(value: str | None, field: AnalysisField) -> Address | None:
        if value is None or not value.strip():
            # An empty Reply-To is normal. An empty From cannot identify a sender.
            if value is not None and field == "from_address":
                issue(field, "invalid_address")
            return None
        try:
            result = normalize_address(value)
        except ValueError:
            issue(field, "invalid_address")
            return None
        if result.domain.registrable is None:
            issue(field, "unknown_domain_boundary")
        return result

    sender = address(payload.message.from_address, "from_address")
    reply_to = address(payload.message.reply_to, "reply_to")
    subject = text(payload.message.subject, "subject")
    plain = text(payload.message.plain_text, "plain_text")
    html_text = None
    candidates: list[tuple[str, str, AnalysisField]] = []
    if payload.message.html is not None:
        parser = _HtmlEvidence()
        try:
            parser.feed(payload.message.html)
            parser.close()
            html_text = text("".join(parser.text), "html")
            candidates.extend((url, label, "html") for url, label in parser.links)
            if parser.ambiguous:
                issue("html", "ambiguous_html")
            if parser.link_limit:
                issue("html", "link_limit_reached")
        except (ValueError, AssertionError):
            issue("html", "ambiguous_html")
    # Preserve the original text during URL parsing; NFKC could otherwise hide deceptive syntax.
    if payload.message.plain_text is not None:
        for match in TEXT_URL.finditer(payload.message.plain_text):
            if len(candidates) >= MAX_LINKS:
                issue("plain_text", "link_limit_reached")
                break
            url = match.group().rstrip(".,;!?")
            while url.endswith(")") and url.count(")") > url.count("("):
                url = url[:-1]
            candidates.append((url, "", "plain_text"))
    links: dict[tuple[str, str], Link] = {}
    for raw, label, field in candidates:
        try:
            url = normalize_url(raw)
        except ValueError as error:
            issue(field, str(error))
            continue
        if not url.domain.is_ip and url.domain.registrable is None:
            issue(field, "unknown_domain_boundary")
        label = text(label, field) or ""
        links.setdefault((url.canonical, label), Link(url, label, field))
    body_parts = list(dict.fromkeys(value for value in (plain, html_text) if value))
    body = "\n".join(body_parts) if plain is not None or html_text is not None else None
    attachments = (
        None
        if payload.attachments is None
        else tuple(
            Attachment(
                filename=unicodedata.normalize("NFC", item.filename),
                content_type=None
                if item.content_type is None
                else item.content_type.strip().lower(),
                size_bytes=item.size_bytes,
            )
            for item in payload.attachments
        )
    )
    return NormalizedMessage(
        sender=sender,
        reply_to=reply_to,
        subject=subject,
        body_text=body,
        links=tuple(links.values()),
        attachments=attachments,
        coverage=Coverage(
            available_fields=sorted(name for name, value in values.items() if value is not None),
            unavailable_fields=sorted(name for name, value in values.items() if value is None),
            truncated_fields=sorted(payload.truncated_fields),
            issues=[issues[key] for key in sorted(issues)],
            links_considered=len(candidates),
            unique_links=len(links),
            attachment_records=len(attachments or ()),
            limitations=[
                "authentication_unverified",
                "urls_not_fetched",
                "attachment_bytes_not_inspected",
                "html_not_rendered",
                "quoted_content_not_separated",
            ],
        ),
    )
