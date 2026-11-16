"""Synthetic cases for parsing, domain identity, coverage, and offline behavior."""

import socket

import pytest
from app.analysis_schemas import AnalysisRequest
from app.domains import _offline_extractor, normalize_domain
from app.normalization import normalize_address, normalize_message, normalize_url


def normalized(payload, **fields):
    payload["message"].update(fields)
    return normalize_message(AnalysisRequest.model_validate(payload))


def issues(result):
    return {(issue.field, issue.code) for issue in result.coverage.issues}


@pytest.mark.parametrize(
    ("host", "expected", "private"),
    [
        ("MAIL.Example.COM.", "example.com", False),
        ("mail.example.co.uk", "example.co.uk", False),
        ("a.alice.github.io", "alice.github.io", True),
        ("bob.github.io", "bob.github.io", True),
        ("a.b.ck", "a.b.ck", False),
        ("www.ck", "www.ck", False),
        ("a.city.kawasaki.jp", "city.kawasaki.jp", False),
        ("bücher.de", "xn--bcher-kva.de", False),
        ("example.com。", "example.com", False),
        ("accounts.example.com.attacker.net", "attacker.net", False),
        ("intranet", None, False),
        ("example.test", None, False),
        ("co.uk", None, False),
    ],
)
def test_domain_boundaries(host, expected, private):
    result = normalize_domain(host)
    assert result.registrable == expected
    assert result.is_private_suffix == private


@pytest.mark.parametrize(
    "host",
    [
        "",
        "a..com",
        "-a.com",
        "a_.com",
        "a%2ecom",
        "a.com/x",
        "a.com\\evil",
        "a@b.com",
        "a\n.com",
        "a" * 64 + ".com",
    ],
)
def test_invalid_domains(host):
    with pytest.raises(ValueError):
        normalize_domain(host)


def test_first_psl_lookup_and_html_extraction_never_use_network(monkeypatch, payload, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("Normalization attempted network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setenv("TLDEXTRACT_CACHE", str(tmp_path / "must-not-exist"))
    _offline_extractor.cache_clear()
    result = normalized(
        payload,
        from_address="a@example.com",
        plain_text="",
        html='<img src="http://127.0.0.1/secret">'
        '<a href="http://169.254.169.254/latest/meta-data">link</a>',
    )
    assert result.links[0].url.domain.is_ip
    assert not list(tmp_path.iterdir())


def test_changed_psl_snapshot_requires_explicit_review(monkeypatch, tmp_path):
    (tmp_path / ".tld_set_snapshot").write_text("unexpected suffix data")
    monkeypatch.setattr("app.domains.files", lambda package: tmp_path)
    _offline_extractor.cache_clear()
    with pytest.raises(RuntimeError, match="reviewed dependency pin"):
        normalize_domain("example.com")


def test_mailbox_and_encoded_display_name():
    result = normalize_address("=?UTF-8?B?Sm9zw6k=?= <Alice@BÜCHER.de>")
    assert result.display_name == "José"
    assert result.mailbox == "Alice@xn--bcher-kva.de"
    assert result.domain.registrable == "xn--bcher-kva.de"


@pytest.mark.parametrize(
    "address",
    [
        "",
        "missing-domain",
        "a@example.com, b@example.net",
        "Team: a@example.com;",
        "a@example.com\r\nBcc: b@example.net",
        "<>",
        "a@[127.0.0.1]",
        "a@-bad.com",
        "(" * 1000 + "a@example.com" + ")" * 1000,
    ],
)
def test_ambiguous_addresses_rejected(address):
    with pytest.raises(ValueError):
        normalize_address(address)


@pytest.mark.parametrize(
    ("raw", "canonical", "ip", "userinfo"),
    [
        ("HTTPS://Example.COM:443/a?q=1#frag", "https://example.com/a?q=1", False, False),
        ("http://example.com:80", "http://example.com/", False, False),
        ("https://example.com:8443/", "https://example.com:8443/", False, False),
        ("//bücher.de/a", "https://xn--bcher-kva.de/a", False, False),
        ("www.example.com", "https://www.example.com/", False, False),
        ("https://example.com@evil.net/a", "https://example.com@evil.net/a", False, True),
        ("http://192.0.2.1", "http://192.0.2.1/", True, False),
        ("http://[2001:db8::1]:80/a", "http://[2001:db8::1]/a", True, False),
    ],
)
def test_url_normalization(raw, canonical, ip, userinfo):
    result = normalize_url(raw)
    assert result.canonical == canonical
    assert result.domain.is_ip == ip
    assert result.has_userinfo == userinfo
    if userinfo:
        assert result.domain.registrable == "evil.net"


def test_unicode_ip_host_is_recognized_after_idna():
    result = normalize_url("https://１９２。０。２。１/")
    assert result.domain.is_ip
    assert result.canonical == "https://192.0.2.1/"


def test_unpaired_unicode_surrogates_do_not_escape_as_url_evidence():
    with pytest.raises(ValueError, match="invalid_url"):
        normalize_url("https://example.com/\ud800")


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("/login", "relative_url"),
        ("javascript:alert(1)", "unsupported_url_scheme"),
        ("mailto:a@example.com", "unsupported_url_scheme"),
        ("data:text/html,hello", "unsupported_url_scheme"),
        ("https://example.com\\@evil.net", "invalid_url"),
        ("https://ex\nample.com", "invalid_url"),
        ("https://example.com:0", "invalid_url"),
        ("https://example.com:65536", "invalid_url"),
        ("https://[::1", "invalid_url"),
        ("https://exam%70le.com", "invalid_url"),
        ("https:///path", "invalid_url"),
        ("http://[fe80::1%25en0]", "invalid_url"),
        ("https://example.com/a b", "invalid_url"),
        ("https://example.com/" + "x" * 2048, "url_too_long"),
    ],
)
def test_invalid_and_unsupported_urls(raw, reason):
    with pytest.raises(ValueError, match=reason):
        normalize_url(raw)


def test_inert_html_entities_and_nested_anchor_text(payload):
    result = normalized(
        payload,
        plain_text=None,
        html=(
            "<head><title>ignored</title></head><style>hidden</style><script>alert(1)</script>"
            "<template>ignored</template><p>Hello &amp; שלום</p>"
            '<a href="https://example.net/?a=1&amp;b=2"><b>https://example.com</b></a>'
        ),
    )
    assert result.body_text == "Hello & שלום https://example.com"
    assert len(result.links) == 1
    assert result.links[0].url.canonical == "https://example.net/?a=1&b=2"
    assert result.links[0].label == "https://example.com"
    assert "html_not_rendered" in result.coverage.limitations


def test_link_dedup_keeps_distinct_display_evidence(payload):
    result = normalized(
        payload,
        html=(
            '<a href="https://EXAMPLE.com:443/#x">label</a>'
            '<a href="https://example.com/#y">label</a>'
            '<a href="https://example.com/">different label</a>'
        ),
        plain_text="https://example.com/ https://example.com/#fragment",
    )
    assert result.coverage.links_considered == 5
    assert result.coverage.unique_links == 3
    assert {link.label for link in result.links} == {"label", "different label", ""}


def test_plain_text_punctuation_and_parentheses(payload):
    result = normalized(
        payload,
        html="",
        plain_text=("See (https://example.com/a_(b)). Then https://example.net/login!"),
    )
    assert [link.url.canonical for link in result.links] == [
        "https://example.com/a_(b)",
        "https://example.net/login",
    ]


@pytest.mark.parametrize(
    "html",
    [
        '<a href="https://example.com">unfinished',
        '<a href="https://example.com" href="https://example.net">duplicate</a>',
        '<a href="https://example.com">outer<a href="https://example.net">inner</a></a>',
        "<script>unfinished",
    ],
)
def test_ambiguous_html_is_reported(payload, html):
    assert ("html", "ambiguous_html") in issues(normalized(payload, html=html))


def test_invalid_links_and_addresses_are_explicit_coverage_issues(payload):
    result = normalized(
        payload,
        from_address="invalid",
        reply_to="a@local",
        plain_text="",
        html='<a href="/relative">a</a><a href="javascript:x">b</a>'
        '<a href="https://example.com:bad">c</a>',
    )
    assert result.sender is None
    assert issues(result) == {
        ("from_address", "invalid_address"),
        ("reply_to", "unknown_domain_boundary"),
        ("html", "relative_url"),
        ("html", "unsupported_url_scheme"),
        ("html", "invalid_url"),
    }


def test_raw_link_budget_cannot_be_bypassed_with_duplicates(payload):
    result = normalized(
        payload, html='<a href="https://example.com">x</a>' * 101, plain_text="https://example.net"
    )
    assert result.coverage.links_considered == 100
    assert len(result.links) == 1
    assert ("html", "link_limit_reached") in issues(result)
    assert ("plain_text", "link_limit_reached") in issues(result)


def test_plain_text_link_limit(payload):
    result = normalized(payload, html=None, plain_text="https://example.com " * 101)
    assert result.coverage.links_considered == 100
    assert ("plain_text", "link_limit_reached") in issues(result)


def test_text_normalization_and_expansion_limit(payload):
    result = normalized(
        payload, subject="ＵＲＧＥＮＴ\tשלום\x00\x7f", html="", plain_text="\ufdfa" * 2000
    )
    assert result.subject == "URGENT שלום��"
    assert len(result.body_text) == 16000
    assert ("subject", "invalid_text") in issues(result)
    assert ("plain_text", "normalized_text_limit_reached") in issues(result)


def test_missing_empty_truncated_and_attachment_metadata_are_distinct(payload):
    payload["attachments"] = [
        {"filename": "cafe\u0301.pdf", "content_type": "Application/PDF ", "size_bytes": 0}
    ]
    payload["truncated_fields"] = ["html", "attachments"]
    result = normalized(payload, plain_text=None, html="", reply_to="")
    assert result.body_text == ""
    assert result.reply_to is None
    assert "reply_to" in result.coverage.available_fields
    assert "plain_text" in result.coverage.unavailable_fields
    assert result.coverage.truncated_fields == ["attachments", "html"]
    assert result.attachments[0].filename == "café.pdf"
    assert result.attachments[0].content_type == "application/pdf"
    assert result.attachments[0].size_bytes == 0
    assert result.coverage.attachment_records == 1


def test_authentication_claims_do_not_change_normalization(payload):
    baseline = normalized(payload)
    claimed = normalized(payload, authentication_results="mx.google.com; spf=pass; dmarc=pass")
    assert baseline.links == claimed.links
    assert "authentication_unverified" in claimed.coverage.limitations
