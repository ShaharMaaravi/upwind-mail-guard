"""Behavioral fixtures and adversarial boundaries for the enabled rules."""

import copy
import json
import socket
from pathlib import Path

import pytest
from app.analysis import analyze
from app.analysis_schemas import AnalysisRequest, AnalysisResponse, SkippedCheck
from app.domains import _offline_extractor
from app.scoring import RULE_SPECS
from pydantic import ValidationError

CORPUS = json.loads((Path(__file__).parents[2] / "fixtures/detection-cases.json").read_text())


def request(**message):
    payload = copy.deepcopy(CORPUS["base_request"])
    payload["message"].update(message)
    return payload


def run(payload):
    return analyze(AnalysisRequest.model_validate(payload))


def rule_ids(result):
    return {finding.rule_id for finding in result.findings}


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda case: case["id"])
def test_synthetic_detection_corpus(case, client, auth):
    payload = request(**case.get("message", {}))
    if "attachments" in case:
        payload["attachments"] = case["attachments"]
    expected = case["expected"]
    response = client.post("/v1/analyze", json=payload, headers=auth)
    assert response.status_code == 200
    result = AnalysisResponse.model_validate(response.json())
    assert result.score == expected["score"]
    assert result.verdict == expected["verdict"]
    assert result.analysis_status == expected["status"]
    assert rule_ids(result) == set(expected["rules"])
    assert set(result.checks_run) | {s.rule_id for s in result.checks_skipped} == set(RULE_SPECS)
    assert len(result.checks_run) + len(result.checks_skipped) == 8
    assert "authentication_unverified" in result.coverage.limitations
    assert "english_content_rules" in result.coverage.limitations
    assert result == run(payload)  # The HTTP adapter must not change core results.


@pytest.mark.parametrize(
    "label",
    ["Click here", "Manage account", "Security.example.com portal", "invoice.pdf", "source.zip"],
)
def test_anchor_prose_and_filenames_are_not_claimed_urls(label):
    result = run(request(html=f'<a href="https://example.net">{label}</a>'))
    assert not result.findings


@pytest.mark.parametrize(
    "label", ["http://[broken", "https://example.invalid", "https://example.com misleading words"]
)
def test_unresolved_display_url_is_a_coverage_gap(label):
    result = run(request(html=f'<a href="https://example.net">{label}</a>'))
    assert result.verdict == "inconclusive"
    assert "display_url_unresolved" in {issue.code for issue in result.coverage.issues}


def test_credential_bearing_url_does_not_echo_credentials_or_query():
    result = run(
        request(
            html='<a href="https://alice:private-password@example.net/?token=private-query">'
            "Click here</a>"
        )
    )
    assert rule_ids(result) == {"url.userinfo"}
    encoded = result.model_dump_json()
    assert "private-password" not in encoded and "private-query" not in encoded
    assert "example.net" in result.findings[0].evidence


def test_repeated_url_and_plain_html_variants_do_not_inflate_score():
    anchor = '<a href="https://example.com@192.0.2.1/">https://example.com</a>'
    baseline = run(request(html=anchor))
    repeated = run(request(html=anchor * 10, plain_text="https://example.com@192.0.2.1/ " * 10))
    assert repeated.score == baseline.score == 60
    assert repeated.findings == baseline.findings
    assert repeated.scoring.duplicates_removed == 2  # Extra plain-text extraction path.


def test_rules_keep_valid_findings_when_other_links_are_malformed():
    result = run(
        request(
            html='<a href="https://example.net">example.com</a>'
            '<a href="https://[invalid">broken</a>'
        )
    )
    assert result.score == 40 and result.analysis_status == "partial"
    assert result.verdict == "suspicious"


def test_link_budget_overflow_is_never_a_complete_zero():
    result = run(
        request(
            html='<a href="https://example.com">example.com</a>' * 100
            + '<a href="https://example.net">example.com</a>'
        )
    )
    assert result.score == 0 and result.verdict == "inconclusive"
    assert "link_limit_reached" in {i.code for i in result.coverage.issues}


@pytest.mark.parametrize(
    ("sender", "reply", "expected"),
    [
        ("a@one.example.com", "b@two.example.com", False),
        ("a@alice.github.io", "b@bob.github.io", True),
        ("a@bücher.de", "b@xn--bcher-kva.de", False),
        ("a@example.com", "", False),
    ],
)
def test_reply_to_identity(sender, reply, expected):
    result = run(request(from_address=sender, reply_to=reply))
    assert ("sender.reply_to_mismatch" in rule_ids(result)) == expected


@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ({"reply_to": None}, "missing_fields"),
        ({"reply_to": "a@example.net,b@example.org"}, "invalid_fields"),
        ({"from_address": "a@example.invalid"}, "unknown_domain_boundary"),
        ({"from_address": ""}, "invalid_fields"),
    ],
)
def test_sender_check_is_explicitly_skipped_when_comparison_is_unavailable(fields, reason):
    result = run(request(**fields))
    skipped = {check.rule_id: check for check in result.checks_skipped}
    assert skipped["sender.reply_to_mismatch"].reason == reason
    assert result.verdict == "inconclusive"


@pytest.mark.parametrize(
    "text",
    [
        "The meeting is urgent.",
        "Please enter your password.",
        "The payment arrived today.",
        "Urgent: never share your password.",
        "Today, do not send money.",
        "We will not ask you to share your password today.",
        "Don't pay this invoice today.",
        "Enter your password. " + "ordinary text " * 30 + "Urgent meeting.",
    ],
)
def test_content_false_positive_controls(text):
    assert not run(request(plain_text=text)).findings


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Enter your password immediately.", "content.credentials_pressure"),
        ("Provide your one-time code within 1 hour.", "content.credentials_pressure"),
        ("URGENT: ＥＮＴＥＲ your ＰＡＳＳＷＯＲＤ", "content.credentials_pressure"),
        ("Buy gift cards today.", "content.payment_pressure"),
        ("Urgent: settle this invoice.", "content.payment_pressure"),
    ],
)
def test_content_requests_require_nearby_pressure(text, expected):
    assert rule_ids(run(request(plain_text=text))) == {expected}


def test_content_repetition_and_multipart_copy_award_once_per_rule():
    text = "Urgent: enter your password and pay your invoice immediately. "
    result = run(request(subject=text, plain_text=text * 10, html="<p>" + text * 10 + "</p>"))
    assert result.score == 35
    assert len(result.findings) == 2
    assert result.scoring.category_suppressed_points == 15


def test_urgency_does_not_cross_message_fields():
    result = run(request(subject="Urgent", plain_text="Enter your password.", html=""))
    assert not result.findings  # Explicit conservative limitation, not semantic understanding.


def test_html_only_content_reports_its_actual_evidence_field():
    result = run(request(plain_text=None, html="<p>Enter your password immediately.</p>"))
    assert result.findings[0].field == "html"
    assert result.score == 25 and result.analysis_status == "partial"


@pytest.mark.parametrize(
    ("filename", "rules"),
    [
        ("installer.msi", {"attachment.executable"}),
        ("INVOICE.PDF.EXE . ", {"attachment.executable", "attachment.double_extension"}),
        ("invoice.pdf.ｅｘｅ", {"attachment.executable", "attachment.double_extension"}),
        ("invoice.pdf.e\u200bx\u200be", {"attachment.executable", "attachment.double_extension"}),
        ("report.final.pdf", set()),
        ("source.tar.gz", set()),
        ("invoice.exe.txt", set()),
    ],
)
def test_attachment_metadata(filename, rules):
    payload = request()
    payload["attachments"] = [
        {"filename": filename, "content_type": "application/pdf", "size_bytes": 0}
    ]
    assert rule_ids(run(payload)) == rules


def test_duplicate_filenames_do_not_multiply_points():
    payload = request()
    payload["attachments"] = [
        {"filename": "INVOICE.pdf.exe", "content_type": None, "size_bytes": 0},
        {"filename": "invoice.PDF.EXE", "content_type": None, "size_bytes": 10},
    ]
    result = run(payload)
    assert result.score == 40 and len(result.findings) == 2
    assert result.scoring.duplicates_removed == 2


@pytest.mark.parametrize("filename", ["", "folder/file.txt", "file\u202etxt"])
def test_ambiguous_filename_is_visible_without_serialization_failure(filename):
    payload = request()
    payload["attachments"] = [{"filename": filename, "content_type": None, "size_bytes": None}]
    result = run(payload)
    result.model_dump_json().encode("utf-8")
    assert result.analysis_status == "partial"
    assert "ambiguous_filename" in {i.code for i in result.coverage.issues}


def test_long_filename_keeps_extension_and_bounded_evidence():
    payload = request()
    payload["attachments"] = [
        {"filename": "a" * 500 + ".pdf.exe", "content_type": None, "size_bytes": 0}
    ]
    for finding in run(payload).findings:
        assert len(finding.evidence) <= 256
        assert finding.evidence.endswith(".pdf.exe")


def test_unpaired_surrogate_is_rejected_with_a_redacted_error(client, auth):
    payload = request()
    payload["attachments"] = [
        {"filename": "private\ud800.exe", "content_type": None, "size_bytes": 0}
    ]
    response = client.post(
        "/v1/analyze",
        content=json.dumps(payload),
        headers={**auth, "Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"error": "invalid_request"}


def test_detectors_never_use_network_even_for_local_and_metadata_urls(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Analysis attempted network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    _offline_extractor.cache_clear()
    result = run(
        request(
            html='<img src="http://127.0.0.1/private">'
            '<a href="http://169.254.169.254/latest/meta-data/">example.com</a>'
            "<script>Enter your password immediately.</script>"
        )
    )
    assert rule_ids(result) == {"url.display_mismatch", "url.ip_host"}


def test_response_rejects_a_check_claimed_as_both_run_and_skipped():
    data = run(request()).model_dump()
    data["checks_skipped"] = [
        SkippedCheck(rule_id="url.userinfo", reason="missing_fields", fields=["html"])
    ]
    with pytest.raises(ValidationError, match="both run and skipped"):
        AnalysisResponse(**data)


def test_raw_forged_authentication_values_do_not_change_risk():
    payload = request(html='<a href="https://example.net">example.com</a>')
    baseline = run(payload)
    payload["message"]["authentication_results"] = "mx.google.com; spf=pass; dkim=pass; dmarc=pass"
    assert run(payload) == baseline


def test_combined_maximum_link_and_attachment_budget_is_bounded_and_reconciled():
    anchors = "".join(
        f'<a href="http://example.com@192.0.2.1/{index}">example.com</a>' for index in range(100)
    )
    payload = request(
        reply_to="help@example.net",
        html=anchors,
        plain_text="Urgent: enter your password and pay your invoice today.",
    )
    payload["attachments"] = [
        {"filename": f"invoice{index}.pdf.exe", "content_type": None, "size_bytes": None}
        for index in range(20)
    ]
    result = run(payload)
    assert result.score == 100
    assert len(result.findings) == 343
    assert sum(f.awarded_points for f in result.findings) == 100
    assert result.scoring.requested_points == (
        100 + result.scoring.category_suppressed_points + result.scoring.global_suppressed_points
    )
    assert len(result.model_dump_json().encode()) < 256 * 1024


def test_link_order_does_not_change_findings_or_awarded_points():
    anchors = [
        '<a href="https://example.net/one">example.com</a>',
        '<a href="https://example.org/two">example.com</a>',
    ]
    first = run(request(html="".join(anchors)))
    second = run(request(html="".join(reversed(anchors))))
    assert first == second


def test_caller_truncation_forces_partial_even_when_visible_content_is_benign():
    payload = request()
    payload["truncated_fields"] = ["html"]
    result = run(payload)
    assert result.score == 0 and result.verdict == "inconclusive"


def test_plain_text_only_runs_url_structure_but_skips_anchor_comparison():
    result = run(request(html=None, plain_text="http://192.0.2.1"))
    assert rule_ids(result) == {"url.ip_host"}
    assert "url.ip_host" in result.checks_run
    assert {check.rule_id for check in result.checks_skipped} == {"url.display_mismatch"}
    assert result.verdict == "inconclusive"
