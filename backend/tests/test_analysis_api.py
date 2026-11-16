import json
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parents[2] / "fixtures" / "analysis-request.json"


def test_analysis_fixture_reports_real_findings_and_exact_contributions(client, auth, caplog):
    payload = json.loads(FIXTURE.read_text())
    response = client.post("/v1/analyze", json=payload, headers=auth)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    data = response.json()
    assert data["request_id"] == payload["request_id"]
    assert data["policy_version"] == "heuristic-v2"
    assert data["normalization_version"] == "normalize-v2"
    assert data["analysis_status"] == "partial"
    assert data["verdict"] == "high_risk"
    assert data["score"] == 95
    assert len(data["checks_run"]) == 8 and data["checks_skipped"] == []
    assert {f["rule_id"]: f["awarded_points"] for f in data["findings"]} == {
        "url.display_mismatch": 40,
        "attachment.executable": 35,
        "attachment.double_extension": 5,
        "sender.reply_to_mismatch": 15,
    }
    assert data["scoring"] == {
        "requested_points": 110,
        "category_suppressed_points": 15,
        "global_suppressed_points": 0,
        "duplicates_removed": 0,
    }
    assert "detection_rules_not_implemented" not in data["coverage"]["limitations"]
    assert data["coverage"]["attachment_records"] == 1
    assert data["coverage"]["unique_links"] == 2
    for value in payload["message"].values():
        if value:
            assert value not in caplog.text
    assert payload["message"]["from_address"] not in response.text


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(schema_version="2"),
        lambda p: p.update(findings=[{"rule_id": "forged"}]),
        lambda p: p.update(score=0),
        lambda p: p.update(gmail_token="private-token"),
        lambda p: p["message"].update(plain_text="x" * 16001),
        lambda p: p["message"].update(subject=True),
        lambda p: p.update(truncated_fields=["attachments"]),
        lambda p: p.update(truncated_fields=["html", "html"]),
        lambda p: p.update(message=dict.fromkeys(p["message"])),
        lambda p: p.update(
            attachments=[{"filename": "x", "content_type": None, "size_bytes": None}] * 21
        ),
        lambda p: p.update(
            attachments=[{"filename": "x" * 513, "content_type": None, "size_bytes": None}]
        ),
        lambda p: p.update(attachments=[{"filename": "x", "content_type": None, "size_bytes": -1}]),
        lambda p: p.update(
            attachments=[{"filename": "x", "content_type": None, "size_bytes": True}]
        ),
        lambda p: p.update(
            attachments=[{"filename": "x", "content_type": None, "size_bytes": "1"}]
        ),
        lambda p: p.update(
            attachments=[
                {
                    "filename": "x",
                    "content_type": None,
                    "size_bytes": 0,
                    "bytes": "private-attachment-content",
                }
            ]
        ),
    ],
)
def test_rejects_invalid_analysis_contract(client, auth, payload, mutation, caplog):
    mutation(payload)
    response = client.post("/v1/analyze", json=payload, headers=auth)
    assert response.status_code == 422
    assert response.json() == {"error": "invalid_request"}
    assert "private-attachment-content" not in caplog.text


def test_analysis_endpoint_authenticates_before_json(client):
    response = client.post("/v1/analyze", content="private malformed JSON")
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}


def test_analysis_and_diagnostic_share_rate_limit(client, auth, payload):
    for _ in range(15):
        assert client.post("/v1/diagnose", json=payload, headers=auth).status_code == 200
        assert client.post("/v1/analyze", json=payload, headers=auth).status_code == 200
    assert client.post("/v1/analyze", json=payload, headers=auth).status_code == 429


def test_empty_attachment_list_is_available_not_missing(client, auth, payload):
    payload["attachments"] = []
    response = client.post("/v1/analyze", json=payload, headers=auth).json()
    assert "attachments" in response["coverage"]["available_fields"]
    assert "attachments" not in response["coverage"]["unavailable_fields"]
    assert response["score"] == 0 and response["verdict"] == "inconclusive"


def test_malformed_addresses_and_html_degrade_to_coverage_not_server_error(client, auth, payload):
    payload["message"].update(
        from_address="(" * 1000 + "a@example.com" + ")" * 1000,
        html='<a href="https://[bad">unfinished',
        subject="\u0000secret",
    )
    response = client.post("/v1/analyze", json=payload, headers=auth)
    assert response.status_code == 200
    codes = {issue["code"] for issue in response.json()["coverage"]["issues"]}
    assert {"invalid_address", "ambiguous_html", "invalid_url", "invalid_text"} <= codes
