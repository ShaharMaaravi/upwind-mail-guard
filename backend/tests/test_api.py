import json

import pytest
from app.config import Settings
from app.main import create_app


def test_health_is_public_minimal_and_not_cacheable(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["cache-control"] == "no-store"


def test_diagnostic_counts_without_echoing_content(client, auth, payload, caplog):
    response = client.post("/v1/diagnose", json=payload, headers=auth)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "diagnostic_only"
    assert data["request_id"] == payload["request_id"]
    assert data["field_characters"] == {
        key: None if value is None else len(value) for key, value in payload["message"].items()
    }
    assert data["attachments_status"] == "not_inspected"
    assert data["authentication_status"] == "unverified"
    assert "score" not in data and "verdict" not in data
    for value in payload["message"].values():
        if value:
            assert value not in response.text
            assert value not in caplog.text


@pytest.mark.parametrize("authorization", [None, "Bearer wrong", "Basic abc", "Bearer "])
def test_rejects_unauthorized_before_parsing(client, authorization):
    headers = {} if authorization is None else {"Authorization": authorization}
    response = client.post("/v1/diagnose", content=b"not json", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == {"error": "unauthorized"}


def test_duplicate_authorization_rejected(client, auth, payload):
    headers = list(auth.items()) * 2
    assert client.post("/v1/diagnose", json=payload, headers=headers).status_code == 401


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(schema_version="2"),
        lambda p: p.update(gmail_token="must-not-be-accepted"),
        lambda p: p.update(request_id="private@example.test"),
        lambda p: p["message"].update(subject=123),
        lambda p: p["message"].update(subject="x" * 2049),
        lambda p: p["message"].update(plain_text="x" * 16001),
        lambda p: p["message"].update(extra_field="private content"),
        lambda p: p.update(truncated_fields=["subject", "subject"]),
        lambda p: p.update(truncated_fields=["authentication_results"]),
        lambda p: p.update(message=dict.fromkeys(p["message"])),
    ],
)
def test_invalid_inputs_are_redacted(client, auth, payload, mutation, caplog):
    mutation(payload)
    response = client.post("/v1/diagnose", json=payload, headers=auth)
    assert response.status_code == 422
    assert response.json() == {"error": "invalid_request"}
    assert "private content" not in caplog.text


def test_truncation_and_unavailable_are_preserved(client, auth, payload):
    payload["truncated_fields"] = ["html"]
    data = client.post("/v1/diagnose", json=payload, headers=auth).json()
    assert data["truncated_fields"] == ["html"]
    assert data["field_characters"]["authentication_results"] is None
    assert data["field_characters"]["reply_to"] == 0


def test_malformed_json_does_not_echo(client, auth):
    response = client.post(
        "/v1/diagnose",
        content='{"private-email-content":',
        headers={**auth, "Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"error": "invalid_request"}


def test_forged_authentication_is_not_trusted(client, auth, payload):
    payload["message"]["authentication_results"] = "mx.google.com; dmarc=pass; spf=pass"
    data = client.post("/v1/diagnose", json=payload, headers=auth).json()
    assert data["authentication_status"] == "unverified"
    assert "score" not in data


def test_rate_limit_recovers(monkeypatch, client, auth, payload):
    monkeypatch.setattr("app.security.time.monotonic", lambda: 1000)
    for _ in range(30):
        assert client.post("/v1/diagnose", json=payload, headers=auth).status_code == 200
    response = client.post("/v1/diagnose", json=payload, headers=auth)
    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"
    assert client.get("/healthz").status_code == 200
    monkeypatch.setattr("app.security.time.monotonic", lambda: 1061)
    assert client.post("/v1/diagnose", json=payload, headers=auth).status_code == 200


def test_media_type_and_encoding(client, auth, payload):
    assert client.post("/v1/diagnose", content=json.dumps(payload), headers=auth).status_code == 415
    assert (
        client.post(
            "/v1/diagnose", json=payload, headers={**auth, "Content-Encoding": "gzip"}
        ).status_code
        == 415
    )


def test_declared_oversize(client, auth):
    response = client.post(
        "/v1/diagnose",
        content=b"{}",
        headers={**auth, "Content-Type": "application/json", "Content-Length": "262145"},
    )
    assert response.status_code == 413


@pytest.mark.parametrize("value", ["", "short", "REPLACE_WITH_A_RANDOM_TOKEN", "x" * 129, "א" * 43])
def test_startup_fails_closed(monkeypatch, value):
    monkeypatch.setenv("MAIL_GUARD_API_TOKEN", value)
    with pytest.raises(ValueError, match="MAIL_GUARD_API_TOKEN"):
        create_app()


def test_secret_is_not_in_config_representation():
    secret = "private-token-" + "z" * 43
    assert secret not in repr(Settings(api_token=secret))
