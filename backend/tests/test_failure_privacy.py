"""Unexpected errors must not expose message content through responses or server logs."""

import asyncio
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from app.config import Settings
from app.security import RequestGuard

MARKER = "synthetic-private-failure-marker"
ROOT = Path(__file__).parents[2]


@pytest.mark.parametrize("failure", ["exception", "invalid_response"])
def test_unexpected_analysis_errors_are_redacted(
    client, auth, payload, monkeypatch, caplog, failure
):
    def faulty(_):
        if failure == "exception":
            raise ValueError(MARKER + auth["Authorization"])
        return {"private_content": MARKER}

    monkeypatch.setattr("app.main.analyze", faulty)
    response = client.post("/v1/analyze", json=payload, headers=auth)
    assert response.status_code == 500
    assert response.json() == {"error": "internal_error"}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert MARKER not in response.text + caplog.text
    assert auth["Authorization"] not in caplog.text
    errors = [r for r in caplog.records if r.name == "app.security"]
    assert len(errors) == 1 and errors[0].message == "request_failed"
    assert errors[0].exc_info is None and errors[0].stack_info is None
    assert client.get("/healthz").status_code == 200


def test_late_failure_cannot_emit_second_response_or_original_traceback(caplog):
    sent = []

    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        raise ValueError(MARKER)

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        sent.append(message)

    with pytest.raises(RuntimeError, match="^response_failed$") as error:
        asyncio.run(
            RequestGuard(inner, Settings(api_token="z" * 43))(
                {"type": "http", "path": "/healthz", "method": "GET"}, receive, send
            )
        )
    assert len(sent) == 1
    assert MARKER not in "".join(traceback.format_exception(error.value)) + caplog.text


def test_cancellation_is_not_converted_to_server_error(caplog):
    async def inner(scope, receive, send):
        raise asyncio.CancelledError()

    async def unused(*_):
        pytest.fail("Cancellation must not send a response")

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            RequestGuard(inner, Settings(api_token="z" * 43))(
                {"type": "http", "path": "/healthz", "method": "GET"}, unused, unused
            )
        )
    assert "request_failed" not in caplog.text


def create_fault_app():
    """Subprocess-only test factory; never shipped in the container or production routes."""
    import app.main

    def faulty(payload):
        if payload.message.subject == "invalid_response":
            return {"private_content": MARKER}
        raise ValueError(MARKER + os.environ["MAIL_GUARD_API_TOKEN"])

    app.main.analyze = faulty
    return app.main.create_app()


def test_real_uvicorn_failure_logs_do_not_contain_content_or_credentials():
    token = secrets.token_urlsafe(32)
    # Pass a bound socket to the child: no fixed port and no reservation race.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "test_failure_privacy:create_fault_app",
                "--factory",
                "--app-dir",
                str(ROOT / "backend/tests"),
                "--fd",
                str(listener.fileno()),
                "--no-access-log",
            ],
            env={**os.environ, "PYTHONPATH": str(ROOT / "backend"), "MAIL_GUARD_API_TOKEN": token},
            pass_fds=(listener.fileno(),),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            ready = False
            for _ in range(100):
                if process.poll() is not None:
                    break
                try:
                    with urllib.request.urlopen(origin + "/healthz", timeout=0.2) as reply:
                        ready = reply.status == 200
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
                if ready:
                    break
            assert ready, "Fault-injection server did not become ready"
            payload = json.loads((ROOT / "fixtures/analysis-request.json").read_text())
            for failure in ("exception", "invalid_response"):
                payload["message"]["subject"] = failure
                request = urllib.request.Request(
                    origin + "/v1/analyze",
                    data=json.dumps(payload).encode(),
                    headers={
                        "Authorization": "Bearer " + token,
                        "Content-Type": "application/json",
                    },
                )
                with pytest.raises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(request, timeout=5)
                assert error.value.code == 500
                assert json.loads(error.value.read()) == {"error": "internal_error"}
        finally:
            process.terminate()
            output = process.communicate(timeout=10)[0].decode()
        assert output.count("request_failed") == 2
        assert MARKER not in output and token not in output
        assert "Traceback" not in output
