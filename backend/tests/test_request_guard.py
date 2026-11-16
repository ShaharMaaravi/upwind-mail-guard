"""Raw ASGI tests exercise transport edges that HTTP clients normally normalize away."""

import asyncio
from functools import partial

import pytest
from app.config import Settings
from app.security import RequestGuard

TOKEN = "z" * 43


def run_guard(chunks, headers=(), *, path, delay=0, authenticated=True):
    sent = []
    received = []
    called = []

    async def inner(scope, receive, send):
        called.append(True)
        received.append(await receive())

    messages = iter(chunks)

    async def receive():
        if delay:
            await asyncio.sleep(delay)
        return next(messages)

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "path": path,
        "method": "POST",
        "headers": [
            (b"content-type", b"application/json"),
            (b"authorization", ("Bearer " + (TOKEN if authenticated else "wrong")).encode()),
            *headers,
        ],
    }
    guard = RequestGuard(
        inner, Settings(api_token=TOKEN, max_body_bytes=8, body_timeout_seconds=0.01)
    )
    asyncio.run(guard(scope, receive, send))
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    return status, called, received


@pytest.fixture(params=["/v1/diagnose", "/v1/analyze"])
def exercise(request):
    return partial(run_guard, path=request.param)


def test_chunked_oversize_stops_before_parser(exercise):
    status, called, _ = exercise(
        [
            {"type": "http.request", "body": b"12345", "more_body": True},
            {"type": "http.request", "body": b"6789"},
        ]
    )
    assert status == 413 and not called


def test_exact_limit_replayed_once(exercise):
    status, called, received = exercise(
        [
            {"type": "http.request", "body": b"1234", "more_body": True},
            {"type": "http.request", "body": b"5678"},
        ]
    )
    assert status is None and called
    assert received[0]["body"] == b"12345678"


def test_lying_content_length_cannot_bypass_limit(exercise):
    status, called, _ = exercise(
        [{"type": "http.request", "body": b"123456789"}], [(b"content-length", b"1")]
    )
    assert status == 413 and not called


@pytest.mark.parametrize("length", [b"-1", b"abc", b"1.5"])
def test_invalid_length_rejected_without_reading(exercise, length):
    status, called, _ = exercise([], [(b"content-length", length)])
    assert status == 400 and not called


def test_duplicate_length_rejected(exercise):
    status, called, _ = exercise([], [(b"content-length", b"1"), (b"content-length", b"1")])
    assert status == 400 and not called


def test_huge_length_does_not_attempt_giant_integer_conversion(exercise):
    status, called, _ = exercise([], [(b"content-length", b"9" * 5000)])
    assert status == 413 and not called


def test_length_mismatch(exercise):
    status, called, _ = exercise(
        [{"type": "http.request", "body": b"{}"}], [(b"content-length", b"3")]
    )
    assert status == 400 and not called


def test_slow_upload_times_out(exercise):
    status, called, _ = exercise([], delay=0.1)
    assert status == 408 and not called


def test_disconnected_client_does_not_reach_parser(exercise):
    status, called, _ = exercise([{"type": "http.disconnect"}])
    assert status is None and not called


def test_invalid_token_never_reads_body(exercise):
    status, called, _ = exercise([], authenticated=False)
    assert status == 401 and not called
