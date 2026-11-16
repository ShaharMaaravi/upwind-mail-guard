import pytest
from app.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient

TOKEN = "synthetic-test-token-" + "x" * 43


@pytest.fixture
def client():
    with TestClient(create_app(Settings(api_token=TOKEN))) as instance:
        yield instance


@pytest.fixture
def auth():
    return {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def payload():
    return {
        "schema_version": "1",
        "request_id": "00000000-0000-4000-8000-000000000001",
        "message": {
            "from_address": "Sender <sender@example.test>",
            "reply_to": "",
            "subject": "Synthetic integration test",
            "plain_text": "Hello 🔒 שלום",
            "html": '<a href="https://example.test">Hello</a>',
            "authentication_results": None,
        },
        "truncated_fields": [],
    }
