"""Application factory: importable in tests, fail-closed when launched without a secret."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.config import Settings
from app.schemas import DiagnosticRequest, DiagnosticResponse
from app.security import RequestGuard


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_environment()
    app = FastAPI(
        title="Upwind Mail Guard",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        redirect_slashes=False,
    )
    app.add_middleware(RequestGuard, settings=settings)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _error: RequestValidationError) -> JSONResponse:
        # FastAPI's default error detail includes submitted values, including message content.
        return JSONResponse({"error": "invalid_request"}, status_code=422)

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/diagnose", response_model=DiagnosticResponse)
    def diagnose(payload: DiagnosticRequest) -> DiagnosticResponse:
        return DiagnosticResponse(
            request_id=payload.request_id,
            field_characters={
                name: None if value is None else len(value)
                for name, value in payload.message.model_dump().items()
            },
            truncated_fields=payload.truncated_fields,
        )

    return app
