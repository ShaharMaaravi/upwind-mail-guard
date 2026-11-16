"""Diagnostic contract. Missing fields are null; empty strings mean available but empty."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

FieldName = Literal[
    "from_address", "reply_to", "subject", "plain_text", "html", "authentication_results"
]
ShortText = Annotated[str, Field(max_length=2048)]
BodyText = Annotated[str, Field(max_length=16000)]
HeaderText = Annotated[str, Field(max_length=4096)]
RequestId = Annotated[
    str, Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Message(StrictModel):
    from_address: ShortText | None
    reply_to: ShortText | None
    subject: ShortText | None
    plain_text: BodyText | None
    html: BodyText | None
    authentication_results: HeaderText | None


class DiagnosticRequest(StrictModel):
    schema_version: Literal["1"]
    request_id: RequestId
    message: Message
    truncated_fields: Annotated[list[FieldName], Field(max_length=6)]

    @model_validator(mode="after")
    def validate_coverage(self) -> "DiagnosticRequest":
        if all(value is None for value in self.message.model_dump().values()):
            raise ValueError("No readable message fields")
        if len(set(self.truncated_fields)) != len(self.truncated_fields):
            raise ValueError("Duplicate coverage fields")
        if any(getattr(self.message, name) is None for name in self.truncated_fields):
            raise ValueError("Unavailable fields cannot also be truncated")
        return self


class DiagnosticResponse(StrictModel):
    schema_version: Literal["1"] = "1"
    request_id: RequestId
    status: Literal["diagnostic_only"] = "diagnostic_only"
    field_characters: dict[FieldName, int | None]
    truncated_fields: list[FieldName]
    attachments_status: Literal["not_inspected"] = "not_inspected"
    authentication_status: Literal["unverified"] = "unverified"
