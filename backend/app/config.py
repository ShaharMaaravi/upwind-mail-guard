"""Fail-closed configuration; never include secret values in errors or reprs."""

import os
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    api_token: str = field(repr=False)
    max_body_bytes: int = 256 * 1024
    body_timeout_seconds: float = 5
    requests_per_minute: int = 30

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", self.api_token):
            raise ValueError(
                "MAIL_GUARD_API_TOKEN must be a 43-128 character URL-safe random token"
            )

    @classmethod
    def from_environment(cls) -> "Settings":
        return cls(api_token=os.environ.get("MAIL_GUARD_API_TOKEN", ""))
