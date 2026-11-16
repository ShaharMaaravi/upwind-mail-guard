"""Versioned analysis contract, kept separate from the live diagnostic API."""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from app.schemas import Message, RequestId, StrictModel

AnalysisField = Literal[
    "from_address",
    "reply_to",
    "subject",
    "plain_text",
    "html",
    "authentication_results",
    "attachments",
]
Category = Literal["url", "sender", "content", "attachment"]
Severity = Literal["low", "medium", "high"]
Verdict = Literal[
    "low_observed_risk", "suspicious", "high_risk", "inconclusive", "analysis_unavailable"
]
Points = Annotated[int, Field(ge=0, le=100)]


class AttachmentMetadata(StrictModel):
    filename: Annotated[str, Field(max_length=512)]
    content_type: Annotated[str, Field(max_length=128)] | None
    size_bytes: Annotated[int, Field(ge=0, le=10**12)] | None


class AnalysisRequest(StrictModel):
    schema_version: Literal["1"]
    request_id: RequestId
    message: Message
    attachments: Annotated[list[AttachmentMetadata], Field(max_length=20)] | None = None
    truncated_fields: Annotated[list[AnalysisField], Field(max_length=7)]

    @model_validator(mode="after")
    def consistent_coverage(self) -> "AnalysisRequest":
        values = {**self.message.model_dump(), "attachments": self.attachments}
        if all(value is None for value in values.values()):
            raise ValueError("No readable message fields")
        if len(set(self.truncated_fields)) != len(self.truncated_fields):
            raise ValueError("Duplicate coverage fields")
        if any(values[name] is None for name in self.truncated_fields):
            raise ValueError("Unavailable fields cannot be truncated")
        return self


class CoverageIssue(StrictModel):
    field: AnalysisField
    code: Literal[
        "invalid_address",
        "unknown_domain_boundary",
        "invalid_url",
        "unsupported_url_scheme",
        "relative_url",
        "link_limit_reached",
        "url_too_long",
        "ambiguous_html",
        "invalid_text",
        "normalized_text_limit_reached",
        "ambiguous_filename",
        "display_url_unresolved",
    ]


class Coverage(StrictModel):
    available_fields: list[AnalysisField]
    unavailable_fields: list[AnalysisField]
    truncated_fields: list[AnalysisField]
    issues: list[CoverageIssue]
    links_considered: Annotated[int, Field(ge=0, le=100)]
    unique_links: Annotated[int, Field(ge=0, le=100)]
    attachment_records: Annotated[int, Field(ge=0, le=20)]
    limitations: list[
        Literal[
            "authentication_unverified",
            "urls_not_fetched",
            "attachment_bytes_not_inspected",
            "html_not_rendered",
            "quoted_content_not_separated",
            "english_content_rules",
        ]
    ]


class Finding(StrictModel):
    finding_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    rule_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.]{2,63}$")]
    category: Category
    severity: Severity
    field: AnalysisField
    evidence: Annotated[str, Field(max_length=256)]
    explanation: Annotated[str, Field(min_length=1, max_length=400)]
    requested_points: Points
    awarded_points: Points
    category_suppressed_points: Points
    global_suppressed_points: Points

    @model_validator(mode="after")
    def reconcile_points(self) -> "Finding":
        if self.requested_points != (
            self.awarded_points + self.category_suppressed_points + self.global_suppressed_points
        ):
            raise ValueError("Finding points do not reconcile")
        return self


class ScoreAccounting(StrictModel):
    requested_points: Annotated[int, Field(ge=0)]
    category_suppressed_points: Annotated[int, Field(ge=0)]
    global_suppressed_points: Annotated[int, Field(ge=0)]
    duplicates_removed: Annotated[int, Field(ge=0)]


class SkippedCheck(StrictModel):
    rule_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.]{2,63}$")]
    reason: Literal["missing_fields", "invalid_fields", "unknown_domain_boundary"]
    fields: list[AnalysisField]


class AnalysisResponse(StrictModel):
    schema_version: Literal["1"] = "1"
    request_id: RequestId
    policy_version: str
    normalization_version: str
    analysis_status: Literal["complete", "partial", "unavailable"]
    score: Points | None
    verdict: Verdict
    findings: list[Finding]
    scoring: ScoreAccounting | None
    checks_run: list[str]
    checks_skipped: list[SkippedCheck] = Field(default_factory=list)
    coverage: Coverage

    @model_validator(mode="after")
    def no_false_reassurance(self) -> "AnalysisResponse":
        skipped_ids = [check.rule_id for check in self.checks_skipped]
        if len(set(skipped_ids)) != len(skipped_ids) or set(skipped_ids) & set(self.checks_run):
            raise ValueError("Checks cannot be both run and skipped or skipped twice")
        if self.analysis_status == "unavailable":
            if (
                self.score is not None
                or self.verdict != "analysis_unavailable"
                or self.findings
                or self.scoring is not None
                or self.checks_run
            ):
                raise ValueError("Unavailable analysis cannot carry a score or findings")
            return self
        if self.score is None or not self.checks_run or self.scoring is None:
            raise ValueError("Scored analysis requires completed checks and accounting")
        if len(set(self.checks_run)) != len(self.checks_run):
            raise ValueError("Duplicate check IDs")
        if any(f.rule_id not in self.checks_run for f in self.findings):
            raise ValueError("Finding from an unexecuted check")
        if len({f.finding_id for f in self.findings}) != len(self.findings):
            raise ValueError("Duplicate finding IDs")
        if self.score != sum(f.awarded_points for f in self.findings):
            raise ValueError("Score does not match findings")
        for name in ("requested_points", "category_suppressed_points", "global_suppressed_points"):
            if getattr(self.scoring, name) != sum(getattr(f, name) for f in self.findings):
                raise ValueError("Aggregate accounting does not match findings")
        expected = (
            "high_risk"
            if self.score >= 60
            else "suspicious"
            if self.score >= 25
            else "inconclusive"
            if self.analysis_status == "partial"
            else "low_observed_risk"
        )
        if self.verdict != expected:
            raise ValueError("Verdict does not match score and coverage")
        if self.analysis_status == "complete" and (
            self.coverage.unavailable_fields
            or self.coverage.truncated_fields
            or self.coverage.issues
            or self.checks_skipped
        ):
            raise ValueError("Incomplete input cannot be presented as complete")
        return self
