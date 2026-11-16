"""Analysis orchestration. Milestone 1 deliberately has no enabled detectors."""

from app.analysis_schemas import AnalysisRequest, AnalysisResponse
from app.normalization import NORMALIZATION_VERSION, normalize_message
from app.scoring import POLICY_VERSION


def analyze(payload: AnalysisRequest) -> AnalysisResponse:
    normalized = normalize_message(payload)
    coverage = normalized.coverage.model_copy(
        update={
            "limitations": ["detection_rules_not_implemented", *normalized.coverage.limitations]
        }
    )
    return AnalysisResponse(
        request_id=payload.request_id,
        policy_version=POLICY_VERSION,
        normalization_version=NORMALIZATION_VERSION,
        analysis_status="unavailable",
        score=None,
        verdict="analysis_unavailable",
        findings=[],
        scoring=None,
        checks_run=[],
        coverage=coverage,
    )
