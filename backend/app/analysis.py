"""Pure orchestration from validated input through rules, scoring, and honest coverage."""

from app.analysis_schemas import AnalysisRequest, AnalysisResponse
from app.normalization import NORMALIZATION_VERSION, normalize_message
from app.rules import run_rules
from app.scoring import POLICY_VERSION, score_signals


def analyze(payload: AnalysisRequest) -> AnalysisResponse:
    normalized = normalize_message(payload)
    evaluation = run_rules(normalized)
    issues = {
        (issue.field, issue.code): issue
        for issue in (*normalized.coverage.issues, *evaluation.issues)
    }
    coverage = normalized.coverage.model_copy(
        update={
            "issues": [issues[key] for key in sorted(issues)],
            "limitations": [*normalized.coverage.limitations, "english_content_rules"],
        }
    )
    shared = dict(
        request_id=payload.request_id,
        policy_version=POLICY_VERSION,
        normalization_version=NORMALIZATION_VERSION,
        checks_run=list(evaluation.checks_run),
        checks_skipped=list(evaluation.checks_skipped),
        coverage=coverage,
    )
    if not evaluation.checks_run:
        return AnalysisResponse(
            **shared,
            analysis_status="unavailable",
            score=None,
            verdict="analysis_unavailable",
            findings=[],
            scoring=None,
        )
    result = score_signals(evaluation.signals)
    partial = bool(
        coverage.unavailable_fields
        or coverage.truncated_fields
        or coverage.issues
        or evaluation.checks_skipped
    )
    verdict = (
        "high_risk"
        if result.score >= 60
        else "suspicious"
        if result.score >= 25
        else "inconclusive"
        if partial
        else "low_observed_risk"
    )
    return AnalysisResponse(
        **shared,
        analysis_status="partial" if partial else "complete",
        score=result.score,
        verdict=verdict,
        findings=list(result.findings),
        scoring=result.accounting,
    )
