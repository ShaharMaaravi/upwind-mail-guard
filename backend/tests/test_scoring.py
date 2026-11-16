"""These tests inject signals; they do not claim detector accuracy."""

from itertools import permutations

import pytest
from app.analysis_schemas import AnalysisRequest, AnalysisResponse
from app.normalization import normalize_message
from app.scoring import Signal, score_signals
from pydantic import ValidationError


def signal(rule="url.display_mismatch", key="https://example.net/", evidence="Example URL"):
    return Signal(rule_id=rule, evidence_key=key, field="html", evidence=evidence)


def test_exact_contributions_and_category_cap():
    result = score_signals((signal(), signal("url.userinfo"), signal("url.ip_host")))
    assert result.score == 60
    assert [f.awarded_points for f in result.findings] == [40, 20, 0]
    assert [f.category_suppressed_points for f in result.findings] == [0, 5, 15]
    assert result.accounting.requested_points == 80
    assert result.accounting.category_suppressed_points == 20
    assert result.accounting.global_suppressed_points == 0


def test_global_and_category_caps_reconcile_even_for_zero_point_findings():
    result = score_signals(
        (
            signal(),
            signal("url.userinfo"),
            signal("attachment.executable"),
            signal("attachment.double_extension"),
            signal("content.credentials_pressure"),
            signal("content.payment_pressure"),
            signal("sender.reply_to_mismatch"),
        )
    )
    assert result.score == 100
    assert len(result.findings) == 7
    assert result.accounting.requested_points == 185
    assert result.accounting.category_suppressed_points == 35
    assert result.accounting.global_suppressed_points == 50
    assert sum(f.awarded_points for f in result.findings) == 100
    for finding in result.findings:
        assert finding.requested_points == (
            finding.awarded_points
            + finding.category_suppressed_points
            + finding.global_suppressed_points
        )


def test_deduplication_and_order_independence():
    signals = (signal(evidence="z"), signal(evidence="a"), signal("url.userinfo"))
    expected = score_signals(signals)
    for ordered in permutations(signals):
        assert score_signals(ordered) == expected
    assert expected.accounting.duplicates_removed == 1
    assert expected.findings[0].evidence == "a"
    assert score_signals((signal(),)).findings[0].finding_id == expected.findings[0].finding_id


def test_distinct_evidence_gets_distinct_ids_but_remains_capped():
    result = score_signals((signal(key="a"), signal(key="b")))
    assert result.score == 60
    assert len({f.finding_id for f in result.findings}) == 2
    assert result.accounting.duplicates_removed == 0


@pytest.mark.parametrize(
    ("rule", "key", "evidence"),
    [
        ("authentication.pass", "x", "x"),
        ("url.userinfo", "", "x"),
        ("url.userinfo", "x" * 2049, "x"),
        ("url.userinfo", "x", "x" * 257),
    ],
)
def test_invalid_signals_fail_closed(rule, key, evidence):
    with pytest.raises(ValueError):
        signal(rule, key, evidence)


def test_signal_count_is_bounded():
    with pytest.raises(ValueError, match="Too many"):
        score_signals((signal(),) * 513)


def scored_response(payload, signals=()):
    result = score_signals(signals)
    return dict(
        request_id=payload["request_id"],
        policy_version="heuristic-v1",
        normalization_version="normalize-v1",
        analysis_status="partial",
        score=result.score,
        verdict="inconclusive",
        findings=list(result.findings),
        scoring=result.accounting,
        checks_run=["url.userinfo"],
        coverage=normalize_message(AnalysisRequest.model_validate(payload)).coverage,
    )


def test_no_findings_is_inconclusive_when_coverage_is_partial(payload):
    response = AnalysisResponse(**scored_response(payload))
    assert response.score == 0 and response.verdict == "inconclusive"


@pytest.mark.parametrize(
    "mutation",
    [
        {"checks_run": []},
        {"checks_run": ["url.userinfo", "url.userinfo"]},
        {"score": 1},
        {"score": None},
        {"verdict": "low_observed_risk"},
        {"analysis_status": "unavailable"},
        {"scoring": None},
        {"analysis_status": "complete", "verdict": "low_observed_risk"},
    ],
)
def test_response_rejects_contradictory_scores_and_coverage(payload, mutation):
    data = scored_response(payload)
    data.update(mutation)
    with pytest.raises(ValidationError):
        AnalysisResponse(**data)


def test_response_rejects_unexecuted_rule_and_incorrect_accounting(payload):
    data = scored_response(payload, (signal(),))
    data["verdict"] = "suspicious"
    with pytest.raises(ValidationError, match="unexecuted"):
        AnalysisResponse(**data)
    data["checks_run"] = ["url.display_mismatch"]
    data["scoring"] = data["scoring"].model_copy(update={"requested_points": 0})
    with pytest.raises(ValidationError, match="accounting"):
        AnalysisResponse(**data)


@pytest.mark.parametrize(
    ("rules", "score", "verdict"),
    [
        (["url.ip_host"], 15, "inconclusive"),
        (["url.userinfo"], 25, "suspicious"),
        (["url.display_mismatch", "url.userinfo"], 60, "high_risk"),
    ],
)
def test_partial_coverage_does_not_hide_positive_risk(payload, rules, score, verdict):
    data = scored_response(payload, tuple(signal(rule) for rule in rules))
    data.update(checks_run=rules, verdict=verdict)
    response = AnalysisResponse(**data)
    assert response.score == score and response.verdict == verdict
