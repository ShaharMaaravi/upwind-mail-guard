"""Pure provisional scoring policy; detectors will produce signals in milestone 2."""

import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType

from app.analysis_schemas import AnalysisField, Category, Finding, ScoreAccounting, Severity

POLICY_VERSION = "heuristic-v1"
CATEGORY_CAPS = MappingProxyType({"url": 60, "sender": 20, "content": 35, "attachment": 40})


@dataclass(frozen=True)
class RuleSpec:
    category: Category
    severity: Severity
    points: int
    explanation: str


# This is policy metadata, not a registry of implemented detectors.
RULE_SPECS = MappingProxyType(
    {
        "url.display_mismatch": RuleSpec(
            "url",
            "high",
            40,
            "The displayed URL and destination belong to different registrable domains.",
        ),
        "url.userinfo": RuleSpec(
            "url",
            "medium",
            25,
            "The URL contains user information before @, which can disguise its actual host.",
        ),
        "url.ip_host": RuleSpec(
            "url", "low", 15, "The URL uses an IP address instead of a domain name."
        ),
        "sender.reply_to_mismatch": RuleSpec(
            "sender", "low", 15, "The sender and Reply-To use different registrable domains."
        ),
        "content.credentials_pressure": RuleSpec(
            "content",
            "medium",
            25,
            "A credential request appears together with pressure or urgency.",
        ),
        "content.payment_pressure": RuleSpec(
            "content", "medium", 25, "A payment request appears together with pressure or urgency."
        ),
        "attachment.executable": RuleSpec(
            "attachment",
            "high",
            35,
            "Attachment filename metadata indicates an executable file type.",
        ),
        "attachment.double_extension": RuleSpec(
            "attachment",
            "medium",
            20,
            "The filename has a potentially misleading double extension.",
        ),
    }
)


@dataclass(frozen=True)
class Signal:
    rule_id: str
    evidence_key: str
    field: AnalysisField
    evidence: str

    def __post_init__(self) -> None:
        if self.rule_id not in RULE_SPECS:
            raise ValueError("Unknown rule ID")
        if not self.evidence_key or len(self.evidence_key) > 2048 or len(self.evidence) > 256:
            raise ValueError("Invalid evidence bounds")


@dataclass(frozen=True)
class ScoreResult:
    score: int
    findings: tuple[Finding, ...]
    accounting: ScoreAccounting


def score_signals(signals: tuple[Signal, ...]) -> ScoreResult:
    """Deduplicate, rank deterministically, apply category caps, then the global cap.

    Empty signals yield an internal sum of zero. The API must also know which detectors ran;
    it must never expose that zero when no detector was executed.
    """
    if len(signals) > 512:
        raise ValueError("Too many rule signals")
    unique: dict[tuple[str, str], Signal] = {}
    # Stable representative if the same evidence arrives through multiple extraction paths.
    for signal in sorted(signals, key=lambda s: (s.rule_id, s.evidence_key, s.field, s.evidence)):
        unique.setdefault((signal.rule_id, signal.evidence_key), signal)
    ordered = sorted(
        unique.values(), key=lambda s: (-RULE_SPECS[s.rule_id].points, s.rule_id, s.evidence_key)
    )
    category_used = dict.fromkeys(CATEGORY_CAPS, 0)
    findings = []
    total = 0
    for signal in ordered:
        spec = RULE_SPECS[signal.rule_id]
        category_award = min(
            spec.points, CATEGORY_CAPS[spec.category] - category_used[spec.category]
        )
        category_used[spec.category] += category_award
        award = min(category_award, 100 - total)
        total += award
        stable_id = hashlib.sha256(
            json.dumps(
                [signal.rule_id, signal.evidence_key], ensure_ascii=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        findings.append(
            Finding(
                finding_id=stable_id,
                rule_id=signal.rule_id,
                category=spec.category,
                severity=spec.severity,
                field=signal.field,
                evidence=signal.evidence,
                explanation=spec.explanation,
                requested_points=spec.points,
                awarded_points=award,
                category_suppressed_points=spec.points - category_award,
                global_suppressed_points=category_award - award,
            )
        )
    return ScoreResult(
        score=total,
        findings=tuple(findings),
        accounting=ScoreAccounting(
            requested_points=sum(f.requested_points for f in findings),
            category_suppressed_points=sum(f.category_suppressed_points for f in findings),
            global_suppressed_points=sum(f.global_suppressed_points for f in findings),
            duplicates_removed=len(signals) - len(unique),
        ),
    )
