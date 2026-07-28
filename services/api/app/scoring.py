from dataclasses import dataclass

from .detection import Signal


@dataclass(frozen=True)
class ScoreResult:
    score: float
    confidence: float
    severity: str
    contributions: list[Signal]


def score_signals(signals: list[Signal], evidence_sources: int = 1) -> ScoreResult:
    raw = sum(signal.weight * max(0, min(signal.value, 1)) for signal in signals)
    score = round(max(0, min(raw, 100)), 1)
    confidence = round(min(0.45 + 0.1 * evidence_sources + 0.07 * len([s for s in signals if s.weight > 0]), 0.98), 2)
    severity = "critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 45 else "low" if score >= 20 else "informational"
    return ScoreResult(score=score, confidence=confidence, severity=severity, contributions=signals)

