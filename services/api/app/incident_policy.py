from .detection import Signal


INCIDENT_MIN_SCORE = 45
AMBIGUOUS_BRANDS = frozenset({"aquila", "autonom", "electrica", "sameday"})
HIGH_INTENT_SIGNALS = frozenset(
    {
        "exact_brand_nonofficial",
        "edit_distance",
        "mixed_script",
        "suspicious_tokens",
        "threat_feed_verdict",
        "unicode_confusable",
        "enrichment.just_registered",
        "enrichment.new_registration",
        "enrichment.recent_registration",
    }
)


def should_create_incident(brand_canonical: str, signals: list[Signal], score: float) -> bool:
    """Keep broad observations while preventing weak lexical matches from flooding triage."""
    if score < INCIDENT_MIN_SCORE:
        return False
    names = {signal.name for signal in signals if signal.value > 0 and signal.weight > 0}
    has_high_intent = bool(names & HIGH_INTENT_SIGNALS)
    if "shared_hosting_impersonation" in names and not has_high_intent:
        return False
    if brand_canonical in AMBIGUOUS_BRANDS and not has_high_intent:
        return False
    return True


def source_signals(payload: dict) -> list[Signal]:
    verdicts = payload.get("verdicts")
    overall = verdicts.get("overall") if isinstance(verdicts, dict) else None
    if isinstance(overall, dict) and overall.get("malicious") is True:
        return [Signal("threat_feed_verdict", 1, 35, "Public urlscan metadata marked the observed page malicious")]
    return []
