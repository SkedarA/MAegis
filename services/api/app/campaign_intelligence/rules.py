import math
from dataclasses import dataclass
from datetime import datetime


SHARED_PROVIDER_MARKERS = ("cloudflare", "amazon", "google", "microsoft", "akamai", "fastly", "github", "vercel", "netlify")
RELATION_WEIGHTS = {"resolves_to": 25, "aliases_to": 5, "uses_nameserver": 18, "uses_mx": 8, "presents_certificate": 35, "shares_certificate_profile": 15, "certificate_contains": 20, "registered_by": 2, "shares_registration_profile": 20, "hosted_by_asn": 8, "redirects_to": 25, "uses_path_template": 25, "uses_domain_template": 25, "shares_favicon": 25, "shares_structure": 35}
RELATION_FAMILIES = {"resolves_to": "network", "hosted_by_asn": "network", "aliases_to": "dns", "uses_nameserver": "dns", "uses_mx": "dns", "presents_certificate": "certificate", "shares_certificate_profile": "certificate", "certificate_contains": "certificate", "registered_by": "registration", "shares_registration_profile": "registration", "redirects_to": "url_behavior", "uses_path_template": "url_behavior", "uses_domain_template": "lexical", "shares_favicon": "content", "shares_structure": "content"}
FAMILY_CAPS = {"network": 25, "dns": 22, "certificate": 35, "registration": 20, "url_behavior": 30, "lexical": 25, "content": 40, "temporal": 20, "intelligence": 35}


@dataclass(frozen=True)
class RuleResult:
    weight: int
    reason: str
    strong: bool
    family: str


@dataclass(frozen=True)
class LinkScore:
    score: int
    classification: str
    admitted: bool
    independent_families: int
    family_scores: dict[str, int]
    reasons: list[str]


def promotion_eligible(campaign_confidence: float, threat_confidence: float, brand_relevance: float) -> bool:
    """Fail closed: automatic promotion requires three separately high gates."""
    return campaign_confidence >= .75 and threat_confidence >= .85 and brand_relevance >= .65


def relation_rule(relation_type: str, target_type: str, target_value: str, attributes: dict | None = None) -> RuleResult:
    value = target_value.lower()
    shared = any(marker in value or marker in str(attributes or {}).lower() for marker in SHARED_PROVIDER_MARKERS)
    base = RELATION_WEIGHTS.get(relation_type, 0)
    family = RELATION_FAMILIES.get(relation_type, "other")
    if shared and relation_type in {"resolves_to", "hosted_by_asn", "uses_nameserver", "redirects_to"}:
        return RuleResult(0, f"Shared provider {target_value} is context only", False, family)
    reason = {"resolves_to": "shared non-generic IP", "aliases_to": "shared DNS alias", "uses_nameserver": "shared non-generic nameserver", "uses_mx": "shared mail infrastructure", "presents_certificate": "exact TLS certificate reuse", "shares_certificate_profile": "matching certificate issuance profile", "certificate_contains": "shared certificate SAN group", "registered_by": "shared registrar", "shares_registration_profile": "matching registration-batch profile", "redirects_to": "shared redirect destination", "uses_path_template": "matching normalized URL path template", "uses_domain_template": "matching multi-brand lure-name template", "shares_favicon": "exact favicon fingerprint", "shares_structure": "shared page structure"}.get(relation_type, f"shared {target_type}")
    return RuleResult(base, reason, base >= 18, family)


def rarity_factor(indicator_degree: int, total_domains: int) -> float:
    """Down-weight hubs while retaining full value for rare indicators."""
    if indicator_degree <= 2:
        return 1.0
    if total_domains <= indicator_degree:
        return 0.0
    return max(0.05, min(1.0, math.log((total_domains + 1) / indicator_degree) / math.log(max(2, total_domains))))


def score_direct_link(signals: list[dict], first_seen_a: datetime, first_seen_b: datetime, trusted_intel: bool = False) -> LinkScore:
    family_scores: dict[str, int] = {}
    reasons: list[str] = []
    for signal in signals:
        rule = relation_rule(signal["relation_type"], signal.get("target_type", "entity"), signal.get("target_value", ""), signal.get("attributes"))
        age_days = max(0, float(signal.get("age_days", 0)))
        freshness = 1.0 if age_days <= 30 else .7 if age_days <= 90 else .4 if age_days <= 180 else .15
        effective = round(rule.weight * rarity_factor(int(signal.get("degree", 1)), int(signal.get("total_domains", 1))) * freshness)
        if effective <= 0:
            reasons.append(rule.reason)
            continue
        family_scores[rule.family] = min(FAMILY_CAPS.get(rule.family, 20), family_scores.get(rule.family, 0) + effective)
        reasons.append(f"+{effective} {rule.reason} (used by {signal.get('degree', 1)} domains; {round(age_days)} days old)")
    age_hours = abs((first_seen_a - first_seen_b).total_seconds()) / 3600
    temporal = 15 if age_hours <= 24 else 10 if age_hours <= 72 else 5 if age_hours <= 168 else 0
    if temporal:
        family_scores["temporal"] = temporal
        reasons.append(f"+{temporal} first observed within {round(age_hours)} hours")
    if trusted_intel:
        family_scores["intelligence"] = 25
        reasons.append("+25 at least one domain has trusted threat-intelligence evidence")
    independent = len([family for family, value in family_scores.items() if value > 0])
    score = min(100, sum(family_scores.values()))
    admitted = score >= 55 and independent >= 2
    classification = "strong_campaign_linkage" if admitted and score >= 75 and independent >= 3 else "probable_campaign" if admitted else "possible_infrastructure_reuse" if score >= 30 else "insufficient_evidence"
    return LinkScore(score, classification, admitted, independent, family_scores, reasons)


PATTERN_CATALOG = [
    {"key": "cloaked_infrastructure_reuse", "name": "Cloaked infrastructure reuse", "version": "2.0", "required": ["content_unavailable", "strong_infrastructure_link"], "minimum_independent_signals": 2, "description": "Inaccessible content requires a rare infrastructure link plus independent temporal, content, URL or intelligence evidence."},
    {"key": "rapid_domain_rotation", "name": "Rapid domain rotation", "version": "2.0", "required": ["temporal_cluster", "shared_infrastructure"], "minimum_independent_signals": 2, "description": "Domains activate within seven days while rare infrastructure is reused; shared-platform hubs are excluded."},
    {"key": "multi_brand_credential_kit", "name": "Multi-brand credential kit", "version": "2.0", "required": ["multiple_brand_matches", "shared_structure_or_path"], "minimum_independent_signals": 2, "description": "A content or URL fingerprint connects a kit targeting multiple brands."},
]
