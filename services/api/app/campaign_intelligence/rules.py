from dataclasses import dataclass


SHARED_PROVIDER_MARKERS = ("cloudflare", "amazon", "google", "microsoft", "akamai", "fastly", "github", "vercel", "netlify")
RELATION_WEIGHTS = {"resolves_to": 25, "aliases_to": 5, "uses_nameserver": 18, "uses_mx": 8, "presents_certificate": 35, "certificate_contains": 20, "registered_by": 2, "hosted_by_asn": 8, "redirects_to": 25, "shares_favicon": 25, "shares_structure": 35}


@dataclass(frozen=True)
class RuleResult:
    weight: int
    reason: str
    strong: bool


def relation_rule(relation_type: str, target_type: str, target_value: str, attributes: dict | None = None) -> RuleResult:
    value = target_value.lower()
    shared = any(marker in value or marker in str(attributes or {}).lower() for marker in SHARED_PROVIDER_MARKERS)
    base = RELATION_WEIGHTS.get(relation_type, 0)
    if shared and relation_type in {"resolves_to", "hosted_by_asn", "uses_nameserver"}:
        return RuleResult(0, f"Shared provider {target_value} is retained as context but cannot link a campaign", False)
    reason = {
        "resolves_to": "Domains share a non-generic IP address",
        "aliases_to": "Domain uses a DNS alias (context only)",
        "uses_nameserver": "Domains share a non-generic nameserver",
        "uses_mx": "Domains share mail infrastructure",
        "presents_certificate": "Domains reuse an exact TLS certificate fingerprint",
        "certificate_contains": "Certificate SANs connect the domains",
        "registered_by": "Domains share a registrar (weak evidence)",
        "redirects_to": "URLs share a redirect destination",
        "shares_favicon": "Pages share an exact favicon hash",
        "shares_structure": "Pages share a structural fingerprint",
    }.get(relation_type, f"Shared {target_type}")
    return RuleResult(base, reason, base >= 18)


PATTERN_CATALOG = [
    {"key": "cloaked_infrastructure_reuse", "name": "Cloaked infrastructure reuse", "version": "1.0", "required": ["content_unavailable", "strong_infrastructure_link"], "minimum_independent_signals": 2, "description": "Inaccessible content is evidence only when supported by reused certificate, dedicated IP, nameserver or structural indicators."},
    {"key": "rapid_domain_rotation", "name": "Rapid domain rotation", "version": "1.0", "required": ["temporal_cluster", "shared_infrastructure"], "minimum_independent_signals": 2, "description": "New domains appearing in a narrow time window while stable campaign infrastructure is reused."},
    {"key": "multi_brand_credential_kit", "name": "Multi-brand credential kit", "version": "1.0", "required": ["multiple_brand_matches", "shared_structure_or_path"], "minimum_independent_signals": 2, "description": "A reusable kit or infrastructure cluster targeting more than one brand."},
]
