import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

DETECTOR_VERSION = "rules-2.0"
SUSPICIOUS_TOKENS = {
    "account", "auth", "billing", "delivery", "help", "id", "invoice", "login",
    "pay", "payment", "portal", "secure", "security", "signin", "support", "track",
    "tracking", "update", "verification", "verify", "wallet",
}
SHARED_HOSTING_SUFFIXES = (
    "github.io",
    "netlify.app",
    "pages.dev",
    "vercel.app",
    "wasmer.app",
    "web.app",
)
CONFUSABLES = str.maketrans({"а": "a", "е": "e", "і": "i", "ї": "i", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "ӏ": "l", "ı": "i"})
KEYBOARD_NEIGHBORS = {"a": "qwsz", "e": "wsdfr", "i": "ujko", "m": "njk", "o": "iklp", "r": "edft", "t": "rfgy"}


@dataclass(frozen=True)
class Signal:
    name: str
    value: float
    weight: float
    explanation: str


def normalize_domain(value: str) -> tuple[str, str]:
    raw = value.strip()
    candidate = urlsplit(raw if "://" in raw else f"//{raw}", scheme="https").hostname
    if not candidate:
        raise ValueError("A valid domain or URL is required")
    unicode_domain = unicodedata.normalize("NFKC", candidate.rstrip(".").lower())
    try:
        ascii_domain = unicode_domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domain is not valid IDNA") from exc
    if len(ascii_domain) > 253 or any(len(label) > 63 for label in ascii_domain.split(".")):
        raise ValueError("Domain exceeds DNS length limits")
    return ascii_domain, unicode_domain


def registrable_label(domain: str) -> str:
    labels = domain.split(".")
    return labels[-2] if len(labels) >= 2 else labels[0]


def canonical_brand(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKD", value).lower())


def is_official_domain(domain: str, official_domains: list[str]) -> bool:
    normalized = domain.lower().rstrip(".")
    return any(normalized == item.lower().rstrip(".") or normalized.endswith(f".{item.lower().rstrip('.')}") for item in official_domains)


def damerau_levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    matrix = [[0] * (len(right) + 1) for _ in range(len(left) + 1)]
    for i in range(len(left) + 1):
        matrix[i][0] = i
    for j in range(len(right) + 1):
        matrix[0][j] = j
    for i in range(1, len(left) + 1):
        for j in range(1, len(right) + 1):
            cost = 0 if left[i - 1] == right[j - 1] else 1
            matrix[i][j] = min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and left[i - 1] == right[j - 2] and left[i - 2] == right[j - 1]:
                matrix[i][j] = min(matrix[i][j], matrix[i - 2][j - 2] + cost)
    return matrix[-1][-1]


def script_groups(text: str) -> set[str]:
    groups: set[str] = set()
    for character in text:
        if not character.isalpha():
            continue
        name = unicodedata.name(character, "")
        if "LATIN" in name:
            groups.add("latin")
        elif "CYRILLIC" in name:
            groups.add("cyrillic")
        elif "GREEK" in name:
            groups.add("greek")
        else:
            groups.add("other")
    return groups


def analyze_domain(domain: str, unicode_domain: str, brand_name: str, official_domains: list[str]) -> list[Signal]:
    brand = canonical_brand(brand_name)
    labels = unicode_domain.split(".")
    candidate_labels = labels[:-1] if len(labels) > 1 else labels
    compact_labels = [canonical_brand(label) for label in candidate_labels]
    tokens = set(re.split(r"[-_.]", unicode_domain))
    suspicious = sorted(tokens & SUSPICIOUS_TOKENS)
    signals: list[Signal] = []

    if is_official_domain(domain, official_domains):
        return [Signal("official_allowlist", 1, -100, "Domain is the official asset or one of its subdomains")]

    brand_matches = [index for index, compact in enumerate(compact_labels) if brand and brand in compact]
    exact_matches = [index for index, compact in enumerate(compact_labels) if compact == brand]
    registrable_index = len(labels) - 2 if len(labels) >= 2 else 0

    if registrable_index in exact_matches:
        signals.append(Signal("exact_brand_nonofficial", 1, 38, "An exact protected-brand label is registered outside the official allowlist"))
    if any(compact_labels[index] != brand for index in brand_matches):
        matched = next(candidate_labels[index] for index in brand_matches if compact_labels[index] != brand)
        signals.append(Signal("brand_token", 1, 22, f"Hostname label '{matched}' contains the protected brand plus additional text"))

    distances = [
        (damerau_levenshtein(compact, brand), compact)
        for compact in compact_labels
        if brand and compact and brand not in compact and len(compact) >= max(3, len(brand) - 2)
    ]
    if distances:
        distance, nearest = min(distances, key=lambda item: item[0])
        similarity = 1 - distance / max(len(nearest), len(brand), 1)
        if 0 < distance <= 2:
            signals.append(Signal("edit_distance", similarity, 28, f"Nearest hostname label has brand edit distance {distance} with similarity {similarity:.2f}"))
    if suspicious:
        signals.append(Signal("suspicious_tokens", min(len(suspicious) / 2, 1), 20, f"Risk-associated tokens: {', '.join(suspicious)}"))

    for label in candidate_labels:
        groups = script_groups(label)
        if len(groups) > 1:
            signals.append(Signal("mixed_script", 1, 30, f"Hostname label mixes scripts: {', '.join(sorted(groups))}"))
            break
    for label in candidate_labels:
        mapped = label.translate(CONFUSABLES)
        if mapped != label and canonical_brand(mapped) == brand:
            signals.append(Signal("unicode_confusable", 1, 35, "Unicode confusables visually map to the protected brand"))
            break

    if any(index < registrable_index for index in brand_matches):
        signals.append(Signal("deceptive_subdomain", 1, 30, "The protected brand appears in a non-official subdomain"))
    if any(domain == suffix or domain.endswith(f".{suffix}") for suffix in SHARED_HOSTING_SUFFIXES) and brand_matches:
        signals.append(Signal("shared_hosting_impersonation", 1, 18, "A brand-bearing hostname is deployed on a shared application-hosting suffix"))
    return signals


def generate_candidates(brand_name: str, tlds: tuple[str, ...] = ("com", "net", "org", "co"), limit: int = 250) -> list[str]:
    brand = canonical_brand(brand_name)
    if len(brand) < 3:
        return []
    labels: set[str] = set()
    for i in range(len(brand)):
        labels.add(brand[:i] + brand[i + 1 :])
        if i + 1 < len(brand):
            labels.add(brand[:i] + brand[i + 1] + brand[i] + brand[i + 2 :])
        for replacement in KEYBOARD_NEIGHBORS.get(brand[i], ""):
            labels.add(brand[:i] + replacement + brand[i + 1 :])
    for token in ("login", "secure", "support", "verify"):
        labels.add(f"{brand}-{token}")
        labels.add(f"{token}-{brand}")
    return sorted(f"{label}.{tld}" for label in labels if len(label) >= 3 for tld in tlds)[:limit]
