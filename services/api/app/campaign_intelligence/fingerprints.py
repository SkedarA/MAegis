import re
import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import parse_qsl, unquote, urlsplit

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f-]{27,}$", re.I)
HEX_RE = re.compile(r"^[0-9a-f]{8,}$", re.I)
INTEGER_RE = re.compile(r"^\d+$")
TOKEN_RE = re.compile(r"^[a-z0-9_-]{20,}$", re.I)


def normalize_url_template(value: str | None) -> str | None:
    if not value: return None
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    segments: list[str] = []
    for raw in unquote(parsed.path).lower().split("/"):
        if not raw: continue
        if UUID_RE.match(raw): segments.append("{uuid}")
        elif INTEGER_RE.match(raw): segments.append("{integer}")
        elif HEX_RE.match(raw): segments.append("{hex}")
        elif TOKEN_RE.match(raw): segments.append("{token}")
        else: segments.append(raw[:80])
    if not segments: return None
    keys = sorted({key.lower()[:80] for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    return "/" + "/".join(segments) + ("?" + "&".join(keys) if keys else "")


def url_hostname(value: str | None) -> str | None:
    if not value: return None
    return urlsplit(value if "://" in value else f"https://{value}").hostname


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def rdap_registration_profile(payload: dict) -> str | None:
    """Build a batch-registration fingerprint without retaining registrant PII."""
    registered = next((_timestamp(item.get("eventDate")) for item in payload.get("events", []) if item.get("eventAction") in {"registration", "registered"}), None)
    if not registered:
        return None
    registrar = payload.get("registrar") or next((item.get("handle") for item in payload.get("entities", []) if "registrar" in (item.get("roles") or [])), None)
    statuses = sorted(str(item).lower() for item in payload.get("status", []) if item)[:8]
    material = {"registrar": str(registrar or "unknown").lower(), "registered_hour": registered.strftime("%Y-%m-%dT%H"), "statuses": statuses}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def certificate_issuance_profile(payload: dict) -> str | None:
    """Correlate certificates issued in a batch while avoiding issuer-only links."""
    issued = _timestamp(payload.get("not_before"))
    expires = _timestamp(payload.get("not_after"))
    issuer = str(payload.get("issuer") or "").strip().lower()
    if not issued or not issuer:
        return None
    lifetime = round((expires - issued).total_seconds() / 86400) if expires else None
    material = {"issuer": issuer, "issued_hour": issued.strftime("%Y-%m-%dT%H"), "lifetime_days": lifetime, "san_count": len(payload.get("sans") or [])}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def domain_lure_template(domain: str, brand_tokens: list[str]) -> str | None:
    """Abstract enrolled brand tokens to connect one kit targeting many firms."""
    label = domain.lower().split(".", 1)[0]
    normalized = re.sub(r"[^a-z0-9]+", "-", label).strip("-")
    segments = normalized.split("-")
    for token in sorted({re.sub(r"[^a-z0-9]", "", value.lower()) for value in brand_tokens if len(value) >= 2}, key=len, reverse=True):
        if len(token) <= 3 and token not in segments:
            continue
        compact = normalized.replace("-", "")
        offset = compact.find(token)
        if offset < 0:
            continue
        # Preserve lure words around the protected name, but abstract the name.
        normalized = re.sub(re.escape(token), "{brand}", normalized.replace("-", ""), count=1)
        break
    if "{brand}" not in normalized:
        return None
    return re.sub(r"\d+", "{n}", normalized)


def page_structure_fingerprint(payload: dict) -> str | None:
    explicit = payload.get("structure_hash") or payload.get("dom_hash")
    if explicit:
        return str(explicit).lower()
    forms = payload.get("forms")
    if not isinstance(forms, list) or not forms:
        return None
    material = []
    for form in forms[:20]:
        if not isinstance(form, dict):
            continue
        material.append({"method": str(form.get("method") or "get").lower(), "inputs": sorted(str(item).lower() for item in (form.get("input_types") or [])), "action_host": url_hostname(form.get("action"))})
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest() if material else None
