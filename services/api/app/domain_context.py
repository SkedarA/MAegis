from datetime import datetime
from typing import Any

from .enrichment import registration_date


PLATFORM_SUFFIXES: dict[str, dict[str, str]] = {
    "pages.dev": {"name": "Cloudflare Pages", "contact": "https://abuse.cloudflare.com/"},
    "workers.dev": {"name": "Cloudflare Workers", "contact": "https://abuse.cloudflare.com/"},
    "vercel.app": {"name": "Vercel", "contact": "https://vercel.com/abuse"},
    "netlify.app": {"name": "Netlify", "contact": "https://www.netlify.com/abuse/"},
    "github.io": {"name": "GitHub Pages", "contact": "https://support.github.com/contact/report-abuse"},
    "web.app": {"name": "Firebase Hosting", "contact": "https://support.google.com/code/contact/cloud_platform_report"},
    "firebaseapp.com": {"name": "Firebase Hosting", "contact": "https://support.google.com/code/contact/cloud_platform_report"},
    "onrender.com": {"name": "Render", "contact": "https://render.com/legal/aup"},
    "railway.app": {"name": "Railway", "contact": "https://railway.com/legal/fair-use"},
    "wasmer.app": {"name": "Wasmer Edge", "contact": "https://wasmer.io/contact"},
}
COMPOUND_SUFFIXES = frozenset({"co.uk", "com.au", "com.br", "com.ph", "com.ro", "co.za"})


def platform_for(domain: str) -> tuple[str, dict[str, str]] | None:
    normalized = domain.lower().rstrip(".")
    for suffix, provider in PLATFORM_SUFFIXES.items():
        if normalized != suffix and normalized.endswith(f".{suffix}"):
            return suffix, provider
    return None


def registrable_domain(domain: str) -> str:
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    suffix = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix in COMPOUND_SUFFIXES else ".".join(labels[-2:])


def _vcard_values(entity: dict[str, Any], field: str) -> list[str]:
    vcard = entity.get("vcardArray")
    rows = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list) else []
    values: list[str] = []
    for row in rows:
        if isinstance(row, list) and len(row) >= 4 and row[0] == field and isinstance(row[3], str):
            values.append(row[3].removeprefix("mailto:"))
    return values


def registrar_from_rdap(rdap: dict[str, Any] | None) -> dict[str, str | None]:
    raw = (rdap or {}).get("raw") if isinstance(rdap, dict) else None
    entities = raw.get("entities", []) if isinstance(raw, dict) else []
    registrar = next((item for item in entities if isinstance(item, dict) and "registrar" in item.get("roles", [])), None)
    if not registrar:
        return {"name": None, "contact": None}
    names = _vcard_values(registrar, "fn")
    emails = _vcard_values(registrar, "email")
    urls = _vcard_values(registrar, "url")
    return {
        "name": names[0] if names else registrar.get("handle"),
        "contact": emails[0] if emails else urls[0] if urls else None,
    }


def build_domain_context(domain: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    platform = platform_for(domain)
    rdap = next((item.get("payload") for item in evidence if item.get("evidence_type") == "rdap"), None)
    registered: datetime | None = None if platform else registration_date(rdap or {})
    registrar = {"name": None, "contact": None} if platform else registrar_from_rdap(rdap)
    if platform:
        suffix, provider = platform
        return {
            "domain_type": "platform_tenant",
            "registrable_domain": suffix,
            "platform_suffix": suffix,
            "hosting_provider": provider,
            "registrar": registrar,
            "registration_date": None,
            "registration_relevant": False,
        }
    return {
        "domain_type": "registered_domain",
        "registrable_domain": registrable_domain(domain),
        "platform_suffix": None,
        "hosting_provider": {"name": None, "contact": None},
        "registrar": registrar,
        "registration_date": registered.isoformat() if registered else None,
        "registration_relevant": True,
    }
