from datetime import datetime
from typing import Any

from .enrichment import registration_date


PLATFORM_SUFFIXES: dict[str, dict[str, str | None]] = {
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
    "azurewebsites.net": {"name": "Microsoft Azure App Service", "contact": "https://www.microsoft.com/en-us/concern/azure"},
    "herokuapp.com": {"name": "Heroku", "contact": None},
    "myshopify.com": {"name": "Shopify", "contact": "https://www.shopify.com/legal/tools/report-an-issue/report-a-merchant"},
    "wixsite.com": {"name": "Wix", "contact": "https://www.wix.com/about/abuse"},
    "wordpress.com": {"name": "WordPress.com", "contact": "https://wordpress.com/abuse/"},
    "weebly.com": {"name": "Weebly", "contact": None},
    "replit.app": {"name": "Replit", "contact": "https://replit.com/report"},
    "glitch.me": {"name": "Glitch", "contact": None},
    "ngrok-free.app": {"name": "ngrok", "contact": "https://ngrok.com/abuse"},
}

CNAME_PROVIDERS: dict[str, dict[str, str | None]] = {
    **PLATFORM_SUFFIXES,
    "vercel-dns.com": PLATFORM_SUFFIXES["vercel.app"],
    "netlifyglobalcdn.com": PLATFORM_SUFFIXES["netlify.app"],
    "herokudns.com": PLATFORM_SUFFIXES["herokuapp.com"],
    "cloudfront.net": {"name": "Amazon CloudFront", "contact": "https://support.aws.amazon.com/#/contacts/report-abuse"},
    "azurefd.net": {"name": "Microsoft Azure Front Door", "contact": "https://www.microsoft.com/en-us/concern/azure"},
    "trafficmanager.net": {"name": "Microsoft Azure Traffic Manager", "contact": "https://www.microsoft.com/en-us/concern/azure"},
    "shopify.com": PLATFORM_SUFFIXES["myshopify.com"],
}

NAMESERVER_PROVIDERS: dict[str, dict[str, str | None]] = {
    "cloudflare.com": {"name": "Cloudflare DNS / proxy", "contact": "https://abuse.cloudflare.com/"},
    "awsdns": {"name": "Amazon Route 53", "contact": "https://support.aws.amazon.com/#/contacts/report-abuse"},
    "azure-dns": {"name": "Microsoft Azure DNS", "contact": "https://www.microsoft.com/en-us/concern/azure"},
    "digitalocean.com": {"name": "DigitalOcean", "contact": "https://www.digitalocean.com/company/contact/abuse"},
    "hetzner.com": {"name": "Hetzner", "contact": "https://abuse.hetzner.com/issues/new"},
    "googledomains.com": {"name": "Google Cloud DNS", "contact": "https://support.google.com/code/contact/cloud_platform_report"},
}

NETWORK_PROVIDERS: dict[str, dict[str, str | None]] = {
    "CLOUDFLARE": {"name": "Cloudflare", "contact": "https://abuse.cloudflare.com/"},
    "AMAZON": {"name": "Amazon Web Services", "contact": "https://support.aws.amazon.com/#/contacts/report-abuse"},
    "GOOGLE": {"name": "Google Cloud", "contact": "https://support.google.com/code/contact/cloud_platform_report"},
    "MICROSOFT": {"name": "Microsoft Azure", "contact": "https://www.microsoft.com/en-us/concern/azure"},
    "DIGITALOCEAN": {"name": "DigitalOcean", "contact": "https://www.digitalocean.com/company/contact/abuse"},
    "HETZNER": {"name": "Hetzner", "contact": "https://abuse.hetzner.com/issues/new"},
    "OVH": {"name": "OVHcloud", "contact": "https://www.ovh.com/abuse/"},
}

COMPOUND_SUFFIXES = frozenset({"co.uk", "com.au", "com.br", "com.ph", "com.ro", "co.za"})


def _attribution(name: str | None, contact: str | None, source: str, confidence: str, evidence: str | None) -> dict[str, str | None]:
    return {"name": name, "contact": contact, "source": source, "confidence": confidence, "evidence": evidence}


def _suffix_match(value: str, suffix: str) -> bool:
    normalized = value.lower().rstrip(".")
    return normalized == suffix or normalized.endswith(f".{suffix}")


def platform_for(domain: str) -> tuple[str, dict[str, str | None]] | None:
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


def _walk_entities(entities: list[Any]):
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        yield entity
        nested = entity.get("entities")
        if isinstance(nested, list):
            yield from _walk_entities(nested)


def registrar_from_rdap(rdap: dict[str, Any] | None) -> dict[str, str | None]:
    raw = (rdap or {}).get("raw") if isinstance(rdap, dict) else None
    entities = list(_walk_entities(raw.get("entities", []))) if isinstance(raw, dict) else []
    registrar = next((item for item in entities if "registrar" in (item.get("roles") or [])), None)
    if not registrar:
        return _attribution(None, None, "automatic", "unknown", None)
    nested = list(_walk_entities(registrar.get("entities", [])))
    abuse = next((item for item in nested if "abuse" in (item.get("roles") or [])), None)
    names = _vcard_values(registrar, "fn") or _vcard_values(registrar, "org")
    contacts = (_vcard_values(abuse or {}, "email") + _vcard_values(abuse or {}, "url") + _vcard_values(registrar, "email") + _vcard_values(registrar, "url"))
    name = names[0] if names else registrar.get("handle")
    return _attribution(name, contacts[0] if contacts else None, "rdap", "high" if names else "medium", f"RDAP registrar entity {registrar.get('handle') or 'without handle'}")


def hosting_from_evidence(evidence: list[dict[str, Any]]) -> dict[str, str | None]:
    dns_payloads = [item.get("payload") for item in evidence if item.get("evidence_type") == "dns" and isinstance(item.get("payload"), dict)]
    for payload in reversed(dns_payloads):
        records = payload.get("records") or {}
        for cname in records.get("CNAME", []):
            for suffix, provider in CNAME_PROVIDERS.items():
                if _suffix_match(str(cname), suffix):
                    return _attribution(provider["name"], provider["contact"], "dns_cname", "high", f"CNAME {cname}")

    source_payloads = [item.get("payload") for item in evidence if item.get("evidence_type") == "source_observation" and isinstance(item.get("payload"), dict)]
    for payload in reversed(source_payloads):
        asn_name = payload.get("page_asnname")
        if not isinstance(asn_name, str) or not asn_name.strip():
            continue
        normalized = asn_name.upper()
        provider = next((value for key, value in NETWORK_PROVIDERS.items() if key in normalized), None)
        if provider:
            return _attribution(provider["name"], provider["contact"], "urlscan_network", "medium", f"urlscan network {asn_name}")
        return _attribution(f"{asn_name} (network)", None, "urlscan_network", "low", f"urlscan network {asn_name}")

    for payload in reversed(dns_payloads):
        records = payload.get("records") or {}
        for nameserver in records.get("NS", []):
            normalized = str(nameserver).lower()
            provider = next((value for suffix, value in NAMESERVER_PROVIDERS.items() if suffix in normalized), None)
            if provider:
                return _attribution(provider["name"], provider["contact"], "dns_nameserver", "low", f"Nameserver {nameserver}; may identify DNS or proxy rather than origin hosting")
    return _attribution(None, None, "automatic", "unknown", None)


def _apply_override(context: dict[str, Any], override: dict[str, Any] | None) -> dict[str, Any]:
    if not override:
        context["override"] = {"active": False, "updated_by": None, "updated_at": None, "rationale": None}
        return context
    for key in ("hosting_provider", "registrar"):
        name = override.get(f"{key}_name")
        contact = override.get(f"{key}_contact")
        if name is not None or contact is not None:
            context[key] = _attribution(name, contact, "analyst_override", "analyst_verified", "Manual analyst attribution")
    context["override"] = {
        "active": True,
        "updated_by": override.get("updated_by"),
        "updated_at": override.get("updated_at"),
        "rationale": override.get("rationale"),
    }
    return context


def build_domain_context(domain: str, evidence: list[dict[str, Any]], override: dict[str, Any] | None = None) -> dict[str, Any]:
    platform = platform_for(domain)
    rdap = next((item.get("payload") for item in reversed(evidence) if item.get("evidence_type") == "rdap"), None)
    registered: datetime | None = None if platform else registration_date(rdap or {})
    registrar = _attribution(None, None, "not_applicable", "high", "Parent platform registration is unrelated") if platform else registrar_from_rdap(rdap)
    if platform:
        suffix, provider = platform
        context = {
            "domain_type": "platform_tenant",
            "registrable_domain": suffix,
            "platform_suffix": suffix,
            "hosting_provider": _attribution(provider["name"], provider["contact"], "platform_suffix", "high", f"Hostname is a tenant beneath {suffix}"),
            "registrar": registrar,
            "registration_date": None,
            "registration_relevant": False,
        }
    else:
        context = {
            "domain_type": "registered_domain",
            "registrable_domain": registrable_domain(domain),
            "platform_suffix": None,
            "hosting_provider": hosting_from_evidence(evidence),
            "registrar": registrar,
            "registration_date": registered.isoformat() if registered else None,
            "registration_relevant": True,
        }
    return _apply_override(context, override)
