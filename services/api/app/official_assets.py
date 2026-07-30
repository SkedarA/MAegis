from .detection import normalize_domain


ASSET_TYPES = frozenset({"domain", "subdomain", "wildcard"})


def normalize_official_asset(value: str, asset_type: str) -> str:
    if asset_type not in ASSET_TYPES:
        raise ValueError("Unsupported official asset type")
    raw = value.strip().lower().rstrip(".")
    if raw.startswith("*."):
        raw = raw[2:]
    domain, _ = normalize_domain(raw)
    return f"*.{domain}" if asset_type == "wildcard" else domain
