from collections.abc import Iterable


def _text_values(value) -> Iterable[str]:
    if isinstance(value, str):
        yield value.strip().lower().rstrip(".")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                candidate = item.get("ldhName") or item.get("unicodeName") or item.get("value")
                if candidate:
                    yield str(candidate).strip().lower().rstrip(".")
            elif isinstance(item, str):
                yield item.strip().lower().rstrip(".")


def evidence_correlation_keys(evidence_rows: Iterable[dict]) -> set[str]:
    keys: set[str] = set()
    for row in evidence_rows:
        payload = row.get("payload") or {}
        evidence_type = str(row.get("evidence_type") or "").lower()
        records = payload.get("records") if isinstance(payload, dict) else None
        if isinstance(records, dict):
            for record_type in ("A", "AAAA", "NS", "MX", "CNAME"):
                for value in _text_values(records.get(record_type, [])):
                    keys.add(f"{record_type.lower()}:{value}")
        for value in _text_values(payload.get("resolved_addresses", [])):
            keys.add(f"ip:{value}")
        if evidence_type == "rdap" or "rdap" in payload:
            rdap = payload.get("rdap") if isinstance(payload.get("rdap"), dict) else payload
            for value in _text_values(rdap.get("nameservers", [])):
                keys.add(f"ns:{value}")
        if evidence_type == "tls_certificate":
            fingerprint = payload.get("fingerprint") or payload.get("sha256")
            if fingerprint:
                keys.add(f"tls:{str(fingerprint).lower()}")
        for field, prefix in (("page_ip", "ip"), ("page_asn", "asn"), ("page_asnname", "asn_name"), ("favicon_hash", "favicon")):
            value = payload.get(field)
            if value:
                keys.add(f"{prefix}:{str(value).strip().lower()}")
    return keys


def correlation_reason(key: str) -> str:
    prefix, _, value = key.partition(":")
    labels = {"a": "Shared IPv4", "aaaa": "Shared IPv6", "ip": "Shared IP", "ns": "Shared nameserver", "mx": "Shared mail server", "cname": "Shared CNAME", "tls": "Shared TLS certificate", "asn": "Shared ASN", "asn_name": "Shared network provider", "favicon": "Shared favicon hash"}
    return f"{labels.get(prefix, 'Shared infrastructure')}: {value}"
