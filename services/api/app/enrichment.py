import asyncio
import ipaddress
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .detection import Signal


DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


@dataclass(frozen=True)
class EnrichmentResult:
    evidence_type: str
    source: str
    payload: dict[str, Any]


def public_addresses(values: list[str]) -> list[str]:
    addresses: list[str] = []
    for value in values:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError("Private, loopback, link-local, reserved, and internal addresses are blocked")
        addresses.append(str(address))
    if not addresses:
        raise ValueError("Domain has no public A or AAAA records")
    return sorted(set(addresses))


async def fetch_dns(domain: str, lifetime: float = 5.0) -> dict[str, Any]:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = lifetime

    async def query(record_type: str) -> tuple[str, list[str], str | None]:
        try:
            answer = await resolver.resolve(domain, record_type, lifetime=lifetime, raise_on_no_answer=False)
            values = sorted({item.to_text().rstrip(".")[:2048] for item in answer})[:100] if answer.rrset else []
            return record_type, values, None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return record_type, [], None
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            return record_type, [], type(exc).__name__

    results = await asyncio.gather(*(query(record_type) for record_type in DNS_RECORD_TYPES))
    records = {record_type: values for record_type, values, _ in results}
    errors = {record_type: error for record_type, _, error in results if error}
    addresses = records["A"] + records["AAAA"]
    return {
        "domain": domain,
        "records": records,
        "errors": errors,
        "resolved_addresses": addresses,
        "all_addresses_public": bool(addresses) and all(ipaddress.ip_address(value).is_global for value in addresses),
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


async def fetch_tls(domain: str, addresses: list[str], timeout: float = 8.0) -> dict[str, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    candidates = public_addresses(addresses)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    last_error: Exception | None = None
    for address in candidates:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    address,
                    443,
                    ssl=context,
                    server_hostname=domain,
                    ssl_handshake_timeout=timeout,
                ),
                timeout=timeout,
            )
            del reader
            ssl_object = writer.get_extra_info("ssl_object")
            der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
            if not der:
                raise ValueError("TLS peer did not provide a certificate")
            certificate = x509.load_der_x509_certificate(der)
            try:
                sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                sans = []
            return {
                "domain": domain,
                "connected_address": address,
                "port": 443,
                "protocol": ssl_object.version(),
                "cipher": ssl_object.cipher()[0] if ssl_object.cipher() else None,
                "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
                "serial_number": format(certificate.serial_number, "x"),
                "subject": certificate.subject.rfc4514_string(),
                "issuer": certificate.issuer.rfc4514_string(),
                "sans": sorted(sans)[:500],
                "not_before": certificate.not_valid_before_utc.isoformat(),
                "not_after": certificate.not_valid_after_utc.isoformat(),
                "chain_verified": False,
                "collected_at": datetime.now(timezone.utc).isoformat(),
            }
        except (OSError, TimeoutError, ValueError, ssl.SSLError) as exc:
            last_error = exc
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ssl.SSLError):
                    pass
    raise ConnectionError(f"TLS collection failed for all public addresses: {type(last_error).__name__}")


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def registration_date(rdap: dict[str, Any]) -> datetime | None:
    for event in rdap.get("events", []):
        if event.get("eventAction") in {"registration", "registered"}:
            return _parse_timestamp(event.get("eventDate"))
    return None


def enrichment_signals(
    dns_payload: dict[str, Any] | None,
    rdap_payload: dict[str, Any] | None,
    tls_payload: dict[str, Any] | None,
    *,
    now: datetime | None = None,
) -> list[Signal]:
    current = now or datetime.now(timezone.utc)
    signals: list[Signal] = []
    if dns_payload and dns_payload.get("records", {}).get("MX"):
        signals.append(Signal("enrichment.mx_configured", 1, 8, "The candidate has mail-exchange records and can receive email"))
    registered = registration_date(rdap_payload or {})
    if registered:
        age_days = max(0, (current - registered).days)
        if age_days <= 30:
            signals.append(Signal("enrichment.new_registration", 1, 15, f"The domain was registered {age_days} days ago"))
        elif age_days <= 90:
            signals.append(Signal("enrichment.recent_registration", 1, 8, f"The domain was registered {age_days} days ago"))
    issued = _parse_timestamp((tls_payload or {}).get("not_before"))
    if issued:
        age_days = max(0, (current - issued).days)
        if age_days <= 30:
            signals.append(Signal("enrichment.recent_certificate", 1, 6, f"The TLS certificate was issued {age_days} days ago"))
    return signals
