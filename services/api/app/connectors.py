import hashlib
import gzip
import asyncio
import socket
from pathlib import Path
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx

from .config import get_settings
from .detection import canonical_brand, normalize_domain


@dataclass(frozen=True)
class ConnectorObservation:
    source: str
    domain: str
    url: str | None
    observed_at: datetime
    raw_hash: str
    payload: dict[str, Any]


class Connector(ABC):
    name: str
    version = "1.0"

    @abstractmethod
    async def fetch(self, target: str, checkpoint: dict[str, Any]) -> tuple[list[ConnectorObservation], dict[str, Any]]:
        """Return relevant observations and the next durable checkpoint."""

    @staticmethod
    def observation(source: str, domain: str, payload: dict[str, Any], url: str | None = None) -> ConnectorObservation:
        raw = repr(sorted(payload.items())).encode()
        return ConnectorObservation(source, domain, url, datetime.now(timezone.utc), hashlib.sha256(raw).hexdigest(), payload)


class CertificateTransparencyConnector(Connector):
    name = "certificate_transparency"

    async def fetch(self, target: str, checkpoint: dict[str, Any]) -> tuple[list[ConnectorObservation], dict[str, Any]]:
        settings = get_settings()
        params = {"q": f"%{target}%", "output": "json"}
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
            response = await client.get(settings.ct_search_url, params=params)
            response.raise_for_status()
        rows = response.json()
        seen = set(checkpoint.get("seen", []))
        observations: list[ConnectorObservation] = []
        for row in rows[:1000]:
            for value in str(row.get("name_value", "")).splitlines():
                candidate = value.removeprefix("*.").strip()
                if target.lower() not in candidate.lower() or candidate in seen:
                    continue
                try:
                    domain, _ = normalize_domain(candidate)
                except ValueError:
                    continue
                observations.append(self.observation(self.name, domain, row))
                seen.add(domain)
        next_checkpoint = {"seen": sorted(seen)[-3000:], "last_poll": datetime.now(timezone.utc).isoformat()}
        return observations, next_checkpoint


class DNSCandidateConnector(Connector):
    name = "dns_candidates"
    version = "1.1"

    async def fetch(self, target: str, checkpoint: dict[str, Any]) -> tuple[list[ConnectorObservation], dict[str, Any]]:
        try:
            rows = await asyncio.to_thread(socket.getaddrinfo, target, 443, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            addresses = sorted({item[4][0] for item in rows})
        except socket.gaierror:
            return [], checkpoint
        payload = {"addresses": addresses, "queried_domain": target}
        return [self.observation(self.name, target, payload)], {"last_domain": target, "last_poll": datetime.now(timezone.utc).isoformat()}


class RDAPRegistrationConnector(Connector):
    """Emits freshly registered generated candidates, including names with no DNS yet."""

    name = "rdap_candidates"
    version = "2.0"

    def __init__(self, max_age_days: int = 90):
        self.max_age_days = max(0, max_age_days)

    async def fetch(self, target: str, checkpoint: dict[str, Any]) -> tuple[list[ConnectorObservation], dict[str, Any]]:
        rdap = await fetch_rdap(target)
        next_checkpoint = {"last_domain": target, "last_poll": datetime.now(timezone.utc).isoformat()}
        if rdap.get("status") == "not_found":
            return [], next_checkpoint
        registered_at = rdap_registration_date(rdap)
        if registered_at is None:
            return [], {**next_checkpoint, "result": "registration_date_missing"}
        age_seconds = (datetime.now(timezone.utc) - registered_at).total_seconds()
        age_days = max(0, int(age_seconds // 86400))
        if age_seconds < -86400 or age_days > self.max_age_days:
            return [], {**next_checkpoint, "result": "outside_freshness_window", "registration_age_days": age_days}
        payload = {
            "queried_domain": target,
            "rdap": rdap,
            "fresh_registration": {
                "registered_at": registered_at.isoformat(),
                "age_days": age_days,
                "window_days": self.max_age_days,
            },
        }
        return [self.observation(self.name, target, payload)], next_checkpoint


class URLhausConnector(Connector):
    name = "urlhaus"

    async def fetch(self, target: str, checkpoint: dict[str, Any]) -> tuple[list[ConnectorObservation], dict[str, Any]]:
        settings = get_settings()
        if not settings.urlhaus_auth_key:
            return [], {**checkpoint, "status": "credential_required"}
        headers = {"Auth-Key": settings.urlhaus_auth_key}
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": target}, headers=headers)
            response.raise_for_status()
        payload = response.json()
        if payload.get("query_status") != "ok":
            return [], {"last_domain": target, "last_poll": datetime.now(timezone.utc).isoformat()}
        return [self.observation(self.name, target, payload)], {"last_domain": target, "last_poll": datetime.now(timezone.utc).isoformat()}


class URLScanConnector(Connector):
    """Reads public urlscan search metadata without visiting candidate websites."""

    name = "urlscan"

    async def fetch(self, target: str, checkpoint: dict[str, Any]) -> tuple[list[ConnectorObservation], dict[str, Any]]:
        query = f"task.url:{target} AND date:>now-30d"
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
            response = await client.get("https://urlscan.io/api/v1/search/", params={"q": query, "size": 100})
            response.raise_for_status()
        payload = response.json()
        seen = set(checkpoint.get("seen", []))
        observations: list[ConnectorObservation] = []
        for row in payload.get("results", []):
            task = row.get("task") or {}
            page = row.get("page") or {}
            scan_id = str(task.get("uuid") or row.get("_id") or "")
            domains: set[str] = set()
            for value in (task.get("url"), page.get("url"), page.get("domain")):
                if not value:
                    continue
                candidate = str(value).strip()
                hostname = urlsplit(candidate if "://" in candidate else f"//{candidate}", scheme="https").hostname
                if hostname and target in canonical_brand(hostname):
                    domains.add(hostname)
            for candidate in sorted(domains):
                key = f"{scan_id}:{candidate}"
                if key in seen:
                    continue
                try:
                    domain, _ = normalize_domain(candidate)
                except ValueError:
                    continue
                evidence = {
                    "scan_id": scan_id,
                    "scan_url": f"https://urlscan.io/result/{scan_id}/" if scan_id else None,
                    "submitted_url": task.get("url"),
                    "effective_url": page.get("url"),
                    "page_domain": page.get("domain"),
                    "page_title": page.get("title"),
                    "page_ip": page.get("ip"),
                    "page_asn": page.get("asn"),
                    "page_asnname": page.get("asnname"),
                    "page_country": page.get("country"),
                    "observed_at": task.get("time"),
                    "verdicts": row.get("verdicts") or {},
                }
                observations.append(self.observation(self.name, domain, evidence, url=task.get("url")))
                seen.add(key)
        return observations, {"seen": sorted(seen)[-3000:], "last_poll": datetime.now(timezone.utc).isoformat(), "query": query}


class CZDSZoneConnector(Connector):
    """Streams approved CZDS zone files and retains only target-matching names."""

    name = "czds"

    async def fetch(self, target: str, checkpoint: dict[str, Any]) -> tuple[list[ConnectorObservation], dict[str, Any]]:
        directory = Path(get_settings().czds_directory)
        observations: list[ConnectorObservation] = []
        processed = set(checkpoint.get("files", []))
        files = sorted(directory.glob("*.zone.gz")) if directory.exists() else []
        compact_target = target.lower().replace("-", "")
        for path in files:
            signature = f"{path.name}:{path.stat().st_mtime_ns}:{path.stat().st_size}"
            if signature in processed:
                continue
            with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as stream:
                for line in stream:
                    domain = line.partition(" ")[0].rstrip(".").lower()
                    label = domain.split(".", 1)[0].replace("-", "")
                    if compact_target not in label:
                        continue
                    payload = {"zone_file": path.name, "record": line[:1000].strip()}
                    observations.append(self.observation(self.name, domain, payload))
                    if len(observations) >= 5000:
                        break
            processed.add(signature)
        return observations, {"files": sorted(processed)[-1000:], "last_poll": datetime.now(timezone.utc).isoformat()}


async def fetch_rdap(domain: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
        response = await client.get(f"{get_settings().rdap_base_url}{domain}")
        if response.status_code == 404:
            return {"status": "not_found"}
        response.raise_for_status()
        data = response.json()
    return {
        "handle": data.get("handle"),
        "status": data.get("status", []),
        "events": data.get("events", []),
        "nameservers": [item.get("ldhName") for item in data.get("nameservers", [])],
        "entities": [{"handle": item.get("handle"), "roles": item.get("roles", [])} for item in data.get("entities", [])],
        "raw": data,
    }


def rdap_registration_date(rdap: dict[str, Any]) -> datetime | None:
    for event in rdap.get("events", []):
        if event.get("eventAction") not in {"registration", "registered"}:
            continue
        value = event.get("eventDate")
        if not isinstance(value, str):
            continue
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
