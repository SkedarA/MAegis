import re
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
