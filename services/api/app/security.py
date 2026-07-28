from dataclasses import dataclass
from fastapi import Header, HTTPException, status

from .config import get_settings


DEMO_TENANT_ID = "00000000-0000-4000-8000-000000000001"


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    subject: str
    role: str


def require_principal(
    x_api_key: str | None = Header(default=None),
    x_tenant_id: str = Header(default=DEMO_TENANT_ID),
    x_role: str = Header(default="administrator"),
) -> Principal:
    settings = get_settings()
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    if x_role not in {"viewer", "analyst", "manager", "administrator"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unknown role")
    return Principal(tenant_id=x_tenant_id, subject="api-key", role=x_role)


def require_analyst(principal: Principal) -> None:
    if principal.role not in {"analyst", "manager", "administrator"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Analyst role required")

