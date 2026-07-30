from functools import lru_cache
from typing import Self

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MAEGIS_", env_file=".env", extra="ignore")

    environment: str = "development"
    database_url: str = "postgresql+psycopg://maegis:maegis@postgres:5432/maegis"
    api_key: str | None = None
    capture_enabled: bool = False
    ct_search_url: str = "https://crt.sh/"
    rdap_base_url: str = "https://rdap.org/domain/"
    urlhaus_auth_key: str | None = None
    czds_directory: str = "/data/czds"
    ai_base_url: str | None = None
    ai_api_key: str | None = None
    ai_model: str = "local-model"
    max_generated_candidates: int = 750
    discovery_brand_batch_size: int = 5
    discovery_dns_batch_size: int = 40
    discovery_rdap_batch_size: int = 20
    fresh_registration_max_age_days: int = 90
    discovery_poll_interval_seconds: int = 900
    monitor_default_interval_seconds: int = 21600
    monitor_batch_size: int = 100
    monitor_batches_per_cycle: int = 5
    monitor_concurrency: int = 10
    monitor_claim_seconds: int = 300
    monitor_poll_interval_seconds: int = 60
    worker_health_stale_seconds: int = 2400
    cors_origins: str = "http://localhost:3000"

    @model_validator(mode="after")
    def production_secrets_are_required(self) -> Self:
        if self.environment == "production" and (not self.api_key or len(self.api_key) < 32):
            raise ValueError("MAEGIS_API_KEY must contain at least 32 characters in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
