from functools import lru_cache
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
    max_generated_candidates: int = 250
    discovery_brand_batch_size: int = 5
    discovery_poll_interval_seconds: int = 900


@lru_cache
def get_settings() -> Settings:
    return Settings()
