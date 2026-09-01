"""Central config. Reads .env; every value is env-overridable."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    anthropic_api_key: str = "sk-ant-placeholder"
    anthropic_model: str = "claude-haiku-4-5-20251001"

    wazuh_api_url: str = "https://localhost:55000"
    wazuh_api_user: str = "wazuh"
    wazuh_api_password: str = "wazuh"
    wazuh_verify_ssl: bool = False

    database_url: str = "sqlite:///./ai_soc_xdr.db"

    correlation_window_minutes: int = 30


settings = Settings()
