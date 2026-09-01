"""Central config. Reads .env; every value is env-overridable."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    anthropic_api_key: str = "sk-ant-placeholder"
    anthropic_model: str = "claude-haiku-4-5-20251001"

    # Wazuh indexer (alerts live in wazuh-alerts-*, not the Manager API)
    wazuh_api_url: str = "https://localhost:9200"
    wazuh_api_user: str = "zuumb-ingest"
    wazuh_api_password: str = "changeme"
    wazuh_verify_ssl: bool = False
    wazuh_alerts_index: str = "wazuh-alerts-*"
    wazuh_live_polling: bool = False  # start the background poller on app startup
    wazuh_poll_seconds: int = 60

    database_url: str = "sqlite:///./zuumb.db"

    correlation_window_minutes: int = 30


settings = Settings()
