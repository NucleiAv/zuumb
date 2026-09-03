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
    # chain stitcher: an entity in more incidents than this is a hub (proxy/jump box),
    # not a real link — dropped so it can't stitch unrelated incidents into one chain.
    # Lower it if real traffic is dense enough that legit chains stay small.
    chain_max_entity_spread: int = 4

    # Active response (Phase 14). SEPARATE least-privilege Manager API user — never
    # the ingestion credential. Its RBAC policy should allow only active-response:command.
    wazuh_ar_api_url: str = "https://localhost:55000"
    wazuh_ar_api_user: str = "zuumb-ar"
    wazuh_ar_api_password: str = "changeme"
    # DEFAULT ON: an approved action is logged as intent, nothing is dispatched to a
    # host. Flip to false only when you mean for approvals to hit real machines.
    response_dry_run: bool = True
    response_rate_limit_seconds: int = 30  # min gap between two dispatched actions


settings = Settings()
