from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # Watchlist — stored as comma-separated strings, split on demand
    watched_domains: str = ""
    watched_emails: str = ""
    watched_ips: str = ""
    watched_vendors: str = ""

    # API Keys
    github_token: str = ""
    alienvault_otx_key: str = ""
    abuseipdb_key: str = ""
    ransomware_live_pro_key: str = ""
    hudson_rock_api_key: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    slack_webhook_url: str = ""

    # Database
    database_url: str = "sqlite:///./watchdog.db"

    # App
    app_secret_key: str = "change-me-in-production"
    log_level: str = "INFO"
    replay_mode: bool = False
    data_retention_days: int = 30

    # Canary
    canary_github_gist_token: str = ""
    canary_domain: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    def _split(self, val: str) -> List[str]:
        return [v.strip() for v in val.split(",") if v.strip()]

    def watched_domains_list(self) -> List[str]:
        return self._split(self.watched_domains)

    def watched_emails_list(self) -> List[str]:
        return self._split(self.watched_emails)

    def watched_ips_list(self) -> List[str]:
        return self._split(self.watched_ips)

    def watched_vendors_list(self) -> List[str]:
        return self._split(self.watched_vendors)


settings = Settings()
