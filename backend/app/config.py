"""Runtime configuration. All values come from environment variables prefixed BASTION_.

No secret has a default value. The process refuses to start if a required secret is missing.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BASTION_", env_file=".env", extra="ignore")

    # Connection used by the API process. This role has least-privilege grants and is subject to RLS.
    database_url: str
    # Connection used ONLY by migrations and the bootstrap CLI. Never give this to the API process.
    database_admin_url: str = ""
    # Fernet key used to encrypt TOTP secrets at rest. Generate with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    field_encryption_key: str

    environment: str = "production"  # "development" enables /docs and relaxes nothing else
    cookie_secure: bool = True
    allowed_origin: str = "http://localhost:5173"
    trust_proxy_headers: bool = False  # only true when running behind a proxy you control

    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    login_rate_limit_per_minute: int = 20
    max_body_bytes: int = 65536
    # True on Vercel and other serverless hosts: no connection pool, and no prepared statements so the
    # app also works behind a transaction-mode pooler such as PgBouncer.
    serverless: bool = False

    @property
    def is_development(self) -> bool:
        return self.environment == "development"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
