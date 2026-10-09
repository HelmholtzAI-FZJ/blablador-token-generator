import yaml
from pathlib import Path
from functools import lru_cache
from pydantic import BaseModel
from typing import ClassVar, List


class AppConfig(BaseModel):
    name: str = "Token Generator"
    host: str = "0.0.0.0"
    port: int = 8080
    secret_key: str = "change-me"
    # Keys the HMAC of stored API tokens. Kept separate from secret_key so
    # rotating the session signing key does not invalidate API tokens.
    token_hash_key: str = ""
    debug: bool = False
    api_url: str = "http://localhost:8080"
    secure_cookies: bool = False
    jwt_expiration_hours: int = 24
    validate_rate_limit: str = "600/minute"
    # "memory://" is per process; use redis://... with multiple workers/pods.
    rate_limit_storage_uri: str = "memory://"


class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:///./tokens.db"


class OAuthConfig(BaseModel):
    client_id: str = ""
    client_secret: str = ""
    authorize_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    redirect_uri: str = ""
    scopes: List[str] = []
    # Treat the provider's email as verified even without an
    # email_verified=true claim. Only enable if the IdP guarantees it.
    trust_provider_emails: bool = False


class TokenConfig(BaseModel):
    default_expiration_days: int = 90
    max_expiration_days: int = 365
    token_length_bytes: int = 32
    token_prefix: str = "blablador"


class LoginConfig(BaseModel):
    name: str = "Login"
    description: str = "Authenticate to create and manage API tokens for your applications."


class LocalAuthConfig(BaseModel):
    enabled: bool = False
    allow_registration: bool = False


class AdminConfig(BaseModel):
    admin_emails: List[str] = []
    admin_subjects: List[str] = []


class ModelConfig(BaseModel):
    id: str
    object: str = "model"
    created: int
    owned_by: str
    max_model_len: int | None = None


class BlabladorConfig(BaseModel):
    api_url: str = "https://ptj.blablador.fz-juelich.de"
    models: List[ModelConfig] = []


class Config(BaseModel):
    app: AppConfig = AppConfig()
    database: DatabaseConfig = DatabaseConfig()
    oauth: OAuthConfig = OAuthConfig()
    login: LoginConfig = LoginConfig()
    local: LocalAuthConfig = LocalAuthConfig()
    tokens: TokenConfig = TokenConfig()
    admin: AdminConfig = AdminConfig()
    blablador: BlabladorConfig = BlabladorConfig()

    # Known weak/default secret values that must never be used in production.
    # Declared as ClassVar so Pydantic does not treat it as a model field.
    WEAK_SECRET_VALUES: ClassVar[List[str]] = [
        "change-me",
        "change-me-in-production",
        "your-secret-key",
        "secret",
        "",
    ]

    def validate_security(self) -> None:
        """Validate security-critical configuration at startup.

        Refuses to start if the JWT secret_key is a known weak/default value
        or too short (<32 chars). This prevents token forgery via default
        or guessable signing keys.

        Raises:
            ValueError: If the secret_key is weak, default, or too short.
        """
        for field in ("secret_key", "token_hash_key"):
            secret = getattr(self.app, field)
            if secret in Config.WEAK_SECRET_VALUES:
                raise ValueError(
                    f"{field} must not be a default or weak value. "
                    f"Set a strong, unique {field} in config.yaml. "
                    'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
                )
            if len(secret) < 32:
                raise ValueError(
                    f"{field} must be at least 32 characters long "
                    f"(current: {len(secret)}). Use a strong, random secret. "
                    'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
                )
        if self.app.token_hash_key == self.app.secret_key:
            raise ValueError("token_hash_key must differ from secret_key")


@lru_cache()
def get_config() -> Config:
    import os
    default_path = Path(__file__).parent.parent / "config.yaml"
    config_path = Path(os.environ.get("CONFIG_PATH", default_path))
    if config_path.exists():
        with open(config_path) as f:
            data = yaml.safe_load(f)
            config = Config(**data)
    else:
        config = Config()

    # Allow secrets to be overridden by environment variables.
    # This prevents storing secrets in config files on disk.
    secret_key = os.environ.get("JWT_SECRET_KEY")
    if secret_key:
        config.app.secret_key = secret_key

    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        config.database.url = database_url

    rate_limit_storage_uri = os.environ.get("RATE_LIMIT_STORAGE_URI")
    if rate_limit_storage_uri:
        config.app.rate_limit_storage_uri = rate_limit_storage_uri

    token_hash_key = os.environ.get("TOKEN_HASH_KEY")
    if token_hash_key:
        config.app.token_hash_key = token_hash_key

    oauth_client_secret = os.environ.get("OAUTH_CLIENT_SECRET")
    if oauth_client_secret:
        config.oauth.client_secret = oauth_client_secret

    config.validate_security()
    return config
