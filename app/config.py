import yaml
from pathlib import Path
from functools import lru_cache
from pydantic import BaseModel
from typing import List


class AppConfig(BaseModel):
    name: str = "Token Generator"
    host: str = "0.0.0.0"
    port: int = 8080
    secret_key: str = "change-me"
    debug: bool = False
    api_url: str = "http://localhost:8080"


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


class TokenConfig(BaseModel):
    default_expiration_days: int = 365
    token_length_bytes: int = 32


class LoginConfig(BaseModel):
    name: str = "Login"
    description: str = "Authenticate to create and manage API tokens for your applications."


class AdminConfig(BaseModel):
    admin_emails: List[str] = []


class Config(BaseModel):
    app: AppConfig = AppConfig()
    database: DatabaseConfig = DatabaseConfig()
    oauth: OAuthConfig = OAuthConfig()
    login: LoginConfig = LoginConfig()
    tokens: TokenConfig = TokenConfig()
    admin: AdminConfig = AdminConfig()


@lru_cache()
def get_config() -> Config:
    config_path = Path(__file__).parent.parent / "config.yaml"
    if config_path.exists():
        with open(config_path) as f:
            data = yaml.safe_load(f)
            return Config(**data)
    return Config()