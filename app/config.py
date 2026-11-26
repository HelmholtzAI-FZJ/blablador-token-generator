import yaml
from ipaddress import ip_network
from pathlib import Path
from functools import lru_cache
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing import ClassVar, List, Literal
from urllib.parse import parse_qs, urlsplit

from limits import parse


class SecurityConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class AppConfig(SecurityConfigModel):
    environment: Literal["production", "development"] = "production"
    name: str = "Token Generator"
    host: str = "0.0.0.0"
    port: int = Field(8080, ge=1, le=65535)
    secret_key: str = "change-me"
    # Keys the HMAC of stored API tokens. Kept separate from secret_key so
    # rotating the session signing key does not invalidate API tokens.
    token_hash_key: str = ""
    debug: bool = False
    api_url: str = "https://localhost:8080"
    # Secure, __Host- prefixed cookies. Only disable for local development
    # over plain http.
    secure_cookies: bool = True
    jwt_expiration_hours: int = Field(24, ge=1, le=24)
    admin_jwt_expiration_hours: int = Field(1, ge=1, le=24)
    # Level for the token_generator.* loggers; audit/account events are
    # always kept at INFO.
    log_level: str = "INFO"
    # One line per request (route template, status, duration, client).
    access_log: bool = True
    # Largest accepted request body; every endpoint needs only a few KB.
    max_body_bytes: int = Field(65536, ge=1024, le=1048576)
    body_timeout_seconds: float = Field(10.0, gt=0, le=60)
    max_concurrent_requests: int = Field(128, ge=1, le=4096)
    readiness_timeout_seconds: float = Field(2.0, gt=0, le=10)


class DatabaseConfig(SecurityConfigModel):
    url: str = "sqlite+aiosqlite:///./tokens.db"
    # Log SQL statements (never their parameters) for debugging.
    echo: bool = False
    ssl_ca_file: str | None = None
    # Apply pending schema migrations at startup. When false, startup refuses
    # an outdated schema; run "python -m app.migrate" separately.
    auto_migrate: bool = True
    connect_timeout_seconds: float = Field(5.0, gt=0, le=30)
    statement_timeout_seconds: float = Field(5.0, gt=0, le=60)
    lock_timeout_seconds: float = Field(2.0, gt=0, le=30)
    idle_transaction_timeout_seconds: float = Field(15.0, gt=0, le=120)

    @model_validator(mode="after")
    def check_deadlines(self) -> "DatabaseConfig":
        if self.lock_timeout_seconds > self.statement_timeout_seconds:
            raise ValueError("Database lock timeout must not exceed the statement timeout")
        if self.idle_transaction_timeout_seconds < self.statement_timeout_seconds:
            raise ValueError("Idle transaction timeout must allow a statement to finish")
        return self


class OAuthConfig(SecurityConfigModel):
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
    request_timeout_seconds: float = Field(10.0, gt=0, le=60)
    max_response_bytes: int = Field(65536, ge=1024, le=1048576)


class TokenConfig(SecurityConfigModel):
    default_expiration_days: int = Field(90, ge=1, le=365)
    max_expiration_days: int = Field(365, ge=1, le=365)
    # Random bytes per token; below 16 tokens become guessable.
    token_length_bytes: int = Field(32, ge=16, le=127)
    token_prefix: str = Field("blablador", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
    # Tokens a user may hold (active, expired or revoked) before deleting some.
    max_tokens_per_user: int = Field(100, ge=1, le=10000)
    max_applications_per_user: int = Field(20, ge=1, le=1000)
    last_used_update_seconds: int = Field(60, ge=1, le=3600)


    @model_validator(mode="after")
    def check_token_policy(self) -> "TokenConfig":
        if self.default_expiration_days > self.max_expiration_days:
            raise ValueError("default_expiration_days must not exceed max_expiration_days")
        if len(self.token_prefix) + 1 + 2 * self.token_length_bytes > 256:
            raise ValueError("Generated API tokens must fit the 256 character input limit")
        return self


class LoginConfig(SecurityConfigModel):
    name: str = "Login"
    description: str = "Authenticate to create and manage API tokens for your applications."


class LocalAuthConfig(SecurityConfigModel):
    enabled: bool = False
    allow_registration: bool = False
    max_concurrent_password_operations: int = Field(4, ge=1, le=64)
    blocked_passwords: List[str] = [
        "passwordpassword", "passwordpassword1", "123456789012345",
        "12345678901234567890", "qwertyuiopasdfgh", "correcthorsebatterystaple",
    ]


class RateLimitConfig(SecurityConfigModel):
    # Counter storage. "memory://" is per process; use Redis
    # (verified "rediss://") in production with several workers or replicas.
    storage_uri: str = "memory://"
    # Unauthenticated endpoints, per client IP. Many users can share one
    # address (campus NAT, VPN, a course), so these are generous.
    pages: str = "120/minute"
    oauth_callback: str = "60/minute"
    local_login: str = "10/minute"
    local_login_account: str = "5/minute"
    preauth: str = "240/minute"
    storage_timeout_seconds: float = Field(0.5, gt=0, le=5)
    # Authenticated endpoints, per signed-in user.
    tokens_read: str = "60/minute"
    tokens_write: str = "30/minute"
    session: str = "30/minute"
    account_delete: str = "5/minute"
    admin: str = "120/minute"
    # Claiming a course seat, per signed-in user.
    course_join: str = "10/minute"
    # Sending or resending course invitations, per teacher.
    course_invite: str = "10/minute"
    # Token validation, per client IP. Addresses or CIDRs listed in
    # token_validation_exempt (e.g. the API gateway) are not limited.
    token_validation: str = "600/minute"
    token_validation_exempt: List[str] = []

    @field_validator("pages", "oauth_callback", "local_login", "local_login_account",
                     "preauth", "tokens_read", "tokens_write", "session", "account_delete",
                     "admin", "course_join", "course_invite", "token_validation")
    @classmethod
    def check_limit(cls, value: str) -> str:
        if parse(value).amount < 1:
            raise ValueError("Rate limits must be positive")
        return value

    @field_validator("token_validation_exempt")
    @classmethod
    def _check_networks(cls, value: List[str]) -> List[str]:
        for entry in value:
            ip_network(entry, strict=False)
        return value


class AdminConfig(SecurityConfigModel):
    admin_emails: List[str] = []
    admin_subjects: List[str] = []


class SmtpConfig(SecurityConfigModel):
    """Outgoing mail, used to tell admins about applications without owners."""
    enabled: bool = False
    host: str = ""
    port: int = Field(587, ge=1, le=65535)
    username: str = ""
    password: str = ""
    from_address: str = ""
    # STARTTLS on a plain connection (port 587), or TLS from the start (465).
    starttls: bool = True
    use_tls: bool = False
    timeout_seconds: float = Field(10.0, gt=0, le=60)

    @model_validator(mode="after")
    def check_smtp(self) -> "SmtpConfig":
        if self.starttls and self.use_tls:
            raise ValueError("smtp.starttls and smtp.use_tls are mutually exclusive")
        if self.enabled and not (self.host and self.from_address):
            raise ValueError("smtp.enabled requires smtp.host and smtp.from_address")
        return self


class NotificationsConfig(SecurityConfigModel):
    """Mail about tokens that are about to expire. Sent by
    `python -m app.manage notify-expiring-tokens`, which the chart runs as a
    CronJob; nothing runs in the web process. Requires `smtp.enabled`."""
    expiry_reminders: bool = False
    # Days before expiry; one mail per threshold, tightest last.
    warning_days: List[int] = [30, 7, 1]
    # Tokens handled per run before the job stops and continues the next day.
    batch_size: int = Field(200, ge=1, le=1000)

    @field_validator("warning_days")
    @classmethod
    def check_warning_days(cls, value: List[int]) -> List[int]:
        if not value:
            raise ValueError("notifications.warning_days must not be empty")
        if any(day < 1 or day > 365 for day in value):
            raise ValueError("notifications.warning_days must be between 1 and 365")
        if len(set(value)) != len(value):
            raise ValueError("notifications.warning_days must not repeat")
        return sorted(value, reverse=True)


DEFAULT_COURSE_TERMS = (
    "I run this course and am responsible for how its participants use their tokens. "
    "I will tell them the service's terms of use, revoke tokens that are misused, and "
    "not share the join link outside the course."
)


DEFAULT_INVITATION_SUBJECT = "Your access to Blablador for the course"
DEFAULT_INVITATION_BODY = (
    "Hello,\n\n"
    "for this course you will use Blablador, an LLM service. Use the personal link "
    "below to get your API token."
)
DEFAULT_INVITATION_FOOTER = (
    "Your personal link to join \"{course}\" ({start} to {end}):\n\n"
    "    {link}\n\n"
    "Open the link and press \"Show my token\" to get your API token; no sign-in is needed. "
    "The link works once, for one person; do not forward it. "
    "If you sign in to {app_name} with your JSC account and this email address, "
    "the token moves to your account.\n\n"
    "-- \n"
    "Sent by {app_name} on behalf of {teacher_name} <{teacher_email}>. "
    "Reply to this message to reach them. If you did not expect it, ignore it.\n"
)
INVITATION_FOOTER_FIELDS = ("course", "start", "end", "link", "app_name", "teacher_name", "teacher_email")


class CourseConfig(SecurityConfigModel):
    """Courses: a teacher (set by an admin) shares a join link; each student
    who signs in and opens it gets one token that ends with the course."""
    enabled: bool = False
    # Longest course, first to last day inclusive.
    max_days: int = Field(21, ge=1, le=365)
    max_seats: int = Field(60, ge=1, le=1000)
    max_active_per_teacher: int = Field(1, ge=1, le=100)
    # How far ahead a course may be scheduled.
    max_days_ahead: int = Field(180, ge=0, le=365)
    # Random bytes in a join link's code.
    join_code_bytes: int = Field(24, ge=16, le=64)
    # Days after a course ends before its tokens are purged.
    retention_days: int = Field(30, ge=0, le=3650)
    # Mailed invitations (need smtp.enabled): the default text teachers
    # edit; the link, dates and a footer naming the teacher are always added.
    invitation_subject: str = Field(DEFAULT_INVITATION_SUBJECT, min_length=1, max_length=200)
    invitation_body: str = Field(DEFAULT_INVITATION_BODY, min_length=1, max_length=4000)
    invitation_max_body_chars: int = Field(4000, ge=100, le=20000)
    # Appended to every invitation after the teacher's text; teachers cannot
    # change it. Placeholders: {course}, {start}, {end} (first and last day),
    # {link}, {app_name}, {teacher_name}, {teacher_email}. {link} is required.
    invitation_footer: str = Field(DEFAULT_INVITATION_FOOTER, min_length=1, max_length=4000)
    # For testing: keep each unused invitation's link so administrators can
    # open it. Links are otherwise stored only as hashes. Keep off in production.
    admin_can_view_invitation_links: bool = False
    # Sends per invitation, the first included, so resending cannot spam.
    max_invitation_sends: int = Field(3, ge=1, le=20)
    terms_version: str = Field("1", min_length=1, max_length=32)
    terms_text: str = Field(DEFAULT_COURSE_TERMS, min_length=1, max_length=4000)

    @field_validator("invitation_footer")
    @classmethod
    def check_invitation_footer(cls, value: str) -> str:
        from string import Formatter
        try:
            fields = {name for _, name, _, _ in Formatter().parse(value) if name is not None}
        except ValueError as exc:
            raise ValueError(f"courses.invitation_footer is not a valid template: {exc}") from None
        unknown = fields - set(INVITATION_FOOTER_FIELDS)
        if unknown:
            raise ValueError(f"courses.invitation_footer has unknown placeholders: {sorted(unknown)}; "
                             f"use {', '.join('{' + f + '}' for f in INVITATION_FOOTER_FIELDS)}")
        if "link" not in fields:
            raise ValueError("courses.invitation_footer must contain {link}")
        return value


class ModelConfig(SecurityConfigModel):
    id: str
    object: str = "model"
    created: int
    owned_by: str
    max_model_len: int | None = None


SAFE_URL = r"^https?://[^\s\"'`$\\]+$"


class BlabladorConfig(SecurityConfigModel):
    api_url: str = Field("https://ptj.blablador.fz-juelich.de", pattern=SAFE_URL)
    # What the "Try it" curl command on token pages calls. Empty: this
    # service's own /api/v1/user, which checks the token and names its
    # owner. Characters unsafe in a pasted shell command are refused.
    test_url: str = Field("", pattern=r"^$|" + SAFE_URL, max_length=500)
    models: List[ModelConfig] = []


class Config(SecurityConfigModel):
    app: AppConfig = AppConfig()
    database: DatabaseConfig = DatabaseConfig()
    oauth: OAuthConfig = OAuthConfig()
    login: LoginConfig = LoginConfig()
    local: LocalAuthConfig = LocalAuthConfig()
    tokens: TokenConfig = TokenConfig()
    rate_limits: RateLimitConfig = RateLimitConfig()
    admin: AdminConfig = AdminConfig()
    smtp: SmtpConfig = SmtpConfig()
    notifications: NotificationsConfig = NotificationsConfig()
    courses: CourseConfig = CourseConfig()
    blablador: BlabladorConfig = BlabladorConfig()

    @property
    def token_test_url(self) -> str:
        """The URL the "Try it" curl command on token pages calls."""
        return self.blablador.test_url or self.app.api_url.rstrip("/") + "/api/v1/user"

    @model_validator(mode="after")
    def check_course_tokens_fit(self) -> "Config":
        # Course tokens are <prefix>-course-<hex>.
        if self.courses.enabled and (
            len(self.tokens.token_prefix) + len("-course-") + 2 * self.tokens.token_length_bytes > 256
        ):
            raise ValueError("Course tokens must fit the 256 character input limit; shorten tokens.token_prefix")
        return self

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
            normalized = secret.strip()
            if normalized.lower() in Config.WEAK_SECRET_VALUES or normalized.upper().startswith(("REPLACE_", "YOUR_")):
                raise ValueError(
                    f"{field} must not be a default or weak value. "
                    f"Set a strong, unique {field} in config.yaml. "
                    'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
                )
            if len(normalized) < 32:
                raise ValueError(
                    f"{field} must be at least 32 characters long "
                    f"(current: {len(secret)}). Use a strong, random secret. "
                    'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
                )
        if self.app.token_hash_key.strip() == self.app.secret_key.strip():
            raise ValueError("token_hash_key must differ from secret_key")
        if self.app.admin_jwt_expiration_hours > self.app.jwt_expiration_hours:
            raise ValueError("Admin sessions must not outlive ordinary sessions")
        if self.app.log_level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("Invalid log_level")
        if self.local.allow_registration:
            raise ValueError("Public local registration is not supported")
        if self.app.environment == "production":
            if self.app.debug or not self.app.secure_cookies:
                raise ValueError("Production requires debug=false and secure_cookies=true")
            if self.oauth.client_id:
                if not all(getattr(self.oauth, field) for field in ("client_secret", "authorize_url", "token_url", "userinfo_url", "redirect_uri")):
                    raise ValueError("Production OAuth requires complete confidential-client configuration")
            elif not self.local.enabled:
                raise ValueError("Production requires an OAuth client or local authentication")
            urls = {"app.api_url": self.app.api_url, **{
                f"oauth.{field}": getattr(self.oauth, field)
                for field in ("authorize_url", "token_url", "userinfo_url", "redirect_uri")
            }}
            for field, value in urls.items():
                if value:
                    url = urlsplit(value)
                    if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
                        raise ValueError(f"{field} must be an HTTPS URL without credentials or fragments")
            if self.rate_limits.storage_uri.startswith("memory://"):
                raise ValueError("Production requires a shared Redis rate-limit backend")
            if not self.rate_limits.storage_uri.startswith("rediss://"):
                raise ValueError("Production Redis connections require verified TLS (rediss://)")
            redis_options = query_options(self.rate_limits.storage_uri, "rate_limits.storage_uri")
            if redis_options.get("ssl_cert_reqs", "required").lower() != "required" or redis_options.get("ssl_check_hostname", "true").lower() not in {"true", "1"}:
                raise ValueError("Production Redis TLS must verify certificates and hostnames")
            if self.smtp.enabled and self.smtp.username and not (self.smtp.starttls or self.smtp.use_tls):
                raise ValueError("Production SMTP credentials require STARTTLS or TLS")
            if not self.database.url.startswith("postgresql+asyncpg://"):
                raise ValueError("Production requires PostgreSQL with the asyncpg driver")
            database_options = query_options(self.database.url, "database.url")
            if database_options.get("ssl", "verify-full") not in {"verify-full", "verify-ca", "require"}:
                raise ValueError("Production PostgreSQL TLS must not be disabled")
            if not self.database.ssl_ca_file and database_options.get("ssl") != "verify-full":
                raise ValueError("Production PostgreSQL connections require a trusted CA or ssl=verify-full")
            import os
            for peer in os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1").split(","):
                if peer.strip():
                    trusted_network(peer.strip(), "FORWARDED_ALLOW_IPS")
            for peer in self.rate_limits.token_validation_exempt:
                trusted_network(peer, "rate_limits.token_validation_exempt")


def query_options(url: str, field: str) -> dict[str, str]:
    """A URL's query parameters, refusing repeated ones.

    Clients disagree on which copy of a repeated parameter counts (redis-py
    uses the first), so a check of one copy proves nothing about the other.
    """
    options = parse_qs(urlsplit(url).query, keep_blank_values=True)
    repeated = sorted(name for name, values in options.items() if len(values) > 1)
    if repeated:
        raise ValueError(f"{field} must not repeat query parameters ({', '.join(repeated)})")
    return {name: values[0] for name, values in options.items()}


# Narrower than this is a specific proxy or gateway network; wider (such as
# 0.0.0.0/1 plus 128.0.0.0/1) amounts to trusting everyone.
MIN_TRUSTED_PREFIX = {4: 8, 6: 8}


def trusted_network(entry: str, field: str) -> None:
    """Validate a trusted proxy or gateway entry as Uvicorn will read it.

    Uvicorn parses entries strictly: one with host bits set ("10.42.0.7/16")
    silently matches nothing, so every client would share the proxy's
    address and its rate-limit budget.
    """
    try:
        network = ip_network(entry)
    except ValueError:
        raise ValueError(
            f"{field} entries must be IP addresses or networks without host bits, not {entry!r}"
        ) from None
    if network.prefixlen < MIN_TRUSTED_PREFIX[network.version]:
        raise ValueError(f"{field} must name specific proxy or gateway networks, not {entry}")


@lru_cache()
def get_config() -> Config:
    import os
    default_path = Path(__file__).parent.parent / "config.yaml"
    config_path = Path(os.environ.get("CONFIG_PATH", default_path))
    if config_path.exists():
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{config_path} must contain a mapping of configuration sections")
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
    database_ssl_ca_file = os.environ.get("DATABASE_SSL_CA_FILE")
    if database_ssl_ca_file:
        config.database.ssl_ca_file = database_ssl_ca_file

    rate_limit_storage_uri = os.environ.get("RATE_LIMIT_STORAGE_URI")
    if rate_limit_storage_uri:
        config.rate_limits.storage_uri = rate_limit_storage_uri

    token_hash_key = os.environ.get("TOKEN_HASH_KEY")
    if token_hash_key:
        config.app.token_hash_key = token_hash_key

    oauth_client_secret = os.environ.get("OAUTH_CLIENT_SECRET")
    if oauth_client_secret:
        config.oauth.client_secret = oauth_client_secret

    smtp_password = os.environ.get("SMTP_PASSWORD")
    if smtp_password:
        config.smtp.password = smtp_password

    environment = os.environ.get("APP_ENVIRONMENT")
    if environment:
        config.app.environment = environment
    config = Config.model_validate(config.model_dump())
    config.validate_security()
    return config
