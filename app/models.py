import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, ForeignKey, Index, Integer, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.sqlite import JSON
from typing import Optional


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        # Local accounts log in by email, so their emails are unique. OAuth
        # accounts are identified by subject; their email is profile data an
        # identity provider may not have verified, so it must not be unique.
        Index(
            "uq_users_local_email", "email", unique=True,
            sqlite_where=text("unity_id IS NULL"),
            postgresql_where=text("unity_id IS NULL"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    unity_id: Mapped[str | None] = mapped_column(String(255), unique=True, index=True, nullable=True)
    email: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(255))
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    # Embedded in session JWTs; bumping it invalidates all existing sessions.
    session_epoch: Mapped[int] = mapped_column(Integer, default=0)

    tokens: Mapped[list["Token"]] = relationship("Token", back_populates="user", cascade="all, delete-orphan")


class Token(Base):
    __tablename__ = "tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="tokens")


class RevokedJWT(Base):
    """Tracks revoked session JWTs (the access_token cookie).

    When a user logs out, their JWT jti is added here so the token
    can't be replayed even if stolen.  Entries are purged once the
    JWT's natural expiry has passed.
    """

    __tablename__ = "revoked_jwts"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    revoked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class DeletedUser(Base):
    """Tombstone for deleted users.

    OAuth login recreates users from provider data, so a plain row
    deletion would silently resurrect the account on next login.
    This table records deletion so re-login is blocked until an
    admin explicitly re-creates the user. It holds keyed hashes of the
    subject and email only (see app/tombstones.py).
    """

    __tablename__ = "deleted_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    unity_id_hash: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    email_hash: Mapped[str] = mapped_column(String(64), index=True)
    deleted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)