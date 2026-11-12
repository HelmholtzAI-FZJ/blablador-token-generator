import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, CheckConstraint, ForeignKey, Index, Integer, UniqueConstraint, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from typing import Optional

from app.timeutil import utcnow


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
    # Whether the email was verified when last signing in; only then may it
    # claim application invitations sent to that address.
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # Embedded in session JWTs; bumping it invalidates all existing sessions.
    session_epoch: Mapped[int] = mapped_column(Integer, default=0)

    tokens: Mapped[list["Token"]] = relationship(
        "Token", back_populates="user", cascade="all, delete-orphan", foreign_keys="Token.user_id"
    )
    memberships: Mapped[list["ApplicationMember"]] = relationship(
        "ApplicationMember", back_populates="user", passive_deletes=True
    )


class Application(Base):
    """A service or program that authenticates with its own tokens.

    Owners manage its people and may delete it; members manage its tokens.
    An application whose last owner left is orphaned until an admin takes
    it over.
    """

    __tablename__ = "applications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    orphaned_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, index=True)

    members: Mapped[list["ApplicationMember"]] = relationship(
        "ApplicationMember", back_populates="application", cascade="all, delete-orphan"
    )
    tokens: Mapped[list["Token"]] = relationship(
        "Token", back_populates="application", cascade="all, delete-orphan"
    )


ROLE_OWNER = "owner"
ROLE_MEMBER = "member"


class ApplicationMember(Base):
    """A person's role in an application.

    Added by email; user_id stays empty (an invitation) until someone with
    that verified email signs in.
    """

    __tablename__ = "application_members"
    __table_args__ = (
        UniqueConstraint("application_id", "email", name="uq_application_members_email"),
        UniqueConstraint("application_id", "user_id", name="uq_application_members_user"),
        CheckConstraint("role IN ('owner', 'member')", name="ck_application_members_role"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    application_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=True
    )
    email: Mapped[str] = mapped_column(String(255), index=True)
    role: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    application: Mapped["Application"] = relationship("Application", back_populates="members")
    user: Mapped[Optional["User"]] = relationship("User", back_populates="memberships")


class Token(Base):
    """A personal token (user_id) or an application token (application_id)."""

    __tablename__ = "tokens"
    __table_args__ = (
        CheckConstraint("(user_id IS NULL) <> (application_id IS NULL)", name="ck_tokens_owner"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=True
    )
    application_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=True
    )
    # Who created an application token; it outlives their membership.
    created_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL", name="fk_tokens_created_by_id"),
        index=True, nullable=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    user: Mapped[Optional["User"]] = relationship("User", back_populates="tokens", foreign_keys=[user_id])
    application: Mapped[Optional["Application"]] = relationship("Application", back_populates="tokens")
    created_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[created_by_id])

    @property
    def reported_user(self) -> Optional["User"]:
        """The person validation reports: the owner, or an application
        token's creator while their account exists."""
        return self.user or self.created_by


class RevokedJWT(Base):
    """Tracks revoked session JWTs (the access_token cookie).

    When a user logs out, their JWT jti is added here so the token
    can't be replayed even if stolen.  Entries are purged (on the next
    logout) once the JWT's natural expiry has passed.
    """

    __tablename__ = "revoked_jwts"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    revoked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


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
    deleted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
