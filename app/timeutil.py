"""UTC helpers.

Timestamps are stored as naive UTC datetimes. Anything leaving the service
carries an explicit offset, because browsers parse an ISO string without
one as local time.
"""
from datetime import UTC, datetime
from typing import overload


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


@overload
def isoformat_utc(value: datetime) -> str: ...
@overload
def isoformat_utc(value: None) -> None: ...
def isoformat_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()
