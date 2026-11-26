import pytest
from fastapi import HTTPException
from starlette.requests import Request
from app.api.validate import is_possible_token, validate_token
from app.auth import generate_token
from app.timeutil import utcnow


def make_request() -> Request:
    """Create a minimal Request object for rate-limiter tests."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/auth/validate",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 0),
    }
    return Request(scope)


class TestValidateEndpoint:
    @pytest.mark.asyncio
    async def test_validate_valid_token(self, test_db, test_token):
        response = await validate_token(
            request=make_request(),
            bearer_token=test_token["plain_token"],
            db=test_db
        )

        assert response.valid is True
        assert response.user_id == test_token["token"].user_id
        assert response.email == "test@example.com"
        assert response.email == response.user.email

    @pytest.mark.asyncio
    async def test_validate_invalid_token(self, test_db):
        with pytest.raises(HTTPException) as exc_info:
            await validate_token(
                request=make_request(),
                bearer_token="invalid_token_123",
                db=test_db
            )

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_validate_revoked_token(self, test_db, test_token):
        token = test_token["token"]
        token.revoked_at = utcnow()
        await test_db.commit()

        with pytest.raises(HTTPException) as exc_info:
            await validate_token(
                request=make_request(),
                bearer_token=test_token["plain_token"],
                db=test_db
            )

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_validate_nonexistent_token(self, test_db):
        with pytest.raises(HTTPException) as exc_info:
            await validate_token(
                request=make_request(),
                bearer_token=generate_token(),
                db=test_db
            )

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Token not found or revoked"


class TestMalformedToken:
    """A value generate_token cannot have produced is reported as malformed
    rather than as a revoked token, so a truncated copy is visible."""

    @pytest.mark.parametrize("body", [
        "5" * 63,          # one character short of the default 64
        "5" * 65,          # one character too many
        "z" * 64,          # not hexadecimal
        "5" * 63 + ".",    # a character from the end of a sentence
    ])
    def test_values_this_service_cannot_issue(self, body):
        assert is_possible_token(f"blablador-{body}") is False

    def test_a_shorter_whole_byte_body_is_wellformed(self):
        # token_length_bytes may be lowered (16..127): a shorter token issued
        # then still validates and must not be called malformed.
        assert is_possible_token("blablador-" + "5" * 32) is True

    def test_missing_prefix_is_malformed(self):
        assert is_possible_token("5" * 64) is False

    def test_empty_body_is_malformed(self):
        assert is_possible_token("blablador-") is False

    def test_issued_tokens_are_wellformed(self):
        for _ in range(20):
            assert is_possible_token(generate_token()) is True

    def test_upper_case_hex_is_accepted(self):
        assert is_possible_token("blablador-" + "A" * 64) is True

    @pytest.mark.asyncio
    async def test_truncated_token_says_malformed(self, test_db):
        issued = generate_token()
        with pytest.raises(HTTPException) as exc_info:
            await validate_token(
                request=make_request(),
                bearer_token=issued[:-1],
                db=test_db,
            )

        assert exc_info.value.status_code == 401
        assert "malformed" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_malformed_token_keeps_www_authenticate(self, test_db):
        with pytest.raises(HTTPException) as exc_info:
            await validate_token(
                request=make_request(),
                bearer_token="blablador-" + "5" * 63,
                db=test_db,
            )

        challenge = exc_info.value.headers["WWW-Authenticate"]
        assert challenge.startswith('Bearer error="invalid_token", error_description="This is not a blablador token')
