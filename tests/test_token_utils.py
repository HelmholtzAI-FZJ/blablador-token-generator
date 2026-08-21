import pytest
from app.auth import hash_token, generate_token


class TestTokenUtils:
    def test_generate_token(self):
        token1 = generate_token()
        token2 = generate_token()

        assert len(token1) == 74
        assert len(token2) == 74
        assert token1 != token2

    def test_generate_token_has_prefix(self):
        token = generate_token()
        assert token.startswith("blablador-")

    def test_hash_token(self):
        token = "test_token_value"
        hashed = hash_token(token)

        assert len(hashed) == 64
        assert hashed == hash_token(token)
        assert hashed != hash_token("different_token")

    def test_hash_is_sha256(self):
        import hashlib
        token = "test_token_value"
        expected = hashlib.sha256(token.encode()).hexdigest()

        assert hash_token(token) == expected