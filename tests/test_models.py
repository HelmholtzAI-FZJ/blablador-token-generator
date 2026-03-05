import pytest
from app.models import User, Token
from app.auth import hash_token, generate_token
from datetime import datetime


class TestUserModel:
    @pytest.mark.asyncio
    async def test_create_user(self, test_db):
        user = User(
            unity_id="user-123",
            email="user@test.com",
            name="Test User",
            is_admin=False
        )
        test_db.add(user)
        await test_db.commit()
        
        assert user.id is not None
        assert user.unity_id == "user-123"
        assert user.email == "user@test.com"
        assert user.is_admin is False


class TestTokenModel:
    @pytest.mark.asyncio
    async def test_create_token(self, test_db, test_user):
        plain_token = generate_token()
        token = Token(
            user_id=test_user.id,
            token_hash=hash_token(plain_token),
            name="My Token"
        )
        test_db.add(token)
        await test_db.commit()
        
        assert token.id is not None
        assert token.user_id == test_user.id
        assert token.name == "My Token"
        assert token.revoked_at is None
    
    @pytest.mark.asyncio
    async def test_revoke_token(self, test_db, test_token):
        token = test_token["token"]
        assert token.revoked_at is None
        
        token.revoked_at = datetime.utcnow()
        await test_db.commit()
        
        assert token.revoked_at is not None