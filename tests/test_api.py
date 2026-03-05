import pytest
from fastapi import HTTPException
from app.api.validate import validate_token
from app.models import Token
from app.auth import hash_token, generate_token


class TestValidateEndpoint:
    @pytest.mark.asyncio
    async def test_validate_valid_token(self, test_db, test_token):
        response = await validate_token(bearer_token=test_token["plain_token"], db=test_db)
        
        assert response.valid is True
        assert response.user_id == test_token["token"].user_id
    
    @pytest.mark.asyncio
    async def test_validate_invalid_token(self, test_db):
        with pytest.raises(HTTPException) as exc_info:
            await validate_token(bearer_token="invalid_token_123", db=test_db)
        
        assert exc_info.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_validate_revoked_token(self, test_db, test_token):
        token = test_token["token"]
        from datetime import datetime
        token.revoked_at = datetime.utcnow()
        await test_db.commit()
        
        with pytest.raises(HTTPException) as exc_info:
            await validate_token(bearer_token=test_token["plain_token"], db=test_db)
        
        assert exc_info.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_validate_nonexistent_token(self, test_db):
        with pytest.raises(HTTPException) as exc_info:
            await validate_token(bearer_token="0" * 64, db=test_db)
        
        assert exc_info.value.status_code == 401