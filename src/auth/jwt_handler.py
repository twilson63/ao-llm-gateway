"""JWT token handling for admin authentication."""
from datetime import datetime, timedelta
from typing import Any, Optional

from jose import JWTError, jwt
from src.config import get_settings

settings = get_settings()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Payload data to encode in the token
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()
    
    # Ensure 'sub' is a string (python-jose requirement)
    if "sub" in to_encode and isinstance(to_encode["sub"], dict):
        # Convert dict to JSON string for storage
        import json
        to_encode["sub"] = json.dumps(to_encode["sub"])
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.secret_key,
        algorithm=settings.algorithm
    )
    
    return encoded_jwt


def verify_token(token: str) -> Optional[dict[str, Any]]:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token string to verify
        
    Returns:
        Decoded token payload if valid, None if invalid
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )
        
        # Convert 'sub' back to dict if it's a JSON string
        if payload.get("sub") and isinstance(payload["sub"], str):
            import json
            try:
                payload["sub"] = json.loads(payload["sub"])
            except json.JSONDecodeError:
                pass  # Keep as string if not valid JSON
        
        return payload
    except JWTError:
        return None


def decode_token(token: str) -> Optional[dict[str, Any]]:
    """
    Decode a JWT token without verification (for inspection).
    
    Args:
        token: JWT token string to decode
        
    Returns:
        Decoded token payload or None if invalid format
    """
    try:
        # Decode without verification - useful for debugging
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm],
            options={"verify_signature": False}
        )
        return payload
    except JWTError:
        return None
