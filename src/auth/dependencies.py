"""Authentication dependencies for protected routes."""
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from src.auth.jwt_handler import verify_token

# Security scheme for bearer token
security = HTTPBearer(auto_error=False)


async def get_current_user(request: Request) -> dict:
    """
    Get the current authenticated user from the JWT token in cookies.
    
    Extracts the JWT from the 'access_token' cookie and verifies it.
    
    Args:
        request: FastAPI request object
        
    Returns:
        User data from the token payload
        
    Raises:
        HTTPException: If token is missing or invalid
    """
    # Try to get token from cookie first
    token = request.cookies.get("access_token")
    
    # If not in cookie, try Authorization header
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove "Bearer " prefix
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify the token
    payload = verify_token(token)
    
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Extract user data from payload
    user_data = payload.get("sub")
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Return user data as a dict
    if isinstance(user_data, dict):
        return user_data
    
    # If it's just a string (like email), create a simple user dict
    return {"email": user_data}


async def require_auth(
    request: Request,
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Dependency that requires authentication for protected routes.
    
    This is a convenience wrapper around get_current_user that can be
    used to explicitly mark routes as requiring authentication.
    
    Args:
        request: FastAPI request object
        current_user: The authenticated user from get_current_user
        
    Returns:
        User data from the verified token
        
    Raises:
        HTTPException: If user is not authenticated
    """
    return current_user


def get_token_from_request(request: Request) -> Optional[str]:
    """
    Extract JWT token from request (cookie or header).
    
    Args:
        request: FastAPI request object
        
    Returns:
        Token string if found, None otherwise
    """
    # Try cookie first
    token = request.cookies.get("access_token")
    
    if token:
        return token
    
    # Try Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:]
    
    return None
