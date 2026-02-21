"""Authentication router for admin endpoints."""
import logging
import time
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr

from src.auth.dependencies import get_current_user
from src.auth.jwt_handler import create_access_token, verify_token
from src.config import get_settings
from src.utils.encryption import verify_password
from src.utils.lmdb_store import get_rate_limit_store

settings = get_settings()

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])

# Rate limiting using LMDB for persistence
MAX_LOGIN_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 300  # 5 minutes


def _check_rate_limit(email: str) -> bool:
    """
    Check if the email has exceeded the login attempt rate limit using LMDB.
    
    Args:
        email: Email being used for login
        
    Returns:
        True if within limit, False if exceeded
    """
    store = get_rate_limit_store()
    
    # Use "login" prefix for login attempts
    identifier = f"login:{email}"
    allowed, status = store.check_limit(
        identifier,
        limit=MAX_LOGIN_ATTEMPTS,
        window_seconds=RATE_LIMIT_WINDOW_SECONDS
    )
    
    return allowed


def _get_rate_limit_reset_time(email: str) -> int:
    """Get the time when the rate limit will reset."""
    store = get_rate_limit_store()
    identifier = f"login:{email}"
    _, status = store.check_limit(
        identifier,
        limit=MAX_LOGIN_ATTEMPTS,
        window_seconds=RATE_LIMIT_WINDOW_SECONDS
    )
    
    return int(status["reset_at"])


def _get_cookie_settings() -> dict:
    """
    Get appropriate cookie settings based on environment.
    
    Returns:
        Dictionary of cookie parameters
    """
    # Check if running in production (HTTPS)
    # In production, set secure=True
    is_production = settings.secret_key != "change-me-in-production"
    
    cookie_settings = {
        "httponly": True,
        "samesite": "lax",
        "path": "/",
        "max_age": settings.access_token_expire_minutes * 60,
    }
    
    # Add secure flag in production
    if is_production:
        cookie_settings["secure"] = True
    
    return cookie_settings


class LoginRequest(BaseModel):
    """Request model for login endpoint."""
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    """Response model for successful login."""
    success: bool
    message: str
    user: Optional[dict] = None


class MeResponse(BaseModel):
    """Response model for current user endpoint."""
    email: str
    authenticated: bool


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    response: Response,
    login_data: LoginRequest
):
    """
    Authenticate admin user and return JWT token.
    
    Rate limited to prevent brute force attacks.
    Returns JWT in HTTP-only secure cookie.
    
    Args:
        request: FastAPI request object
        response: FastAPI response object for setting cookies
        login_data: Login credentials
        
    Returns:
        LoginResponse with success status
        
    Raises:
        HTTPException: If credentials are invalid or rate limited
    """
    # Check rate limit
    if not _check_rate_limit(login_data.email):
        logger.warning(f"Rate limit exceeded for email: {login_data.email}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later."
        )
    
    # Verify credentials
    # NEVER log passwords - only log failed attempts with email
    if login_data.email != settings.admin_email:
        logger.warning(f"Failed login attempt for unknown email: {login_data.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Verify password
    if not verify_password(login_data.password, settings.admin_password):
        logger.warning(f"Failed login attempt for email: {login_data.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Create JWT token
    token_data = {
        "sub": {"email": settings.admin_email, "role": "admin"}
    }
    
    access_token = create_access_token(
        token_data,
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes)
    )
    
    # Set cookie with token
    cookie_settings = _get_cookie_settings()
    response.set_cookie(
        key="access_token",
        value=access_token,
        **cookie_settings
    )
    
    logger.info(f"Successful login for admin: {settings.admin_email}")
    
    return LoginResponse(
        success=True,
        message="Login successful",
        user={"email": settings.admin_email, "role": "admin"}
    )


@router.post("/logout")
async def logout(response: Response):
    """
    Logout current user by clearing the authentication cookie.
    
    Args:
        response: FastAPI response object
        
    Returns:
        Success message
    """
    response.delete_cookie(
        key="access_token",
        path="/",
        httponly=True,
        samesite="lax"
    )
    
    return {"success": True, "message": "Logged out successfully"}


@router.get("/me", response_model=MeResponse)
async def get_current_user_info(
    current_user: dict = Depends(get_current_user)
):
    """
    Get current authenticated user information.
    
    Requires valid JWT token in cookie or Authorization header.
    
    Args:
        current_user: Current authenticated user from dependency
        
    Returns:
        User information
    """
    return MeResponse(
        email=current_user.get("email", "unknown"),
        authenticated=True
    )


@router.get("/verify")
async def verify_auth(request: Request):
    """
    Verify if user is authenticated.
    
    Returns authentication status without requiring re-authentication.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Authentication status
    """
    token = request.cookies.get("access_token")
    
    if not token:
        # Try header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
    
    if token:
        payload = verify_token(token)
        if payload:
            return {
                "authenticated": True,
                "user": payload.get("sub")
            }
    
    return {"authenticated": False}
