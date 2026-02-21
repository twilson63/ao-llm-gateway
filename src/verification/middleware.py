"""AO LLM Gateway - Verification Middleware

This module provides the HyperBEAM identity verification middleware
that validates RFC-9421 HTTP Message Signatures.
"""

import time
from typing import Optional
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from src.config import get_settings
from src.verification.signature_base import build_signature_base, compute_content_digest
from src.verification.httpsig import (
    parse_signature_header,
    parse_signature_input,
    verify_rsa_signature,
    get_public_key
)


# In-memory access key storage (MVP - would be database in production)
# Maps (authority, process_id) -> {key_id, public_key_pem, is_enabled}
ACCESS_KEYS: dict = {}


def register_access_key(
    authority: str,
    process_id: str,
    key_id: str,
    public_key_pem: str,
    is_enabled: bool = True
) -> None:
    """Register an access key for an AO process."""
    key = (authority, process_id)
    ACCESS_KEYS[key] = {
        "key_id": key_id,
        "public_key_pem": public_key_pem,
        "is_enabled": is_enabled
    }


def check_access_key(authority: str, process_id: str) -> Optional[dict]:
    """
    Check if access key exists for the given authority/process_id.
    
    Args:
        authority: Wallet address
        process_id: AO process ID
        
    Returns:
        Access key info dict if found, None otherwise
    """
    key = (authority, process_id)
    return ACCESS_KEYS.get(key)


def extract_process_id(request: Request) -> str:
    """Extract process ID from request headers."""
    process_id = request.headers.get("X-HyperBEAM-Process-ID")
    if not process_id:
        raise HTTPException(
            status_code=401,
            detail="Missing X-HyperBEAM-Process-ID header"
        )
    return process_id


def extract_authority(request: Request) -> str:
    """Extract authority (wallet address) from request headers."""
    authority = request.headers.get("X-HyperBEAM-Authority")
    if not authority:
        raise HTTPException(
            status_code=401,
            detail="Missing X-HyperBEAM-Authority header"
        )
    return authority


def extract_signature(request: Request) -> tuple:
    """
    Extract signature and signature-input headers.
    
    Returns:
        Tuple of (signature_value_bytes, signature_input_dict)
    """
    signature_header = request.headers.get("X-HyperBEAM-Signature")
    if not signature_header:
        raise HTTPException(
            status_code=401,
            detail="Missing X-HyperBEAM-Signature header"
        )
    
    signature_input_header = request.headers.get("X-HyperBEAM-Signature-Input")
    if not signature_input_header:
        raise HTTPException(
            status_code=401,
            detail="Missing X-HyperBEAM-Signature-Input header"
        )
    
    # Parse the signature header
    sig_parsed = parse_signature_header(signature_header)
    signature_value = sig_parsed["value"]
    
    # Parse the signature input
    sig_input_parsed = parse_signature_input(signature_input_header)
    
    return signature_value, sig_input_parsed


def extract_timestamp(request: Request) -> int:
    """Extract and validate timestamp from request headers."""
    timestamp_str = request.headers.get("X-HyperBEAM-Timestamp")
    if not timestamp_str:
        raise HTTPException(
            status_code=401,
            detail="Missing X-HyperBEAM-Timestamp header"
        )
    
    try:
        timestamp = int(timestamp_str)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="Invalid timestamp format"
        )
    
    return timestamp


def validate_timestamp(timestamp: int, tolerance_seconds: int = 300) -> bool:
    """
    Validate that timestamp is within tolerance window.
    
    Args:
        timestamp: Unix timestamp from request
        tolerance_seconds: Allowed time window (default 5 minutes)
        
    Returns:
        True if timestamp is valid
        
    Raises:
        HTTPException: If timestamp is expired or too far in future
    """
    current_time = int(time.time())
    time_diff = abs(current_time - timestamp)
    
    if time_diff > tolerance_seconds:
        raise HTTPException(
            status_code=401,
            detail=f"Timestamp expired or too far in future (diff: {time_diff}s)"
        )
    
    return True


async def verify_signature(
    request: Request,
    authority: str,
    process_id: str,
    signature_value: bytes,
    signature_input: dict,
    body: bytes = None
) -> bool:
    """
    Verify the HTTP message signature.
    
    Args:
        request: The FastAPI request object
        authority: Wallet address from headers
        process_id: AO process ID from headers
        signature_value: Decoded signature bytes
        signature_input: Parsed Signature-Input dictionary
        body: Pre-read request body (if None, will read from request)
        
    Returns:
        True if signature is valid
        
    Raises:
        HTTPException: If signature verification fails
    """
    # Look up access key
    access_key = check_access_key(authority, process_id)
    if not access_key:
        raise HTTPException(
            status_code=403,
            detail="Unknown authority or process ID"
        )
    
    if not access_key.get("is_enabled", True):
        raise HTTPException(
            status_code=403,
            detail="Access key is disabled"
        )
    
    # Get the key_id from signature input params
    keyid = signature_input.get("params", {}).get("keyid")
    if not keyid:
        raise HTTPException(
            status_code=401,
            detail="Missing keyid in Signature-Input"
        )
    
    # Verify keyid matches registered key
    if keyid != access_key["key_id"]:
        raise HTTPException(
            status_code=401,
            detail="Key ID mismatch"
        )
    
    # Get public key
    public_key_pem = access_key["public_key_pem"]
    if not public_key_pem:
        raise HTTPException(
            status_code=500,
            detail="Public key not configured for this access key"
        )
    
    # Build the signature base
    method = request.method
    authority_host = request.url.hostname or "localhost"
    if request.url.port:
        authority_host += f":{request.url.port}"
    path = str(request.url.path)
    if request.url.query:
        path += f"?{request.url.query}"
    
    # Get content type and body
    content_type = request.headers.get("content-type", "")
    if body is None:
        body = await request.body()
    
    # Get created timestamp from signature input
    created = signature_input.get("params", {}).get("created")
    if created:
        try:
            created = int(created)
        except (ValueError, TypeError):
            created = None
    
    # Build signature base per RFC-9421
    signature_base = build_signature_base(
        method=method,
        authority=authority_host,
        path=path,
        content_type=content_type,
        body=body,
        created=created,
        keyid=keyid
    )
    
    # Verify the signature
    is_valid = verify_rsa_signature(
        signature=signature_value,
        message=signature_base.encode('utf-8'),
        public_key_pem=public_key_pem,
        algorithm="RSA-PSS-SHA256"
    )
    
    if not is_valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid signature"
        )
    
    return True


class HyperBeamIdentityMiddleware(BaseHTTPMiddleware):
    """
    Middleware to verify HyperBEAM identity using RFC-9421 signatures.
    
    Expects headers:
    - X-HyperBEAM-Process-ID: AO process ID
    - X-HyperBEAM-Authority: Wallet address
    - X-HyperBEAM-Signature: Signature value
    - X-HyperBEAM-Signature-Input: Signature input parameters
    - X-HyperBEAM-Timestamp: Unix timestamp
    
    On success, attaches process_id to request.state.
    """
    
    # Paths that don't require verification
    EXEMPT_PATHS = {
        "/",
        "/health",
        "/ready",
        "/docs",
        "/openapi.json",
        "/admin",
        "/admin/login",
        "/auth",
    }
    
    async def dispatch(self, request: Request, call_next):
        # Skip verification for exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)
        
        # Skip paths that start with /admin or /auth (these handle their own auth)
        if request.url.path.startswith("/admin") or request.url.path.startswith("/auth"):
            return await call_next(request)
        
        try:
            # Extract required headers
            process_id = extract_process_id(request)
            authority = extract_authority(request)
            timestamp = extract_timestamp(request)
            signature_value, signature_input = extract_signature(request)
            
            # Read and store body for downstream use (proxy router)
            # This must be done BEFORE any verification that reads the body
            body = await request.body()
            request.state.body = body
            
            # Validate timestamp
            settings = get_settings()
            validate_timestamp(timestamp, settings.timestamp_tolerance_seconds)
            
            # Verify signature - pass body that was already read
            await verify_signature(
                request,
                authority,
                process_id,
                signature_value,
                signature_input,
                body
            )
            
            # Attach process_id to request state for downstream use
            request.state.process_id = process_id
            request.state.authority = authority
            
        except HTTPException:
            # Re-raise HTTP exceptions (they contain proper error responses)
            raise
        except Exception as e:
            # Unexpected error - return 500
            return JSONResponse(
                status_code=500,
                content={"detail": f"Verification error: {str(e)}"}
            )
        
        return await call_next(request)


async def verify_hyperbeam_identity(request: Request) -> dict:
    """
    Dependency function for verifying HyperBEAM identity.
    
    Can be used as a dependency for specific routes:
    
    @app.post("/proxy/{provider}/{model}")
    async def proxy_handler(
        request: Request,
        identity: dict = Depends(verify_hyperbeam_identity)
    ):
        # identity contains process_id and authority
        ...
    
    Args:
        request: FastAPI request object
        
    Returns:
        Dictionary with process_id and authority
        
    Raises:
        HTTPException: If verification fails
    """
    # Extract required headers
    process_id = extract_process_id(request)
    authority = extract_authority(request)
    timestamp = extract_timestamp(request)
    signature_value, signature_input = extract_signature(request)
    
    # Validate timestamp
    settings = get_settings()
    validate_timestamp(timestamp, settings.timestamp_tolerance_seconds)
    
    # Verify signature
    await verify_signature(
        request,
        authority,
        process_id,
        signature_value,
        signature_input
    )
    
    return {
        "process_id": process_id,
        "authority": authority
    }
