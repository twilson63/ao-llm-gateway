"""Proxy router for forwarding requests to LLM providers."""
import json
from typing import Optional
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import StreamingResponse

from src.database import get_db
from src.models import Provider, ProviderModel
from src.proxy.client import ProxyClient
from src.utils.lmdb_store import get_rate_limit_store

router = APIRouter(prefix="/proxy", tags=["proxy"])


async def get_provider_and_model(
    provider_name: str,
    model_name: str,
    db
) -> tuple[Provider, ProviderModel]:
    """Lookup provider and model from database."""
    
    # Find provider
    provider = db.query(Provider).filter(
        Provider.name == provider_name,
        Provider.is_enabled == True
    ).first()
    
    if not provider:
        raise HTTPException(
            status_code=404,
            detail=f"Provider '{provider_name}' not found or disabled"
        )
    
    # Find model
    model = db.query(ProviderModel).filter(
        ProviderModel.provider_id == provider.id,
        ProviderModel.model_name == model_name,
        ProviderModel.is_enabled == True
    ).first()
    
    if not model:
        raise HTTPException(
            status_code=404,
            detail=f"Model '{model_name}' not supported by provider '{provider_name}'"
        )
    
    return provider, model


async def check_rate_limit(
    process_id: str,
    provider_id: int,
    provider_limit: int = None
) -> None:
    """Check rate limit for process+provider combination."""
    
    store = get_rate_limit_store()
    identifier = f"process:{process_id}:provider:{provider_id}"
    
    # Get limit from config or use default
    limit = provider_limit or 60  # default: 60/min
    
    allowed, status = store.check_limit(
        identifier,
        limit=limit,
        window_seconds=60  # 1 minute window
    )
    
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "limit": status["limit"],
                "reset_at": status["reset_at"]
            },
            headers={
                "X-RateLimit-Limit": str(status["limit"]),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(status["reset_at"]))
            }
        )


@router.api_route(
    "/{provider_name}/{model_name}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"]
)
async def proxy_request(
    request: Request,
    provider_name: str,
    model_name: str,
    path: str = "",
    db = Depends(get_db)
):
    """Proxy request to LLM provider with verification.
    
    URL format: /{provider_name}/{model_name}/{api_endpoint}
    
    Examples:
    - /openai/gpt-4/v1/chat/completions
    - /anthropic/claude-3-opus/v1/messages
    - /ollama/llama3.1/v1/chat/completions
    """
    
    # Get process_id from request state (set by middleware)
    process_id = getattr(request.state, "process_id", None)
    if not process_id:
        raise HTTPException(
            status_code=401,
            detail="Request not verified. Missing HyperBEAM signature verification."
        )
    
    # Get provider and model
    provider, model = await get_provider_and_model(provider_name, model_name, db)
    
    # Check rate limit
    await check_rate_limit(process_id, provider.id, getattr(provider, 'rate_limit', None))
    
    # Build target URL
    endpoint = model.endpoint_override or provider.endpoint_path
    if not endpoint.startswith('/'):
        endpoint = '/' + endpoint
    
    if path:
        endpoint = endpoint.rstrip('/') + '/' + path
    
    target_url = f"{provider.base_url}{endpoint}"
    
    # Decrypt API key
    from src.utils.encryption import decrypt_api_key
    api_key = decrypt_api_key(provider.api_key_encrypted)
    
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="API key decryption failed"
        )
    
    # Build headers
    headers = await build_proxy_headers(request, provider, api_key)
    
    # Get request body - try to use stored body from middleware first
    body = getattr(request.state, "body", None)
    if body is None:
        body = await request.body()
    
    # Forward request
    client = ProxyClient()
    try:
        response = await client.forward(
            method=request.method,
            url=target_url,
            headers=headers,
            body=body or b"",
            timeout=provider.timeout_seconds,
            api_key=api_key,
            auth_type=provider.auth_type
        )
        
        # Return streaming response
        return StreamingResponse(
            response.aiter_bytes(),
            status_code=response.status_code,
            headers={
                k: v for k, v in response.headers.items()
                if k.lower() not in ['transfer-encoding', 'content-encoding']
            },
            media_type=response.headers.get('content-type', 'application/json')
        )
        
    except TimeoutError:
        raise HTTPException(status_code=504, detail="Gateway timeout")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Provider error: {str(e)}")


async def build_proxy_headers(
    request: Request,
    provider: Provider,
    api_key: str
) -> dict:
    """Build headers for forwarded request.
    
    Steps:
    1. Copy all headers from incoming request
    2. Apply header_mapping (rename headers per provider config)
    3. Filter to allowed headers (with mapped headers included)
    4. Strip HyperBEAM headers
    5. Inject API key per auth_type
    6. Add provider default_headers
    """
    
    # Start with all headers from original request (will filter later)
    # Use lowercase keys throughout for consistency
    all_headers = {k.lower(): v for k, v in request.headers.items()}
    
    # Apply header mapping (rename headers per provider config)
    # This happens BEFORE filtering to allowed headers
    # Collect target header names to include them in allowed list
    mapped_target_headers = set()
    if provider.header_mapping:
        try:
            header_mapping = json.loads(provider.header_mapping)
            for source, target in header_mapping.items():
                source_lower = source.lower()
                target_lower = target.lower()
                if source_lower in all_headers:
                    all_headers[target_lower] = all_headers.pop(source_lower)
                    mapped_target_headers.add(target_lower)
        except json.JSONDecodeError:
            pass  # Skip header mapping if invalid JSON
    
    # Now filter to allowed headers (including any mapped target headers)
    allowed_headers = {
        "content-type",
        "content-length",
        "accept",
        "accept-encoding",
        "accept-language",
        "cache-control",
        "connection",
        "user-agent",
        "x-request-id"
    }
    # Include mapped target headers in the allowed set
    allowed_headers.update(mapped_target_headers)
    
    headers = {
        k: v for k, v in all_headers.items()
        if k in allowed_headers
    }
    
    # Strip HyperBEAM authentication headers (not for provider)
    headers.pop("x-hyperbeam-process-id", None)
    headers.pop("x-hyperbeam-authority", None)
    headers.pop("x-hyperbeam-signature", None)
    headers.pop("x-hyperbeam-timestamp", None)
    headers.pop("x-hyperbeam-signature-input", None)
    
    # Inject API key based on auth_type
    if provider.auth_type == "bearer":
        headers["authorization"] = f"Bearer {api_key}"
    elif provider.auth_type == "header":
        header_name = provider.auth_header_name or "X-API-Key"
        headers[header_name.lower()] = api_key
    elif provider.auth_type == "query_param":
        # API key will be added to URL query string
        pass  # Handled by ProxyClient
    
    # Add provider default headers
    if provider.default_headers:
        try:
            default_headers = json.loads(provider.default_headers)
            headers.update({
                k.lower(): v for k, v in default_headers.items()
            })
        except json.JSONDecodeError:
            pass  # Skip default headers if invalid JSON
    
    return headers


@router.get("/health")
async def proxy_health():
    """Health check for proxy service."""
    return {"status": "ok", "service": "proxy"}
