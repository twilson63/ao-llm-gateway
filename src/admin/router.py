"""Admin router for AO LLM Gateway."""
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel

from src.auth.dependencies import get_current_user
from src.database import get_db
from src.models import AccessKey, Provider, ProviderModel
from src.utils.encryption import encrypt_api_key as encrypt_key

# Initialize templates - use absolute path
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "admin" / "templates"))

router = APIRouter(prefix="/admin", tags=["admin"])


# ==================== Login ====================

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render login page."""
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login")
async def login(
    request: Request,
    response: Response,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Handle login form submission."""
    from src.config import get_settings
    from src.auth.jwt_handler import create_access_token
    from src.utils.encryption import verify_password
    from datetime import timedelta
    
    settings = get_settings()
    
    # Verify credentials
    if email != settings.admin_email:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid credentials"
        })
    
    if not verify_password(password, settings.admin_password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid credentials"
        })
    
    # Create JWT token
    token_data = {
        "sub": {"email": settings.admin_email, "role": "admin"}
    }
    
    access_token = create_access_token(
        token_data,
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes)
    )
    
    # Set cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=settings.access_token_expire_minutes * 60
    )
    
    response.headers["Location"] = "/admin/dashboard"
    return response(status_code=302)


# ==================== Dashboard ====================

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Render dashboard page with stats."""
    # Get stats
    try:
        total_keys = db.query(AccessKey).count()
        active_keys = db.query(AccessKey).filter(AccessKey.is_enabled == True).count()
        total_providers = db.query(Provider).count()
        enabled_providers = db.query(Provider).filter(Provider.is_enabled == True).count()
        
        # Get recent keys - convert to dicts to avoid SQLAlchemy template issues
        recent_keys_raw = db.query(AccessKey).order_by(AccessKey.created_at.desc()).limit(5).all()
        recent_keys = []
        for k in recent_keys_raw:
            recent_keys.append({
                "key_id": str(k.key_id)[:8] if k.key_id else "",
                "authority": k.authority,
                "process_id": k.process_id,
                "is_enabled": k.is_enabled,
                "created_at": k.created_at.strftime('%Y-%m-%d') if k.created_at else ""
            })
        
        stats = {
            "total_keys": total_keys,
            "active_keys": active_keys,
            "total_providers": total_providers,
            "enabled_providers": enabled_providers
        }
    except Exception as e:
        # Fallback if DB queries fail
        stats = {"total_keys": 0, "active_keys": 0, "total_providers": 0, "enabled_providers": 0}
        recent_keys = []
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "current_user": current_user,
        "stats": stats,
        "recent_keys": recent_keys
    })


# ==================== Access Keys ====================

class AccessKeyForm(BaseModel):
    authority: Optional[str] = None
    process_id: Optional[str] = None
    is_enabled: bool = True


@router.get("/keys", response_class=HTMLResponse)
async def list_keys(
    request: Request,
    current_user: dict = Depends(get_current_user),
    search: str = "",
    filter_enabled: str = "",
    db: Session = Depends(get_db)
):
    """Render access keys list with optional filtering."""
    query = db.query(AccessKey)
    
    # Apply search filter
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (AccessKey.key_id.ilike(search_term)) |
            (AccessKey.authority.ilike(search_term)) |
            (AccessKey.process_id.ilike(search_term))
        )
    
    # Apply status filter
    if filter_enabled == "true":
        query = query.filter(AccessKey.is_enabled == True)
    elif filter_enabled == "false":
        query = query.filter(AccessKey.is_enabled == False)
    
    keys = query.order_by(AccessKey.created_at.desc()).all()
    
    return templates.TemplateResponse("keys.html", {
        "request": request,
        "current_user": current_user,
        "keys": keys
    })


@router.post("/keys", response_class=HTMLResponse)
async def create_key(
    request: Request,
    current_user: dict = Depends(get_current_user),
    authority: Optional[str] = Form(None),
    process_id: Optional[str] = Form(None),
    is_enabled: bool = Form(True),
    db: Session = Depends(get_db)
):
    """Create a new access key via HTMX."""
    # Generate key credentials
    key_id = str(uuid.uuid4())
    key_secret = f"sk_{uuid.uuid4().hex}{uuid.uuid4().hex}"
    
    # Get user ID from current user (for now, use a default)
    # In production, this would come from the database user record
    user_id = "default-admin"
    
    # Create the access key
    access_key = AccessKey(
        id=str(uuid.uuid4()),
        user_id=user_id,
        key_id=key_id,
        key_secret=key_secret,
        authority=authority,
        process_id=process_id,
        is_enabled=is_enabled
    )
    
    db.add(access_key)
    db.commit()
    db.refresh(access_key)
    
    # Return the new row as HTML
    return templates.TemplateResponse("keys.html", {
        "request": request,
        "current_user": current_user,
        "keys": [access_key]
    })


@router.get("/keys/{key_id}/edit", response_class=HTMLResponse)
async def edit_key_form(
    request: Request,
    key_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Render edit form for a key via HTMX."""
    key = db.query(AccessKey).filter(AccessKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    # Return inline edit form
    return f"""
    <tr id="key-edit-{key.id}" class="bg-gray-50">
        <td colspan="6" class="px-6 py-4">
            <form hx-put="/admin/keys/{key.id}"
                  hx-target="#key-row-{key.id}"
                  hx-swap="outerHTML"
                  class="space-y-4">
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Authority</label>
                        <input type="text" name="authority" value="{key.authority or ''}" 
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Process ID</label>
                        <input type="text" name="process_id" value="{key.process_id or ''}" 
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
                    </div>
                </div>
                <div class="flex items-center justify-between">
                    <div class="flex items-center">
                        <input type="checkbox" name="is_enabled" {'checked' if key.is_enabled else ''} 
                               class="h-4 w-4 text-blue-600 border-gray-300 rounded">
                        <label class="ml-2 block text-sm text-gray-700">Enabled</label>
                    </div>
                    <div class="flex space-x-2">
                        <button type="submit" class="px-3 py-1 bg-blue-600 text-white rounded text-sm">Save</button>
                        <button type="button" 
                                hx-get="/admin/keys/{key.id}/cancel-edit"
                                hx-target="#key-row-{key.id}"
                                hx-swap="outerHTML"
                                class="px-3 py-1 bg-gray-200 text-gray-700 rounded text-sm">Cancel</button>
                    </div>
                </div>
            </form>
        </td>
    </tr>
    """


@router.get("/keys/{key_id}/cancel-edit", response_class=HTMLResponse)
async def cancel_edit_key(
    request: Request,
    key_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cancel edit and show the key row again."""
    key = db.query(AccessKey).filter(AccessKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    return templates.TemplateResponse("partials/key_row.html", {
        "request": request,
        "key": key
    })


@router.put("/keys/{key_id}")
async def update_key(
    request: Request,
    key_id: str,
    current_user: dict = Depends(get_current_user),
    authority: Optional[str] = Form(None),
    process_id: Optional[str] = Form(None),
    is_enabled: bool = Form(True),
    db: Session = Depends(get_db)
):
    """Update an access key via HTMX."""
    key = db.query(AccessKey).filter(AccessKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    key.authority = authority
    key.process_id = process_id
    key.is_enabled = is_enabled
    
    db.commit()
    db.refresh(key)
    
    # Return updated row
    return templates.TemplateResponse("keys.html", {
        "request": request,
        "current_user": current_user,
        "keys": [key]
    })


@router.patch("/keys/{key_id}/toggle")
async def toggle_key(
    request: Request,
    key_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Toggle key enabled/disabled via HTMX."""
    key = db.query(AccessKey).filter(AccessKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    key.is_enabled = not key.is_enabled
    db.commit()
    
    # Return updated row
    return templates.TemplateResponse("keys.html", {
        "request": request,
        "current_user": current_user,
        "keys": [key]
    })


@router.delete("/keys/{key_id}")
async def delete_key(
    request: Request,
    key_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete an access key via HTMX."""
    key = db.query(AccessKey).filter(AccessKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    db.delete(key)
    db.commit()
    
    return ""


# ==================== Providers ====================

@router.get("/providers", response_class=HTMLResponse)
async def list_providers(
    request: Request,
    current_user: dict = Depends(get_current_user),
    search: str = "",
    filter_provider_enabled: str = "",
    db: Session = Depends(get_db)
):
    """Render providers list with optional filtering."""
    query = db.query(Provider)
    
    # Apply search filter
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (Provider.name.ilike(search_term)) |
            (Provider.display_name.ilike(search_term))
        )
    
    # Apply status filter
    if filter_provider_enabled == "true":
        query = query.filter(Provider.is_enabled == True)
    elif filter_provider_enabled == "false":
        query = query.filter(Provider.is_enabled == False)
    
    providers = query.order_by(Provider.created_at.desc()).all()
    
    return templates.TemplateResponse("providers.html", {
        "request": request,
        "current_user": current_user,
        "providers": providers
    })


@router.post("/providers", response_class=HTMLResponse)
async def create_provider(
    request: Request,
    current_user: dict = Depends(get_current_user),
    name: str = Form(...),
    display_name: str = Form(...),
    base_url: str = Form(...),
    endpoint_url: str = Form("/v1/chat/completions"),
    auth_type: str = Form("bearer"),
    auth_header_name: Optional[str] = Form(None),
    api_key: Optional[str] = Form(None),
    timeout_seconds: int = Form(60),
    retry_count: int = Form(3),
    default_headers: Optional[str] = Form(None),
    header_mapping: Optional[str] = Form(None),
    request_transform: Optional[str] = Form(None),
    is_enabled: bool = Form(True),
    db: Session = Depends(get_db)
):
    """Create a new provider via HTMX."""
    # Check if name already exists
    existing = db.query(Provider).filter(Provider.name == name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Provider with this name already exists")
    
    # Encrypt API key if provided
    encrypted_api_key = None
    if api_key:
        encrypted_api_key = encrypt_key(api_key)
    
    # Create the provider
    provider = Provider(
        id=str(uuid.uuid4()),
        name=name,
        display_name=display_name,
        base_url=base_url,
        endpoint_url=endpoint_url,
        auth_type=auth_type,
        auth_header_name=auth_header_name,
        encrypted_api_key=encrypted_api_key,
        timeout_seconds=timeout_seconds,
        retry_count=retry_count,
        default_headers=default_headers,
        header_mapping=header_mapping,
        request_transform=request_transform,
        is_enabled=is_enabled
    )
    
    db.add(provider)
    db.commit()
    db.refresh(provider)
    
    # Return the new row as HTML
    return templates.TemplateResponse("providers.html", {
        "request": request,
        "current_user": current_user,
        "providers": [provider]
    })


@router.get("/providers/{provider_id}/edit", response_class=HTMLResponse)
async def edit_provider_form(
    request: Request,
    provider_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Render edit form for a provider via HTMX."""
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    
    # Return inline edit form with all fields
    return f"""
    <tr id="provider-edit-{provider.id}" class="bg-gray-50">
        <td colspan="7" class="px-6 py-4">
            <form hx-put="/admin/providers/{provider.id}"
                  hx-target="#provider-row-{provider.id}"
                  hx-swap="outerHTML"
                  class="space-y-4">
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Name</label>
                        <input type="text" name="name" value="{provider.name}" 
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Display Name</label>
                        <input type="text" name="display_name" value="{provider.display_name}" 
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Base URL</label>
                        <input type="url" name="base_url" value="{provider.base_url}" 
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Endpoint Path</label>
                        <input type="text" name="endpoint_url" value="{provider.endpoint_url or '/v1/chat/completions'}" 
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Auth Type</label>
                        <select name="auth_type" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
                            <option value="bearer" {'selected' if provider.auth_type == 'bearer' else ''}>Bearer Token</option>
                            <option value="header" {'selected' if provider.auth_type == 'header' else ''}>HTTP Header</option>
                            <option value="query_param" {'selected' if provider.auth_type == 'query_param' else ''}>Query Parameter</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Auth Header Name</label>
                        <input type="text" name="auth_header_name" value="{provider.auth_header_name or ''}" 
                               placeholder="X-API-Key"
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Timeout (seconds)</label>
                        <input type="number" name="timeout_seconds" value="{provider.timeout_seconds or 60}" 
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Retry Count</label>
                        <input type="number" name="retry_count" value="{provider.retry_count or 3}" 
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
                    </div>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700">API Key (leave empty to keep current)</label>
                    <input type="password" name="api_key" placeholder="••••••••" 
                           class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Default Headers (JSON)</label>
                        <textarea name="default_headers" rows="2" 
                                  class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">{provider.default_headers or ''}</textarea>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Header Mapping (JSON)</label>
                        <textarea name="header_mapping" rows="2" 
                                  class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">{provider.header_mapping or ''}</textarea>
                    </div>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700">Request Transform (Jinja2/JSON)</label>
                    <textarea name="request_transform" rows="2" 
                              class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">{provider.request_transform or ''}</textarea>
                </div>
                <div class="flex items-center justify-between">
                    <div class="flex items-center">
                        <input type="checkbox" name="is_enabled" {'checked' if provider.is_enabled else ''} 
                               class="h-4 w-4 text-purple-600 border-gray-300 rounded">
                        <label class="ml-2 block text-sm text-gray-700">Enabled</label>
                    </div>
                    <div class="flex space-x-2">
                        <button type="submit" class="px-3 py-1 bg-purple-600 text-white rounded text-sm">Save</button>
                        <button type="button"
                                hx-post="/admin/providers/{provider.id}/test"
                                hx-target="#edit-test-result-{provider.id}"
                                hx-swap="innerHTML"
                                class="px-3 py-1 bg-blue-600 text-white rounded text-sm">Test</button>
                        <button type="button" 
                                hx-get="/admin/providers/{provider.id}/cancel-edit"
                                hx-target="#provider-row-{provider.id}"
                                hx-swap="outerHTML"
                                class="px-3 py-1 bg-gray-200 text-gray-700 rounded text-sm">Cancel</button>
                    </div>
                </div>
                <div id="edit-test-result-{provider.id}" class="mt-2 text-sm"></div>
            </form>
        </td>
    </tr>
    """


@router.get("/providers/{provider_id}/cancel-edit", response_class=HTMLResponse)
async def cancel_edit_provider(
    request: Request,
    provider_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cancel edit and show the provider row again."""
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    
    return templates.TemplateResponse("providers.html", {
        "request": request,
        "current_user": current_user,
        "providers": [provider]
    })


@router.put("/providers/{provider_id}")
async def update_provider(
    request: Request,
    provider_id: str,
    current_user: dict = Depends(get_current_user),
    name: str = Form(...),
    display_name: str = Form(...),
    base_url: str = Form(...),
    endpoint_url: str = Form("/v1/chat/completions"),
    auth_type: str = Form("bearer"),
    auth_header_name: Optional[str] = Form(None),
    api_key: Optional[str] = Form(None),
    timeout_seconds: int = Form(60),
    retry_count: int = Form(3),
    default_headers: Optional[str] = Form(None),
    header_mapping: Optional[str] = Form(None),
    request_transform: Optional[str] = Form(None),
    is_enabled: bool = Form(True),
    db: Session = Depends(get_db)
):
    """Update a provider via HTMX."""
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    
    # Check name uniqueness (exclude current)
    existing = db.query(Provider).filter(
        Provider.name == name,
        Provider.id != provider_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Provider with this name already exists")
    
    provider.name = name
    provider.display_name = display_name
    provider.base_url = base_url
    provider.endpoint_url = endpoint_url
    provider.auth_type = auth_type
    provider.auth_header_name = auth_header_name
    provider.timeout_seconds = timeout_seconds
    provider.retry_count = retry_count
    provider.default_headers = default_headers
    provider.header_mapping = header_mapping
    provider.request_transform = request_transform
    provider.is_enabled = is_enabled
    
    # Update API key if provided
    if api_key:
        provider.encrypted_api_key = encrypt_key(api_key)
    
    db.commit()
    db.refresh(provider)
    
    # Return updated row
    return templates.TemplateResponse("providers.html", {
        "request": request,
        "current_user": current_user,
        "providers": [provider]
    })


@router.patch("/providers/{provider_id}/toggle")
async def toggle_provider(
    request: Request,
    provider_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Toggle provider enabled/disabled via HTMX."""
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    
    provider.is_enabled = not provider.is_enabled
    db.commit()
    
    # Return updated row
    return templates.TemplateResponse("providers.html", {
        "request": request,
        "current_user": current_user,
        "providers": [provider]
    })


@router.delete("/providers/{provider_id}")
async def delete_provider(
    request: Request,
    provider_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a provider via HTMX."""
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    
    db.delete(provider)
    db.commit()
    
    return ""


@router.post("/providers/{provider_id}/test")
async def test_provider(
    request: Request,
    provider_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Test provider connection."""
    import httpx
    import json
    
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    
    # Get decrypted API key
    from src.utils.encryption import decrypt_api_key
    api_key = None
    if provider.encrypted_api_key:
        api_key = decrypt_api_key(provider.encrypted_api_key)
    
    if not api_key:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "No API key configured"}
        )
    
    # Build the request based on auth type
    headers = {}
    if provider.default_headers:
        try:
            headers.update(json.loads(provider.default_headers))
        except:
            pass
    
    if provider.auth_type == "bearer":
        headers["Authorization"] = f"Bearer {api_key}"
    elif provider.auth_type == "header":
        header_name = provider.auth_header_name or "X-API-Key"
        headers[header_name] = api_key
    elif provider.auth_type == "query_param":
        pass  # Will add as query param below
    
    # Build the URL
    url = provider.base_url.rstrip('/') + (provider.endpoint_url or '/v1/chat/completions')
    
    if provider.auth_type == "query_param":
        separator = '&' if '?' in url else '?'
        url = f"{url}{separator}api_key={api_key}"
    
    # Test request (lightweight - just check connectivity)
    test_payload = {
        "model": "gpt-3.5-turbo",  # Use cheapest model for test
        "messages": [{"role": "user", "content": "test"}],
        "max_tokens": 1
    }
    
    try:
        with httpx.Client(timeout=10) as client:
            response = client.post(url, json=test_payload, headers=headers)
            
        if response.status_code < 400:
            return JSONResponse(content={"success": True, "message": "Connection successful"})
        else:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": f"API returned status {response.status_code}: {response.text[:200]}"}
            )
    except httpx.TimeoutException:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Connection timed out"}
        )
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": f"Connection failed: {str(e)}"}
        )
