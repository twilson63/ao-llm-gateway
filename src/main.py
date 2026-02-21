"""AO LLM Gateway - Main FastAPI Application"""
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from src.config import get_settings, generate_password_hash
from src.database import init_db
from src.utils.lmdb_store import init_rate_limit_store
from src.middleware.rate_limit import RateLimitMiddleware

settings = get_settings()

from src.admin.router import router as admin_router
from src.auth.router import router as auth_router
from src.verification.middleware import HyperBeamIdentityMiddleware
from src.proxy.router import router as proxy_router

# Get the base directory
BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(
    title="AO LLM Gateway",
    description="A self-hosted LLM proxy service for AO and HyperBEAM autonomous agents",
    version="1.0.0",
)

# Configure Jinja2 templates
templates = Jinja2Templates(directory=str(BASE_DIR / "src" / "admin" / "templates"))

# Add HyperBEAM identity middleware for signature verification
app.add_middleware(HyperBeamIdentityMiddleware)

# Add rate limiting middleware for proxy endpoints
app.add_middleware(RateLimitMiddleware, default_limit=60, default_window=60)


@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    # Initialize LMDB rate limit store
    init_rate_limit_store("./data/ratelimit.db")
    
    # Initialize database
    init_db()
    
    # Check if admin password needs to be hashed
    # If ADMIN_PASSWORD is set in plain text, hash it
    plain_password = os.getenv("ADMIN_PASSWORD_PLAIN")
    if plain_password:
        # Generate hash and log it (don't store plain password)
        hashed = generate_password_hash(plain_password)
        print(f"\n" + "="*60)
        print(f"Generated bcrypt hash for admin password:")
        print(f"ADMIN_PASSWORD={hashed}")
        print(f"Add this to your .env file and remove ADMIN_PASSWORD_PLAIN")
        print(f"="*60 + "\n")


@app.get("/health")
async def health_check():
    """Health check endpoint - returns service health status."""
    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "service": "ao-llm-gateway",
            "version": "1.0.0"
        }
    )


@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint - verifies service is ready to accept traffic."""
    return JSONResponse(
        status_code=200,
        content={
            "status": "ready",
            "service": "ao-llm-gateway",
            "version": "1.0.0"
        }
    )


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Root endpoint with landing page."""
    return templates.TemplateResponse("landing.html", {"request": request})


# Include routers
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(proxy_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port)
