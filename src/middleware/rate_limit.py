"""Rate limiting middleware for proxy endpoints."""
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from src.utils.lmdb_store import get_rate_limit_store


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware for AO process requests."""
    
    def __init__(self, app, default_limit: int = 60, default_window: int = 60):
        super().__init__(app)
        self.default_limit = default_limit
        self.default_window = default_window
    
    async def dispatch(self, request: Request, call_next):
        """Check rate limit for each request."""
        # Skip non-proxy routes
        if not request.url.path.startswith("/"):
            return await call_next(request)
        
        # Skip auth routes (no rate limit on login)
        if request.url.path.startswith("/auth/"):
            return await call_next(request)
        
        # Skip health checks
        if request.url.path in ["/health", "/ready"]:
            return await call_next(request)
        
        # Get process ID from request state (set by verification middleware)
        process_id = getattr(request.state, "process_id", None)
        
        if process_id:
            store = get_rate_limit_store()
            identifier = f"process:{process_id}"
            
            allowed, status = store.check_limit(
                identifier,
                limit=self.default_limit,
                window_seconds=self.default_window
            )
            
            if not allowed:
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error": "Rate limit exceeded",
                        "limit": status["limit"],
                        "remaining": 0,
                        "reset_at": status["reset_at"],
                        "window": self.default_window
                    },
                    headers={
                        "X-RateLimit-Limit": str(status["limit"]),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(status["reset_at"]))
                    }
                )
        
        return await call_next(request)


def add_rate_limit_headers(response, status: dict):
    """Add rate limit headers to response."""
    response.headers["X-RateLimit-Limit"] = str(status["limit"])
    response.headers["X-RateLimit-Remaining"] = str(status["remaining"])
    response.headers["X-RateLimit-Reset"] = str(int(status["reset_at"]))
    return response
