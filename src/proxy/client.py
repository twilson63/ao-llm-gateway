"""HTTP client for forwarding requests to LLM providers."""
import httpx
from typing import Optional, AsyncIterator
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse


class ProxyClient:
    """Async HTTP client for proxy requests."""
    
    def __init__(self, default_timeout: int = 60):
        self.default_timeout = default_timeout
    
    async def forward(
        self,
        method: str,
        url: str,
        headers: dict,
        body: bytes,
        timeout: int = None,
        api_key: str = None,
        auth_type: str = None
    ) -> httpx.Response:
        """Forward request to target URL.
        
        Args:
            method: HTTP method
            url: Target URL
            headers: Request headers (will be modified)
            body: Request body
            timeout: Request timeout in seconds
            api_key: API key (for query_param auth)
            auth_type: Authentication type
            
        Returns:
            httpx.Response
        """
        
        # Handle query_param auth
        if auth_type == "query_param" and api_key:
            url = self._add_query_param(url, "api_key", api_key)
        
        timeout = timeout or self.default_timeout
        
        # Create client with appropriate timeouts
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=timeout/2),
            follow_redirects=True,
            http2=True  # Enable HTTP/2 if provider supports it
        ) as client:
            
            # Stream request body for large payloads
            stream = self._get_stream(body)
            
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=stream,
                follow_redirects=True
            )
            
            return response
    
    def _add_query_param(self, url: str, key: str, value: str) -> str:
        """Add query parameter to URL."""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[key] = [value]
        new_query = urlencode(query, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    def _get_stream(self, body: bytes) -> Optional[AsyncIterator[bytes]]:
        """Get stream for request body."""
        # For small bodies, just return content directly
        if len(body) < 1024 * 1024:  # < 1MB
            return body
        
        # For large bodies, stream in chunks
        async def iter_body():
            chunk_size = 64 * 1024  # 64KB chunks
            for i in range(0, len(body), chunk_size):
                yield body[i:i + chunk_size]
        
        return iter_body()
    
    async def stream_response(self, response: httpx.Response) -> AsyncIterator[bytes]:
        """Yield response chunks for streaming."""
        async for chunk in response.aiter_bytes():
            yield chunk


class ProviderError(Exception):
    """Error from LLM provider."""
    pass


class ProviderTimeout(ProviderError):
    """Provider timeout."""
    pass
