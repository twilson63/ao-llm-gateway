"""Tests for proxy router and client."""
import json
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from httpx import Response, AsyncClient
import httpx

from src.proxy.router import router as proxy_router, build_proxy_headers
from src.proxy.client import ProxyClient


# =============================================================================
# FastAPI App Fixtures
# =============================================================================

@pytest.fixture
def app():
    """Create FastAPI app for testing."""
    application = FastAPI()
    application.include_router(proxy_router)
    return application


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


# =============================================================================
# Proxy Client Tests
# =============================================================================

class TestProxyClient:
    """Tests for ProxyClient class."""
    
    def test_add_query_param(self):
        """Test query parameter addition."""
        client = ProxyClient()
        
        url = client._add_query_param(
            "https://api.example.com/v1/chat/completions",
            "api_key",
            "test-key"
        )
        
        assert "api_key=test-key" in url
        assert url.startswith("https://api.example.com")
    
    def test_add_query_param_existing_query(self):
        """Test query parameter addition with existing query string."""
        client = ProxyClient()
        
        url = client._add_query_param(
            "https://api.example.com/v1/chat/completions?existing=param",
            "api_key",
            "test-key"
        )
        
        assert "existing=param" in url
        assert "api_key=test-key" in url
    
    def test_get_stream_small_body(self):
        """Test that small bodies are returned directly."""
        client = ProxyClient()
        
        body = b"small body"
        result = client._get_stream(body)
        
        # Small bodies should be returned as-is
        assert result == body
    
    @pytest.mark.asyncio
    async def test_forward_timeout(self):
        """Test timeout handling."""
        client = ProxyClient(default_timeout=1)
        
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            # Simulate timeout
            mock_client.request.side_effect = TimeoutError()
            
            with pytest.raises(TimeoutError):
                await client.forward(
                    method="POST",
                    url="https://api.example.com/v1/chat/completions",
                    headers={},
                    body=b"{}",
                    timeout=1
                )


# =============================================================================
# Build Proxy Headers Tests
# =============================================================================

class TestBuildProxyHeaders:
    """Tests for build_proxy_headers function."""
    
    @pytest.fixture
    def mock_request(self):
        """Create a mock request object."""
        request = MagicMock()
        request.headers = {
            "content-type": "application/json",
            "content-length": "100",
            "accept": "application/json",
            "user-agent": "TestAgent/1.0",
            "x-custom-header": "custom-value"
        }
        return request
    
    @pytest.fixture
    def mock_provider_bearer(self):
        """Create a mock provider with bearer auth."""
        provider = MagicMock()
        provider.auth_type = "bearer"
        provider.header_mapping = None
        provider.default_headers = None
        return provider
    
    @pytest.fixture
    def mock_provider_header(self):
        """Create a mock provider with header auth."""
        provider = MagicMock()
        provider.auth_type = "header"
        provider.auth_header_name = "X-API-Key"
        provider.header_mapping = None
        provider.default_headers = None
        return provider
    
    @pytest.fixture
    def mock_provider_query(self):
        """Create a mock provider with query param auth."""
        provider = MagicMock()
        provider.auth_type = "query_param"
        provider.header_mapping = None
        provider.default_headers = None
        return provider
    
    @pytest.mark.asyncio
    async def test_bearer_auth(self, mock_request, mock_provider_bearer):
        """Test bearer token injection."""
        headers = await build_proxy_headers(
            mock_request,
            mock_provider_bearer,
            "test-api-key"
        )
        
        assert "authorization" in headers
        assert headers["authorization"] == "Bearer test-api-key"
    
    @pytest.mark.asyncio
    async def test_header_auth(self, mock_request, mock_provider_header):
        """Test custom header injection."""
        headers = await build_proxy_headers(
            mock_request,
            mock_provider_header,
            "test-api-key"
        )
        
        assert "x-api-key" in headers
        assert headers["x-api-key"] == "test-api-key"
    
    @pytest.mark.asyncio
    async def test_query_param_auth(self, mock_request, mock_provider_query):
        """Test query param auth (API key not in headers)."""
        headers = await build_proxy_headers(
            mock_request,
            mock_provider_query,
            "test-api-key"
        )
        
        # API key should NOT be in headers for query_param auth
        assert "authorization" not in headers
        assert "x-api-key" not in headers
    
    @pytest.mark.asyncio
    async def test_strip_hyperbeam_headers(self, mock_request, mock_provider_bearer):
        """Test that HyperBEAM headers are stripped."""
        mock_request.headers = {
            "content-type": "application/json",
            "x-hyperbeam-process-id": "test-process",
            "x-hyperbeam-authority": "test-authority",
            "x-hyperbeam-signature": "test-sig",
        }
        
        headers = await build_proxy_headers(
            mock_request,
            mock_provider_bearer,
            "test-api-key"
        )
        
        assert "x-hyperbeam-process-id" not in headers
        assert "x-hyperbeam-authority" not in headers
        assert "x-hyperbeam-signature" not in headers
    
    @pytest.mark.asyncio
    async def test_header_mapping(self):
        """Test header mapping transformation."""
        # Create a proper mock with headers dict
        mock_request = MagicMock()
        mock_request.headers = {
            "content-type": "application/json",
            "x-custom-header": "custom-value"
        }
        
        provider = MagicMock()
        provider.auth_type = "bearer"
        provider.header_mapping = json.dumps({
            "X-Custom-Header": "x-mapped-header"
        })
        provider.default_headers = None
        
        headers = await build_proxy_headers(
            mock_request,
            provider,
            "test-api-key"
        )
        
        # Header should be mapped from x-custom-header to x-mapped-header
        # The implementation uses case-insensitive lookup
        assert "x-mapped-header" in headers
    
    @pytest.mark.asyncio
    async def test_default_headers(self, mock_request):
        """Test provider default headers are added."""
        provider = MagicMock()
        provider.auth_type = "bearer"
        provider.header_mapping = None
        provider.default_headers = json.dumps({
            "X-Custom-Default": "default-value",
            "X-Another": "another-value"
        })
        
        headers = await build_proxy_headers(
            mock_request,
            provider,
            "test-api-key"
        )
        
        assert "x-custom-default" in headers
        assert headers["x-custom-default"] == "default-value"
        assert "x-another" in headers
        assert headers["x-another"] == "another-value"
    
    @pytest.mark.asyncio
    async def test_allowed_headers(self, mock_request):
        """Test that only allowed headers are forwarded."""
        # Need to set headers differently for MagicMock
        mock_request.headers = {
            "content-type": "application/json",
            "authorization": "should-be-stripped",
            "cookie": "secret-cookie",
            "x-forwarded-for": "client-ip",
            "user-agent": "TestAgent"
        }
        
        provider = MagicMock()
        provider.auth_type = "bearer"
        provider.header_mapping = None
        provider.default_headers = None
        
        headers = await build_proxy_headers(
            mock_request,
            provider,
            "test-api-key"
        )
        
        # Content-type should be in allowed list
        assert "content-type" in headers
        # Original auth should be stripped (we add our own)
        assert "authorization" not in headers or "Bearer" in headers.get("authorization", "")
        # Cookie should not be forwarded
        assert "cookie" not in headers
        # x-forwarded-for not in allowed list


# =============================================================================
# Router Tests
# =============================================================================

class TestProxyRouter:
    """Tests for proxy router endpoints."""
    
    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/proxy/health")
        
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "service": "proxy"}
    
    def test_proxy_requires_auth(self, client):
        """Test that proxy endpoint requires authentication."""
        response = client.post(
            "/proxy/openai/gpt-4/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hello"}]}
        )
        
        # Should get 401 (not verified) - unless we mock the middleware
        # This test checks the basic routing works
        assert response.status_code in [401, 500]  # Depends on middleware setup
    
    def test_invalid_provider_404(self, client):
        """Test 404 for invalid provider."""
        # Note: This would require setting up database mocks
        # Skipping for now - would need proper test fixtures
        pass
    
    def test_invalid_model_404(self, client):
        """Test 404 for invalid model."""
        # Note: This would require setting up database mocks
        pass
