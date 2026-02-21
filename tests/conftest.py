"""Pytest fixtures for auth module testing."""
import json
import pytest
import time
from datetime import timedelta
from typing import Dict, Optional, List
from unittest.mock import MagicMock, patch

import bcrypt
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwt

# Import the modules under test
from src.auth.jwt_handler import create_access_token, verify_token
from src.auth.router import router as auth_router
from src.auth.dependencies import get_current_user
from src.utils.encryption import (
    hash_password, verify_password, 
    encrypt_api_key, decrypt_api_key
)
from src.utils.lmdb_store import get_rate_limit_store, init_rate_limit_store
from src.config import Settings


# =============================================================================
# Test Settings - Override default settings for testing
# =============================================================================

class TestSettings(Settings):
    """Test settings - use test values."""
    admin_email: str = "testadmin@example.com"
    admin_password: str = "$2b$12$F5C.dBK8hL/FWcnPVKMO0uxp8Rf/oHv98BJXvcIT4mCPteNGbIuDO"  # Hash of "testadmin"
    secret_key: str = "test-secret-key-for-testing-only"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    encryption_key: str = "test-32-byte-encryption-key!!"
    environment: str = "development"


@pytest.fixture
def test_settings():
    """Return test settings instance."""
    return TestSettings()


@pytest.fixture
def mock_settings(test_settings):
    """Patch settings in auth modules that import it."""
    with patch("src.auth.jwt_handler.settings", test_settings), \
         patch("src.auth.router.settings", test_settings), \
         patch("src.utils.encryption.settings", test_settings):
        yield test_settings


# =============================================================================
# FastAPI App and Client Fixtures
# =============================================================================

@pytest.fixture
def app(mock_settings):
    """Create FastAPI app for testing."""
    application = FastAPI()
    application.include_router(auth_router)
    return application


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


# =============================================================================
# JWT Token Fixtures
# =============================================================================

@pytest.fixture
def valid_token(mock_settings):
    """Create a valid JWT token."""
    token_data = {
        "sub": {"email": mock_settings.admin_email, "role": "admin"}
    }
    return create_access_token(token_data)


@pytest.fixture
def expired_token(mock_settings):
    """Create an expired JWT token."""
    token_data = {
        "sub": {"email": mock_settings.admin_email, "role": "admin"}
    }
    return create_access_token(token_data, expires_delta=timedelta(seconds=-1))


@pytest.fixture
def valid_token_with_dict_sub(mock_settings):
    """Create a valid JWT token with dict subject."""
    token_data = {
        "sub": {"email": "user@example.com", "role": "admin", "user_id": 123}
    }
    return create_access_token(token_data)


# =============================================================================
# Password Fixtures
# =============================================================================

@pytest.fixture
def sample_password():
    """Sample password for testing."""
    return "testpassword123"


@pytest.fixture
def hashed_sample_password(sample_password):
    """Hash of sample password."""
    return hash_password(sample_password)


@pytest.fixture
def admin_hashed_password():
    """Hash of the test admin password ('testadmin')."""
    # This is bcrypt hash of "testadmin"
    return "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYIbXn8U7dy"


# =============================================================================
# Rate Limiting Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def clean_rate_limit(tmp_path):
    """Clean rate limit storage before each test."""
    # Initialize LMDB store with temp path for tests
    store_path = str(tmp_path / "test_ratelimit.db")
    init_rate_limit_store(store_path)
    yield
    # Cleanup handled by LMDB store


# =============================================================================
# Encryption Fixtures
# =============================================================================

@pytest.fixture
def sample_api_key():
    """Sample API key for encryption testing."""
    return "sk-test-1234567890abcdefghijklmnopqrstuvwxyz"


# =============================================================================
# Provider Test Fixtures
# =============================================================================

@pytest.fixture
def sample_openai_provider():
    """
    Sample OpenAI provider with bearer authentication.
    
    Returns a dict suitable for creating a Provider model or schema.
    """
    return {
        "name": "openai",
        "display_name": "OpenAI",
        "base_url": "https://api.openai.com",
        "endpoint_path": "/v1/chat/completions",
        "auth_type": "bearer",
        "api_key": "sk-openai-test-key-12345",
        "default_headers": {
            "Content-Type": "application/json"
        },
        "header_mapping": {},
        "timeout_seconds": 60,
        "retry_count": 3,
        "is_enabled": True,
        "models": [
            {
                "model_name": "gpt-4",
                "display_name": "GPT-4",
                "model_config": {
                    "max_tokens": 4096,
                    "temperature": 0.7
                }
            },
            {
                "model_name": "gpt-4-turbo",
                "display_name": "GPT-4 Turbo",
                "model_config": {
                    "max_tokens": 128000,
                    "temperature": 0.7
                }
            }
        ]
    }


@pytest.fixture
def sample_anthropic_provider():
    """
    Sample Anthropic provider with custom header authentication.
    
    Returns a dict suitable for creating a Provider model or schema.
    """
    return {
        "name": "anthropic",
        "display_name": "Anthropic",
        "base_url": "https://api.anthropic.com",
        "endpoint_path": "/v1/messages",
        "auth_type": "header",
        "auth_header_name": "x-api-key",
        "api_key": "sk-ant-test-key-67890",
        "default_headers": {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        },
        "header_mapping": {
            "x-api-key": "x-api-key"
        },
        "timeout_seconds": 90,
        "retry_count": 3,
        "is_enabled": True,
        "models": [
            {
                "model_name": "claude-3-opus",
                "display_name": "Claude 3 Opus",
                "model_config": {
                    "max_tokens": 4096,
                    "temperature": 0.7
                }
            },
            {
                "model_name": "claude-3-sonnet",
                "display_name": "Claude 3 Sonnet",
                "model_config": {
                    "max_tokens": 4096,
                    "temperature": 0.7
                }
            }
        ]
    }


@pytest.fixture
def sample_ollama_provider():
    """
    Sample Ollama provider with local endpoint (no API key).
    
    Returns a dict suitable for creating a Provider model or schema.
    """
    return {
        "name": "ollama",
        "display_name": "Ollama (Local)",
        "base_url": "http://localhost:11434",
        "endpoint_path": "/api/chat",
        "auth_type": "query_param",
        "api_key": None,  # No API key for local providers
        "default_headers": {
            "Content-Type": "application/json"
        },
        "header_mapping": {},
        "timeout_seconds": 120,
        "retry_count": 2,
        "is_enabled": True,
        "models": [
            {
                "model_name": "llama2",
                "display_name": "Llama 2",
                "endpoint_override": "/api/chat",
                "model_config": {
                    "temperature": 0.7
                }
            },
            {
                "model_name": "mistral",
                "display_name": "Mistral",
                "endpoint_override": "/api/chat",
                "model_config": {
                    "temperature": 0.7
                }
            }
        ]
    }


@pytest.fixture
def mock_provider_factory(mock_settings):
    """
    Factory fixture for generating test providers with customizable parameters.
    
    Usage:
        provider = mock_provider_factory(auth_type="bearer", name="custom")
    """
    def _create_provider(
        name: str = "test-provider",
        display_name: str = "Test Provider",
        base_url: str = "https://api.example.com",
        endpoint_path: str = "/v1/chat/completions",
        auth_type: str = "bearer",
        auth_header_name: Optional[str] = None,
        api_key: str = "test-key-12345",
        default_headers: Optional[Dict[str, str]] = None,
        header_mapping: Optional[Dict[str, str]] = None,
        timeout_seconds: int = 60,
        retry_count: int = 3,
        is_enabled: bool = True,
        models: Optional[List[Dict]] = None
    ) -> Dict:
        """Create a provider dict with specified parameters."""
        
        # Validate auth_header_name requirement
        if auth_type == "header" and not auth_header_name:
            auth_header_name = "X-API-Key"
        
        if default_headers is None:
            default_headers = {"Content-Type": "application/json"}
        
        if header_mapping is None:
            header_mapping = {}
        
        if models is None:
            models = [
                {
                    "model_name": "test-model",
                    "display_name": "Test Model",
                    "model_config": {"temperature": 0.7}
                }
            ]
        
        return {
            "name": name,
            "display_name": display_name,
            "base_url": base_url,
            "endpoint_path": endpoint_path,
            "auth_type": auth_type,
            "auth_header_name": auth_header_name,
            "api_key": api_key,
            "default_headers": default_headers,
            "header_mapping": header_mapping,
            "timeout_seconds": timeout_seconds,
            "retry_count": retry_count,
            "is_enabled": is_enabled,
            "models": models
        }
    
    return _create_provider


# =============================================================================
# Cookie Helper
# =============================================================================

def set_auth_cookie(response, token):
    """Helper to set auth cookie on response (for testing)."""
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        path="/"
    )
    return response
