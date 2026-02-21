"""Tests for admin provider endpoints."""
import uuid
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.database import Base, get_db
from src.models import Provider
from src.config import get_settings
from src.main import app
from src.utils.encryption import encrypt_api_key, decrypt_api_key
from src.auth.dependencies import get_current_user


# ==================== Fixtures ====================

@pytest.fixture(scope="function")
def mock_admin_user():
    """Mock admin user for authentication."""
    return {"email": "admin@example.com", "role": "admin"}


@pytest.fixture(scope="function")
def test_db(mock_admin_user):
    """Create an in-memory SQLite database for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    
    Base.metadata.create_all(bind=engine)
    
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    
    def override_get_db():
        try:
            yield db
        finally:
            pass
    
    # Override both dependencies
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: mock_admin_user
    
    yield db
    
    db.close()
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def test_client(test_db):
    """Create a FastAPI test client with the test database."""
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


@pytest.fixture
def test_provider(test_db):
    """Create a test provider in the database."""
    encrypted_key = encrypt_api_key("sk-test-key-12345")
    
    provider = Provider(
        id=str(uuid.uuid4()),
        name="test-provider",
        display_name="Test Provider",
        base_url="https://api.test.com",
        endpoint_url="/v1/chat/completions",
        auth_type="bearer",
        auth_header_name=None,
        encrypted_api_key=encrypted_key,
        timeout_seconds=60,
        retry_count=3,
        default_headers=None,
        header_mapping=None,
        request_transform=None,
        is_enabled=True
    )
    test_db.add(provider)
    test_db.commit()
    test_db.refresh(provider)
    return provider


# ==================== Tests ====================

class TestProviderList:
    """Tests for GET /admin/providers."""
    
    def test_list_providers_empty(self, test_client, test_db):
        """Test listing providers when none exist."""
        response = test_client.get("/admin/providers")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
    
    def test_list_providers_with_data(self, test_client, test_db, test_provider):
        """Test listing providers with existing data."""
        response = test_client.get("/admin/providers")
        assert response.status_code == 200
        assert "test-provider" in response.text
    
    def test_list_providers_search(self, test_client, test_db, test_provider):
        """Test provider search filtering."""
        response = test_client.get("/admin/providers?search=test")
        assert response.status_code == 200
    
    def test_list_providers_filter_enabled(self, test_client, test_db, test_provider):
        """Test filtering by enabled status."""
        response = test_client.get("/admin/providers?filter_provider_enabled=true")
        assert response.status_code == 200


class TestProviderCreate:
    """Tests for POST /admin/providers."""
    
    def test_create_provider(self, test_client, test_db):
        """Test creating a new provider."""
        response = test_client.post("/admin/providers", data={
            "name": "new-provider",
            "display_name": "New Provider",
            "base_url": "https://api.new.com",
            "endpoint_path": "/v1/chat/completions",
            "auth_type": "bearer",
            "api_key": "sk-new-key",
            "timeout_seconds": 60,
            "retry_count": 3,
            "is_enabled": True
        })
        assert response.status_code == 200
        
        # Verify provider was created in database
        provider = test_db.query(Provider).filter(Provider.name == "new-provider").first()
        assert provider is not None
        assert provider.display_name == "New Provider"
    
    def test_create_provider_encrypts_key(self, test_client, test_db):
        """Test that API key is encrypted on creation."""
        response = test_client.post("/admin/providers", data={
            "name": "encrypted-provider",
            "display_name": "Encrypted Provider",
            "base_url": "https://api.enc.com",
            "endpoint_url": "/v1/chat/completions",
            "auth_type": "bearer",
            "api_key": "sk-secret-key-12345",
            "timeout_seconds": 60,
            "retry_count": 3,
            "is_enabled": True
        })
        
        # Verify encrypted key in database
        provider = test_db.query(Provider).filter(Provider.name == "encrypted-provider").first()
        assert provider.encrypted_api_key is not None
        
        # Verify we can decrypt it back
        decrypted = decrypt_api_key(provider.encrypted_api_key)
        assert decrypted == "sk-secret-key-12345"
    
    def test_create_provider_duplicate_name(self, test_client, test_db, test_provider):
        """Test that creating provider with duplicate name fails."""
        response = test_client.post("/admin/providers", data={
            "name": "test-provider",  # Already exists
            "display_name": "Duplicate",
            "base_url": "https://api.dup.com",
            "endpoint_path": "/v1/chat/completions",
            "auth_type": "bearer",
            "timeout_seconds": 60,
            "retry_count": 3,
            "is_enabled": True
        })
        assert response.status_code == 400


class TestProviderEdit:
    """Tests for GET /admin/providers/{provider_id}/edit."""
    
    def test_edit_provider_form(self, test_client, test_db, test_provider):
        """Test getting provider edit form."""
        response = test_client.get(f"/admin/providers/{test_provider.id}/edit")
        assert response.status_code == 200
        assert "test-provider" in response.text
    
    def test_edit_nonexistent_provider(self, test_client, test_db):
        """Test editing nonexistent provider returns 404."""
        fake_id = str(uuid.uuid4())
        response = test_client.get(f"/admin/providers/{fake_id}/edit")
        assert response.status_code == 404


class TestProviderUpdate:
    """Tests for PUT /admin/providers/{provider_id}."""
    
    def test_update_provider(self, test_client, test_db, test_provider):
        """Test updating a provider."""
        response = test_client.put(f"/admin/providers/{test_provider.id}", data={
            "name": "updated-provider",
            "display_name": "Updated Provider",
            "base_url": "https://api.updated.com",
            "endpoint_path": "/v1/completions",
            "auth_type": "bearer",
            "timeout_seconds": 90,
            "retry_count": 5,
            "is_enabled": False
        })
        assert response.status_code == 200
        
        # Verify update
        test_db.refresh(test_provider)
        assert test_provider.name == "updated-provider"
        assert test_provider.display_name == "Updated Provider"
        assert test_provider.timeout_seconds == 90
    
    def test_update_provider_with_new_key(self, test_client, test_db, test_provider):
        """Test updating provider with new API key."""
        response = test_client.put(f"/admin/providers/{test_provider.id}", data={
            "name": test_provider.name,
            "display_name": test_provider.display_name,
            "base_url": test_provider.base_url,
            "endpoint_url": test_provider.endpoint_url,
            "auth_type": test_provider.auth_type,
            "api_key": "sk-new-key-56789",
            "timeout_seconds": test_provider.timeout_seconds,
            "retry_count": test_provider.retry_count,
            "is_enabled": test_provider.is_enabled
        })
        
        # Verify key was updated
        test_db.refresh(test_provider)
        decrypted = decrypt_api_key(test_provider.encrypted_api_key)
        assert decrypted == "sk-new-key-56789"


class TestProviderDelete:
    """Tests for DELETE /admin/providers/{provider_id}."""
    
    def test_delete_provider(self, test_client, test_db, test_provider):
        """Test deleting a provider."""
        provider_id = test_provider.id
        response = test_client.delete(f"/admin/providers/{provider_id}")
        assert response.status_code == 200
        
        # Verify deletion
        provider = test_db.query(Provider).filter(Provider.id == provider_id).first()
        assert provider is None
    
    def test_delete_nonexistent_provider(self, test_client, test_db):
        """Test deleting nonexistent provider."""
        fake_id = str(uuid.uuid4())
        response = test_client.delete(f"/admin/providers/{fake_id}")
        assert response.status_code == 404


class TestProviderToggle:
    """Tests for PATCH /admin/providers/{provider_id}/toggle."""
    
    def test_toggle_provider(self, test_client, test_db, test_provider):
        """Test toggling provider enabled status."""
        original_status = test_provider.is_enabled
        
        response = test_client.patch(f"/admin/providers/{test_provider.id}/toggle")
        assert response.status_code == 200
        
        # Verify toggle
        test_db.refresh(test_provider)
        assert test_provider.is_enabled != original_status
    
    def test_toggle_provider_twice(self, test_client, test_db, test_provider):
        """Test toggling provider twice returns to original status."""
        original_status = test_provider.is_enabled
        
        # Toggle twice
        test_client.patch(f"/admin/providers/{test_provider.id}/toggle")
        test_client.patch(f"/admin/providers/{test_provider.id}/toggle")
        
        test_db.refresh(test_provider)
        assert test_provider.is_enabled == original_status


class TestProviderEncryption:
    """Tests for API key encryption/decryption."""
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test that encryption/decryption works correctly."""
        original_key = "sk-test-api-key-123456789"
        encrypted = encrypt_api_key(original_key)
        decrypted = decrypt_api_key(encrypted)
        
        assert decrypted == original_key
        assert encrypted != original_key  # Verify it's actually encrypted
    
    def test_encrypted_key_not_plaintext(self, test_client, test_db):
        """Test that stored API key is not plaintext."""
        response = test_client.post("/admin/providers", data={
            "name": "secret-provider",
            "display_name": "Secret Provider",
            "base_url": "https://api.secret.com",
            "endpoint_url": "/v1/chat/completions",
            "auth_type": "bearer",
            "api_key": "sk-very-secret-key",
            "timeout_seconds": 60,
            "retry_count": 3,
            "is_enabled": True
        })
        
        provider = test_db.query(Provider).filter(Provider.name == "secret-provider").first()
        
        # Verify the stored key is encrypted (not plaintext)
        assert provider.encrypted_api_key != "sk-very-secret-key"
        assert "sk-very-secret-key" not in str(provider.encrypted_api_key)
