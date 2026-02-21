"""SQLAlchemy models for AO LLM Gateway."""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, DateTime, Text, Index
from sqlalchemy.orm import relationship

from .database import Base


def generate_uuid() -> str:
    """Generate a UUID string."""
    return str(uuid.uuid4())


class User(Base):
    """Admin user model."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    access_keys = relationship("AccessKey", back_populates="user", cascade="all, delete-orphan")


class AccessKey(Base):
    """Access key for API authentication."""
    __tablename__ = "access_keys"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    key_id = Column(String(36), unique=True, nullable=False, index=True)
    key_secret = Column(String(255), nullable=False)
    authority = Column(String(255), nullable=True)  # HyperBEAM authority (address or domain)
    process_id = Column(String(255), nullable=True)  # AO process ID for request routing
    is_enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", back_populates="access_keys")


class Provider(Base):
    """LLM Provider configuration."""
    __tablename__ = "providers"
    __table_args__ = (
        Index('ix_providers_auth_type', 'auth_type'),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False, unique=True, index=True)
    display_name = Column(String(255), nullable=False)
    base_url = Column(String(500), nullable=False)
    encrypted_api_key = Column(Text, nullable=True)  # Encrypted API key storage
    default_headers = Column(Text, nullable=True)  # JSON string for additional headers
    
    # New fields for flexible endpoint configuration
    endpoint_url = Column(String(500), nullable=False, default="/v1/chat/completions")
    auth_type = Column(String(20), nullable=False, default="bearer")  # "bearer", "header", "query_param"
    auth_header_name = Column(String(50), nullable=True)  # Custom header name for "header" auth
    header_mapping = Column(Text, nullable=True)  # JSON string for header mapping
    request_transform = Column(Text, nullable=True)  # Jinja2 template or JSONata expression
    response_transform = Column(Text, nullable=True)  # Response transformation
    timeout_seconds = Column(Integer, nullable=False, default=60)
    retry_count = Column(Integer, nullable=False, default=3)
    is_enabled = Column(Boolean, default=True, nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    models = relationship("ProviderModel", back_populates="provider", cascade="all, delete-orphan", foreign_keys="ProviderModel.provider_id")


class ProviderModel(Base):
    """Model configuration for a provider."""
    __tablename__ = "provider_models"
    __table_args__ = (
        Index('ix_provider_models_provider_id', 'provider_id'),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    provider_id = Column(String(36), ForeignKey("providers.id", ondelete="CASCADE"), nullable=False)
    model_name = Column(String(100), nullable=False)
    display_name = Column(String(255), nullable=True)
    
    # New fields for model-specific configuration
    endpoint_override = Column(String(200), nullable=True)  # Override provider endpoint for this model
    model_config = Column(Text, nullable=True)  # JSON string for model-specific settings (max_tokens, temperature, etc.)
    
    is_enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    provider = relationship("Provider", back_populates="models", foreign_keys=[provider_id])


class RateLimit(Base):
    """Rate limit configuration per process."""
    __tablename__ = "rate_limits"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    process_id = Column(String(255), unique=True, nullable=False, index=True)
    requests_per_minute = Column(Integer, default=60, nullable=False)
    requests_per_day = Column(Integer, default=10000, nullable=False)
    requests_minute_count = Column(Integer, default=0, nullable=False)
    requests_day_count = Column(Integer, default=0, nullable=False)
    last_minute_reset = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_day_reset = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
