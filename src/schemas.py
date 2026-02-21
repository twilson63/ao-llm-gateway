"""Pydantic schemas for request/response models."""
import json
import re
from datetime import datetime
from typing import Optional, List, Dict, Any

from pydantic import (
    BaseModel, EmailStr, Field, ConfigDict, 
    field_validator, model_validator
)
from pydantic import HttpUrl


# ==================== User Schemas ====================

class UserBase(BaseModel):
    """Base user schema."""
    email: EmailStr


class UserCreate(UserBase):
    """Schema for creating a user."""
    password: str = Field(..., min_length=8)


class UserUpdate(BaseModel):
    """Schema for updating a user."""
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8)
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    """Schema for user response."""
    id: str
    created_at: datetime
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


# ==================== AccessKey Schemas ====================

class AccessKeyBase(BaseModel):
    """Base access key schema."""
    authority: Optional[str] = None
    process_id: Optional[str] = None
    is_enabled: bool = True


class AccessKeyCreate(AccessKeyBase):
    """Schema for creating an access key."""
    pass


class AccessKeyUpdate(BaseModel):
    """Schema for updating an access key."""
    authority: Optional[str] = None
    process_id: Optional[str] = None
    is_enabled: Optional[bool] = None


class AccessKeyResponse(AccessKeyBase):
    """Schema for access key response."""
    id: str
    user_id: str
    key_id: str
    key_secret: str  # Note: Only returned on creation
    created_at: datetime
    updated_at: datetime
    last_used_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AccessKeySecretResponse(BaseModel):
    """Schema for access key secret (only shown on creation)."""
    key_id: str
    key_secret: str
    message: str = "Store this secret securely. It will not be shown again."


# ==================== ProviderModel Schemas ====================

class ProviderModelBase(BaseModel):
    """Base provider model schema."""
    model_name: str = Field(..., min_length=1, max_length=100)
    display_name: Optional[str] = Field(None, max_length=255)
    is_enabled: bool = True


class ProviderModelCreate(ProviderModelBase):
    """Schema for creating a provider model."""
    endpoint_override: Optional[str] = Field(None, max_length=200)
    model_settings: Optional[Dict[str, Any]] = Field(None, description="Model-specific settings")
    
    @field_validator('model_settings')
    @classmethod
    def validate_model_settings(cls, v):
        """Ensure model_settings is valid JSON if provided."""
        if v is not None:
            try:
                json.dumps(v)
            except (TypeError, ValueError) as e:
                raise ValueError(f"Invalid model_settings JSON: {e}")
        return v
    
    def to_model_config(self) -> Optional[Dict[str, Any]]:
        """Compatibility method for model_config."""
        return self.model_settings


class ProviderModelUpdate(BaseModel):
    """Schema for updating a provider model."""
    model_name: Optional[str] = Field(None, min_length=1, max_length=100)
    display_name: Optional[str] = Field(None, max_length=255)
    endpoint_override: Optional[str] = Field(None, max_length=200)
    model_settings: Optional[Dict[str, Any]] = Field(None, description="Model-specific settings")
    is_enabled: Optional[bool] = None
    
    @field_validator('model_settings')
    @classmethod
    def validate_model_settings(cls, v):
        """Ensure model_settings is valid JSON if provided."""
        if v is not None:
            try:
                json.dumps(v)
            except (TypeError, ValueError) as e:
                raise ValueError(f"Invalid model_settings JSON: {e}")
        return v
    
    def to_model_config(self) -> Optional[Dict[str, Any]]:
        """Compatibility method for model_config."""
        return self.model_settings


class ProviderModelResponse(ProviderModelBase):
    """Schema for provider model response."""
    id: str
    provider_id: str
    endpoint_override: Optional[str] = None
    model_settings: Optional[Dict[str, Any]] = Field(None, description="Model-specific settings")
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
    
    @field_validator('model_settings', mode='before')
    @classmethod
    def parse_model_settings(cls, v):
        """Parse model_settings from JSON string if needed."""
        if v is None:
            return None
        if isinstance(v, dict):
            return v
        try:
            return json.loads(v)
        except (TypeError, ValueError):
            return None
    
    def to_model_config(self) -> Optional[Dict[str, Any]]:
        """Compatibility method for model_config."""
        return self.model_settings


class ProviderModelListResponse(BaseModel):
    """Schema for provider model list response."""
    id: str
    model_name: str
    display_name: Optional[str]
    is_enabled: bool
    endpoint_override: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


# ==================== Provider Schemas ====================

class ProviderBase(BaseModel):
    """Base provider schema."""
    name: str = Field(..., min_length=1, max_length=100)
    display_name: str = Field(..., min_length=1, max_length=255)
    base_url: str = Field(..., min_length=1, max_length=500)
    is_enabled: bool = True


class ProviderCreate(ProviderBase):
    """Schema for creating a provider."""
    api_key: Optional[str] = None  # Plain text API key (will be encrypted)
    default_headers: Optional[Dict[str, str]] = None
    endpoint_path: str = Field(default="/v1/chat/completions")
    auth_type: str = Field(default="bearer")
    auth_header_name: Optional[str] = Field(None, max_length=50)
    header_mapping: Optional[Dict[str, str]] = None
    request_transform: Optional[str] = None
    response_transform: Optional[str] = None
    timeout_seconds: int = Field(default=60, ge=1, le=300)
    retry_count: int = Field(default=3, ge=0, le=10)
    models: List[ProviderModelCreate] = Field(default_factory=list)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        """Ensure name is lowercase, alphanumeric with hyphens only."""
        if not re.match(r'^[a-z0-9-]+$', v):
            raise ValueError("Name must be lowercase, alphanumeric with hyphens only")
        return v
    
    @field_validator('endpoint_path')
    @classmethod
    def validate_endpoint_path(cls, v):
        """Ensure endpoint_path starts with /."""
        if not v.startswith('/'):
            raise ValueError("endpoint_path must start with /")
        return v
    
    @field_validator('auth_type')
    @classmethod
    def validate_auth_type(cls, v):
        """Ensure auth_type is valid."""
        valid_types = ["bearer", "header", "query_param"]
        if v not in valid_types:
            raise ValueError(f"auth_type must be one of: {valid_types}")
        return v
    
    @field_validator('header_mapping')
    @classmethod
    def validate_header_mapping(cls, v):
        """Ensure header_mapping keys are valid header names."""
        if v is not None:
            # Basic validation for header names (RFC 7230)
            header_pattern = re.compile(r'^[a-zA-Z][a-zA-Z0-9\-]*$')
            for key in v.keys():
                if not header_pattern.match(key):
                    raise ValueError(f"Invalid header name: {key}")
        return v
    
    @field_validator('default_headers')
    @classmethod
    def validate_default_headers(cls, v):
        """Ensure default_headers keys are valid header names."""
        if v is not None:
            header_pattern = re.compile(r'^[a-zA-Z][a-zA-Z0-9\-]*$')
            for key in v.keys():
                if not header_pattern.match(key):
                    raise ValueError(f"Invalid header name: {key}")
        return v
    
    @model_validator(mode='after')
    def validate_auth_header_name(self):
        """Validate auth_header_name based on auth_type."""
        if self.auth_type == "header" and not self.auth_header_name:
            raise ValueError("auth_header_name is required when auth_type is 'header'")
        if self.auth_type == "bearer" and self.auth_header_name:
            # Clear it since it's ignored for bearer auth
            self.auth_header_name = None
        return self


class ProviderUpdate(BaseModel):
    """Schema for updating a provider."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    display_name: Optional[str] = Field(None, min_length=1, max_length=255)
    base_url: Optional[str] = Field(None, min_length=1, max_length=500)
    api_key: Optional[str] = None  # Empty string = don't change, new value = update
    default_headers: Optional[Dict[str, str]] = None
    endpoint_path: Optional[str] = Field(None)
    auth_type: Optional[str] = None
    auth_header_name: Optional[str] = Field(None, max_length=50)
    header_mapping: Optional[Dict[str, str]] = None
    request_transform: Optional[str] = None
    response_transform: Optional[str] = None
    timeout_seconds: Optional[int] = Field(None, ge=1, le=300)
    retry_count: Optional[int] = Field(None, ge=0, le=10)
    is_enabled: Optional[bool] = None
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        """Ensure name is lowercase, alphanumeric with hyphens only."""
        if v is not None and not re.match(r'^[a-z0-9-]+$', v):
            raise ValueError("Name must be lowercase, alphanumeric with hyphens only")
        return v
    
    @field_validator('endpoint_path')
    @classmethod
    def validate_endpoint_path(cls, v):
        """Ensure endpoint_path starts with /."""
        if v is not None and not v.startswith('/'):
            raise ValueError("endpoint_path must start with /")
        return v
    
    @field_validator('auth_type')
    @classmethod
    def validate_auth_type(cls, v):
        """Ensure auth_type is valid."""
        if v is not None:
            valid_types = ["bearer", "header", "query_param"]
            if v not in valid_types:
                raise ValueError(f"auth_type must be one of: {valid_types}")
        return v
    
    @field_validator('header_mapping')
    @classmethod
    def validate_header_mapping(cls, v):
        """Ensure header_mapping keys are valid header names."""
        if v is not None:
            header_pattern = re.compile(r'^[a-zA-Z][a-zA-Z0-9\-]*$')
            for key in v.keys():
                if not header_pattern.match(key):
                    raise ValueError(f"Invalid header name: {key}")
        return v
    
    @field_validator('default_headers')
    @classmethod
    def validate_default_headers(cls, v):
        """Ensure default_headers keys are valid header names."""
        if v is not None:
            header_pattern = re.compile(r'^[a-zA-Z][a-zA-Z0-9\-]*$')
            for key in v.keys():
                if not header_pattern.match(key):
                    raise ValueError(f"Invalid header name: {key}")
        return v
    
    @model_validator(mode='after')
    def validate_auth_header_name(self):
        """Validate auth_header_name based on auth_type."""
        if self.auth_type == "header" and not self.auth_header_name:
            raise ValueError("auth_header_name is required when auth_type is 'header'")
        return self


class ProviderResponse(ProviderBase):
    """Schema for provider response."""
    id: str
    api_key_masked: Optional[str] = None
    default_headers: Optional[Dict[str, str]] = None
    endpoint_path: str
    auth_type: str
    auth_header_name: Optional[str] = None
    header_mapping: Optional[Dict[str, str]] = None
    request_transform: Optional[str] = None
    response_transform: Optional[str] = None
    timeout_seconds: int
    retry_count: int
    models: List[ProviderModelResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
    
    @field_validator('default_headers', 'header_mapping', mode='before')
    @classmethod
    def parse_json_fields(cls, v):
        """Parse JSON string fields."""
        if v is None:
            return None
        if isinstance(v, dict):
            return v
        try:
            return json.loads(v)
        except (TypeError, ValueError):
            return None


class ProviderListResponse(BaseModel):
    """Schema for provider list response."""
    id: str
    name: str
    display_name: str
    base_url: str
    is_enabled: bool
    auth_type: str

    model_config = ConfigDict(from_attributes=True)


# ==================== RateLimit Schemas ====================

class RateLimitBase(BaseModel):
    """Base rate limit schema."""
    requests_per_minute: int = Field(default=60, ge=1)
    requests_per_day: int = Field(default=10000, ge=1)


class RateLimitCreate(RateLimitBase):
    """Schema for creating a rate limit."""
    process_id: str = Field(..., min_length=1)


class RateLimitUpdate(BaseModel):
    """Schema for updating a rate limit."""
    requests_per_minute: Optional[int] = Field(None, ge=1)
    requests_per_day: Optional[int] = Field(None, ge=1)


class RateLimitResponse(RateLimitBase):
    """Schema for rate limit response."""
    id: str
    process_id: str
    requests_minute_count: int
    requests_day_count: int
    last_minute_reset: datetime
    last_day_reset: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RateLimitCheckResponse(BaseModel):
    """Schema for rate limit check response."""
    allowed: bool
    remaining_minute: int
    remaining_day: int
    process_id: str


# ==================== Utility Schemas ====================

class MessageResponse(BaseModel):
    """Generic message response."""
    message: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    database: str
    timestamp: datetime
