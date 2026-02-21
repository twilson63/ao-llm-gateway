"""AO LLM Gateway - Configuration Management"""
import os
from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Admin Configuration
    admin_email: str = "admin@example.com"
    admin_password: str = ""  # Set via ADMIN_PASSWORD env var - REQUIRED
    secret_key: str = "change-me-in-production"
    
    # Database
    database_url: str = "sqlite:///./data/gateway.db"
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Encryption
    encryption_key: str = "default-32-byte-encryption-key!"
    
    # Rate Limiting
    rate_limit_requests_per_minute: int = 60
    rate_limit_window_minutes: int = 1
    
    # Timestamp tolerance
    timestamp_tolerance_seconds: int = 300
    
    # Algorithm
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # Environment
    environment: str = "development"  # "development" or "production"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
    
    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment.lower() == "production"
    
    @property
    def is_secure(self) -> bool:
        """Check if security settings are properly configured."""
        # Check if default values are still in use
        return (
            self.secret_key != "change-me-in-production" and
            self.admin_password != "" and
            self.admin_password != "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYIbXn8U7dy"
        )


def generate_password_hash(password: str) -> str:
    """Generate a bcrypt hash for a password."""
    import bcrypt
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt).decode('utf-8')


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


def get_settings_uncached() -> Settings:
    """Get settings instance without caching (useful for testing)."""
    return Settings()


# Export a singleton instance for convenience
settings = get_settings()
