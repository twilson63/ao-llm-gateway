"""Password hashing and encryption utilities for secure credential storage."""
import base64
import os
from typing import Optional

import bcrypt
from cryptography.fernet import Fernet

from src.config import get_settings

settings = get_settings()


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        Hashed password string
    """
    # Ensure password is bytes
    password_bytes = password.encode('utf-8')
    # Generate salt and hash
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hash.
    
    Args:
        plain_password: Plain text password to verify
        hashed_password: Stored hash to verify against
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        password_bytes = plain_password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        return False


def generate_encryption_key() -> str:
    """
    Generate a new Fernet encryption key.
    
    Returns:
        Base64-encoded encryption key
    """
    return Fernet.generate_key().decode()


def _get_fernet() -> Fernet:
    """
    Get a Fernet cipher instance using the configured encryption key.
    
    Returns:
        Fernet cipher instance
    """
    import hashlib
    
    # Ensure key is properly formatted for Fernet (must be base64-encoded 32 bytes)
    key = settings.encryption_key
    if isinstance(key, str):
        key_bytes = key.encode()
    else:
        key_bytes = key
    
    # If key is not valid, generate a proper key from a hash
    try:
        # Try to use as-is if it's valid base64
        fernet = Fernet(key_bytes if isinstance(key_bytes, bytes) else key_bytes)
    except Exception:
        # Generate a proper key from the input using SHA256
        key_hash = hashlib.sha256(key_bytes).digest()
        fernet = Fernet(base64.urlsafe_b64encode(key_hash))
    
    return fernet


def encrypt_api_key(api_key: str) -> str:
    """
    Encrypt an API key for storage.
    
    Args:
        api_key: Plain text API key to encrypt
        
    Returns:
        Base64-encoded encrypted string
    """
    fernet = _get_fernet()
    encrypted = fernet.encrypt(api_key.encode())
    return base64.urlsafe_b64encode(encrypted).decode()


def decrypt_api_key(encrypted_key: str) -> Optional[str]:
    """
    Decrypt an API key from storage.
    
    Args:
        encrypted_key: Base64-encoded encrypted API key
        
    Returns:
        Decrypted plain text API key, or None if decryption fails
    """
    try:
        # Decode from base64
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_key.encode())
        fernet = _get_fernet()
        decrypted = fernet.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception:
        return None
