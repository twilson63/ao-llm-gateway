"""RFC-9421 HTTP Message Signatures - HTTPSig Module"""

import base64
import re
from typing import Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def parse_signature_header(signature_header: str) -> Dict[str, str]:
    """
    Parse the Signature header into component parts.
    
    Args:
        signature_header: The Signature header value (e.g., 'sig1=:base64data:')
        
    Returns:
        Dictionary with:
        - name: Signature identifier (e.g., "sig1")
        - value: Base64-decoded signature bytes
    """
    # Pattern: sig1=:base64-encoded-signature:
    pattern = r'^(\w+)=:(.+):$'
    match = re.match(pattern, signature_header.strip())
    
    if not match:
        raise ValueError(f"Invalid Signature header format: {signature_header}")
    
    name = match.group(1)
    b64_value = match.group(2)
    
    try:
        value = base64.b64decode(b64_value)
    except Exception as e:
        raise ValueError(f"Invalid base64 in signature: {e}")
    
    return {
        "name": name,
        "value": value
    }


def parse_signature_input(signature_input: str) -> Dict[str, Any]:
    """
    Parse the Signature-Input header.
    
    Args:
        signature_input: The Signature-Input header value
        
    Returns:
        Dictionary with:
        - name: Signature identifier
        - covered_components: List of covered component identifiers
        - params: Dictionary of signature parameters (created, keyid, etc.)
    """
    from src.verification.signature_base import parse_signed_headers
    return parse_signed_headers(signature_input)


def verify_rsa_signature(
    signature: bytes,
    message: bytes,
    public_key_pem: str,
    algorithm: str = "RSA-PSS-SHA256"
) -> bool:
    """
    Verify an RSA signature using the specified algorithm.
    
    Args:
        signature: The signature bytes to verify
        message: The message that was signed
        public_key_pem: PEM-encoded public key
        algorithm: Signature algorithm (RSA-PSS-SHA256 or RSASSA-PKCS1-v1_5-SHA256)
        
    Returns:
        True if signature is valid, False otherwise
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend
    
    try:
        # Load the public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # Choose padding based on algorithm
        if algorithm == "RSA-PSS-SHA256":
            # PSS padding with SHA256
            sig_padding = padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            )
        elif algorithm == "RSASSA-PKCS1-v1_5-SHA256":
            # PKCS1v15 padding (legacy)
            sig_padding = padding.PKCS1v15()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Verify the signature
        public_key.verify(
            signature,
            message,
            sig_padding,
            hashes.SHA256()
        )
        
        return True
        
    except Exception as e:
        # Signature verification failed
        return False


def create_test_keypair() -> Tuple[str, str]:
    """
    Generate a test RSA key pair.
    
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Serialize public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem


def generate_test_signature(
    message: bytes,
    private_key_pem: str,
    algorithm: str = "RSA-PSS-SHA256"
) -> bytes:
    """
    Generate a test signature for the given message.
    
    Args:
        message: The message to sign
        private_key_pem: PEM-encoded private key
        algorithm: Signature algorithm to use
        
    Returns:
        Signature bytes
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    # Choose padding based on algorithm
    if algorithm == "RSA-PSS-SHA256":
        sig_padding = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )
    elif algorithm == "RSASSA-PKCS1-v1_5-SHA256":
        sig_padding = padding.PKCS1v15()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    # Sign the message
    signature = private_key.sign(
        message,
        sig_padding,
        hashes.SHA256()
    )
    
    return signature


def encode_signature_for_header(signature: bytes) -> str:
    """
    Encode signature bytes for use in HTTP Signature header.
    
    Args:
        signature: Raw signature bytes
        
    Returns:
        Base64-encoded signature with =: delimiters
    """
    b64_sig = base64.b64encode(signature).decode('ascii')
    return f":{b64_sig}:"


# In-memory test keys registry (MVP)
# In production, this would query AR.IO or a database
TEST_PUBLIC_KEYS: Dict[str, str] = {}

# Authority -> public key mapping for MVP
AUTHORITY_PUBLIC_KEYS: Dict[str, str] = {}


def register_test_key(key_id: str, public_key_pem: str) -> None:
    """Register a test public key."""
    TEST_PUBLIC_KEYS[key_id] = public_key_pem


def get_public_key(key_id: str) -> Optional[str]:
    """Get a registered public key by key_id."""
    return TEST_PUBLIC_KEYS.get(key_id)


def register_authority_key(authority: str, public_key_pem: str) -> None:
    """Register a public key for an authority (wallet address)."""
    AUTHORITY_PUBLIC_KEYS[authority] = public_key_pem


def get_public_key_for_authority(authority: str) -> Optional[str]:
    """
    Get the public key for a given authority (wallet address).
    
    This is an MVP placeholder - in production this would query
    AR.IO or another authoritative source.
    
    Args:
        authority: The wallet address / authority
        
    Returns:
        PEM-encoded RSA public key, or None if not found
    """
    return AUTHORITY_PUBLIC_KEYS.get(authority)
