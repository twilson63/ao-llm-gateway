"""Tests for AO LLM Gateway - Verification Module"""

import pytest
import time
import base64
from src.verification.signature_base import (
    compute_content_digest,
    build_signature_base,
    parse_signed_headers,
)
from src.verification.httpsig import (
    parse_signature_header,
    parse_signature_input,
    verify_rsa_signature,
    create_test_keypair,
    generate_test_signature,
    encode_signature_for_header,
    register_test_key,
    get_public_key,
    register_authority_key,
    get_public_key_for_authority,
)
from src.verification.middleware import (
    validate_timestamp,
    check_access_key,
    register_access_key,
)


class TestSignatureBase:
    """Tests for signature_base module."""
    
    def test_compute_content_digest(self):
        """Test SHA-256 content digest computation."""
        body = b'{"message": "hello"}'
        digest = compute_content_digest(body)
        
        # Should start with sha-256=
        assert digest.startswith("sha-256=")
        
        # Should be valid base64
        b64_part = digest.split("=", 1)[1]
        decoded = base64.b64decode(b64_part)
        assert len(decoded) == 32  # SHA-256 produces 32 bytes
    
    def test_compute_content_digest_empty(self):
        """Test content digest for empty body."""
        body = b''
        digest = compute_content_digest(body)
        
        # sha-256 of empty string
        assert digest == "sha-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    
    def test_build_signature_base(self):
        """Test RFC-9421 signature base construction."""
        base = build_signature_base(
            method="POST",
            authority="gateway.example.com",
            path="/openai/gpt-4o/v1/chat/completions",
            content_type="application/json",
            body=b'{"model": "gpt-4o"}',
            created=1234567890,
            keyid="test-key-1"
        )
        
        # Should contain method
        assert '"@method"' in base
        assert '"POST"' in base
        
        # Should contain authority
        assert '"@authority"' in base
        assert '"gateway.example.com"' in base
        
        # Should contain path
        assert '"@path"' in base
        assert '"/openai/gpt-4o/v1/chat/completions"' in base
        
        # Should contain content-type
        assert '"content-type"' in base
        assert '"application/json"' in base
        
        # Should contain content-digest
        assert '"content-digest"' in base
        assert 'sha-256=' in base
        
        # Should contain params
        assert "created=1234567890" in base
        assert 'keyid="test-key-1"' in base
    
    def test_parse_signed_headers(self):
        """Test parsing Signature-Input header."""
        input_str = 'sig1=("@method" "@authority" "@path");created=1234567890;keyid="test-key"'
        
        parsed = parse_signed_headers(input_str)
        
        assert parsed["name"] == "sig1"
        assert "@method" in parsed["covered_components"]
        assert "@authority" in parsed["covered_components"]
        assert "@path" in parsed["covered_components"]
        assert parsed["params"]["created"] == "1234567890"
        assert parsed["params"]["keyid"] == "test-key"
    
    def test_parse_signed_headers_simple(self):
        """Test parsing simple Signature-Input without params."""
        input_str = 'sig1=("@method" "@authority")'
        
        parsed = parse_signed_headers(input_str)
        
        assert parsed["name"] == "sig1"
        assert "@method" in parsed["covered_components"]
        assert "@authority" in parsed["covered_components"]
        assert parsed["params"] == {}


class TestHTTPSig:
    """Tests for httpsig module."""
    
    def test_parse_signature_header(self):
        """Test parsing Signature header."""
        # Create a test signature
        test_sig = b'\x00\x01\x02\x03\x04\x05'
        b64_sig = base64.b64encode(test_sig).decode('ascii')
        header = f"sig1=:{b64_sig}:"
        
        parsed = parse_signature_header(header)
        
        assert parsed["name"] == "sig1"
        assert parsed["value"] == test_sig
    
    def test_parse_signature_header_invalid(self):
        """Test parsing invalid Signature header."""
        with pytest.raises(ValueError):
            parse_signature_header("invalid-header")
    
    def test_create_test_keypair(self):
        """Test RSA key pair generation."""
        private_pem, public_pem = create_test_keypair()
        
        assert private_pem.startswith("-----BEGIN PRIVATE KEY-----")
        assert public_pem.startswith("-----BEGIN PUBLIC KEY-----")
        
        # Should be valid PEM format
        assert "PRIVATE KEY" in private_pem
        assert "PUBLIC KEY" in public_pem
    
    def test_generate_and_verify_signature(self):
        """Test signature generation and verification."""
        # Generate keypair
        private_pem, public_pem = create_test_keypair()
        
        # Sign a message
        message = b"Test message for signing"
        signature = generate_test_signature(message, private_pem)
        
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Verify the signature
        is_valid = verify_rsa_signature(signature, message, public_pem)
        assert is_valid is True
    
    def test_verify_invalid_signature(self):
        """Test verification with wrong message."""
        private_pem, public_pem = create_test_keypair()
        
        message = b"Original message"
        wrong_message = b"Different message"
        
        signature = generate_test_signature(message, private_pem)
        
        is_valid = verify_rsa_signature(signature, wrong_message, public_pem)
        assert is_valid is False
    
    def test_verify_wrong_key(self):
        """Test verification with wrong public key."""
        private_pem1, public_pem1 = create_test_keypair()
        private_pem2, public_pem2 = create_test_keypair()
        
        message = b"Test message"
        
        signature = generate_test_signature(message, private_pem1)
        
        is_valid = verify_rsa_signature(signature, message, public_pem2)
        assert is_valid is False
    
    def test_encode_signature_for_header(self):
        """Test encoding signature for HTTP header."""
        sig_bytes = b'\x00\x01\x02\x03'
        encoded = encode_signature_for_header(sig_bytes)
        
        assert encoded.startswith(":")
        assert encoded.endswith(":")
        
        # Should be valid base64
        b64_part = encoded[1:-1]
        decoded = base64.b64decode(b64_part)
        assert decoded == sig_bytes
    
    def test_register_and_get_public_key(self):
        """Test key registration and retrieval."""
        _, public_pem = create_test_keypair()
        
        register_test_key("test-key-123", public_pem)
        
        retrieved = get_public_key("test-key-123")
        assert retrieved == public_pem
        
        # Non-existent key should return None
        assert get_public_key("non-existent") is None
    
    def test_register_and_get_authority_key(self):
        """Test authority key registration and retrieval."""
        _, public_pem = create_test_keypair()
        
        authority = "0xABC123DEF456"
        register_authority_key(authority, public_pem)
        
        retrieved = get_public_key_for_authority(authority)
        assert retrieved == public_pem
        
        # Non-existent authority should return None
        assert get_public_key_for_authority("0xNonExistent") is None


class TestMiddleware:
    """Tests for middleware functions."""
    
    def test_validate_timestamp_valid(self):
        """Test timestamp validation with valid timestamp."""
        current = int(time.time())
        
        # Should not raise
        result = validate_timestamp(current, tolerance_seconds=300)
        assert result is True
    
    def test_validate_timestamp_expired(self):
        """Test timestamp validation with expired timestamp."""
        # 10 minutes ago (beyond 5 min tolerance)
        old_timestamp = int(time.time()) - 600
        
        with pytest.raises(Exception) as exc_info:
            validate_timestamp(old_timestamp, tolerance_seconds=300)
        
        assert "expired" in str(exc_info.value).lower()
    
    def test_validate_timestamp_too_far_future(self):
        """Test timestamp validation with future timestamp."""
        # 10 minutes in the future
        future_timestamp = int(time.time()) + 600
        
        with pytest.raises(Exception) as exc_info:
            validate_timestamp(future_timestamp, tolerance_seconds=300)
        
        assert "future" in str(exc_info.value).lower()
    
    def test_check_access_key(self):
        """Test access key lookup."""
        # Register a test key
        _, public_pem = create_test_keypair()
        register_access_key(
            authority="0x1234567890abcdef",
            process_id="process-123",
            key_id="key-123",
            public_key_pem=public_pem
        )
        
        # Should find it
        key = check_access_key("0x1234567890abcdef", "process-123")
        assert key is not None
        assert key["key_id"] == "key-123"
        
        # Wrong authority should not find it
        assert check_access_key("0xwrong", "process-123") is None
    
    def test_check_access_key_disabled(self):
        """Test access key lookup with disabled key."""
        _, public_pem = create_test_keypair()
        
        # Register disabled key
        register_access_key(
            authority="0xdisabled",
            process_id="process-disabled",
            key_id="key-disabled",
            public_key_pem=public_pem,
            is_enabled=False
        )
        
        # Should still find it (but is_enabled=False)
        key = check_access_key("0xdisabled", "process-disabled")
        assert key is not None
        assert key["is_enabled"] is False


class TestRSAPSSAlgorithm:
    """Tests for RSA-PSS-SHA256 algorithm."""
    
    def test_rsa_pss_signature_generation(self):
        """Test RSA-PSS-SHA256 signature generation."""
        private_pem, public_pem = create_test_keypair()
        
        message = b"RSA-PSS test message"
        signature = generate_test_signature(
            message,
            private_pem,
            algorithm="RSA-PSS-SHA256"
        )
        
        is_valid = verify_rsa_signature(
            signature,
            message,
            public_pem,
            algorithm="RSA-PSS-SHA256"
        )
        assert is_valid is True
    
    def test_pkcs1v15_algorithm(self):
        """Test RSASSA-PKCS1-v1_5-SHA256 algorithm."""
        private_pem, public_pem = create_test_keypair()
        
        message = b"PKCS1v15 test message"
        signature = generate_test_signature(
            message,
            private_pem,
            algorithm="RSASSA-PKCS1-v1_5-SHA256"
        )
        
        is_valid = verify_rsa_signature(
            signature,
            message,
            public_pem,
            algorithm="RSASSA-PKCS1-v1_5-SHA256"
        )
        assert is_valid is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
