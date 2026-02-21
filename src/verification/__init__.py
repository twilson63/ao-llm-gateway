"""Verification module for AO LLM Gateway."""

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
    HyperBeamIdentityMiddleware,
    verify_hyperbeam_identity,
    extract_process_id,
    extract_authority,
    extract_signature,
    extract_timestamp,
    validate_timestamp,
    verify_signature,
    check_access_key,
    register_access_key,
)

__all__ = [
    # signature_base
    "compute_content_digest",
    "build_signature_base",
    "parse_signed_headers",
    # httpsig
    "parse_signature_header",
    "parse_signature_input",
    "verify_rsa_signature",
    "create_test_keypair",
    "generate_test_signature",
    "encode_signature_for_header",
    "register_test_key",
    "get_public_key",
    "register_authority_key",
    "get_public_key_for_authority",
    # middleware
    "HyperBeamIdentityMiddleware",
    "verify_hyperbeam_identity",
    "extract_process_id",
    "extract_authority",
    "extract_signature",
    "extract_timestamp",
    "validate_timestamp",
    "verify_signature",
    "check_access_key",
    "register_access_key",
]
