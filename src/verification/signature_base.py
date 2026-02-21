"""RFC-9421 HTTP Message Signatures - Signature Base Construction"""

import hashlib
import base64
from typing import Optional


def compute_content_digest(body: bytes) -> str:
    """
    Compute SHA-256 content digest per RFC-9421.
    
    Args:
        body: Request body bytes
        
    Returns:
        Digest string in format: sha-256=<base64-encoded-hash>
    """
    sha256_hash = hashlib.sha256(body).digest()
    return f"sha-256={base64.b64encode(sha256_hash).decode('ascii')}"


def build_signature_base(
    method: str,
    authority: str,
    path: str,
    content_type: Optional[str] = None,
    body: Optional[bytes] = None,
    created: Optional[int] = None,
    keyid: Optional[str] = None
) -> str:
    """
    Build RFC-9421 signature base string.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        authority: Host header value (e.g., "gateway.example.com")
        path: Request path including query string
        content_type: Content-Type header value
        body: Request body bytes (used to compute content-digest)
        created: Unix timestamp for the 'created' field
        keyid: Key identifier string
        
    Returns:
        RFC-9421 formatted signature base string
    """
    components = ['"@method"', f'"{method}"',
                  '"@authority"', f'"{authority}"',
                  '"@path"', f'"{path}"']
    
    if content_type:
        components.append('"content-type"')
        components.append(f'"{content_type}"')
    
    if body:
        content_digest = compute_content_digest(body)
        components.append('"content-digest"')
        components.append(f'"{content_digest}"')
    
    # Build signature parameters
    params = []
    if created is not None:
        params.append(f"created={created}")
    if keyid:
        params.append(f'keyid="{keyid}"')
    
    # Join components with newlines per RFC-9421
    signature_base = "\n".join(components)
    
    # Add signature parameters if present
    if params:
        signature_base += f"\n;{';'.join(params)}"
    
    return signature_base


def parse_signed_headers(signature_input: str) -> dict:
    """
    Parse Signature-Input header value.
    
    Args:
        signature_input: The Signature-Input header value (e.g., 'sig1=("@method" "@authority" "@path");created=1234567890;keyid="test-key"')
        
    Returns:
        Dictionary with parsed components:
        - name: Signature name (e.g., "sig1")
        - covered_components: List of covered component identifiers
        - params: Dictionary of signature parameters (created, keyid, etc.)
    """
    # Split by = to get name and value
    parts = signature_input.split("=", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid Signature-Input format: {signature_input}")
    
    name = parts[0].strip()
    value = parts[1].strip()
    
    # Find the first semicolon to separate components from params
    # The covered components are by spaces inside quotes and separated
    # e.g., '("@method" "@authority" "@path");created=1234567890;keyid="test-key"'
    # We need to find the closing paren of the covered components list
    
    # Find the semicolon that separates components from params
    # The covered components are inside parentheses
    paren_end = value.find(")")
    if paren_end == -1:
        raise ValueError(f"Invalid Signature-Input format: missing closing paren in {signature_input}")
    
    covered_str = value[1:paren_end]  # Remove outer parentheses
    param_str = value[paren_end + 1:]  # Everything after the closing paren
    
    params = {}
    
    # Parse parameters
    if param_str.strip():
        param_str = param_str.lstrip(";")
        for param in param_str.split(";"):
            param = param.strip()
            if not param:
                continue
            if "=" in param:
                param_name, param_value = param.split("=", 1)
                param_name = param_name.strip()
                param_value = param_value.strip()
                # Remove quotes if present
                if param_value.startswith('"') and param_value.endswith('"'):
                    param_value = param_value[1:-1]
                params[param_name] = param_value
            else:
                params[param] = True
    
    # Parse covered components (they are space-separated, each may have quotes)
    # Each component is either "@name" or "name"
    # Handle quoted strings with spaces inside parentheses
    covered_components = []
    # Split by space but preserve quoted content
    temp_parts = []
    current = ""
    in_quotes = False
    for char in covered_str:
        if char == '"':
            in_quotes = not in_quotes
            current += char
        elif char == " " and not in_quotes:
            if current:
                temp_parts.append(current)
                current = ""
        else:
            current += char
    if current:
        temp_parts.append(current)
    
    for comp in temp_parts:
        comp = comp.strip()
        # Remove surrounding quotes if present
        if comp.startswith('"') and comp.endswith('"'):
            comp = comp[1:-1]
        covered_components.append(comp)
    
    return {
        "name": name,
        "covered_components": covered_components,
        "params": params
    }
