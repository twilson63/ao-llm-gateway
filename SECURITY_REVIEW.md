# AO LLM Gateway - Security Code Review Report

**Date:** 2026-02-21
**Reviewer:** AI Code Review
**Scope:** Auth module, Verification module, Encryption utilities

---

## Executive Summary

**Overall Rating:** ✅ SECURE with minor improvements recommended

The AO LLM Gateway codebase demonstrates strong security practices for the MVP phase. Critical security controls are implemented correctly including proper password hashing, JWT handling, and RFC-9421 signature verification. Most findings are minor improvements or suggestions for production hardening.

**Risk Level:** LOW for MVP | MEDIUM for production (see recommendations)

---

## Detailed Findings

### 1. Authentication Module (src/auth/)

#### ✅ SECURE: Password Hashing

**Location:** `src/utils/encryption.py`

**Status:** ✅ Implemented correctly

**Details:**
- Uses `bcrypt` with default salt rounds (adaptive)
- Hash format is standard (`$2b$12$...`)
- Comparison uses constant-time function
- No timing leakage observed

**Code:**
```python
def hash_password(password: str) -> str:
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()  # Uses recommended rounds (10-12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)  # ✅ Constant-time
```

**Recommendation:** None - bcrypt is the industry standard.

---

#### ✅ SECURE: JWT Handling

**Location:** `src/auth/jwt_handler.py`

**Status:** ✅ Implemented correctly

**Details:**
- Uses `python-jose` with cryptographic backends
- Tokens include expiry (configurable)
- Proper payload handling (dict serialization)
- Uses HS256 algorithm (HMAC-SHA256)

**Positive Findings:**
- ✅ Expiry validation present
- ✅ Error handling for malformed tokens
- ✅ No sensitive data in JWT payload
- ✅ Configurable expiry time (default 60 min)

**Minor Recommendation:** Consider RS256 (asymmetric) for multi-node deployments if gateway scales horizontally.

---

#### ✅ SECURE: Session Management

**Location:** `src/auth/router.py`

**Status:** ✅ Implemented correctly

**Cookie Settings:**
```python
cookie_settings = {
    "httponly": True,      # ✅ Prevents XSS access
    "samesite": "lax",     # ✅ CSRF protection
    "path": "/",          # ✅ Scoped correctly
    "max_age": ...,         # ✅ Limited lifetime
}

if is_production:
    cookie_settings["secure"] = True  # ✅ HTTPS-only in prod
```

**Positive Findings:**
- ✅ HttpOnly prevents JavaScript token theft
- ✅ SameSite=Lax prevents CSRF attacks
- ✅ Secure flag for production
- ✅ Proper path scoping
- ✅ Explicit cookie deletion on logout

---

#### ⚠️ IMPROVEMENT: Rate Limiting

**Location:** `src/auth/router.py` lines 50-70

**Status:** ⚠️ Working but not production-ready

**Current Implementation:**
```python
login_attempts: dict[str, list[float]] = {}
```

**Issues:**
1. In-memory storage - resets on restart
2. No persistence across instances
3. Memory can grow unbounded (though cleanup helps)
4. Single-node only

**Recommendation (using LMDB - truly open source):**
```python
# Rate limiting with LMDB (OpenLDAP license - BSD-like)
import lmdb
import time
from pathlib import Path

class RateLimitStore:
    def __init__(self, db_path: str = "./data/ratelimit.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.env = lmdb.open(db_path, map_size=10*1024*1024)  # 10MB
    
    def check_limit(self, identifier: str, limit: int, window: int) -> bool:
        """Check if within rate limit. Returns True if allowed."""
        with self.env.begin(write=True) as txn:
            current_time = time.time()
            key = f"ratelimit:{identifier}".encode()
            
            # Get current count and window start
            data = txn.get(key)
            if data:
                count, window_start = map(float, data.decode().split(","))
                if current_time - window_start > window:
                    # Reset window
                    txn.put(key, f"1,{current_time}".encode())
                    return True
                elif count >= limit:
                    return False
                else:
                    txn.put(key, f"{count + 1},{window_start}".encode())
                    return True
            else:
                # New window
                txn.put(key, f"1,{current_time}".encode())
                return True

# Usage:
# rate_store = RateLimitStore()
# if not rate_store.check_limit(email, MAX_LOGIN_ATTEMPTS, RATE_LIMIT_WINDOW_SECONDS):
#     raise HTTPException(429, ...)
```

**Why LMDB over Redis:**
| Feature | LMDB | Redis (SSPL) |
|---------|------|--------------|
| **License** | ✅ OpenLDAP (BSD-like) | ❌ SSPL (not OSI-approved) |
| **Deployment** | ✅ Embedded (no daemon) | Separate service |
| **Speed** | ✅ Memory-mapped | In-memory |
| **ACID** | ✅ Full transactions | Limited |
| **Persistence** | ✅ Automatic | RDB/AOF |
| **Container** | ✅ Single container | Multi-service |

**Risk Level:** LOW for MVP | MEDIUM for production without persistence

---

#### ⚠️ IMPROVEMENT: Timing Attack on User Enumeration

**Location:** `src/auth/router.py` lines 110-135

**Status:** ⚠️ Information disclosure possible

**Current Code:**
```python
if login_data.email != settings.admin_email:
    raise HTTPException(401, detail="Invalid credentials")
    
if not verify_password(...):
    raise HTTPException(401, detail="Invalid credentials")
```

**Issue:** Same error message is used, BUT response time might differ if email check happens before password hashing. In practice, bcrypt hashing takes most time, so this is minimal, but...

**Recommendation:** Add timing padding or always execute password hash:
```python
from src.utils.encryption import verify_password
def _constant_time_compare(known, provided):
    # Implementation already handles this
    pass

# Both paths should take same time
dummy_hash = "$2b$12$fakehash..."
if login_data.email != settings.admin_email:
    verify_password(login_data.password, dummy_hash)  # Waste time
    raise HTTPException(401, detail="Invalid credentials")
```

**Risk Level:** LOW (bcrypt dominates timing)

---

### 2. Verification Module (src/verification/)

#### ✅ SECURE: RFC-9421 Signature Verification

**Location:** `src/verification/httpsig.py`, `middleware.py`

**Status:** ✅ Implemented correctly

**Positive Findings:**

1. **Signature Base Construction** - Properly builds per RFC-9421:
```python
signature_base = build_signature_base(
    method=method,
    authority=authority_host,
    path=path,
    content_type=content_type,
    body=body,
    created=created,
    keyid=keyid
)
```

2. **Hash Algorithms:**
- ✅ RSA-PSS-SHA256 (recommended)
- ✅ RSASSA-PKCS1-v1_5-SHA256 (supported)
- Uses proper padding from cryptography library

3. **Public Key Handling:**
```python
def verify_rsa_signature(...):
    key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    # ✅ Proper padding and hashing
```

4. **Timestamp Validation:**
```python
time_diff = abs(current_time - timestamp)
if time_diff > tolerance_seconds:  # ✅ Prevents replay
    raise HTTPException(401, ...)
```

---

#### ⚠️ IMPROVEMENT: In-Memory Access Key Storage

**Location:** `src/verification/middleware.py` line 23

**Status:** ⚠️ MVP only - use database in production

**Current:**
```python
ACCESS_KEYS: dict = {}
```

**Recommendation:**
```python
from src.database import SessionLocal
from src.models import AccessKey

def check_access_key(authority: str, process_id: str) -> Optional[dict]:
    db = SessionLocal()
    try:
        key = db.query(AccessKey).filter_by(
            authority=authority,
            process_id=process_id,
            is_enabled=True
        ).first()
        return key if key else None
    finally:
        db.close()
```

**Risk Level:** LOW for MVP | HIGH for production (data loss on restart)

---

#### ⚠️ IMPROVEMENT: Request Body Double-Read

**Location:** `src/verification/middleware.py`

**Issue:** The body is consumed for signature verification.

**Current:**
```python
body = await request.body()
# ... later the proxy needs body again
```

**Problem:** FastAPI's `request.body()` can only be consumed once.

**Solution:** Store in `request.state`:
```python
body = await request.body()
request.state.body = body  # Save for later

# Later in proxy:
body = request.state.body
async with httpx.AsyncClient() as client:
    response = await client.post(
        url,
        content=body,  # ✅ Use saved body
        ...
    )
```

**Risk Level:** MEDIUM - proxy may fail without this fix

---

### 3. Encryption Utilities (src/utils/)

#### ✅ SECURE: API Key Encryption

**Location:** `src/utils/encryption.py`

**Status:** ✅ Implemented correctly

**Details:**
- Uses Fernet (AES-128 in CBC mode with HMAC)
- Proper key derivation from secret
- Base64 encoding for storage

```python
def encrypt_api_key(api_key: str) -> str:
    fernet = _get_fernet()
    encrypted = fernet.encrypt(api_key.encode())
    return base64.urlsafe_b64encode(encrypted).decode()
```

**Security Note:** Fernet uses:
- AES-128-CBC for encryption
- HMAC-SHA256 for authentication
- PKCS7 padding

This is secure for the use case.

---

#### ⚠️ IMPROVEMENT: Encryption Key Handling

**Location:** `src/utils/encryption.py` lines 55-72

**Current Implementation:**
```python
def _get_fernet():
    try:
        fernet = Fernet(key_bytes)
    except Exception:
        # Generate from hash
        key_hash = hashlib.sha256(key_bytes).digest()
        fernet = Fernet(base64.urlsafe_b64encode(key_hash))
```

**Issue:** Falls back to key derivation which might be okay, but better to validate key at startup.

**Recommendation:**
```python
# In config.py startup:
def validate_encryption_key():
    if len(settings.encryption_key) != 32:
        raise ValueError(
            "ENCRYPTION_KEY must be 32 characters "
            "(run: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
        )
    # Test Fernet instantiation
    try:
        Fernet(settings.encryption_key)
    except Exception as e:
        raise ValueError(f"Invalid encryption key: {e}")
```

**Risk Level:** LOW - fallback works but should validate

---

### 4. Configuration (src/config.py)

#### ⚠️ IMPROVEMENT: Secret Key Validation

**Location:** `src/config.py`

**Current:**
```python
secret_key: str = "change-me-in-production"
```

**Issue:** Allows using demo secret in production.

**Recommendation:**
```python
@property
def secret_key_valid(self) -> bool:
    return self.secret_key not in [
        "change-me-in-production",
        "",
        "default-secret"
    ]

# In main.py startup:
if not settings.secret_key_valid:
    logger.error("CRITICAL: Using default SECRET_KEY. Set a strong random key.")
    if settings.is_production:
        raise SystemExit(1)
```

**Risk Level:** HIGH if deployed with default key

---

## Summary of Recommendations

### Critical (Must Fix Before Production)

1. ✅ **Rate Limiting:** Move to Redis
2. ✅ **Access Keys:** Persist to database
3. ✅ **Encryption Key:** Validate format at startup
4. ✅ **Secret Key:** Enforce production-grade secret

### Recommended (Should Fix)

1. 📋 **Request Body:** Save in request.state for proxy
2. 📋 **Timing Attack:** Add constant-time comparisons where critical
3. 📋 **Logging:** Add structured security audit logging
4. 📋 **CORS:** Configurable allowed origins

### Optional (Nice to Have)

1. 💡 RS256 for JWT (multi-node support)
2. 💡 Database-backed sessions (server-side JWT invalidation)
3. 💡 Request ID tracing
4. 💡 Security headers (CSP, HSTS, etc.)

---

## Threat Model Assessment

| Threat | Current Protection | Recommendation |
|--------|-------------------|----------------|
| **Brute Force** | In-memory rate limiting | Redis-based |
| **JWT Theft** | HttpOnly cookies | Add refresh tokens |
| **Key Compromise** | None | Key rotation mechanism |
| **API Key Leak** | Fernet encryption | At-rest encryption |
| **Replay Attack** | Timestamp validation | Add nonce tracking |
| **Signature Forgery** | RFC-9421 + RSA | ✅ Adequate |
| **Timing Attack** | Constant-time bcrypt | Add padding |

---

## Conclusion

The AO LLM Gateway Phase 1 MVP implements security controls appropriately for its scope. The critical security concerns (password hashing, JWT handling, HTTPSig verification) are implemented correctly.

**For Production Deployment:**
1. Address all CRITICAL items above
2. Run penetration tests
3. Security audit by external party

**Overall:** 🟢 Safe for MVP, 🟡 Needs hardening for production

---

Reviewed by: AI Security Review
Date: 2026-02-21
Version: 1.0
