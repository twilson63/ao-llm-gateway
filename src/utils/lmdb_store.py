"""LMDB-based rate limiting and key-value store for AO LLM Gateway.

LMDB is truly open source (OpenLDAP license) unlike Redis (SSPL).
"""
import lmdb
import time
import json
from pathlib import Path
from typing import Optional, Dict, Any


class RateLimitStore:
    """Rate limiting store using LMDB for persistence.
    
    LMDB features:
    - Memory-mapped database for speed
    - ACID transactions
    - No separate service (embedded)
    - OpenLDAP license (open source)
    """
    
    def __init__(self, db_path: str = "./data/ratelimit.db", map_size: int = 100*1024*1024):
        """Initialize LMDB environment.
        
        Args:
            db_path: Path to LMDB database file
            map_size: Maximum database size (default 100MB)
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.env = lmdb.open(
            str(self.db_path),
            map_size=map_size,
            max_dbs=2,  # rate_limits and counters
            create=True
        )
        
        # Open named databases
        with self.env.begin(write=True) as txn:
            self.rate_db = self.env.open_db(b"rate_limits", txn=txn, create=True)
            self.counter_db = self.env.open_db(b"counters", txn=txn, create=True)
    
    def check_limit(
        self, 
        identifier: str, 
        limit: int, 
        window_seconds: int
    ) -> tuple[bool, Dict[str, Any]]:
        """Check if identifier is within rate limit.
        
        Args:
            identifier: Unique identifier (e.g., "login:email@example.com" or "process:process_id")
            limit: Maximum allowed requests
            window_seconds: Time window in seconds
            
        Returns:
            Tuple of (allowed: bool, status: dict with count, window_start, remaining, reset_at)
        """
        key = identifier.encode()
        current_time = time.time()
        
        with self.env.begin(write=True, db=self.rate_db) as txn:
            data = txn.get(key)
            
            if data:
                # Parse stored data
                stored = json.loads(data.decode())
                count = stored["count"]
                window_start = stored["window_start"]
                
                # Check if window has expired
                if current_time - window_start > window_seconds:
                    # Reset window
                    new_data = {
                        "count": 1,
                        "window_start": current_time,
                        "first_request": current_time
                    }
                    txn.put(key, json.dumps(new_data).encode())
                    
                    reset_at = current_time + window_seconds
                    remaining = limit - 1
                    
                    return True, {
                        "count": 1,
                        "limit": limit,
                        "window_start": current_time,
                        "remaining": remaining,
                        "reset_at": reset_at
                    }
                else:
                    # Still within window
                    if count >= limit:
                        # Rate limit exceeded
                        reset_at = window_start + window_seconds
                        remaining = 0
                        
                        return False, {
                            "count": count,
                            "limit": limit,
                            "window_start": window_start,
                            "remaining": remaining,
                            "reset_at": reset_at
                        }
                    else:
                        # Within limit, increment
                        count += 1
                        stored["count"] = count
                        txn.put(key, json.dumps(stored).encode())
                        
                        reset_at = window_start + window_seconds
                        remaining = limit - count
                        
                        return True, {
                            "count": count,
                            "limit": limit,
                            "window_start": window_start,
                            "remaining": remaining,
                            "reset_at": reset_at
                        }
            else:
                # First request for this identifier
                new_data = {
                    "count": 1,
                    "window_start": current_time,
                    "first_request": current_time
                }
                txn.put(key, json.dumps(new_data).encode())
                
                reset_at = current_time + window_seconds
                remaining = limit - 1
                
                return True, {
                    "count": 1,
                    "limit": limit,
                    "window_start": current_time,
                    "remaining": remaining,
                    "reset_at": reset_at
                }
    
    def reset_limit(self, identifier: str) -> None:
        """Reset rate limit for identifier.
        
        Args:
            identifier: Rate limit identifier to reset
        """
        with self.env.begin(write=True, db=self.rate_db) as txn:
            txn.delete(identifier.encode())
    
    def get_limit_status(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Get current rate limit status without incrementing.
        
        Args:
            identifier: Rate limit identifier
            
        Returns:
            Status dict or None if not found
        """
        key = identifier.encode()
        
        with self.env.begin(db=self.rate_db) as txn:
            data = txn.get(key)
            
            if data:
                return json.loads(data.decode())
            return None
    
    def cleanup(self) -> None:
        """Close LMDB environment properly."""
        self.env.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


class SlidingWindowRateLimitStore(RateLimitStore):
    """Sliding window rate limiting (more accurate than fixed window).
    
    Tracks individual request timestamps and enforces limit based on
    requests in the last N seconds.
    """
    
    def check_limit(
        self, 
        identifier: str, 
        limit: int, 
        window_seconds: int
    ) -> tuple[bool, Dict[str, Any]]:
        """Sliding window rate limit check."""
        key = identifier.encode()
        current_time = time.time()
        cutoff_time = current_time - window_seconds
        
        with self.env.begin(write=True, db=self.rate_db) as txn:
            data = txn.get(key)
            
            if data:
                stored = json.loads(data.decode())
                requests = stored.get("requests", [])
                
                # Filter out requests outside window
                requests = [t for t in requests if t > cutoff_time]
                
                if len(requests) >= limit:
                    # Rate limit exceeded
                    oldest_in_window = min(requests)
                    reset_at = oldest_in_window + window_seconds
                    
                    return False, {
                        "count": len(requests),
                        "limit": limit,
                        "window_start": cutoff_time,
                        "remaining": 0,
                        "reset_at": reset_at
                    }
                
                # Add current request
                requests.append(current_time)
                stored["requests"] = requests
                txn.put(key, json.dumps(stored).encode())
                
                return True, {
                    "count": len(requests),
                    "limit": limit,
                    "window_start": cutoff_time,
                    "remaining": limit - len(requests),
                    "reset_at": current_time + window_seconds
                }
            else:
                # First request
                new_data = {"requests": [current_time]}
                txn.put(key, json.dumps(new_data).encode())
                
                return True, {
                    "count": 1,
                    "limit": limit,
                    "window_start": cutoff_time,
                    "remaining": limit - 1,
                    "reset_at": current_time + window_seconds
                }


# Singleton instance for global access
_rate_limit_store: Optional[RateLimitStore] = None


def get_rate_limit_store() -> RateLimitStore:
    """Get or create global rate limit store instance."""
    global _rate_limit_store
    if _rate_limit_store is None:
        _rate_limit_store = RateLimitStore()
    return _rate_limit_store


def init_rate_limit_store(db_path: str = "./data/ratelimit.db") -> RateLimitStore:
    """Initialize rate limit store with custom path.
    
    Used during app startup to configure custom path.
    """
    global _rate_limit_store
    _rate_limit_store = RateLimitStore(db_path=db_path)
    return _rate_limit_store
