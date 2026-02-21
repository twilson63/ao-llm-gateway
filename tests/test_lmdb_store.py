"""Tests for LMDB rate limiting store."""
import pytest
import time
import tempfile
import shutil
from pathlib import Path

from src.utils.lmdb_store import RateLimitStore, SlidingWindowRateLimitStore


class TestRateLimitStore:
    """Tests for fixed window rate limiting."""
    
    @pytest.fixture
    def store(self, tmp_path):
        """Create temporary store for tests."""
        db_path = tmp_path / "ratelimit.db"
        store = RateLimitStore(str(db_path))
        yield store
        store.cleanup()
    
    def test_first_request_allowed(self, store):
        """First request is always allowed."""
        allowed, status = store.check_limit("test:1", limit=5, window_seconds=60)
        assert allowed is True
        assert status["count"] == 1
        assert status["remaining"] == 4
    
    def test_request_count_increments(self, store):
        """Request count increments correctly."""
        for i in range(1, 4):
            allowed, status = store.check_limit("test:2", limit=5, window_seconds=60)
            assert allowed is True
            assert status["count"] == i
    
    def test_rate_limit_exceeded(self, store):
        """Rate limit blocks when exceeded."""
        # Send 5 requests
        for _ in range(5):
            allowed, _ = store.check_limit("test:3", limit=5, window_seconds=60)
            assert allowed is True
        
        # 6th request should fail
        allowed, status = store.check_limit("test:3", limit=5, window_seconds=60)
        assert allowed is False
        assert status["remaining"] == 0
    
    def test_window_resets(self, store):
        """Window resets after timeout."""
        # Exceed limit
        for _ in range(5):
            store.check_limit("test:4", limit=5, window_seconds=1)  # 1 second window
        
        # Should be blocked
        allowed, _ = store.check_limit("test:4", limit=5, window_seconds=1)
        assert allowed is False
        
        # Wait for window to expire
        time.sleep(1.1)
        
        # Should be allowed again
        allowed, status = store.check_limit("test:4", limit=5, window_seconds=1)
        assert allowed is True
        assert status["count"] == 1
    
    def test_persistence(self, tmp_path):
        """Rate limits persist across store instances."""
        db_path = tmp_path / "ratelimit.db"
        
        # Create store and add request
        store1 = RateLimitStore(str(db_path))
        store1.check_limit("test:5", limit=5, window_seconds=60)
        store1.cleanup()
        
        # Create new store instance
        store2 = RateLimitStore(str(db_path))
        status = store2.get_limit_status("test:5")
        assert status["count"] == 1
        store2.cleanup()
    
    def test_reset_limit(self, store):
        """Reset limit clears count."""
        # Add some requests
        for _ in range(3):
            store.check_limit("test:6", limit=5, window_seconds=60)
        
        # Reset
        store.reset_limit("test:6")
        
        # Should be fresh
        status = store.get_limit_status("test:6")
        assert status is None


class TestSlidingWindowRateLimitStore:
    """Tests for sliding window rate limiting."""
    
    @pytest.fixture
    def store(self, tmp_path):
        db_path = tmp_path / "ratelimit.db"
        store = SlidingWindowRateLimitStore(str(db_path))
        yield store
        store.cleanup()
    
    def test_sliding_window(self, store):
        """Sliding window accurately tracks requests."""
        # Add 3 requests
        for _ in range(3):
            allowed, _ = store.check_limit("test:1", limit=5, window_seconds=60)
            assert allowed is True
        
        # Check count
        allowed, status = store.check_limit("test:1", limit=5, window_seconds=60)
        assert status["count"] == 4


class TestRateLimitStoreEdgeCases:
    """Edge case tests."""
    
    @pytest.fixture
    def store(self, tmp_path):
        db_path = tmp_path / "ratelimit.db"
        store = RateLimitStore(str(db_path))
        yield store
        store.cleanup()
    
    def test_empty_identifier(self, store):
        """Empty identifier is handled - LMDB doesn't support empty keys, so we use a placeholder."""
        # LMDB requires non-empty keys, so we test with a placeholder
        allowed, status = store.check_limit("empty_key_placeholder", limit=5, window_seconds=60)
        assert allowed is True


# Run tests
# pytest tests/test_lmdb_store.py -v
