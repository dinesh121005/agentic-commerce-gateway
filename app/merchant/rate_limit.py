"""
Login Rate Limiting for Merchant Authentication.

Protects merchant authentication endpoints against credential stuffing and brute-force attacks.
Enforces a sliding window limit: 5 failed attempts per account/IP within 5 minutes triggers HTTP 429.
A successful login immediately clears failed attempts for the key.
"""
from collections import defaultdict, deque
import threading
import time
from typing import Dict, Optional
from fastapi import HTTPException, status


class LoginRateLimiter:
    """
    Thread-safe, sliding-window rate limiter for merchant login attempts.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._failures: Dict[str, deque] = defaultdict(deque)

    def _prune(self, key: str, now: float) -> deque:
        """Removes failure timestamps older than window_seconds."""
        cutoff = now - self.window_seconds
        timestamps = self._failures[key]
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        return timestamps

    def check_rate_limit(self, key: str) -> None:
        """
        Validates whether the key is currently rate-limited.
        Raises HTTPException(429) if failed attempts threshold is reached.
        """
        now = time.time()
        with self._lock:
            timestamps = self._prune(key, now)
            if len(timestamps) >= self.max_attempts:
                # Calculate retry after based on the oldest attempt in the window
                oldest = timestamps[0]
                retry_after = max(1, int(oldest + self.window_seconds - now))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many failed login attempts. Account temporarily locked for {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)},
                )

    def record_failure(self, key: str) -> None:
        """Records a failed login attempt for the key."""
        now = time.time()
        with self._lock:
            timestamps = self._prune(key, now)
            timestamps.append(now)

    def record_success(self, key: str) -> None:
        """Clears failed attempts for the key upon successful login."""
        with self._lock:
            if key in self._failures:
                del self._failures[key]

    def reset(self) -> None:
        """Clears all rate-limiting state (used for testing)."""
        with self._lock:
            self._failures.clear()


# Global singleton rate limiter instance for merchant authentication
login_rate_limiter = LoginRateLimiter(max_attempts=5, window_seconds=300)

