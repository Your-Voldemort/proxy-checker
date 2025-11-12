"""Rate limiting for external API calls."""

import asyncio
import time
from collections import deque
from typing import Optional


class RateLimiter:
    """Simple token bucket rate limiter."""
    
    def __init__(self, max_requests: int, time_window: float = 60.0):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum number of requests in time window
            time_window: Time window in seconds (default: 60s)
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: deque = deque()
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> None:
        """Wait until a request can be made without exceeding rate limit."""
        async with self._lock:
            now = time.monotonic()
            
            # Remove expired requests
            while self.requests and self.requests[0] < now - self.time_window:
                self.requests.popleft()
            
            if len(self.requests) >= self.max_requests:
                # Calculate wait time
                oldest = self.requests[0]
                wait_time = (oldest + self.time_window) - now
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                self.requests.popleft()
            
            self.requests.append(now)