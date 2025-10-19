"""Data models for the proxy checker."""

from dataclasses import dataclass
from typing import Optional

@dataclass
class Proxy:
    """Represents a proxy server to be tested."""
    host: str
    port: int
    protocol: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

    def __str__(self) -> str:
        """Return the proxy as a URL string."""
        if self.username and self.password:
            return f"{self.protocol}://{self.username}:{self.password}@{self.host}:{self.port}"
        return f"{self.protocol}://{self.host}:{self.port}"

@dataclass
class ValidationResult:
    """Stores the results of a proxy validation."""
    proxy: Proxy
    is_working: bool = False
    latency: float = -1.0  # in milliseconds
    anonymity: str = "Unknown"
    geolocation: str = "Unknown"
    error: Optional[str] = None