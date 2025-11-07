from dataclasses import dataclass, field
from typing import Optional, Dict

@dataclass
class Proxy:
    """Represents a proxy server to be tested."""

    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

    def __str__(self) -> str:
        """Return the proxy as a URL string."""
        if self.username and self.password:
            return (
                f"{self.username}:{self.password}@"
                f"{self.host}:{self.port}"
            )
        return f"{self.host}:{self.port}"

@dataclass
class Geolocation:
    country: str = "Unknown"
    city: str = "Unknown"
    isp: str = "Unknown"

@dataclass
class ValidationResult:
    """Stores the results of a proxy validation."""
    proxy: Proxy
    is_working: bool = False
    protocol: Optional[str] = None
    latency: float = -1.0  # in milliseconds
    anonymity: str = "Unknown"
    geolocation: Geolocation = field(default_factory=Geolocation)
    website_tests: Dict[str, bool] = field(default_factory=dict)
    error: Optional[str] = None