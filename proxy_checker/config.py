"""Default configuration for the proxy checker."""

from typing import List, Dict

# Default timeout for network requests in seconds
DEFAULT_TIMEOUT: int = 10

# Default number of concurrent proxy checking tasks
DEFAULT_CONCURRENCY: int = 100

# Test URLs with fallbacks
TEST_URLS: List[str] = [
    "https://www.google.com",
    "https://www.cloudflare.com",
    "https://example.com",
]

# Anonymity check endpoints
ANONYMITY_CHECK_URLS: List[str] = [
    "https://httpbin.org/get",
    "https://api.ipify.org",  # Fallback
]

# Geolocation API configurations
GEO_API_PROVIDERS: Dict[str, Dict] = {
    "ip-api": {
        "url": "http://ip-api.com/json/{ip}",
        "rate_limit": 45,  # per minute
        "free": True,
    },
    "ipinfo": {
        "url": "https://ipinfo.io/{ip}/json",
        "rate_limit": 50000,  # per month
        "api_key_required": True,
    }
}

# Default provider
DEFAULT_GEO_PROVIDER: str = "ip-api"

# Rate limiting
ENABLE_RATE_LIMITING: bool = True
