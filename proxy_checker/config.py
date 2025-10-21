"""Default configuration for the proxy checker."""

# Default timeout for network requests in seconds
DEFAULT_TIMEOUT: int = 10

# URL to test proxy connectivity and get IP details
TEST_URL: str = "https://httpbin.org/get"

# URL for checking proxy anonymity
ANONYMITY_TEST_URL: str = "https://httpbin.org/headers"

# URL for geolocation lookup
GEO_API_URL: str = "http://ip-api.com/json/"

# Default number of concurrent proxy checking tasks
DEFAULT_CONCURRENCY: int = 100

# Default input file for proxies
DEFAULT_PROXY_FILE: str = "proxies.txt"