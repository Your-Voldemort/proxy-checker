"""Parse proxy strings into a structured format."""

import re
from urllib.parse import urlparse

from ..models import Proxy
from ..exceptions import ProxyParsingError


def parse_proxy(proxy_string: str) -> Proxy:
    """Parse proxy string or raise ProxyParsingError."""
    proxy_string = proxy_string.strip()

    if not proxy_string:
        raise ProxyParsingError("Proxy string cannot be empty.")

    try:
        # Try parsing as URL first (with protocol)
        if "://" in proxy_string:
            parsed = urlparse(proxy_string)
            if not parsed.hostname or not parsed.port:
                raise ProxyParsingError(f"Invalid proxy URL: {proxy_string}")
            return Proxy(
                host=parsed.hostname,
                port=parsed.port,
                username=parsed.username,
                password=parsed.password,
                protocol=parsed.scheme if parsed.scheme else None,
            )

        # Parse without protocol: [username:password@]host:port
        auth_pattern = re.compile(
            r"^(?:(?P<username>[^:@]+):(?P<password>[^@]+)@)?"
            r"(?P<host>[^:]+):(?P<port>\d+)$"
        )

        match = auth_pattern.match(proxy_string)
        if match:
            data = match.groupdict()
            return Proxy(
                host=data["host"],
                port=int(data["port"]),
                username=data.get("username"),
                password=data.get("password"),
            )

        raise ProxyParsingError(f"Invalid proxy format: {proxy_string}")

    except (ValueError, AttributeError) as e:
        raise ProxyParsingError(f"Failed to parse proxy '{proxy_string}': {e}") from e