"""Parse proxy strings into a structured format."""

import re
from typing import Optional

from ..models import Proxy
from ..exceptions import ProxyParsingError

PROXY_REGEX = re.compile(
    r"^(?:(?P<username>\w+):(?P<password>\w+)@)?"
    r"(?P<host>[\w\.-]+):(?P<port>\d+)$"
)

def parse_proxy(proxy_string: str) -> Optional[Proxy]:
    """
    Parse a proxy string into a Proxy object.

    Args:
        proxy_string: The proxy string to parse.

    Returns:
        A Proxy object if parsing is successful, otherwise None.
    
    Raises:
        ProxyParsingError: If the proxy string is invalid.
    """
    match = PROXY_REGEX.match(proxy_string)
    if not match:
        raise ProxyParsingError(f"Invalid proxy format: {proxy_string}")

    data = match.groupdict()
    return Proxy(
        host=data["host"],
        port=int(data["port"]),
        username=data.get("username"),
        password=data.get("password"),
    )