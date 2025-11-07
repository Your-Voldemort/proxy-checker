"""Determines the anonymity level of a proxy."""

import aiohttp

from ...models import Proxy
from ...exceptions import AnonymityCheckError

async def get_anonymity_level(
    proxy: Proxy, session: aiohttp.ClientSession
) -> str:
    """
    Determines the anonymity level of a proxy.

    Args:
        proxy: The proxy to check.
        session: The aiohttp session to use.

    Returns:
        The anonymity level of the proxy.

    Raises:
        AnonymityCheckError: If the anonymity check fails.
    """
    try:
        async with session.get(
            "http://httpbin.org/get",
            proxy=f"http://{proxy}",
            timeout=5,
        ) as response:
            if response.status != 200:
                raise AnonymityCheckError("Failed to get anonymity level.")

            data = await response.json()
            headers = data.get("headers", {})
            
            if "X-Forwarded-For" in headers or "Via" in headers:
                return "Transparent"
            
            # A more robust check would be to compare the origin IP
            # with the proxy's IP. For now, we'll assume that if no
            # identifying headers are present, the proxy is elite.
            return "Elite"
            
    except aiohttp.ClientError as e:
        raise AnonymityCheckError(f"Anonymity check failed: {e}") from e