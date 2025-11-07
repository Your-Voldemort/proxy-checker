"""Detects the protocol of a proxy."""

import asyncio
from typing import Optional

import aiohttp
from aiohttp_socks import ProxyConnector

from ...models import Proxy

async def get_proxy_protocol(
    proxy: Proxy, session: aiohttp.ClientSession
) -> Optional[str]:
    """
    Detects the protocol of a proxy.

    Args:
        proxy: The proxy to check.
        session: The aiohttp session to use.

    Returns:
        The protocol of the proxy, or None if no protocol is found.
    """
    protocols = ["socks5", "socks4", "https", "http"]
    for protocol in protocols:
        connector = ProxyConnector.from_url(f"{protocol}://{proxy}")
        try:
            async with session.get(
                "http://www.google.com",
                proxy=f"{protocol}://{proxy}",
                timeout=5,
            ) as response:
                if response.status == 200:
                    return protocol
        except (
            aiohttp.ClientProxyConnectionError,
            asyncio.TimeoutError,
            aiohttp.ClientHttpProxyError,
        ):
            continue
        finally:
            await connector.close()
    return None