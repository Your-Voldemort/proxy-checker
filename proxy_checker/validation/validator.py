"""Core proxy validation logic."""

import asyncio
import logging
import time
from typing import Dict, List, Optional

from aiohttp import ClientSession

from ..models import Proxy, ValidationResult
from .checkers.anonymity_checker import get_anonymity_level
from .checkers.geolocation_checker import get_geolocation
from .checkers.protocol_checker import get_proxy_protocol


async def validate_proxy(
    proxy: Proxy,
    session: ClientSession,
    test_urls: Optional[List[str]] = None,
) -> ValidationResult:
    """
    Validates a single proxy.

    Args:
        proxy: The proxy to validate.
        session: The aiohttp session to use.
        test_urls: A list of URLs to test the proxy against.

    Returns:
        A ValidationResult object.
    """
    start_time = time.monotonic()
    protocol = await get_proxy_protocol(proxy, session)
    latency = (time.monotonic() - start_time) * 1000

    if not protocol:
        return ValidationResult(proxy=proxy, is_working=False, error="All protocols failed")

    try:
        anonymity = await get_anonymity_level(proxy, session)
        geolocation = await get_geolocation(proxy.host, session)
        website_tests = await _test_custom_urls(proxy, session, test_urls or [])
    except Exception as e:
        logging.error(f"Error validating {proxy}: {e}")
        return ValidationResult(proxy=proxy, is_working=False, error=str(e))

    return ValidationResult(
        proxy=proxy,
        is_working=True,
        protocol=protocol,
        latency=latency,
        anonymity=anonymity,
        geolocation=geolocation,
        website_tests=website_tests,
    )


async def _test_custom_urls(
    proxy: Proxy, session: ClientSession, urls: List[str]
) -> Dict[str, bool]:
    """Tests the proxy against a list of custom URLs."""
    results: Dict[str, bool] = {}
    for url in urls:
        try:
            async with session.get(
                url, proxy=f"http://{proxy}", timeout=5
            ) as response:
                results[url] = response.status == 200
        except (asyncio.TimeoutError, ClientError):
            results[url] = False
    return results