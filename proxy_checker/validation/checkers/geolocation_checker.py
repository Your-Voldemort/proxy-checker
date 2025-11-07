"""Fetches the geolocation of a proxy."""

import aiohttp

from ...models import Geolocation
from ...exceptions import GeolocationError

async def get_geolocation(
    proxy_ip: str, session: aiohttp.ClientSession
) -> Geolocation:
    """
    Fetches the geolocation of a proxy.

    Args:
        proxy_ip: The IP address of the proxy.
        session: The aiohttp session to use.

    Returns:
        The geolocation of the proxy.

    Raises:
        GeolocationError: If the geolocation lookup fails.
    """
    try:
        async with session.get(
            f"http://ip-api.com/json/{proxy_ip}"
        ) as response:
            if response.status != 200:
                raise GeolocationError("Failed to get geolocation.")

            data = await response.json()
            return Geolocation(
                country=data.get("country", "Unknown"),
                city=data.get("city", "Unknown"),
                isp=data.get("isp", "Unknown"),
            )
    except aiohttp.ClientError as e:
        raise GeolocationError(f"Geolocation lookup failed: {e}") from e