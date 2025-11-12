"""A reusable aiohttp client session."""

import logging
from typing import Optional
import aiohttp

async def get_aiohttp_session() -> aiohttp.ClientSession:
    """Returns a new aiohttp ClientSession."""
    return aiohttp.ClientSession()

async def get_my_ip() -> Optional[str]:
    """
    Retrieves the user's real IP address.
    
    Returns:
        The user's IP address, or None if retrieval fails.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.ipify.org?format=json",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    ip = data.get("ip")
                    logging.info(f"Detected real IP: {ip}")
                    return ip
    except Exception as e:
        logging.warning(f"Failed to retrieve real IP: {e}")
    return None