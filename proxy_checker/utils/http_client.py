"""A reusable aiohttp client session."""

import aiohttp

async def get_aiohttp_session() -> aiohttp.ClientSession:
    """
    Returns a new aiohttp ClientSession.
    """
    return aiohttp.ClientSession()