"""Core proxy validation logic."""

import asyncio
import logging
import time
from typing import Optional, Set

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientConnectorError, ClientError
from aiohttp_socks import ProxyConnector

from .config import ANONYMITY_TEST_URL, DEFAULT_TIMEOUT, GEO_API_URL, TEST_URL
from .models import Proxy, ValidationResult


class ProxyValidator:
    """A class to validate a single proxy."""

    def __init__(
        self,
        session: ClientSession,
        proxy: Proxy,
        my_ip: str,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        """
        Initializes the validator.

        Args:
            session: The shared aiohttp ClientSession.
            proxy: The proxy to be validated.
            my_ip: The user's real IP for anonymity checks.
            timeout: The request timeout in seconds.
        """
        self._session: ClientSession = session
        self._proxy: Proxy = proxy
        self._my_ip: str = my_ip
        self._timeout: ClientTimeout = ClientTimeout(total=timeout)

    async def check(self) -> ValidationResult:
        """
        Performs a full validation of the proxy by trying different protocols.
        """
        protocols_to_try: list[str] = (
            [self._proxy.protocol]
            if self._proxy.protocol
            else ["http", "https", "socks4", "socks5"]
        )

        for protocol in protocols_to_try:
            self._proxy.protocol = protocol
            connector = ProxyConnector.from_url(str(self._proxy))

            try:
                # Create a new session for each attempt to ensure proper protocol handling
                async with ClientSession(connector=connector) as proxy_session:
                    start_time = time.monotonic()
                    async with proxy_session.get(
                        TEST_URL, timeout=self._timeout
                    ) as response:
                        latency = (time.monotonic() - start_time) * 1000  # in ms

                        if response.status == 200:
                            anonymity = await self._get_anonymity(proxy_session)
                            # Geolocation must be checked with a direct connection
                            geolocation = await self._get_geolocation()
                            return ValidationResult(
                                proxy=self._proxy,
                                is_working=True,
                                latency=latency,
                                anonymity=anonymity,
                                geolocation=geolocation,
                            )
                        else:
                            return self._create_error_result(
                                f"HTTP Status {response.status}"
                            )

            except (ClientConnectorError, asyncio.TimeoutError, ClientError):
                # Continue to the next protocol if one fails
                continue
            except Exception as e:
                # Catch any other unexpected errors
                logging.debug(f"Unexpected validation error for {self._proxy}: {e}")
                return self._create_error_result(f"Unexpected error: {e}")

        # If all protocols failed
        return self._create_error_result("All protocols failed")

    async def _get_anonymity(self, proxy_session: ClientSession) -> str:
        """Determines the anonymity level of the proxy."""
        if not self._my_ip:
            return "Unknown"
        try:
            # The session is already using the proxy, so no 'proxy' param needed
            async with proxy_session.get(
                ANONYMITY_TEST_URL, timeout=self._timeout
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    headers = {h.lower() for h in data.get("headers", {})}
                    origin_ips = {
                        ip.strip() for ip in data.get("origin", "").split(",")
                    }

                    proxy_headers: Set[str] = {
                        "via",
                        "forwarded",
                        "x-forwarded-for",
                        "x-forwarded-host",
                        "x-forwarded-proto",
                        "x-proxy-id",
                        "proxy-connection",
                    }

                    if self._my_ip in origin_ips:
                        return "Transparent"
                    if not proxy_headers.intersection(headers):
                        return "Elite"
                    return "Anonymous"
        except Exception as e:
            logging.debug(f"Anonymity check failed for {self._proxy}: {e}")
            return "Unknown"
        return "Unknown"

    async def _get_geolocation(self) -> str:
        """Fetches geolocation data for the proxy's IP address."""
        try:
            async with self._session.get(f"{GEO_API_URL}{self._proxy.host}", timeout=self._timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "success":
                        country = data.get("country", "N/A")
                        city = data.get("city", "N/A")
                        return f"{city}, {country}"
        except Exception as e:
            logging.debug(f"Geolocation check failed for {self._proxy}: {e}")
            return "Unknown"
        return "Unknown"

    def _create_error_result(self, error_msg: str) -> ValidationResult:
        """Creates a ValidationResult for a failed check."""
        return ValidationResult(
            proxy=self._proxy,
            is_working=False,
            error=error_msg,
        )