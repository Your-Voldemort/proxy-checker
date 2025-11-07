"""Core proxy validation logic."""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Set

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import (
    ClientConnectorError,
    ClientError,
    ProxyConnectionError,
)
from aiohttp_socks import ProxyConnector

from .config import (
    ANONYMITY_TEST_URL,
    DEFAULT_TIMEOUT,
    GEO_API_URL,
    TEST_URL,
    USER_AGENTS,
)
from .models import Geolocation, Proxy, ValidationResult


class ProxyValidator:
    """A class to validate a single proxy."""

    def __init__(
        self,
        session: ClientSession,
        proxy: Proxy,
        my_ip: str,
        timeout: int = DEFAULT_TIMEOUT,
        test_urls: Optional[List[str]] = None,
    ):
        """
        Initializes the validator.

        Args:
            session: The shared aiohttp ClientSession.
            proxy: The proxy to be validated.
            my_ip: The user's real IP for anonymity checks.
            timeout: The request timeout in seconds.
            test_urls: A list of URLs to test the proxy against.
        """
        self._session: ClientSession = session
        self._proxy: Proxy = proxy
        self._my_ip: str = my_ip
        self._timeout: ClientTimeout = ClientTimeout(total=timeout)
        self._test_urls: List[str] = test_urls or []
        self._user_agent_cycle = iter(USER_AGENTS)

    async def check(self) -> ValidationResult:
        """
        Performs a full validation of the proxy by trying different protocols.
        """
        protocols_to_try: list[str] = (
            [self._proxy.protocol]
            if self._proxy.protocol
            else ["socks5", "socks4", "https", "http"]
        )

        for protocol in protocols_to_try:
            self._proxy.protocol = protocol
            connector = self._get_connector(protocol)

            try:
                start_time = time.monotonic()
                async with self._session.get(
                    TEST_URL, timeout=self._timeout, connector=connector
                ) as response:
                    latency = (time.monotonic() - start_time) * 1000  # in ms

                    if response.status == 200:
                        anonymity = await self._get_anonymity(connector)
                        geolocation = await self._get_geolocation()
                        website_tests = await self._test_custom_urls(connector)

                        return ValidationResult(
                            proxy=self._proxy,
                            is_working=True,
                            protocol=protocol,
                            latency=latency,
                            anonymity=anonymity,
                            geolocation=geolocation,
                            website_tests=website_tests,
                        )
                    else:
                        logging.debug(
                            f"Protocol {protocol} for {self._proxy} failed with status {response.status}"
                        )
                        continue

            except (
                ProxyConnectionError,
                ClientConnectorError,
                asyncio.TimeoutError,
                ClientError,
            ) as e:
                logging.debug(f"Protocol {protocol} for {self._proxy} failed: {e}")
                continue
            except Exception as e:
                logging.error(f"Unexpected validation error for {self._proxy}: {e}")
                return self._create_error_result(f"Unexpected error: {e}")

        return self._create_error_result("All protocols failed")

    def _get_connector(self, protocol: str) -> Optional[ProxyConnector]:
        """Returns a ProxyConnector for the given protocol, if applicable."""
        if protocol in ("socks4", "socks5"):
            return ProxyConnector.from_url(str(self._proxy))
        return None  # For HTTP/HTTPS, we use the session's proxy parameter

    async def _get_anonymity(self, connector: Optional[ProxyConnector]) -> str:
        """Determines the anonymity level of the proxy."""
        if not self._my_ip:
            return "Unknown"
        try:
            async with self._session.get(
                ANONYMITY_TEST_URL,
                timeout=self._timeout,
                connector=connector,
                proxy=str(self._proxy) if not connector else None,
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

    async def _get_geolocation(self) -> Geolocation:
        """Fetches geolocation data for the proxy's IP address."""
        try:
            # Geolocation lookup should be a direct request, not through the proxy
            async with ClientSession() as direct_session:
                async with direct_session.get(
                    f"{GEO_API_URL}{self._proxy.host}", timeout=self._timeout
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("status") == "success":
                            return Geolocation(
                                country=data.get("country", "N/A"),
                                city=data.get("city", "N/A"),
                                isp=data.get("isp", "N/A"),
                            )
        except Exception as e:
            logging.debug(f"Geolocation check failed for {self._proxy}: {e}")
        return Geolocation()

    async def _test_custom_urls(
        self, connector: Optional[ProxyConnector]
    ) -> Dict[str, bool]:
        """Tests the proxy against a list of custom URLs."""
        results: Dict[str, bool] = {}
        for url in self._test_urls:
            try:
                headers = {"User-Agent": self._get_next_user_agent()}
                async with self._session.get(
                    url,
                    timeout=self._timeout,
                    connector=connector,
                    proxy=str(self._proxy) if not connector else None,
                    headers=headers,
                ) as response:
                    results[url] = response.status == 200
            except Exception:
                results[url] = False
        return results

    def _get_next_user_agent(self) -> str:
        """Cycles through the list of user agents."""
        try:
            return next(self._user_agent_cycle)
        except StopIteration:
            self._user_agent_cycle = iter(USER_AGENTS)
            return next(self._user_agent_cycle)

    def _create_error_result(self, error_msg: str) -> ValidationResult:
        """Creates a ValidationResult for a failed check."""
        return ValidationResult(
            proxy=self._proxy, is_working=False, error=error_msg
        )