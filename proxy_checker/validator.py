"""Core proxy validation logic."""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Set

import aiohttp
from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import (
    ClientConnectorError,
    ClientError,
    ProxyConnectionError,
)
from aiohttp_socks import ProxyConnector

from .config import (
    ANONYMITY_CHECK_URLS,
    DEFAULT_TIMEOUT,
    GEO_API_URL,
    TEST_URL,
    USER_AGENTS,
)
from .exceptions import ValidationError
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
        direct_session: Optional[ClientSession] = None,
    ):
        """
        Initializes the validator.

        Args:
            session: The shared aiohttp ClientSession.
            proxy: The proxy to be validated.
            my_ip: The user's real IP for anonymity checks.
            timeout: The request timeout in seconds.
            test_urls: A list of URLs to test the proxy against.
            direct_session: Optional session for direct connections.
        """
        self._session = session
        self._direct_session = direct_session or session
        self._proxy = proxy
        self._my_ip = my_ip
        self._timeout = ClientTimeout(total=timeout)
        self._test_urls = test_urls or []
        self._user_agent_cycle = iter(USER_AGENTS)

    async def check(self) -> ValidationResult:
        """Performs a full validation of the proxy by trying different protocols."""
        protocols_to_try: list[str] = (
            [self._proxy.protocol]
            if self._proxy.protocol
            else ["socks5", "socks4", "https", "http"]
        )
        
        for protocol in protocols_to_try:
            # Don't mutate the proxy object
            connector = self._get_connector(protocol)
            
            try:
                start_time = time.monotonic()
                proxy_url = self._build_proxy_url(protocol)
                
                async with self._session.get(
                    TEST_URL,
                    timeout=self._timeout,
                    connector=connector,
                    proxy=proxy_url if not connector else None
                ) as response:
                    latency = (time.monotonic() - start_time) * 1000
                    
                    if response.status == 200:
                        anonymity = await self._get_anonymity(connector, protocol)
                        geolocation = await self._get_geolocation()
                        website_tests = await self._test_custom_urls(connector, protocol)
                        
                        # Create new proxy instance with detected protocol
                        validated_proxy = Proxy(
                            host=self._proxy.host,
                            port=self._proxy.port,
                            username=self._proxy.username,
                            password=self._proxy.password,
                            protocol=protocol
                        )
                        
                        return ValidationResult(
                            proxy=validated_proxy,
                            is_working=True,
                            protocol=protocol,
                            latency=latency,
                            anonymity=anonymity,
                            geolocation=geolocation,
                            website_tests=website_tests,
                        )
            except (ValidationError, ClientError, asyncio.TimeoutError) as e:
                logging.debug(f"Proxy {self._proxy} check failed for protocol {protocol}: {e}")
                continue
        
        return ValidationResult(proxy=self._proxy, is_working=False)

    def _build_proxy_url(self, protocol: str) -> str:
        """Build proxy URL with protocol prefix."""
        auth = f"{self._proxy.username}:{self._proxy.password}@" if self._proxy.username else ""
        return f"{protocol}://{auth}{self._proxy.host}:{self._proxy.port}"

    def _get_connector(self, protocol: str) -> Optional[ProxyConnector]:
        """Returns a ProxyConnector for SOCKS protocols."""
        if protocol in ("socks4", "socks5"):
            return ProxyConnector.from_url(self._build_proxy_url(protocol))
        return None

    async def _get_anonymity(self, connector: Optional[ProxyConnector], protocol: str) -> str:
        """Determines the anonymity level of the proxy."""
        if not self._my_ip:
            logging.debug("Skipping anonymity check - real IP not available")
            return "Unknown"
        
        try:
            proxy_url = self._build_proxy_url(protocol)
            async with self._session.get(
                ANONYMITY_CHECK_URLS[0], # Use the first URL from the config
                timeout=self._timeout,
                connector=connector,
                proxy=proxy_url if not connector else None,
            ) as response:
                if response.status != 200:
                    logging.warning(
                        f"Anonymity check returned status {response.status} "
                        f"for proxy {self._proxy} (URL: {ANONYMITY_CHECK_URLS[0]})"
                    )
                    return "Unknown"
                
                data = await response.json()
                # Simplified logic from review; assumes httpbin.org or similar
                proxy_ip = data.get("origin")
                headers = data.get("headers", {})

                if proxy_ip and self._my_ip in proxy_ip:
                    return "Transparent"
                
                if 'X-Forwarded-For' in headers or 'Via' in headers:
                    return "Anonymous"

                return "Elite"
                
        except asyncio.TimeoutError:
            logging.debug(
                f"Anonymity check timed out for {self._proxy} "
                f"after {self._timeout.total}s"
            )
        except aiohttp.ClientError as e:
            logging.debug(
                f"Anonymity check failed for {self._proxy}: "
                f"{type(e).__name__} - {e}"
            )
        except Exception as e:
            logging.error(
                f"Unexpected error during anonymity check for {self._proxy}: "
                f"{type(e).__name__} - {e}",
                exc_info=True
            )
        
        return "Unknown"

    async def _get_geolocation(self) -> Geolocation:
        """Fetches geolocation data for the proxy's IP address."""
        try:
            # Use the direct session (or shared session)
            async with self._direct_session.get(
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
        self, connector: Optional[ProxyConnector], protocol: str
    ) -> Dict[str, bool]:
        """Tests the proxy against a list of custom URLs."""
        results: Dict[str, bool] = {}
        proxy_url = self._build_proxy_url(protocol)
        for url in self._test_urls:
            try:
                headers = {"User-Agent": self._get_next_user_agent()}
                async with self._session.get(
                    url,
                    timeout=self._timeout,
                    connector=connector,
                    proxy=proxy_url if not connector else None,
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