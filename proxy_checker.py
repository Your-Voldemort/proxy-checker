# ==============================================================================
# Asynchronous Proxy Checker & Validator
#
# Description:
# This script asynchronously checks a list of proxies from a file, validating
# their connectivity, protocol, anonymity level, and geolocation. It provides
# real-time console output and saves working proxies to categorized files.
#
# Dependencies:
# - aiohttp: For asynchronous HTTP requests.
# - aiohttp-socks: For SOCKS proxy support with aiohttp.
# - aiodns: For asynchronous DNS resolution.
#
# To install dependencies:
# pip install aiohttp aiohttp-socks aiodns
# ==============================================================================

import asyncio
import time
import os
import json
import ipaddress
from collections import namedtuple
from aiohttp import ClientSession, ClientTimeout
from aiohttp_socks import ProxyConnector
from urllib.parse import urlparse

# -- Configuration --
INPUT_FILE = "proxies.txt"
OUTPUT_DIRECTORY = "working_proxies"
REQUEST_TIMEOUT = 10  # in seconds
MAX_CONCURRENT_TASKS = 10  # Semaphore limit for active checks
TARGET_URL_HTTP = "http://httpbin.org/get"
TARGET_URL_HTTPS = "https://httpbin.org/get"
TARGET_URL_HEADERS = "https://httpbin.org/headers"
GEO_API_URL = "http://ip-api.com/json/"
# -- End Configuration --

# --- Data Structures ---
Proxy = namedtuple('Proxy', ['protocol', 'host', 'port', 'username', 'password', 'original_str'])
Result = namedtuple('Result', ['proxy', 'status', 'latency', 'anonymity', 'geolocation'])
GeoLocation = namedtuple('GeoLocation', ['country', 'region', 'city'])

# --- ANSI Color Codes for Console Output ---
class Colors:
    """Container for ANSI color codes for rich console output."""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'

# --- Core Functions ---

def parse_proxy(proxy_str: str) -> Proxy | None:
    """
    Parses a proxy string into a Proxy namedtuple.
    Supports formats: IP:PORT, IP:PORT:USER:PASS, and scheme://...
    """
    original_str = proxy_str.strip()
    if not original_str:
        return None
        
    if '://' in original_str:
        try:
            parsed = urlparse(original_str)
            return Proxy(
                protocol=parsed.scheme, host=parsed.hostname, port=parsed.port,
                username=parsed.username, password=parsed.password, original_str=original_str
            )
        except Exception:
            return None
    else:
        parts = original_str.split(':')
        try:
            if len(parts) == 2:
                return Proxy(None, parts[0], int(parts[1]), None, None, original_str)
            elif len(parts) == 4:
                return Proxy(None, parts[0], int(parts[1]), parts[2], parts[3], original_str)
        except (ValueError, IndexError):
            return None
    return None

async def read_proxies(file_path: str) -> list[Proxy]:
    """
    Reads and parses proxies from a given file path.
    Handles file not found errors and ignores invalid proxy formats.
    """
    proxies = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                proxy = parse_proxy(line)
                if proxy:
                    proxies.append(proxy)
                elif line.strip():
                    print(f"{Colors.RED}Ignoring invalid proxy format: {line.strip()}{Colors.RESET}")
    except FileNotFoundError:
        print(f"{Colors.RED}Error: Input file '{file_path}' not found.{Colors.RESET}")
    return proxies

def get_connector(protocol: str, host: str, port: int, username: str | None, password: str | None) -> ProxyConnector:
    """
    Returns the appropriate aiohttp-socks ProxyConnector for the given proxy details.
    """
    scheme = 'http'
    if 'socks' in protocol:
        scheme = protocol

    auth = ''
    if username and password:
        auth = f'{username}:{password}@'
    
    url = f"{scheme}://{auth}{host}:{port}"

    return ProxyConnector.from_url(url, rdns=True)

async def get_geolocation(geo_session: ClientSession, proxy_host: str) -> GeoLocation:
    """
    Fetches geolocation data for a given IP address using the GeoIP API.
    """
    try:
        async with geo_session.get(f"{GEO_API_URL}{proxy_host}", timeout=ClientTimeout(total=5)) as response:
            if response.status == 200:
                data = await response.json()
                if data.get('status') == 'success':
                    return GeoLocation(data.get('country', 'N/A'), data.get('regionName', 'N/A'), data.get('city', 'N/A'))
    except Exception:
        pass
    return GeoLocation("Unknown", "Unknown", "Unknown")

async def get_anonymity(session: ClientSession, my_ip: str) -> str:
    """
    Determines the anonymity level of the proxy by inspecting request headers.
    """
    try:
        async with session.get(TARGET_URL_HEADERS, timeout=ClientTimeout(total=REQUEST_TIMEOUT)) as response:
            if response.status == 200:
                data = await response.json()
                headers = {h.lower() for h in data.get('headers', {})}
                known_proxy_headers = {'via', 'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-proxy-id', 'proxy-connection'}
                origin_ips = {ip.strip() for ip in data.get('origin', '').split(',')}

                if my_ip in origin_ips:
                    return "Transparent"
                elif not known_proxy_headers.intersection(headers):
                    return "Elite"
                else:
                    return "Anonymous"
    except Exception:
        pass
    return "Unknown"

def print_result(result: Result):
    """Prints a formatted, color-coded result to the console."""
    proxy = result.proxy
    proxy_str = f"{proxy.host}:{proxy.port}"
    if proxy.username:
        proxy_str += f":{proxy.username}:{proxy.password}"

    if result.status == "WORKING":
        status_color = Colors.GREEN
        geo = result.geolocation
        location = f"{geo.city}, {geo.country}"
        print(
            f"[{status_color}WORKING{Colors.RESET}] "
            f"{proxy.protocol.upper():<7} {proxy_str:<25} | "
            f"Latency: {result.latency:<10} | "
            f"Anonymity: {result.anonymity:<12} | "
            f"Location: {location}"
        )
    else:
        status_color = Colors.RED
        print(f"[{status_color}FAILED{Colors.RESET}]  {proxy.protocol.upper():<7} {proxy_str}")

def save_working_proxies(results: list[Result]):
    """Saves working proxies to categorized files based on protocol and anonymity."""
    print(f"\n{Colors.YELLOW}Saving working proxies to '{OUTPUT_DIRECTORY}'...{Colors.RESET}")
    count = 0
    for result in results:
        if result.status == "WORKING":
            count += 1
            anonymity = str(result.anonymity).lower()
            protocol = str(result.proxy.protocol).lower()
            filename = os.path.join(OUTPUT_DIRECTORY, f"{protocol}_{anonymity}.txt")
            with open(filename, 'a') as f:
                f.write(result.proxy.original_str + '\n')
    print(f"{Colors.GREEN}Saved {count} working proxies.{Colors.RESET}")

async def check_proxy(proxy: Proxy, my_ip: str, geo_session: ClientSession, semaphore: asyncio.Semaphore) -> Result:
    """
    Performs a full check on a single proxy, trying multiple protocols if needed.
    Uses a semaphore to limit concurrency.
    """
    async with semaphore:
        protocols_to_try = [proxy.protocol] if proxy.protocol else ['http', 'https', 'socks4', 'socks5']
        
        for protocol in protocols_to_try:
            start_time = time.time()
            connector = get_connector(protocol, proxy.host, proxy.port, proxy.username, proxy.password)
            proxy_with_proto = proxy._replace(protocol=protocol)
            
            try:
                async with ClientSession(connector=connector) as session:
                    target_url = TARGET_URL_HTTPS if protocol == 'https' else TARGET_URL_HTTP
                    async with session.get(target_url, timeout=ClientTimeout(total=REQUEST_TIMEOUT)) as response:
                        if response.status == 200:
                            latency = (time.time() - start_time) * 1000
                            anonymity = await get_anonymity(session, my_ip)
                            geolocation = await get_geolocation(geo_session, proxy.host)
                            result = Result(proxy_with_proto, "WORKING", f"{latency:.2f}ms", anonymity, geolocation)
                            print_result(result)
                            return result # Return on first success
            except Exception:
                # This catches timeouts, connection errors, etc.
                result = Result(proxy_with_proto, "FAILED", "N/A", "N/A", None)
                print_result(result)
        
        # If no protocol worked
        return Result(proxy._replace(protocol="N/A"), "FAILED", "N/A", "N/A", None)

async def main():
    """Main function to orchestrate the proxy checking process."""
    if not os.path.exists(OUTPUT_DIRECTORY):
        os.makedirs(OUTPUT_DIRECTORY)

    my_ip = ""
    try:
        async with ClientSession() as session:
            async with session.get(TARGET_URL_HEADERS, timeout=ClientTimeout(total=5)) as response:
                data = await response.json()
                my_ip = data.get('origin')
    except Exception as e:
        print(f"{Colors.RED}Could not determine real IP. Anonymity checks may be inaccurate. Error: {e}{Colors.RESET}")

    proxies = await read_proxies(INPUT_FILE)
    if not proxies:
        print(f"{Colors.RED}No proxies to check. Exiting.{Colors.RESET}")
        return

    print(f"\n{Colors.YELLOW}Found {len(proxies)} proxies. Starting checks with {MAX_CONCURRENT_TASKS} concurrent tasks... (Your IP: {my_ip}){Colors.RESET}\n")
    
    start_time = time.time()
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
    
    async with ClientSession() as geo_session:
        tasks = [check_proxy(p, my_ip, geo_session, semaphore) for p in proxies]
        results = await asyncio.gather(*tasks)

    total_time = time.time() - start_time
    
    working_proxies = [r for r in results if r and r.status == "WORKING"]
    failed_count = len(proxies) - len(working_proxies)
    
    if working_proxies:
        save_working_proxies(working_proxies)

    print("\n--- Summary ---")
    print(f"Total proxies tested: {len(proxies)}")
    print(f"{Colors.GREEN}Working proxies: {len(working_proxies)}{Colors.RESET}")
    print(f"{Colors.RED}Failed proxies: {failed_count}{Colors.RESET}")
    print(f"Total time: {total_time:.2f} seconds")

def is_loopback_address(ip_string: str) -> bool:
    """
    Determines if the given string is a loopback IP address.

    This function checks for both IPv4 (127.0.0.0/8) and IPv6 (::1)
    loopback addresses using Python's standard `ipaddress` module.

    Args:
        ip_string: The IP address string to check.

    Returns:
        True if the address is a loopback address, False otherwise.
        Returns False for invalid IP address strings.
    """
    try:
        ip = ipaddress.ip_address(ip_string)
        return ip.is_loopback
    except ValueError:
        return False

