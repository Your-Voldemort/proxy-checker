"""Main entry point for the Asynchronous Proxy Checker."""

import asyncio
import logging
import sys
from typing import List, Optional
import argparse
import re
from aiohttp import ClientSession

from .config import (
    DEFAULT_CONCURRENCY,
    DEFAULT_PROXY_FILE,
    DEFAULT_TIMEOUT,
    TEST_URL,
)
from .models import Proxy
from .validator import ProxyValidator
from .writers import get_writer


def parse_proxy_string(proxy_str: str) -> Optional[Proxy]:
    """
    Parses a proxy string into a Proxy object.

    Supports the following formats:
    - protocol://user:pass@host:port
    - protocol://host:port
    - host:port:user:pass
    - host:port
    """
    proxy_str = proxy_str.strip()
    
    # Regex for protocol://user:pass@host:port or protocol://host:port
    url_pattern = re.compile(
        r"^(?P<protocol>\w+)://(?:(?P<username>\w+):(?P<password>\w+)@)?"
        r"(?P<host>[^:]+):(?P<port>\d+)$"
    )
    
    # Regex for host:port:user:pass or host:port
    host_port_pattern = re.compile(
        r"^(?P<host>[^:]+):(?P<port>\d+)"
        r"(?::(?P<username>\w+):(?P<password>\w+))?$"
    )

    match = url_pattern.match(proxy_str)
    if match:
        parts = match.groupdict()
        return Proxy(
            protocol=parts.get("protocol"),
            host=parts["host"],
            port=int(parts["port"]),
            username=parts.get("username"),
            password=parts.get("password"),
        )

    match = host_port_pattern.match(proxy_str)
    if match:
        parts = match.groupdict()
        return Proxy(
            host=parts["host"],
            port=int(parts["port"]),
            username=parts.get("username"),
            password=parts.get("password"),
        )
        
    logging.debug(f"Could not parse proxy string: {proxy_str}")
    return None


def parse_args() -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Asynchronous Proxy Checker.")
    parser.add_argument(
        "proxy_source",
        nargs="?",
        default=None,
        help=f"Path to the file containing proxies. If not provided, reads from stdin.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Path to the output file. If not provided, writes to stdout.",
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        default="text",
        choices=["text", "json", "csv"],
        help="Output format. Defaults to 'text'.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging output.",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Number of concurrent checks. Defaults to {DEFAULT_CONCURRENCY}.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds. Defaults to {DEFAULT_TIMEOUT}.",
    )
    return parser.parse_args()

async def main() -> None:
    """Main asynchronous function."""
    args: argparse.Namespace = parse_args()

    # Configure logging
    log_level: int = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if args.proxy_source:
        logging.info(f"Reading proxies from {args.proxy_source}")
        try:
            with open(args.proxy_source, "r") as f:
                proxy_lines: list[str] = f.readlines()
        except FileNotFoundError:
            logging.error(f"Proxy file not found at '{args.proxy_source}'")
            sys.exit(1)
    else:
        logging.info("Reading proxies from stdin")
        proxy_lines = sys.stdin.readlines()

    proxies: list[Proxy] = [
        p for p in [parse_proxy_string(line) for line in proxy_lines if line.strip()] if p is not None
    ]

    if not proxies:
        logging.warning("No valid proxies found. Exiting.")
        sys.exit(1)

    logging.info(f"Found {len(proxies)} proxies to check.")
    semaphore = asyncio.Semaphore(args.concurrency)

    async with ClientSession() as session:
        # Get real IP for anonymity checks
        my_ip: str = ""
        try:
            async with session.get(TEST_URL, timeout=args.timeout) as response:
                data = await response.json()
                my_ip = data.get("origin", "")
                logging.info(f"Determined real IP: {my_ip}")
        except Exception as e:
            logging.error(f"Could not determine real IP: {e}")
            my_ip = ""

        tasks: list[asyncio.Task] = []
        for proxy in proxies:
            validator = ProxyValidator(session, proxy, my_ip, args.timeout)
            tasks.append(asyncio.create_task(validator.check()))

        results: list[ValidationResult] = await asyncio.gather(
            *tasks, return_exceptions=True
        )

    # Process results, separating successful ones from exceptions
    processed_results: List[ValidationResult] = []
    for result in results:
        if isinstance(result, Exception):
            logging.error(f"An error occurred during validation: {result}")
        elif result:
            processed_results.append(result)

    # Handle output
    if args.output:
        with open(args.output, "w") as f:
            writer = get_writer(args.format, f)
            writer.write(processed_results)
    else:
        writer = get_writer(args.format, sys.stdout)
        writer.write(processed_results)


def run() -> None:
    """Entry point for the console script."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("\nInterrupted by user. Exiting.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    run()