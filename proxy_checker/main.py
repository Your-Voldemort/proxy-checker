"""Main entry point for the Asynchronous Proxy Checker."""

import argparse
import argparse
import asyncio
import logging
import sys
from typing import List
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
    """Parses a proxy string into a Proxy object."""
    if "://" in proxy_str:
        # Handle URL format like http://user:pass@host:port
        try:
            parts = proxy_str.split("://")
            protocol: str = parts[0]
            auth_host_port: str = parts[1]

            if "@" in auth_host_port:
                auth, host_port = auth_host_port.split("@")
                username, password = auth.split(":")
                host, port_str = host_port.split(":")
            else:
                username, password = None, None
                host, port_str = auth_host_port.split(":")

            return Proxy(
                protocol=protocol,
                host=host,
                port=int(port_str),
                username=username,
                password=password,
            )
        except ValueError:
            return None
    else:
        # Handle host:port:user:pass or host:port format
        parts: list[str] = proxy_str.strip().split(":")
        if len(parts) == 2:
            return Proxy(host=parts[0], port=int(parts[1]))
        elif len(parts) == 4:
            return Proxy(
                host=parts[0],
                port=int(parts[1]),
                username=parts[2],
                password=parts[3],
            )
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

        results: list[ValidationResult] = await asyncio.gather(*tasks)

    # Handle output
    output_file = open(args.output, "w") if args.output else sys.stdout
    try:
        writer = get_writer(args.format, output_file)
        writer.write(results)
    finally:
        if output_file is not sys.stdout:
            output_file.close()


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