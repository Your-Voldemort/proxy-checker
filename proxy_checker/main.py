"""Main entry point for the Asynchronous Proxy Checker."""

import asyncio
import logging
import sys
import argparse
from typing import List

from aiohttp import ClientSession

from .config import (
    DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT,
)
from .models import Proxy, ValidationResult
from .parsers.proxy_parser import parse_proxy
from .validation.validator import validate_proxy
from .writers.csv_writer import CsvWriter
from .writers.json_writer import JsonWriter


def parse_args() -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Asynchronous Proxy Checker.")
    parser.add_argument(
        "proxy_source",
        nargs="?",
        default=None,
        help="Path to the file containing proxies. If not provided, reads from stdin.",
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
    parser.add_argument(
        "--test-urls",
        type=str,
        default=None,
        help="A comma-separated list of URLs to test proxies against.",
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
        p
        for p in [parse_proxy(line) for line in proxy_lines if line.strip()]
        if p is not None
    ]

    if not proxies:
        logging.warning("No valid proxies found. Exiting.")
        sys.exit(1)

    logging.info(f"Found {len(proxies)} proxies to check.")
    test_urls: List[str] = (
        [url.strip() for url in args.test_urls.split(",")] if args.test_urls else []
    )
    if test_urls:
        logging.info(f"Testing against custom URLs: {test_urls}")

    semaphore = asyncio.Semaphore(args.concurrency)

    async with ClientSession() as session:
        tasks: list[asyncio.Task] = []
        for proxy in proxies:
            task = asyncio.create_task(
                validate_proxy(proxy, session, test_urls=test_urls)
            )
            tasks.append(task)

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
        if args.format == "json":
            writer = JsonWriter(args.output)
        elif args.format == "csv":
            writer = CsvWriter(args.output)
        else:
            # Simple text writer
            with open(args.output, "w") as f:
                for result in processed_results:
                    if result.is_working:
                        f.write(f"{result.proxy}\n")
            return
        writer.write(processed_results)
    else:
        if args.format == "json":
            # Can't write json to stdout without a proper writer
            print(
                "JSON output to stdout is not supported. Please use a file with -o."
            )
        elif args.format == "csv":
            print("CSV output to stdout is not supported. Please use a file with -o.")
        else:
            for result in processed_results:
                if result.is_working:
                    print(result.proxy)


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