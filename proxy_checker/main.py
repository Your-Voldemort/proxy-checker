"""Main entry point for the Asynchronous Proxy Checker."""

import asyncio
import logging
import sys
import argparse
from pathlib import Path
from urllib.parse import urlparse
from typing import List

from aiohttp import ClientSession

from .config import (
    DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT,
)
from .models import Proxy, ValidationResult
from .exceptions import ProxyParsingError
from .parsers.proxy_parser import parse_proxy
from .utils.http_client import get_my_ip
from .validator import ProxyValidator
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

def validate_args(args: argparse.Namespace) -> argparse.Namespace:
    """Validate command-line arguments."""

    # Validate concurrency
    if args.concurrency <= 0:
        logging.error(f"Concurrency must be positive, got: {args.concurrency}")
        sys.exit(1)
    if args.concurrency > 1000:
        logging.warning(
            f"Concurrency of {args.concurrency} is very high. "
            f"Consider using a lower value to avoid resource exhaustion."
        )

    # Validate timeout
    if args.timeout <= 0:
        logging.error(f"Timeout must be positive, got: {args.timeout}")
        sys.exit(1)
    if args.timeout > 300:
        logging.warning(
            f"Timeout of {args.timeout}s is very high. "
            f"This may cause long wait times."
        )

    # Validate test URLs
    if args.test_urls:
        urls = [url.strip() for url in args.test_urls.split(",")]
        validated_urls = []

        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.scheme not in ("http", "https"):
                    logging.error(
                        f"Invalid URL scheme '{parsed.scheme}' in {url}. "
                        f"Only http and https are supported."
                    )
                    sys.exit(1)
                if not parsed.netloc:
                    logging.error(f"Invalid URL format: {url}")
                    sys.exit(1)
                validated_urls.append(url)
            except Exception as e:
                logging.error(f"Invalid URL '{url}': {e}")
                sys.exit(1)

        args.test_urls = ",".join(validated_urls)

    # Validate output path
    if args.output:
        output_path = Path(args.output)
        if output_path.exists() and not output_path.is_file():
            logging.error(f"Output path exists and is not a file: {args.output}")
            sys.exit(1)
        # Check if directory is writable
        output_dir = output_path.parent
        if not output_dir.exists():
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                logging.error(f"Cannot create output directory: {output_dir}")
                sys.exit(1)

    # Validate proxy source
    if args.proxy_source:
        source_path = Path(args.proxy_source)
        if not source_path.exists():
            logging.error(f"Proxy file not found: {args.proxy_source}")
            sys.exit(1)
        if not source_path.is_file():
            logging.error(f"Proxy source is not a file: {args.proxy_source}")
            sys.exit(1)

    return args

class ProgressTracker:
    """Track and display validation progress."""

    def __init__(self, total: int, verbose: bool = False):
        self.total = total
        self.completed = 0
        self.working = 0
        self.failed = 0
        self.verbose = verbose
        self._lock = asyncio.Lock()

    async def update(self, is_working: bool) -> None:
        """Update progress counters."""
        async with self._lock:
            self.completed += 1
            if is_working:
                self.working += 1
            else:
                self.failed += 1

            if not self.verbose and sys.stdout.isatty():
                # Show progress bar in non-verbose mode
                progress = (self.completed / self.total) * 100
                bar_length = 40
                filled = int(bar_length * self.completed / self.total)
                bar = "=" * filled + "-" * (bar_length - filled)

                print(
                    f"\rProgress: [{bar}] {progress:.1f}% "
                    f"({self.completed}/{self.total}) - "
                    f"Working: {self.working} Failed: {self.failed}",
                    end="",
                    flush=True,
                )
            elif self.verbose and self.completed % 10 == 0:
                logging.info(
                    f"Progress: {self.completed}/{self.total} proxies checked"
                )

    def finish(self) -> None:
        """Print final newline."""
        if not self.verbose and sys.stdout.isatty():
            print()  # New line after progress bar


async def validate_with_progress(
    validator: ProxyValidator,
    semaphore: asyncio.Semaphore,
    progress: ProgressTracker,
) -> ValidationResult:
    """Validate proxy and update progress."""
    async with semaphore:
        result = await validator.check()
        await progress.update(result.is_working)
        return result


async def main() -> None:
    """Main asynchronous function."""
    args: argparse.Namespace = parse_args()
    args = validate_args(args)  # Add validation

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

    proxies: list[Proxy] = []
    for line in proxy_lines:
        if not line.strip():
            continue
        try:
            proxy = parse_proxy(line)
            proxies.append(proxy)
        except ProxyParsingError as e:
            if args.verbose:
                logging.warning(f"Skipping invalid proxy: {e}")
            continue

    if not proxies:
        logging.warning("No valid proxies found. Exiting.")
        sys.exit(1)

    logging.info(f"Found {len(proxies)} proxies to check.")
    test_urls: List[str] = (
        [url.strip() for url in args.test_urls.split(",")] if args.test_urls else []
    )
    if test_urls:
        logging.info(f"Testing against custom URLs: {test_urls}")

    # Get user's real IP for anonymity checks
    my_ip = await get_my_ip()
    if not my_ip:
        logging.warning("Could not detect real IP. Anonymity checks will be skipped.")

    # Create progress tracker
    progress = ProgressTracker(total=len(proxies), verbose=args.verbose)

    semaphore = asyncio.Semaphore(args.concurrency)

    async with ClientSession() as session:
        tasks = [
            asyncio.create_task(
                validate_with_progress(
                    ProxyValidator(
                        session, proxy, my_ip, args.timeout, test_urls
                    ),
                    semaphore,
                    progress,
                )
            )
            for proxy in proxies
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

    progress.finish()

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