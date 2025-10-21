"""Output formatters for validation results."""

import abc
import csv
import json
import sys
from typing import List, IO, Dict, Any

from .models import ValidationResult


class BaseWriter(abc.ABC):
    """Abstract base class for result writers."""

    def __init__(self, output_file: IO[str] = sys.stdout):
        self._output: IO[str] = output_file

    @abc.abstractmethod
    def write(self, results: List[ValidationResult]) -> None:
        """Write the validation results."""
        pass


class TextWriter(BaseWriter):
    """Writes results in a human-readable text format."""

    def write(self, results: List[ValidationResult]) -> None:
        for r in results:
            if r.is_working:
                status = "WORKING"
                details = (
                    f"Latency: {r.latency:.2f}ms | "
                    f"Anonymity: {r.anonymity} | "
                    f"Location: {r.geolocation}"
                )
            else:
                status = "FAILED"
                details = f"Error: {r.error}"

            self._output.write(f"[{status}] {str(r.proxy):<40} | {details}\n")


class JsonWriter(BaseWriter):
    """Writes results in JSON format."""

    def write(self, results: List[ValidationResult]) -> None:
        output_data: List[Dict[str, Any]] = []
        for r in results:
            output_data.append(
                {
                    "proxy": str(r.proxy),
                    "is_working": r.is_working,
                    "latency_ms": r.latency,
                    "anonymity": r.anonymity,
                    "geolocation": r.geolocation,
                    "error": r.error,
                }
            )
        json.dump(output_data, self._output, indent=4)
        self._output.write("\n")


class CsvWriter(BaseWriter):
    """Writes results in CSV format."""

    def write(self, results: List[ValidationResult]) -> None:
        fieldnames: List[str] = [
            "proxy",
            "is_working",
            "latency_ms",
            "anonymity",
            "geolocation",
            "error",
        ]
        writer = csv.DictWriter(self._output, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(
                {
                    "proxy": str(r.proxy),
                    "is_working": r.is_working,
                    "latency_ms": f"{r.latency:.2f}",
                    "anonymity": r.anonymity,
                    "geolocation": r.geolocation,
                    "error": r.error,
                }
            )


def get_writer(
    format_type: str, output_file: IO[str] = sys.stdout
) -> BaseWriter:
    """Factory function to get the appropriate writer."""
    if format_type.lower() == "json":
        return JsonWriter(output_file)
    if format_type.lower() == "csv":
        return CsvWriter(output_file)
    return TextWriter(output_file)