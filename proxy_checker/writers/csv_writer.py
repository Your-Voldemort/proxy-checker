"""Write validation results to a CSV file."""

import csv
from typing import List

from ..models import ValidationResult
from .base_writer import BaseWriter

class CsvWriter(BaseWriter):
    """Write validation results to a CSV file."""

    def __init__(self, output_file: str):
        self.output_file = output_file

    def write(self, results: List[ValidationResult]) -> None:
        """
        Write the validation results to a CSV file.

        Args:
            results: A list of validation results.
        """
        with open(self.output_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "proxy",
                    "protocol",
                    "latency_ms",
                    "anonymity",
                    "country",
                    "city",
                    "isp",
                ]
            )
            for result in results:
                if result.is_working:
                    writer.writerow(
                        [
                            str(result.proxy),
                            result.protocol,
                            result.latency,
                            result.anonymity,
                            result.geolocation.country,
                            result.geolocation.city,
                            result.geolocation.isp,
                        ]
                    )