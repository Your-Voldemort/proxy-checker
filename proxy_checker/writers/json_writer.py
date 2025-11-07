"""Write validation results to a JSON file."""

import json
from typing import List

from ..models import ValidationResult
from .base_writer import BaseWriter

class JsonWriter(BaseWriter):
    """Write validation results to a JSON file."""

    def __init__(self, output_file: str):
        self.output_file = output_file

    def write(self, results: List[ValidationResult]) -> None:
        """
        Write the validation results to a JSON file.

        Args:
            results: A list of validation results.
        """
        output = []
        for result in results:
            if result.is_working:
                output.append(
                    {
                        "proxy": str(result.proxy),
                        "protocol": result.protocol,
                        "latency_ms": result.latency,
                        "anonymity": result.anonymity,
                        "geolocation": {
                            "country": result.geolocation.country,
                            "city": result.geolocation.city,
                            "isp": result.geolocation.isp,
                        },
                        "website_tests": result.website_tests,
                    }
                )

        with open(self.output_file, "w") as f:
            json.dump(output, f, indent=2)