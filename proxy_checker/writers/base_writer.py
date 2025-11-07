"""Base class for all output writers."""

from abc import ABC, abstractmethod
from typing import List

from ..models import ValidationResult

class BaseWriter(ABC):
    """Abstract base class for all output writers."""

    @abstractmethod
    def write(self, results: List[ValidationResult]) -> None:
        """
        Write the validation results to a file.

        Args:
            results: A list of validation results.
        """
        raise NotImplementedError