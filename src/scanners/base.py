from abc import ABC, abstractmethod

from src.api.models import Finding


class BaseScannerAdapter(ABC):
    tool_name: str

    @abstractmethod
    def execute_scan(self, target_path: str) -> list[Finding]:
        """Execute the scanner and return normalized findings."""
