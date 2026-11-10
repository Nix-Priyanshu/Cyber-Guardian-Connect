"""Base class that every connector implements."""
from abc import ABC, abstractmethod
from typing import List, Tuple

from .models import Incident


class ConnectorError(Exception):
    """Raised with a message that is safe to show to the user."""


class BaseConnector(ABC):
    type_label = ""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def test_connection(self) -> Tuple[bool, str]:
        """Return (ok, message). Must not raise for expected problems."""

    @abstractmethod
    def fetch_incidents(self) -> List[Incident]:
        """Return incidents in the common format. Raises ConnectorError on failure."""
