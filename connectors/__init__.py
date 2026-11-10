"""Connectors turn data from an outside source into the common incident format."""
from .base import BaseConnector, ConnectorError
from .file_upload import FileUploadConnector
from .models import Incident
from .rest_api import RestApiConnector


def build_connector(config: dict) -> BaseConnector:
    """Create a connector from a saved connection dictionary."""
    kind = config.get("type")
    if kind == "rest":
        return RestApiConnector(config["name"], config["base_url"], config["api_key"])
    if kind == "file":
        return FileUploadConnector(config["name"], config["filename"], config["text"])
    raise ConnectorError(f"Unknown connection type: {kind!r}")


__all__ = [
    "BaseConnector",
    "ConnectorError",
    "FileUploadConnector",
    "Incident",
    "RestApiConnector",
    "build_connector",
]
