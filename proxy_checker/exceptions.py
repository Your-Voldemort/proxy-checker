"""Custom exceptions for the proxy checker."""


class ProxyCheckerError(Exception):
    """Base exception for the proxy checker."""
    pass


class ProxyParsingError(ProxyCheckerError):
    """Raised when a proxy string cannot be parsed."""
    pass


class ValidationError(ProxyCheckerError):
    """Base exception for validation errors."""
    
    def __init__(self, message: str, proxy: str, details: dict = None):
        self.proxy = proxy
        self.details = details or {}
        super().__init__(message)


class ProtocolDetectionError(ValidationError):
    """Raised when proxy protocol cannot be detected."""
    pass


class AnonymityCheckError(ValidationError):
    """Raised for errors during anonymity checks."""
    pass


class GeolocationError(ValidationError):
    """Raised for errors related to geolocation lookups."""
    pass


class ConnectorError(ValidationError):
    """Raised for connector-related issues."""
    pass