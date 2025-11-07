"""Custom exceptions for the proxy checker."""

class ProxyCheckerError(Exception):
    """Base exception for the proxy checker."""

class ProxyParsingError(ProxyCheckerError):
    """Raised when a proxy string cannot be parsed."""

class GeolocationError(ProxyCheckerError):
    """Raised for errors related to geolocation lookups."""

class AnonymityCheckError(ProxyCheckerError):
    """Raised for errors during anonymity checks."""