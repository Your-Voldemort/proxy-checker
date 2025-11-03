"""Pytest configuration for the test suite."""

import pytest

def pytest_configure(config):
    """
    Configures pytest and adds a custom marker for integration tests.
    
    Integration tests are designed to test the full end-to-end functionality,
    including network-dependent operations like connecting to external services.
    These tests are marked with `@pytest.mark.integration` and can be
    selectively run or skipped.
    
    To run only integration tests:
        pytest -m integration
        
    To skip integration tests:
        pytest -m "not integration"
    """
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )