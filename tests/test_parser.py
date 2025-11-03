"""Unit tests for the proxy string parser."""

import pytest
from proxy_checker.main import parse_proxy_string
from proxy_checker.models import Proxy

@pytest.mark.parametrize(
    "proxy_str, expected",
    [
        (
            "http://user:pass@127.0.0.1:8080",
            Proxy("127.0.0.1", 8080, "http", "user", "pass"),
        ),
        ("socks5://1.2.3.4:1080", Proxy("1.2.3.4", 1080, "socks5")),
        ("127.0.0.1:8000", Proxy("127.0.0.1", 8000)),
        (
            "4.5.6.7:80:user:pass",
            Proxy("4.5.6.7", 80, None, "user", "pass"),
        ),
        ("invalid-string", None),
        ("127.0.0.1:port", None),
    ],
)
def test_parse_proxy_string(proxy_str, expected):
    """Tests that various proxy string formats are parsed correctly."""
    assert parse_proxy_string(proxy_str) == expected