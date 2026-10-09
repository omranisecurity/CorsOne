from corsone.validators import normalize_url, parse_header_json, validate_domain, validate_proxy_url


def test_normalize_url_adds_scheme() -> None:
    assert normalize_url("example.com") == "https://example.com"


def test_validate_domain_rejects_scheme() -> None:
    try:
        validate_domain("https://example.com")
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError for a scheme-prefixed domain")


def test_parse_header_json_supports_mixed_values() -> None:
    parsed = parse_header_json('{"Cookie": "session=abc", "X-Test": "1"}')
    assert parsed == {"Cookie": "session=abc", "X-Test": "1"}


def test_validate_proxy_url_rejects_socks() -> None:
    try:
        validate_proxy_url("socks5://127.0.0.1:1080")
    except ValueError:
        pass
    else:
        raise AssertionError("SOCKS proxies should be rejected")
