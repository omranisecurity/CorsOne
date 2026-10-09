from corsone.payloads import generate_payloads


def test_generate_payloads_contains_expected_names() -> None:
    payloads = generate_payloads("example.com", "attacker.com")
    assert "Reflected Origin" in payloads
    assert "Null Origin" in payloads
    assert payloads["Reflected Origin"] == "https://attacker.com"
    assert payloads["Breaking TLS"] == "http://example.com"
    assert len(payloads) == len(set(payloads.values()))
