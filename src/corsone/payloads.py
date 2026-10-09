"""CORS bypass payload generation."""

from __future__ import annotations


def generate_payloads(origin: str, malicious_domain: str) -> dict[str, str]:
    """Generate representative CORS bypass payloads to test against a target."""
    origin = origin.strip()
    if not origin:
        raise ValueError("Origin cannot be empty when generating payloads.")

    return {
        "Reflected Origin": f"https://{malicious_domain}",
        "Breaking TLS": f"http://{origin}",
        "Trusted Subdomains": f"https://subdomain.{origin}",
        "Unencrypted Subdomains": f"http://subdomain.{origin}",
        "Null Origin": "null",
        "Unencrypted domain ends allow": f"http://attacker{origin}",
        "Domain ends allow": f"https://attacker{origin}",
        "Unencrypted localhost regex": f"http://localhost.{malicious_domain}",
        "Localhost regex": f"https://localhost.{malicious_domain}",
        "Bypass 1": f"http://{malicious_domain}.{origin}",
        "Bypass 2": f"https://{malicious_domain}.{origin}",
        "Bypass 3": f"https://{origin}._.{malicious_domain}",
        "Bypass 4": f"https://{origin}.-.{malicious_domain}",
        "Bypass 5": f"https://{origin}.,.{malicious_domain}",
        "Bypass 6": f"https://{origin}.;.{malicious_domain}",
        "Bypass 7": f"https://{origin}.!.{malicious_domain}",
        "Bypass 8": f"https://{origin}.' .{malicious_domain}",
        "Bypass 9": f"https://{origin}.\".{malicious_domain}",
        "Bypass 10": f"https://{origin}.({malicious_domain}",
        "Bypass 11": f"https://{origin}.){malicious_domain}",
        "Bypass 12": f"https://{origin}" + ".{" + f"{malicious_domain}",
        "Bypass 13": f"https://{origin}" + ".}" + f"{malicious_domain}",
        "Bypass 14": f"https://{origin}.*.{malicious_domain}",
        "Bypass 15": f"https://{origin}.&.{malicious_domain}",
        "Bypass 16": f"https://{origin}.`.{malicious_domain}",
        "Bypass 17": f"https://{origin}.+.{malicious_domain}",
        "Bypass 18": f"https://{origin}.{malicious_domain}",
        "Bypass 19": f"https://{origin}.=.{malicious_domain}",
        "Bypass 20": f"https://{origin}.~.{malicious_domain}",
        "Bypass 21": f"https://{origin}.$.{malicious_domain}",
        "Bypass 22": f"http://s{origin}",
        "Bypass 23": f"https://{origin.replace('.', 'x')}",
        "Regexp bypass 1": f"{origin},.{malicious_domain}",
        "Regexp bypass 2": f"{origin}&.{malicious_domain}",
        "Regexp bypass 3": f"{origin}'.{malicious_domain}",
        "Regexp bypass 4": f"{origin}\".{malicious_domain}",
        "Regexp bypass 5": f"{origin};.{malicious_domain}",
        "Regexp bypass 6": f"{origin}!.{malicious_domain}",
        "Regexp bypass 7": f"{origin}$.{malicious_domain}",
        "Regexp bypass 8": f"{origin}^.{malicious_domain}",
        "Regexp bypass 9": f"{origin}*.{malicious_domain}",
        "Regexp bypass 10": f"{origin}(.{malicious_domain}",
        "Regexp bypass 11": f"{origin}).{malicious_domain}",
        "Regexp bypass 12": f"{origin}+.{malicious_domain}",
        "Regexp bypass 13": f"{origin}=.{malicious_domain}",
        "Regexp bypass 14": f"{origin}`.{malicious_domain}",
        "Regexp bypass 15": f"{origin}~.{malicious_domain}",
        "Regexp bypass 16": f"{origin}-.{malicious_domain}",
        "Regexp bypass 17": f"{origin}_.{malicious_domain}",
        "Regexp bypass 18": f"{origin}|.{malicious_domain}",
        "Regexp bypass 21": f"{origin}%.{malicious_domain}",
    }


__all__ = ["generate_payloads"]
