"""Async scanner implementation."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from threading import Lock
from urllib.parse import unquote, urlparse

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

from .models import ScanConfig, ScanResult
from .payloads import generate_payloads

logger = logging.getLogger("corsone.scanner")
output_lock = Lock()


class CORSVulnerabilityScanner:
    """Run CORS payload checks against one or many endpoints."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.results: list[ScanResult] = []
        self.vulnerable_results: list[ScanResult] = []
        self.error_count = 0
        self.http_status_codes: dict[int, int] = {}

    def _reset_results(self) -> None:
        self.results = []
        self.vulnerable_results = []
        self.error_count = 0
        self.http_status_codes = {}

    async def _test_bypass_async(
        self,
        session: aiohttp.ClientSession,
        url: str,
        bypass_name: str,
        bypass_value: str,
    ) -> ScanResult:
        headers = {"Origin": bypass_value}
        if self.config.custom_headers:
            headers.update(self.config.custom_headers)

        try:
            async with session.request(
                self.config.method,
                url,
                headers=headers,
                proxy=self.config.proxy,
                allow_redirects=False,
            ) as resp:
                acac = resp.headers.get("Access-Control-Allow-Credentials")
                acao = resp.headers.get("Access-Control-Allow-Origin")
                is_vulnerable = (acac is not None and acac.lower() == "true") and (
                    acao == bypass_value
                    or acao == urlparse(url).scheme + "://" + urlparse(url).netloc
                )

                with output_lock:
                    self.http_status_codes[resp.status] = (
                        self.http_status_codes.get(resp.status, 0) + 1
                    )

                result = ScanResult(
                    url=url,
                    bypass_name=bypass_name,
                    bypass_value=bypass_value,
                    is_vulnerable=is_vulnerable,
                    response_code=resp.status,
                    acac=acac,
                    acao=acao,
                )
        except asyncio.TimeoutError:
            result = ScanResult(
                url=url,
                bypass_name=bypass_name,
                bypass_value=bypass_value,
                is_vulnerable=False,
                error="Timeout",
            )
            self.error_count += 1
        except aiohttp.ClientError as exc:
            result = ScanResult(
                url=url,
                bypass_name=bypass_name,
                bypass_value=bypass_value,
                is_vulnerable=False,
                error=str(exc),
            )
            self.error_count += 1

        if self.config.rate_limit > 0:
            await asyncio.sleep(self.config.rate_limit)
        return result

    @asynccontextmanager
    async def _make_session(self) -> AsyncIterator[aiohttp.ClientSession]:
        connector = TCPConnector(
            ssl=self.config.verify_ssl,
            limit=self.config.max_workers * 2,
            use_dns_cache=True,
            ttl_dns_cache=300,
        )
        timeout = ClientTimeout(total=self.config.timeout, connect=5)
        default_headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) "
                "Gecko/20100101 Firefox/128.0"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        async with aiohttp.ClientSession(
            connector=connector,
            headers=default_headers,
            timeout=timeout,
        ) as session:
            yield session

    async def _async_scan(self, urls: Sequence[str]) -> tuple[list[ScanResult], int]:
        self._reset_results()
        async with self._make_session() as session:
            for raw_url in urls:
                url = unquote(raw_url.strip(), encoding="utf-8")
                parsed = urlparse(url)
                origin = parsed.netloc or parsed.path
                if self.config.verbose:
                    logger.info("Starting scan for %s", url)

                payloads = generate_payloads(origin, self.config.custom_domain)
                if self.config.stop_on_first:
                    for name, value in payloads.items():
                        result = await self._test_bypass_async(session, url, name, value)
                        self.results.append(result)
                        if result.is_vulnerable:
                            self.vulnerable_results.append(result)
                            break
                    continue

                semaphore = asyncio.Semaphore(self.config.max_workers)

                async def bounded(
                    target_url: str,
                    name: str,
                    value: str,
                    sem: asyncio.Semaphore = semaphore,
                ) -> ScanResult:
                    async with sem:
                        return await self._test_bypass_async(session, target_url, name, value)

                tasks = [
                    bounded(url, name, value)
                    for name, value in payloads.items()
                ]
                url_results = await asyncio.gather(*tasks)
                self.results.extend(url_results)
                self.vulnerable_results.extend(
                    result for result in url_results if result.is_vulnerable
                )
        return self.results, len(self.vulnerable_results)

    def scan(self, urls: Sequence[str] | None = None) -> tuple[list[ScanResult], int]:
        targets = list(urls) if urls is not None else [self.config.url]
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self._async_scan(targets))
        raise RuntimeError(
            "The synchronous scan() helper cannot be used from a running event loop. "
            "Await _async_scan() instead."
        )


__all__ = ["CORSVulnerabilityScanner"]
