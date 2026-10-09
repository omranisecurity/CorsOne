import asyncio

from aiohttp import web

from corsone.config import build_scan_config
from corsone.scanner import CORSVulnerabilityScanner


async def _make_app() -> web.Application:
    async def handler(request: web.Request) -> web.Response:
        origin = request.headers.get("Origin", "")
        return web.Response(
            text="ok",
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            },
        )

    app = web.Application()
    app.router.add_get("/", handler)
    return app


def test_scanner_finds_vulnerable_origin(capsys) -> None:
    async def _run() -> None:
        app = await _make_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/"
        config = build_scan_config(type("Args", (), {
            "url": url,
            "method": "GET",
            "custom_domain": "attacker.com",
            "rate_limit": 0,
            "timeout": 5,
            "retries": 0,
            "backoff_factor": 0.5,
            "workers": 2,
            "stop_on_first": False,
            "no_color": True,
            "output": None,
            "format": "txt",
            "log": None,
            "headers": None,
            "proxy": None,
            "verbose": False,
            "vuln_only": False,
            "insecure": False,
        })())
        scanner = CORSVulnerabilityScanner(config)
        results, count = await scanner._async_scan([url])
        assert count > 0
        assert any(result.is_vulnerable for result in results)
        assert capsys.readouterr().out == ""
        await runner.cleanup()

    asyncio.run(_run())
