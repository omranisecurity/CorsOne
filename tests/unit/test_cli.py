from corsone import __version__
from corsone.cli import build_parser, main


def test_parser_defaults() -> None:
    parser = build_parser()
    args = parser.parse_args(["-u", "https://example.com"])
    assert args.method == "GET"
    assert args.workers == 5
    assert args.timeout == 10


def test_main_version(capsys) -> None:
    exit_code = main(["--version"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert f"CorsOne {__version__}" in captured.out
